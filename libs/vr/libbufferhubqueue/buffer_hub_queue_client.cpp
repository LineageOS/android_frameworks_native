#include "include/private/dvr/buffer_hub_queue_client.h"

#include <inttypes.h>
#include <log/log.h>
#include <poll.h>
#include <sys/epoll.h>

#include <array>

#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/file_handle.h>
#include <private/dvr/bufferhub_rpc.h>

#define RETRY_EINTR(fnc_call)                 \
  ([&]() -> decltype(fnc_call) {              \
    decltype(fnc_call) result;                \
    do {                                      \
      result = (fnc_call);                    \
    } while (result == -1 && errno == EINTR); \
    return result;                            \
  })()

using android::pdx::ErrorStatus;
using android::pdx::LocalChannelHandle;
using android::pdx::Status;

namespace android {
namespace dvr {

BufferHubQueue::BufferHubQueue(LocalChannelHandle channel_handle)
    : Client{pdx::default_transport::ClientChannel::Create(
          std::move(channel_handle))},
      meta_size_(0),
      buffers_(BufferHubQueue::kMaxQueueCapacity),
      epollhup_pending_(BufferHubQueue::kMaxQueueCapacity, false),
      available_buffers_(BufferHubQueue::kMaxQueueCapacity),
      fences_(BufferHubQueue::kMaxQueueCapacity),
      capacity_(0),
      id_(-1) {
  Initialize();
}

BufferHubQueue::BufferHubQueue(const std::string& endpoint_path)
    : Client{pdx::default_transport::ClientChannelFactory::Create(
          endpoint_path)},
      meta_size_(0),
      buffers_(BufferHubQueue::kMaxQueueCapacity),
      epollhup_pending_(BufferHubQueue::kMaxQueueCapacity, false),
      available_buffers_(BufferHubQueue::kMaxQueueCapacity),
      fences_(BufferHubQueue::kMaxQueueCapacity),
      capacity_(0),
      id_(-1) {
  Initialize();
}

void BufferHubQueue::Initialize() {
  int ret = epoll_fd_.Create();
  if (ret < 0) {
    ALOGE("BufferHubQueue::BufferHubQueue: Failed to create epoll fd: %s",
          strerror(-ret));
    return;
  }

  epoll_event event = {.events = EPOLLIN | EPOLLET,
                       .data = {.u64 = static_cast<uint64_t>(
                                    BufferHubQueue::kEpollQueueEventIndex)}};
  ret = epoll_fd_.Control(EPOLL_CTL_ADD, event_fd(), &event);
  if (ret < 0) {
    ALOGE("BufferHubQueue::Initialize: Failed to add event fd to epoll set: %s",
          strerror(-ret));
  }
}

Status<void> BufferHubQueue::ImportQueue() {
  auto status = InvokeRemoteMethod<BufferHubRPC::GetQueueInfo>();
  if (!status) {
    ALOGE("BufferHubQueue::ImportQueue: Failed to import queue: %s",
          status.GetErrorMessage().c_str());
    return ErrorStatus(status.error());
  } else {
    SetupQueue(status.get().meta_size_bytes, status.get().id);
    return {};
  }
}

void BufferHubQueue::SetupQueue(size_t meta_size_bytes, int id) {
  meta_size_ = meta_size_bytes;
  id_ = id;
  meta_buffer_tmp_.reset(meta_size_ > 0 ? new uint8_t[meta_size_] : nullptr);
}

std::unique_ptr<ConsumerQueue> BufferHubQueue::CreateConsumerQueue() {
  if (auto status = CreateConsumerQueueHandle())
    return std::unique_ptr<ConsumerQueue>(new ConsumerQueue(status.take()));
  else
    return nullptr;
}

std::unique_ptr<ConsumerQueue> BufferHubQueue::CreateSilentConsumerQueue() {
  if (auto status = CreateConsumerQueueHandle())
    return std::unique_ptr<ConsumerQueue>(
        new ConsumerQueue(status.take(), true));
  else
    return nullptr;
}

Status<LocalChannelHandle> BufferHubQueue::CreateConsumerQueueHandle() {
  auto status = InvokeRemoteMethod<BufferHubRPC::CreateConsumerQueue>();
  if (!status) {
    ALOGE(
        "BufferHubQueue::CreateConsumerQueue: Failed to create consumer queue: "
        "%s",
        status.GetErrorMessage().c_str());
    return ErrorStatus(status.error());
  }

  return status;
}

bool BufferHubQueue::WaitForBuffers(int timeout) {
  std::array<epoll_event, kMaxEvents> events;

  // Loop at least once to check for hangups.
  do {
    ALOGD_IF(
        TRACE,
        "BufferHubQueue::WaitForBuffers: queue_id=%d count=%zu capacity=%zu",
        id(), count(), capacity());

    // If there is already a buffer then just check for hangup without waiting.
    const int ret = epoll_fd_.Wait(events.data(), events.size(),
                                   count() == 0 ? timeout : 0);

    if (ret == 0) {
      ALOGI_IF(TRACE,
               "BufferHubQueue::WaitForBuffers: No events before timeout: "
               "queue_id=%d",
               id());
      return count() != 0;
    }

    if (ret < 0 && ret != -EINTR) {
      ALOGE("BufferHubQueue::WaitForBuffers: Failed to wait for buffers: %s",
            strerror(-ret));
      return false;
    }

    const int num_events = ret;

    // A BufferQueue's epoll fd tracks N+1 events, where there are N events,
    // one for each buffer, in the queue and one extra event for the queue
    // client itself.
    for (int i = 0; i < num_events; i++) {
      int64_t index = static_cast<int64_t>(events[i].data.u64);

      ALOGD_IF(TRACE,
               "BufferHubQueue::WaitForBuffers: event %d: index=%" PRId64, i,
               index);

      if (is_buffer_event_index(index)) {
        HandleBufferEvent(static_cast<size_t>(index), events[i].events);
      } else if (is_queue_event_index(index)) {
        HandleQueueEvent(events[i].events);
      } else {
        ALOGW("BufferHubQueue::WaitForBuffers: Unknown event index: %" PRId64,
              index);
      }
    }
  } while (count() == 0 && capacity() > 0 && !hung_up());

  return count() != 0;
}

void BufferHubQueue::HandleBufferEvent(size_t slot, int poll_events) {
  auto buffer = buffers_[slot];
  if (!buffer) {
    ALOGW("BufferHubQueue::HandleBufferEvent: Invalid buffer slot: %zu", slot);
    return;
  }

  auto status = buffer->GetEventMask(poll_events);
  if (!status) {
    ALOGW("BufferHubQueue::HandleBufferEvent: Failed to get event mask: %s",
          status.GetErrorMessage().c_str());
    return;
  }

  const int events = status.get();
  if (events & EPOLLIN) {
    const int ret = OnBufferReady(buffer, &fences_[slot]);
    if (ret == 0 || ret == -EALREADY || ret == -EBUSY) {
      // Only enqueue the buffer if it moves to or is already in the state
      // requested in OnBufferReady(). If the buffer is busy this means that the
      // buffer moved from released to posted when a new consumer was created
      // before the ProducerQueue had a chance to regain it. This is a valid
      // transition that we have to handle because edge triggered poll events
      // latch the ready state even if it is later de-asserted -- don't enqueue
      // or print an error log in this case.
      if (ret != -EBUSY)
        Enqueue(buffer, slot);
    } else {
      ALOGE(
          "BufferHubQueue::HandleBufferEvent: Failed to set buffer ready, "
          "queue_id=%d buffer_id=%d: %s",
          id(), buffer->id(), strerror(-ret));
    }
  } else if (events & EPOLLHUP) {
    // This might be caused by producer replacing an existing buffer slot, or
    // when BufferHubQueue is shutting down. For the first case, currently the
    // epoll FD is cleaned up when the replacement consumer client is imported,
    // we shouldn't detach again if |epollhub_pending_[slot]| is set.
    ALOGW(
        "BufferHubQueue::HandleBufferEvent: Received EPOLLHUP at slot: %zu, "
        "buffer event fd: %d, EPOLLHUP pending: %d",
        slot, buffer->event_fd(), int{epollhup_pending_[slot]});
    if (epollhup_pending_[slot]) {
      epollhup_pending_[slot] = false;
    } else {
      DetachBuffer(slot);
    }
  } else {
    ALOGW(
        "BufferHubQueue::HandleBufferEvent: Unknown event, slot=%zu, epoll "
        "events=%d",
        slot, events);
  }
}

void BufferHubQueue::HandleQueueEvent(int poll_event) {
  auto status = GetEventMask(poll_event);
  if (!status) {
    ALOGW("BufferHubQueue::HandleQueueEvent: Failed to get event mask: %s",
          status.GetErrorMessage().c_str());
    return;
  }

  const int events = status.get();
  if (events & EPOLLIN) {
    // Note that after buffer imports, if |count()| still returns 0, epoll
    // wait will be tried again to acquire the newly imported buffer.
    auto buffer_status = OnBufferAllocated();
    if (!buffer_status) {
      ALOGE("BufferHubQueue::HandleQueueEvent: Failed to import buffer: %s",
            buffer_status.GetErrorMessage().c_str());
    }
  } else if (events & EPOLLHUP) {
    ALOGD_IF(TRACE, "BufferHubQueue::HandleQueueEvent: hang up event!");
    hung_up_ = true;
  } else {
    ALOGW("BufferHubQueue::HandleQueueEvent: Unknown epoll events=%x", events);
  }
}

int BufferHubQueue::AddBuffer(const std::shared_ptr<BufferHubBuffer>& buf,
                              size_t slot) {
  if (is_full()) {
    // TODO(jwcai) Move the check into Producer's AllocateBuffer and consumer's
    // import buffer.
    ALOGE("BufferHubQueue::AddBuffer queue is at maximum capacity: %zu",
          capacity_);
    return -E2BIG;
  }

  if (buffers_[slot] != nullptr) {
    // Replace the buffer if the slot is preoccupied. This could happen when the
    // producer side replaced the slot with a newly allocated buffer. Detach the
    // buffer before setting up with the new one.
    DetachBuffer(slot);
    epollhup_pending_[slot] = true;
  }

  epoll_event event = {.events = EPOLLIN | EPOLLET, .data = {.u64 = slot}};
  const int ret = epoll_fd_.Control(EPOLL_CTL_ADD, buf->event_fd(), &event);
  if (ret < 0) {
    ALOGE("BufferHubQueue::AddBuffer: Failed to add buffer to epoll set: %s",
          strerror(-ret));
    return ret;
  }

  buffers_[slot] = buf;
  capacity_++;
  return 0;
}

int BufferHubQueue::DetachBuffer(size_t slot) {
  auto& buf = buffers_[slot];
  if (buf == nullptr) {
    ALOGE("BufferHubQueue::DetachBuffer: Invalid slot: %zu", slot);
    return -EINVAL;
  }

  const int ret = epoll_fd_.Control(EPOLL_CTL_DEL, buf->event_fd(), nullptr);
  if (ret < 0) {
    ALOGE(
        "BufferHubQueue::DetachBuffer: Failed to detach buffer from epoll set: "
        "%s",
        strerror(-ret));
    return ret;
  }

  buffers_[slot] = nullptr;
  capacity_--;
  return 0;
}

void BufferHubQueue::Enqueue(const std::shared_ptr<BufferHubBuffer>& buf,
                             size_t slot) {
  if (count() == capacity_) {
    ALOGE("BufferHubQueue::Enqueue: Buffer queue is full!");
    return;
  }

  // Set slot buffer back to vector.
  // TODO(jwcai) Here have to dynamically allocate BufferInfo::metadata due to
  // the limitation of the RingBuffer we are using. Would be better to refactor
  // that.
  BufferInfo buffer_info(slot, meta_size_);
  buffer_info.buffer = buf;
  // Swap metadata loaded during onBufferReady into vector.
  std::swap(buffer_info.metadata, meta_buffer_tmp_);

  available_buffers_.Append(std::move(buffer_info));
}

Status<std::shared_ptr<BufferHubBuffer>> BufferHubQueue::Dequeue(
    int timeout, size_t* slot, void* meta, LocalHandle* fence) {
  ALOGD_IF(TRACE, "Dequeue: count=%zu, timeout=%d", count(), timeout);

  if (!WaitForBuffers(timeout))
    return ErrorStatus(ETIMEDOUT);

  std::shared_ptr<BufferHubBuffer> buf;
  BufferInfo& buffer_info = available_buffers_.Front();

  *fence = std::move(fences_[buffer_info.slot]);

  // Report current pos as the output slot.
  std::swap(buffer_info.slot, *slot);
  // Swap buffer from vector to be returned later.
  std::swap(buffer_info.buffer, buf);
  // Swap metadata from vector into tmp so that we can write out to |meta|.
  std::swap(buffer_info.metadata, meta_buffer_tmp_);

  available_buffers_.PopFront();

  if (!buf) {
    ALOGE("BufferHubQueue::Dequeue: Buffer to be dequeued is nullptr");
    return ErrorStatus(ENOBUFS);
  }

  if (meta) {
    std::copy(meta_buffer_tmp_.get(), meta_buffer_tmp_.get() + meta_size_,
              reinterpret_cast<uint8_t*>(meta));
  }

  return {std::move(buf)};
}

ProducerQueue::ProducerQueue(size_t meta_size)
    : ProducerQueue(meta_size, 0, 0, 0, 0) {}

ProducerQueue::ProducerQueue(LocalChannelHandle handle)
    : BASE(std::move(handle)) {
  auto status = ImportQueue();
  if (!status) {
    ALOGE("ProducerQueue::ProducerQueue: Failed to import queue: %s",
          status.GetErrorMessage().c_str());
    Close(-status.error());
  }
}

ProducerQueue::ProducerQueue(size_t meta_size, uint64_t usage_set_mask,
                             uint64_t usage_clear_mask,
                             uint64_t usage_deny_set_mask,
                             uint64_t usage_deny_clear_mask)
    : BASE(BufferHubRPC::kClientPath) {
  auto status = InvokeRemoteMethod<BufferHubRPC::CreateProducerQueue>(
      meta_size, UsagePolicy{usage_set_mask, usage_clear_mask,
                             usage_deny_set_mask, usage_deny_clear_mask});
  if (!status) {
    ALOGE("ProducerQueue::ProducerQueue: Failed to create producer queue: %s",
          status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  SetupQueue(status.get().meta_size_bytes, status.get().id);
}

int ProducerQueue::AllocateBuffer(uint32_t width, uint32_t height,
                                  uint32_t layer_count, uint32_t format,
                                  uint64_t usage, size_t* out_slot) {
  if (out_slot == nullptr) {
    ALOGE("ProducerQueue::AllocateBuffer: Parameter out_slot cannot be null.");
    return -EINVAL;
  }

  if (is_full()) {
    ALOGE("ProducerQueue::AllocateBuffer queue is at maximum capacity: %zu",
          capacity());
    return -E2BIG;
  }

  const size_t kBufferCount = 1U;
  Status<std::vector<std::pair<LocalChannelHandle, size_t>>> status =
      InvokeRemoteMethod<BufferHubRPC::ProducerQueueAllocateBuffers>(
          width, height, layer_count, format, usage, kBufferCount);
  if (!status) {
    ALOGE("ProducerQueue::AllocateBuffer failed to create producer buffer: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  auto buffer_handle_slots = status.take();
  LOG_ALWAYS_FATAL_IF(buffer_handle_slots.size() != kBufferCount,
                      "BufferHubRPC::ProducerQueueAllocateBuffers should "
                      "return one and only one buffer handle.");

  // We only allocate one buffer at a time.
  auto& buffer_handle = buffer_handle_slots[0].first;
  size_t buffer_slot = buffer_handle_slots[0].second;
  ALOGD_IF(TRACE,
           "ProducerQueue::AllocateBuffer, new buffer, channel_handle: %d",
           buffer_handle.value());

  *out_slot = buffer_slot;
  return AddBuffer(BufferProducer::Import(std::move(buffer_handle)),
                   buffer_slot);
}

int ProducerQueue::AddBuffer(const std::shared_ptr<BufferProducer>& buf,
                             size_t slot) {
  ALOGD_IF(TRACE, "ProducerQueue::AddBuffer: queue_id=%d buffer_id=%d slot=%zu",
           id(), buf->id(), slot);
  // For producer buffer, we need to enqueue the newly added buffer
  // immediately. Producer queue starts with all buffers in available state.
  const int ret = BufferHubQueue::AddBuffer(buf, slot);
  if (ret < 0)
    return ret;

  Enqueue(buf, slot);
  return 0;
}

int ProducerQueue::DetachBuffer(size_t slot) {
  auto status =
      InvokeRemoteMethod<BufferHubRPC::ProducerQueueDetachBuffer>(slot);
  if (!status) {
    ALOGE("ProducerQueue::DetachBuffer: Failed to detach producer buffer: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  return BufferHubQueue::DetachBuffer(slot);
}

Status<std::shared_ptr<BufferProducer>> ProducerQueue::Dequeue(
    int timeout, size_t* slot, LocalHandle* release_fence) {
  if (slot == nullptr || release_fence == nullptr) {
    ALOGE("ProducerQueue::Dequeue: Invalid parameter: slot=%p release_fence=%p",
          slot, release_fence);
    return ErrorStatus(EINVAL);
  }

  auto buffer_status =
      BufferHubQueue::Dequeue(timeout, slot, nullptr, release_fence);
  if (!buffer_status)
    return buffer_status.error_status();

  return {std::static_pointer_cast<BufferProducer>(buffer_status.take())};
}

int ProducerQueue::OnBufferReady(const std::shared_ptr<BufferHubBuffer>& buf,
                                 LocalHandle* release_fence) {
  ALOGD_IF(TRACE, "ProducerQueue::OnBufferReady: queue_id=%d buffer_id=%d",
           id(), buf->id());
  auto buffer = std::static_pointer_cast<BufferProducer>(buf);
  return buffer->Gain(release_fence);
}

ConsumerQueue::ConsumerQueue(LocalChannelHandle handle, bool ignore_on_import)
    : BufferHubQueue(std::move(handle)), ignore_on_import_(ignore_on_import) {
  auto status = ImportQueue();
  if (!status) {
    ALOGE("ConsumerQueue::ConsumerQueue: Failed to import queue: %s",
          status.GetErrorMessage().c_str());
    Close(-status.error());
  }

  auto import_status = ImportBuffers();
  if (import_status) {
    ALOGI("ConsumerQueue::ConsumerQueue: Imported %zu buffers.",
          import_status.get());
  } else {
    ALOGE("ConsumerQueue::ConsumerQueue: Failed to import buffers: %s",
          import_status.GetErrorMessage().c_str());
  }
}

Status<size_t> ConsumerQueue::ImportBuffers() {
  auto status = InvokeRemoteMethod<BufferHubRPC::ConsumerQueueImportBuffers>();
  if (!status) {
    ALOGE("ConsumerQueue::ImportBuffers: Failed to import consumer buffer: %s",
          status.GetErrorMessage().c_str());
    return ErrorStatus(status.error());
  }

  int ret;
  int last_error = 0;
  int imported_buffers = 0;

  auto buffer_handle_slots = status.take();
  for (auto& buffer_handle_slot : buffer_handle_slots) {
    ALOGD_IF(TRACE, "ConsumerQueue::ImportBuffers: buffer_handle=%d",
             buffer_handle_slot.first.value());

    std::unique_ptr<BufferConsumer> buffer_consumer =
        BufferConsumer::Import(std::move(buffer_handle_slot.first));

    // Setup ignore state before adding buffer to the queue.
    if (ignore_on_import_) {
      ALOGD_IF(TRACE,
               "ConsumerQueue::ImportBuffers: Setting buffer to ignored state: "
               "buffer_id=%d",
               buffer_consumer->id());
      ret = buffer_consumer->SetIgnore(true);
      if (ret < 0) {
        ALOGE(
            "ConsumerQueue::ImportBuffers: Failed to set ignored state on "
            "imported buffer buffer_id=%d: %s",
            buffer_consumer->id(), strerror(-ret));
        last_error = ret;
      }
    }

    ret = AddBuffer(std::move(buffer_consumer), buffer_handle_slot.second);
    if (ret < 0) {
      ALOGE("ConsumerQueue::ImportBuffers: Failed to add buffer: %s",
            strerror(-ret));
      last_error = ret;
      continue;
    } else {
      imported_buffers++;
    }
  }

  if (imported_buffers > 0)
    return {imported_buffers};
  else
    return ErrorStatus(-last_error);
}

int ConsumerQueue::AddBuffer(const std::shared_ptr<BufferConsumer>& buf,
                             size_t slot) {
  ALOGD_IF(TRACE, "ConsumerQueue::AddBuffer: queue_id=%d buffer_id=%d slot=%zu",
           id(), buf->id(), slot);
  const int ret = BufferHubQueue::AddBuffer(buf, slot);
  if (ret < 0)
    return ret;

  // Check to see if the buffer is already signaled. This is necessary to catch
  // cases where buffers are already available; epoll edge triggered mode does
  // not fire until and edge transition when adding new buffers to the epoll
  // set.
  const int kTimeoutMs = 0;
  pollfd pfd{buf->event_fd(), POLLIN, 0};
  const int count = RETRY_EINTR(poll(&pfd, 1, kTimeoutMs));
  if (count < 0) {
    const int error = errno;
    ALOGE("ConsumerQueue::AddBuffer: Failed to poll consumer buffer: %s",
          strerror(errno));
    return -error;
  }

  if (count == 1)
    HandleBufferEvent(slot, pfd.revents);

  return 0;
}

Status<std::shared_ptr<BufferConsumer>> ConsumerQueue::Dequeue(
    int timeout, size_t* slot, void* meta, size_t meta_size,
    LocalHandle* acquire_fence) {
  if (meta_size != meta_size_) {
    ALOGE(
        "ConsumerQueue::Dequeue: Metadata size (%zu) for the dequeuing buffer "
        "does not match metadata size (%zu) for the queue.",
        meta_size, meta_size_);
    return ErrorStatus(EINVAL);
  }

  if (slot == nullptr || acquire_fence == nullptr) {
    ALOGE(
        "ConsumerQueue::Dequeue: Invalid parameter: slot=%p meta=%p "
        "acquire_fence=%p",
        slot, meta, acquire_fence);
    return ErrorStatus(EINVAL);
  }

  auto buffer_status =
      BufferHubQueue::Dequeue(timeout, slot, meta, acquire_fence);
  if (!buffer_status)
    return buffer_status.error_status();

  return {std::static_pointer_cast<BufferConsumer>(buffer_status.take())};
}

int ConsumerQueue::OnBufferReady(const std::shared_ptr<BufferHubBuffer>& buf,
                                 LocalHandle* acquire_fence) {
  ALOGD_IF(TRACE, "ConsumerQueue::OnBufferReady: queue_id=%d buffer_id=%d",
           id(), buf->id());
  auto buffer = std::static_pointer_cast<BufferConsumer>(buf);
  return buffer->Acquire(acquire_fence, meta_buffer_tmp_.get(), meta_size_);
}

Status<void> ConsumerQueue::OnBufferAllocated() {
  auto status = ImportBuffers();
  if (!status) {
    ALOGE("ConsumerQueue::OnBufferAllocated: Failed to import buffers: %s",
          status.GetErrorMessage().c_str());
    return ErrorStatus(status.error());
  } else if (status.get() == 0) {
    ALOGW("ConsumerQueue::OnBufferAllocated: No new buffers allocated!");
    return ErrorStatus(ENOBUFS);
  } else {
    ALOGD_IF(TRACE,
             "ConsumerQueue::OnBufferAllocated: Imported %zu consumer buffers.",
             status.get());
    return {};
  }
}

}  // namespace dvr
}  // namespace android
