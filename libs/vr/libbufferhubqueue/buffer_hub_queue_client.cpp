#include "include/private/dvr/buffer_hub_queue_client.h"

#include <base/logging.h>
#include <sys/epoll.h>

#include <array>

#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/file_handle.h>
#include <private/dvr/bufferhub_rpc.h>

using android::pdx::LocalHandle;
using android::pdx::LocalChannelHandle;

namespace android {
namespace dvr {

BufferHubQueue::BufferHubQueue(LocalChannelHandle channel_handle,
                               size_t meta_size)
    : Client{pdx::default_transport::ClientChannel::Create(
          std::move(channel_handle))},
      meta_size_(meta_size),
      meta_buffer_tmp_(meta_size ? new uint8_t[meta_size] : nullptr),
      buffers_(BufferHubQueue::kMaxQueueCapacity),
      available_buffers_(BufferHubQueue::kMaxQueueCapacity),
      capacity_(0) {
  Initialize();
}

BufferHubQueue::BufferHubQueue(const std::string& endpoint_path,
                               size_t meta_size)
    : Client{pdx::default_transport::ClientChannelFactory::Create(
          endpoint_path)},
      meta_size_(meta_size),
      meta_buffer_tmp_(meta_size ? new uint8_t[meta_size] : nullptr),
      buffers_(BufferHubQueue::kMaxQueueCapacity),
      available_buffers_(BufferHubQueue::kMaxQueueCapacity),
      capacity_(0) {
  Initialize();
}

void BufferHubQueue::Initialize() {
  int ret = epoll_fd_.Create();
  if (ret < 0) {
    LOG(ERROR) << "BufferHubQueue::BufferHubQueue: Failed to create epoll fd:"
               << strerror(-ret);
    return;
  }

  epoll_event event = {.events = EPOLLIN | EPOLLET,
                       .data = {.u64 = static_cast<uint64_t>(
                                    BufferHubQueue::kEpollQueueEventIndex)}};
  ret = epoll_fd_.Control(EPOLL_CTL_ADD, event_fd(), &event);
  if (ret < 0) {
    LOG(ERROR) << "Failed to register ConsumerQueue into epoll event: "
               << strerror(-ret);
  }
}

std::unique_ptr<ConsumerQueue> BufferHubQueue::CreateConsumerQueue() {
  Status<std::pair<LocalChannelHandle, size_t>> status =
      InvokeRemoteMethod<BufferHubRPC::CreateConsumerQueue>();

  if (!status) {
    LOG(ERROR) << "Cannot create ConsumerQueue: " << status.GetErrorMessage();
    return nullptr;
  }

  auto return_value = status.take();

  VLOG(1) << "CreateConsumerQueue: meta_size_bytes=" << return_value.second;
  return ConsumerQueue::Create(std::move(return_value.first),
                               return_value.second);
}

bool BufferHubQueue::WaitForBuffers(int timeout) {
  std::array<epoll_event, kMaxEvents> events;

  while (count() == 0) {
    int ret = epoll_fd_.Wait(events.data(), events.size(), timeout);

    if (ret == 0) {
      VLOG(1) << "Wait on epoll returns nothing before timeout.";
      return false;
    }

    if (ret < 0 && ret != -EINTR) {
      LOG(ERROR) << "Failed to wait for buffers:" << strerror(-ret);
      return false;
    }

    const int num_events = ret;

    // A BufferQueue's epoll fd tracks N+1 events, where there are N events,
    // one for each buffer, in the queue and one extra event for the queue
    // client itself.
    for (int i = 0; i < num_events; i++) {
      int64_t index = static_cast<int64_t>(events[i].data.u64);

      VLOG(1) << "New BufferHubQueue event " << i << ": index=" << index;

      if (is_buffer_event_index(index) && (events[i].events & EPOLLIN)) {
        auto buffer = buffers_[index];
        ret = OnBufferReady(buffer);
        if (ret < 0) {
          LOG(ERROR) << "Failed to set buffer ready:" << strerror(-ret);
          continue;
        }
        Enqueue(buffer, index);
      } else if (is_buffer_event_index(index) &&
                 (events[i].events & EPOLLHUP)) {
        // This maybe caused by producer replacing an exising buffer slot.
        // Currently the epoll FD is cleaned up when the replacement consumer
        // client is imported.
        LOG(WARNING) << "Receives EPOLLHUP at slot: " << index;
      } else if (is_queue_event_index(index) && (events[i].events & EPOLLIN)) {
        // Note that after buffer imports, if |count()| still returns 0, epoll
        // wait will be tried again to acquire the newly imported buffer.
        ret = OnBufferAllocated();
        if (ret < 0) {
          LOG(ERROR) << "Failed to import buffer:" << strerror(-ret);
          continue;
        }
      } else {
        LOG(WARNING) << "Unknown event " << i << ": u64=" << index
                     << ": events=" << events[i].events;
      }
    }
  }

  return true;
}

int BufferHubQueue::AddBuffer(const std::shared_ptr<BufferHubBuffer>& buf,
                              size_t slot) {
  if (is_full()) {
    // TODO(jwcai) Move the check into Producer's AllocateBuffer and consumer's
    // import buffer.
    LOG(ERROR) << "BufferHubQueue::AddBuffer queue is at maximum capacity: "
               << capacity_;
    return -E2BIG;
  }

  if (buffers_[slot] != nullptr) {
    // Replace the buffer if the slot is preoccupied. This could happen when the
    // producer side replaced the slot with a newly allocated buffer. Detach the
    // buffer and set up with the new one.
    DetachBuffer(slot);
  }

  epoll_event event = {.events = EPOLLIN | EPOLLET, .data = {.u64 = slot}};
  const int ret = epoll_fd_.Control(EPOLL_CTL_ADD, buf->event_fd(), &event);
  if (ret < 0) {
    LOG(ERROR)
        << "BufferHubQueue::AddBuffer: Failed to add buffer to epoll set:"
        << strerror(-ret);
    return ret;
  }

  buffers_[slot] = buf;
  capacity_++;
  return 0;
}

int BufferHubQueue::DetachBuffer(size_t slot) {
  auto& buf = buffers_[slot];
  if (buf == nullptr) {
    LOG(ERROR) << "BufferHubQueue::DetachBuffer: Invalid slot: " << slot;
    return -EINVAL;
  }

  const int ret = epoll_fd_.Control(EPOLL_CTL_DEL, buf->event_fd(), nullptr);
  if (ret < 0) {
    LOG(ERROR) << "BufferHubQueue::DetachBuffer: Failed to detach buffer from  "
                  "epoll set:"
               << strerror(-ret);
    return ret;
  }

  buffers_[slot] = nullptr;
  capacity_--;
  return 0;
}

void BufferHubQueue::Enqueue(std::shared_ptr<BufferHubBuffer> buf,
                             size_t slot) {
  if (count() == capacity_) {
    LOG(ERROR) << "Buffer queue is full!";
    return;
  }

  // Set slot buffer back to vector.
  // TODO(jwcai) Here have to dynamically allocate BufferInfo::metadata due to
  // the limitation of the RingBuffer we are using. Would be better to refactor
  // that.
  BufferInfo buffer_info(slot, meta_size_);
  // Swap buffer into vector.
  std::swap(buffer_info.buffer, buf);
  // Swap metadata loaded during onBufferReady into vector.
  std::swap(buffer_info.metadata, meta_buffer_tmp_);

  available_buffers_.Append(std::move(buffer_info));
}

std::shared_ptr<BufferHubBuffer> BufferHubQueue::Dequeue(int timeout,
                                                         size_t* slot,
                                                         void* meta) {
  VLOG(1) << "Dequeue: count=" << count() << ", timeout=" << timeout;

  if (count() == 0 && !WaitForBuffers(timeout))
    return nullptr;

  std::shared_ptr<BufferHubBuffer> buf;
  BufferInfo& buffer_info = available_buffers_.Front();

  // Report current pos as the output slot.
  std::swap(buffer_info.slot, *slot);
  // Swap buffer from vector to be returned later.
  std::swap(buffer_info.buffer, buf);
  // Swap metadata from vector into tmp so that we can write out to |meta|.
  std::swap(buffer_info.metadata, meta_buffer_tmp_);

  available_buffers_.PopFront();

  if (!buf) {
    LOG(ERROR) << "Dequeue: Buffer to be dequeued is nullptr";
    return nullptr;
  }

  if (meta) {
    std::copy(meta_buffer_tmp_.get(), meta_buffer_tmp_.get() + meta_size_,
              reinterpret_cast<uint8_t*>(meta));
  }

  return buf;
}

ProducerQueue::ProducerQueue(size_t meta_size)
    : ProducerQueue(meta_size, 0, 0, 0, 0) {}

ProducerQueue::ProducerQueue(LocalChannelHandle handle, size_t meta_size)
    : BASE(std::move(handle), meta_size) {}

ProducerQueue::ProducerQueue(size_t meta_size, int usage_set_mask,
                             int usage_clear_mask, int usage_deny_set_mask,
                             int usage_deny_clear_mask)
    : BASE(BufferHubRPC::kClientPath, meta_size) {
  auto status = InvokeRemoteMethod<BufferHubRPC::CreateProducerQueue>(
      meta_size_, usage_set_mask, usage_clear_mask, usage_deny_set_mask,
      usage_deny_clear_mask);
  if (!status) {
    LOG(ERROR)
        << "ProducerQueue::ProducerQueue: Failed to create producer queue: %s"
        << status.GetErrorMessage();
    Close(-status.error());
    return;
  }
}

int ProducerQueue::AllocateBuffer(int width, int height, int format, int usage,
                                  size_t slice_count, size_t* out_slot) {
  if (out_slot == nullptr) {
    LOG(ERROR) << "Parameter out_slot cannot be null.";
    return -EINVAL;
  }

  if (is_full()) {
    LOG(ERROR) << "ProducerQueue::AllocateBuffer queue is at maximum capacity: "
               << capacity();
    return -E2BIG;
  }

  const size_t kBufferCount = 1U;

  Status<std::vector<std::pair<LocalChannelHandle, size_t>>> status =
      InvokeRemoteMethod<BufferHubRPC::ProducerQueueAllocateBuffers>(
          width, height, format, usage, slice_count, kBufferCount);
  if (!status) {
    LOG(ERROR) << "ProducerQueue::AllocateBuffer failed to create producer "
                  "buffer through BufferHub.";
    return -status.error();
  }

  auto buffer_handle_slots = status.take();
  CHECK_EQ(buffer_handle_slots.size(), kBufferCount)
      << "BufferHubRPC::ProducerQueueAllocateBuffers should return one and "
         "only one buffer handle.";

  // We only allocate one buffer at a time.
  auto& buffer_handle = buffer_handle_slots[0].first;
  size_t buffer_slot = buffer_handle_slots[0].second;
  VLOG(1) << "ProducerQueue::AllocateBuffer, new buffer, channel_handle: "
          << buffer_handle.value();

  *out_slot = buffer_slot;
  return AddBuffer(BufferProducer::Import(std::move(buffer_handle)),
                   buffer_slot);
}

int ProducerQueue::AddBuffer(const std::shared_ptr<BufferProducer>& buf,
                             size_t slot) {
  // For producer buffer, we need to enqueue the newly added buffer
  // immediately. Producer queue starts with all buffers in available state.
  const int ret = BufferHubQueue::AddBuffer(buf, slot);
  if (ret < 0)
    return ret;

  Enqueue(buf, slot);
  return 0;
}

int ProducerQueue::DetachBuffer(size_t slot) {
  Status<int> status =
      InvokeRemoteMethod<BufferHubRPC::ProducerQueueDetachBuffer>(slot);
  if (!status) {
    LOG(ERROR) << "ProducerQueue::DetachBuffer failed to detach producer "
                  "buffer through BufferHub, error: "
               << status.GetErrorMessage();
    return -status.error();
  }

  return BufferHubQueue::DetachBuffer(slot);
}

std::shared_ptr<BufferProducer> ProducerQueue::Dequeue(int timeout,
                                                       size_t* slot) {
  auto buf = BufferHubQueue::Dequeue(timeout, slot, nullptr);
  return std::static_pointer_cast<BufferProducer>(buf);
}

int ProducerQueue::OnBufferReady(std::shared_ptr<BufferHubBuffer> buf) {
  auto buffer = std::static_pointer_cast<BufferProducer>(buf);
  return buffer->GainAsync();
}

ConsumerQueue::ConsumerQueue(LocalChannelHandle handle, size_t meta_size)
    : BASE(std::move(handle), meta_size) {
  // TODO(b/34387835) Import consumer queue in case the ProducerQueue we are
  // based on was not empty.
}

int ConsumerQueue::ImportBuffers() {
  Status<std::vector<std::pair<LocalChannelHandle, size_t>>> status =
      InvokeRemoteMethod<BufferHubRPC::ConsumerQueueImportBuffers>();
  if (!status) {
    LOG(ERROR) << "ConsumerQueue::ImportBuffers failed to import consumer "
                  "buffer through BufferBub, error: "
               << status.GetErrorMessage();
    return -status.error();
  }

  int last_error = 0;
  int imported_buffers = 0;

  auto buffer_handle_slots = status.take();
  for (auto& buffer_handle_slot : buffer_handle_slots) {
    VLOG(1) << "ConsumerQueue::ImportBuffers, new buffer, buffer_handle: "
            << buffer_handle_slot.first.value();

    std::unique_ptr<BufferConsumer> buffer_consumer =
        BufferConsumer::Import(std::move(buffer_handle_slot.first));
    int ret = AddBuffer(std::move(buffer_consumer), buffer_handle_slot.second);
    if (ret < 0) {
      LOG(ERROR) << "ConsumerQueue::ImportBuffers failed to add buffer, ret: "
                 << strerror(-ret);
      last_error = ret;
      continue;
    } else {
      imported_buffers++;
    }
  }

  return imported_buffers > 0 ? imported_buffers : last_error;
}

int ConsumerQueue::AddBuffer(const std::shared_ptr<BufferConsumer>& buf,
                             size_t slot) {
  // Consumer queue starts with all buffers in unavailable state.
  return BufferHubQueue::AddBuffer(buf, slot);
}

std::shared_ptr<BufferConsumer> ConsumerQueue::Dequeue(int timeout,
                                                       size_t* slot, void* meta,
                                                       size_t meta_size) {
  if (meta_size != meta_size_) {
    LOG(ERROR) << "metadata size (" << meta_size
               << ") for the dequeuing buffer does not match metadata size ("
               << meta_size_ << ") for the queue.";
    return nullptr;
  }
  auto buf = BufferHubQueue::Dequeue(timeout, slot, meta);
  return std::static_pointer_cast<BufferConsumer>(buf);
}

int ConsumerQueue::OnBufferReady(std::shared_ptr<BufferHubBuffer> buf) {
  auto buffer = std::static_pointer_cast<BufferConsumer>(buf);
  LocalHandle fence;
  return buffer->Acquire(&fence, meta_buffer_tmp_.get(), meta_size_);
}

int ConsumerQueue::OnBufferAllocated() {
  const int ret = ImportBuffers();
  if (ret == 0) {
    LOG(WARNING) << "No new buffer can be imported on buffer allocated event.";
  } else if (ret < 0) {
    LOG(ERROR) << "Failed to import buffers on buffer allocated event.";
  }
  VLOG(1) << "Imported " << ret << " consumer buffers.";
  return ret;
}

}  // namespace dvr
}  // namespace android
