#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/poll.h>

#include <algorithm>
#include <atomic>
#include <thread>

#include <log/log.h>
#include <private/dvr/buffer_channel.h>
#include <private/dvr/bufferhub_rpc.h>
#include <private/dvr/consumer_channel.h>
#include <private/dvr/producer_channel.h>
#include <sync/sync.h>
#include <utils/Trace.h>

using android::pdx::BorrowedHandle;
using android::pdx::ErrorStatus;
using android::pdx::Message;
using android::pdx::RemoteChannelHandle;
using android::pdx::Status;
using android::pdx::rpc::BufferWrapper;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::rpc::WrapBuffer;

namespace android {
namespace dvr {

ProducerChannel::ProducerChannel(BufferHubService* service, int buffer_id,
                                 int channel_id, IonBuffer buffer,
                                 IonBuffer metadata_buffer,
                                 size_t user_metadata_size, int* error)
    : BufferHubChannel(service, buffer_id, channel_id, kProducerType),
      buffer_(std::move(buffer)),
      metadata_buffer_(std::move(metadata_buffer)),
      user_metadata_size_(user_metadata_size),
      metadata_buf_size_(BufferHubDefs::kMetadataHeaderSize +
                         user_metadata_size) {
  if (!buffer_.IsValid()) {
    ALOGE("ProducerChannel::ProducerChannel: Invalid buffer.");
    *error = -EINVAL;
    return;
  }
  if (!metadata_buffer_.IsValid()) {
    ALOGE("ProducerChannel::ProducerChannel: Invalid metadata buffer.");
    *error = -EINVAL;
    return;
  }

  *error = InitializeBuffer();
}

ProducerChannel::ProducerChannel(BufferHubService* service, int channel_id,
                                 uint32_t width, uint32_t height,
                                 uint32_t layer_count, uint32_t format,
                                 uint64_t usage, size_t user_metadata_size,
                                 int* error)
    : BufferHubChannel(service, channel_id, channel_id, kProducerType),
      pending_consumers_(0),
      producer_owns_(true),
      user_metadata_size_(user_metadata_size),
      metadata_buf_size_(BufferHubDefs::kMetadataHeaderSize +
                         user_metadata_size) {
  if (int ret = buffer_.Alloc(width, height, layer_count, format, usage)) {
    ALOGE("ProducerChannel::ProducerChannel: Failed to allocate buffer: %s",
          strerror(-ret));
    *error = ret;
    return;
  }

  if (int ret = metadata_buffer_.Alloc(metadata_buf_size_, /*height=*/1,
                                       /*layer_count=*/1,
                                       BufferHubDefs::kMetadataFormat,
                                       BufferHubDefs::kMetadataUsage)) {
    ALOGE("ProducerChannel::ProducerChannel: Failed to allocate metadata: %s",
          strerror(-ret));
    *error = ret;
    return;
  }

  *error = InitializeBuffer();
}

int ProducerChannel::InitializeBuffer() {
  void* metadata_ptr = nullptr;
  if (int ret = metadata_buffer_.Lock(BufferHubDefs::kMetadataUsage, /*x=*/0,
                                      /*y=*/0, metadata_buf_size_,
                                      /*height=*/1, &metadata_ptr)) {
    ALOGE("ProducerChannel::ProducerChannel: Failed to lock metadata.");
    return ret;
  }
  metadata_header_ =
      reinterpret_cast<BufferHubDefs::MetadataHeader*>(metadata_ptr);

  // Using placement new here to reuse shared memory instead of new allocation
  // and also initialize the value to zero.
  buffer_state_ =
      new (&metadata_header_->buffer_state) std::atomic<uint64_t>(0);
  fence_state_ = new (&metadata_header_->fence_state) std::atomic<uint64_t>(0);
  active_clients_bit_mask_ =
      new (&metadata_header_->active_clients_bit_mask) std::atomic<uint64_t>(0);

  // Producer channel is never created after consumer channel, and one buffer
  // only have one fixed producer for now. Thus, it is correct to assume
  // producer state bit is kFirstClientBitMask for now.
  active_clients_bit_mask_->store(BufferHubDefs::kFirstClientBitMask,
                                  std::memory_order_release);

  acquire_fence_fd_.Reset(epoll_create1(EPOLL_CLOEXEC));
  release_fence_fd_.Reset(epoll_create1(EPOLL_CLOEXEC));
  if (!acquire_fence_fd_ || !release_fence_fd_) {
    ALOGE("ProducerChannel::ProducerChannel: Failed to create shared fences.");
    return -EIO;
  }

  dummy_fence_fd_.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
  if (!dummy_fence_fd_) {
    ALOGE("ProducerChannel::ProducerChannel: Failed to create dummy fences.");
    return EIO;
  }

  epoll_event event;
  event.events = 0;
  event.data.u64 = 0ULL;
  if (epoll_ctl(release_fence_fd_.Get(), EPOLL_CTL_ADD, dummy_fence_fd_.Get(),
                &event) < 0) {
    ALOGE(
        "ProducerChannel::ProducerChannel: Failed to modify the shared "
        "release fence to include the dummy fence: %s",
        strerror(errno));
    return -EIO;
  }

  // Success.
  return 0;
}

std::unique_ptr<ProducerChannel> ProducerChannel::Create(
    BufferHubService* service, int buffer_id, int channel_id, IonBuffer buffer,
    IonBuffer metadata_buffer, size_t user_metadata_size) {
  int error = 0;
  std::unique_ptr<ProducerChannel> producer(new ProducerChannel(
      service, buffer_id, channel_id, std::move(buffer),
      std::move(metadata_buffer), user_metadata_size, &error));

  if (error < 0)
    return nullptr;
  else
    return producer;
}

Status<std::shared_ptr<ProducerChannel>> ProducerChannel::Create(
    BufferHubService* service, int channel_id, uint32_t width, uint32_t height,
    uint32_t layer_count, uint32_t format, uint64_t usage,
    size_t user_metadata_size) {
  int error;
  std::shared_ptr<ProducerChannel> producer(
      new ProducerChannel(service, channel_id, width, height, layer_count,
                          format, usage, user_metadata_size, &error));
  if (error < 0)
    return ErrorStatus(-error);
  else
    return {std::move(producer)};
}

ProducerChannel::~ProducerChannel() {
  ALOGD_IF(TRACE,
           "ProducerChannel::~ProducerChannel: channel_id=%d buffer_id=%d "
           "state=%" PRIx64 ".",
           channel_id(), buffer_id(),
           buffer_state_->load(std::memory_order_acquire));
  for (auto consumer : consumer_channels_) {
    consumer->OnProducerClosed();
  }
  Hangup();
}

BufferHubChannel::BufferInfo ProducerChannel::GetBufferInfo() const {
  // Derive the mask of signaled buffers in this producer / consumer set.
  uint64_t signaled_mask = signaled() ? BufferHubDefs::kFirstClientBitMask : 0;
  for (const ConsumerChannel* consumer : consumer_channels_) {
    signaled_mask |= consumer->signaled() ? consumer->client_state_mask() : 0;
  }

  return BufferInfo(buffer_id(), consumer_channels_.size(), buffer_.width(),
                    buffer_.height(), buffer_.layer_count(), buffer_.format(),
                    buffer_.usage(), pending_consumers_,
                    buffer_state_->load(std::memory_order_acquire),
                    signaled_mask, metadata_header_->queue_index);
}

void ProducerChannel::HandleImpulse(Message& message) {
  ATRACE_NAME("ProducerChannel::HandleImpulse");
  switch (message.GetOp()) {
    case BufferHubRPC::ProducerGain::Opcode:
      OnProducerGain(message);
      break;
    case BufferHubRPC::ProducerPost::Opcode:
      OnProducerPost(message, {});
      break;
  }
}

bool ProducerChannel::HandleMessage(Message& message) {
  ATRACE_NAME("ProducerChannel::HandleMessage");
  switch (message.GetOp()) {
    case BufferHubRPC::GetBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::GetBuffer>(
          *this, &ProducerChannel::OnGetBuffer, message);
      return true;

    case BufferHubRPC::NewConsumer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::NewConsumer>(
          *this, &ProducerChannel::OnNewConsumer, message);
      return true;

    case BufferHubRPC::ProducerPost::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerPost>(
          *this, &ProducerChannel::OnProducerPost, message);
      return true;

    case BufferHubRPC::ProducerGain::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerGain>(
          *this, &ProducerChannel::OnProducerGain, message);
      return true;

    default:
      return false;
  }
}

BufferDescription<BorrowedHandle> ProducerChannel::GetBuffer(
    uint64_t client_state_mask) {
  return {buffer_,
          metadata_buffer_,
          buffer_id(),
          channel_id(),
          client_state_mask,
          acquire_fence_fd_.Borrow(),
          release_fence_fd_.Borrow()};
}

Status<BufferDescription<BorrowedHandle>> ProducerChannel::OnGetBuffer(
    Message& /*message*/) {
  ATRACE_NAME("ProducerChannel::OnGetBuffer");
  ALOGD_IF(TRACE, "ProducerChannel::OnGetBuffer: buffer=%d, state=%" PRIx64 ".",
           buffer_id(), buffer_state_->load(std::memory_order_acquire));
  return {GetBuffer(BufferHubDefs::kFirstClientBitMask)};
}

Status<uint64_t> ProducerChannel::CreateConsumerStateMask() {
  // Try find the next consumer state bit which has not been claimed by any
  // consumer yet.
  // memory_order_acquire is chosen here because all writes in other threads
  // that release active_clients_bit_mask_ need to be visible here.
  uint64_t current_active_clients_bit_mask =
      active_clients_bit_mask_->load(std::memory_order_acquire);
  uint64_t client_state_mask = BufferHubDefs::FindNextAvailableClientStateMask(
      current_active_clients_bit_mask | orphaned_consumer_bit_mask_);
  if (client_state_mask == 0ULL) {
    ALOGE(
        "ProducerChannel::CreateConsumer: reached the maximum mumber of "
        "consumers per producer: 63.");
    return ErrorStatus(E2BIG);
  }
  uint64_t updated_active_clients_bit_mask =
      current_active_clients_bit_mask | client_state_mask;
  // Set the updated value only if the current value stays the same as what was
  // read before. If the comparison succeeds, update the value without
  // reordering anything before or after this read-modify-write in the current
  // thread, and the modification will be visible in other threads that acquire
  // active_clients_bit_mask_. If the comparison fails, load the result of
  // all writes from all threads to updated_active_clients_bit_mask.
  // Keep on finding the next available slient state mask until succeed or out
  // of memory.
  while (!active_clients_bit_mask_->compare_exchange_weak(
      current_active_clients_bit_mask, updated_active_clients_bit_mask,
      std::memory_order_acq_rel, std::memory_order_acquire)) {
    ALOGE("Current active clients bit mask is changed to %" PRIx64
          ", which was expected to be %" PRIx64
          ". Trying to generate a new client state mask to resolve race "
          "condition.",
          updated_active_clients_bit_mask, current_active_clients_bit_mask);
    client_state_mask = BufferHubDefs::FindNextAvailableClientStateMask(
        current_active_clients_bit_mask | orphaned_consumer_bit_mask_);
    if (client_state_mask == 0ULL) {
      ALOGE(
          "ProducerChannel::CreateConsumer: reached the maximum mumber of "
          "consumers per producer: 63.");
      return ErrorStatus(E2BIG);
    }
    updated_active_clients_bit_mask =
        current_active_clients_bit_mask | client_state_mask;
  }

  return {client_state_mask};
}

void ProducerChannel::RemoveConsumerClientMask(uint64_t consumer_state_mask) {
  // Clear up the buffer state and fence state in case there is already
  // something there due to possible race condition between producer post and
  // consumer failed to create channel.
  buffer_state_->fetch_and(~consumer_state_mask, std::memory_order_release);
  fence_state_->fetch_and(~consumer_state_mask, std::memory_order_release);

  // Restore the consumer state bit and make it visible in other threads that
  // acquire the active_clients_bit_mask_.
  active_clients_bit_mask_->fetch_and(~consumer_state_mask,
                                      std::memory_order_release);
}

Status<RemoteChannelHandle> ProducerChannel::CreateConsumer(
    Message& message, uint64_t consumer_state_mask) {
  ATRACE_NAME("ProducerChannel::CreateConsumer");
  ALOGD_IF(TRACE,
           "ProducerChannel::CreateConsumer: buffer_id=%d, producer_owns=%d",
           buffer_id(), producer_owns_);

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status) {
    ALOGE(
        "ProducerChannel::CreateConsumer: Failed to push consumer channel: %s",
        status.GetErrorMessage().c_str());
    RemoveConsumerClientMask(consumer_state_mask);
    return ErrorStatus(ENOMEM);
  }

  auto consumer = std::make_shared<ConsumerChannel>(
      service(), buffer_id(), channel_id, consumer_state_mask,
      shared_from_this());
  const auto channel_status = service()->SetChannel(channel_id, consumer);
  if (!channel_status) {
    ALOGE(
        "ProducerChannel::CreateConsumer: failed to set new consumer channel: "
        "%s",
        channel_status.GetErrorMessage().c_str());
    RemoveConsumerClientMask(consumer_state_mask);
    return ErrorStatus(ENOMEM);
  }

  uint64_t current_buffer_state =
      buffer_state_->load(std::memory_order_acquire);
  if (!producer_owns_ &&
      (BufferHubDefs::IsBufferPosted(current_buffer_state) ||
       BufferHubDefs::IsBufferAcquired(current_buffer_state))) {
    // Signal the new consumer when adding it to a posted producer.
    if (consumer->OnProducerPosted())
      pending_consumers_++;
  }

  return {status.take()};
}

Status<RemoteChannelHandle> ProducerChannel::OnNewConsumer(Message& message) {
  ATRACE_NAME("ProducerChannel::OnNewConsumer");
  ALOGD_IF(TRACE, "ProducerChannel::OnNewConsumer: buffer_id=%d", buffer_id());
  auto status = CreateConsumerStateMask();
  if (!status.ok()) {
    return status.error_status();
  }
  return CreateConsumer(message, /*consumer_state_mask=*/status.get());
}

Status<void> ProducerChannel::OnProducerPost(Message&,
                                             LocalFence acquire_fence) {
  ATRACE_NAME("ProducerChannel::OnProducerPost");
  ALOGD_IF(TRACE, "ProducerChannel::OnProducerPost: buffer_id=%d", buffer_id());
  if (!producer_owns_) {
    ALOGE("ProducerChannel::OnProducerPost: Not in gained state!");
    return ErrorStatus(EBUSY);
  }

  epoll_event event;
  event.events = 0;
  event.data.u64 = 0ULL;
  int ret = epoll_ctl(release_fence_fd_.Get(), EPOLL_CTL_MOD,
                      dummy_fence_fd_.Get(), &event);
  ALOGE_IF(ret < 0,
           "ProducerChannel::OnProducerPost: Failed to modify the shared "
           "release fence to include the dummy fence: %s",
           strerror(errno));

  eventfd_t dummy_fence_count = 0ULL;
  if (eventfd_read(dummy_fence_fd_.Get(), &dummy_fence_count) < 0) {
    const int error = errno;
    if (error != EAGAIN) {
      ALOGE(
          "ProducerChannel::ProducerChannel: Failed to read dummy fence, "
          "error: %s",
          strerror(error));
      return ErrorStatus(error);
    }
  }

  ALOGW_IF(dummy_fence_count > 0,
           "ProducerChannel::ProducerChannel: %" PRIu64
           " dummy fence(s) was signaled during last release/gain cycle "
           "buffer_id=%d.",
           dummy_fence_count, buffer_id());

  post_fence_ = std::move(acquire_fence);
  producer_owns_ = false;

  // Signal any interested consumers. If there are none, the buffer will stay
  // in posted state until a consumer comes online. This behavior guarantees
  // that no frame is silently dropped.
  pending_consumers_ = 0;
  for (auto consumer : consumer_channels_) {
    if (consumer->OnProducerPosted())
      pending_consumers_++;
  }
  ALOGD_IF(TRACE, "ProducerChannel::OnProducerPost: %d pending consumers",
           pending_consumers_);

  return {};
}

Status<LocalFence> ProducerChannel::OnProducerGain(Message& /*message*/) {
  ATRACE_NAME("ProducerChannel::OnGain");
  ALOGD_IF(TRACE, "ProducerChannel::OnGain: buffer_id=%d", buffer_id());
  if (producer_owns_) {
    ALOGE("ProducerChanneL::OnGain: Already in gained state: channel=%d",
          channel_id());
    return ErrorStatus(EALREADY);
  }

  // There are still pending consumers, return busy.
  if (pending_consumers_ > 0) {
    ALOGE(
        "ProducerChannel::OnGain: Producer (id=%d) is gaining a buffer that "
        "still has %d pending consumer(s).",
        buffer_id(), pending_consumers_);
    return ErrorStatus(EBUSY);
  }

  ClearAvailable();
  producer_owns_ = true;
  post_fence_.close();
  return {std::move(returned_fence_)};
}

// TODO(b/112338294) Keep here for reference. Remove it after new logic is
// written.
/* Status<RemoteChannelHandle> ProducerChannel::OnProducerDetach(
    Message& message) {
  ATRACE_NAME("ProducerChannel::OnProducerDetach");
  ALOGD_IF(TRACE, "ProducerChannel::OnProducerDetach: buffer_id=%d",
           buffer_id());

  uint64_t buffer_state = buffer_state_->load(std::memory_order_acquire);
  if (!BufferHubDefs::IsBufferGained(buffer_state)) {
    // Can only detach a BufferProducer when it's in gained state.
    ALOGW(
        "ProducerChannel::OnProducerDetach: The buffer (id=%d, state=0x%" PRIx64
        ") is not in gained state.",
        buffer_id(), buffer_state);
    return {};
  }

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status) {
    ALOGE(
        "ProducerChannel::OnProducerDetach: Failed to push detached buffer "
        "channel: %s",
        status.GetErrorMessage().c_str());
    return ErrorStatus(ENOMEM);
  }

  // Make sure we unlock the buffer.
  if (int ret = metadata_buffer_.Unlock()) {
    ALOGE("ProducerChannel::OnProducerDetach: Failed to unlock metadata.");
    return ErrorStatus(-ret);
  };

  std::unique_ptr<BufferChannel> channel =
      BufferChannel::Create(service(), buffer_id(), channel_id,
                            std::move(buffer_), user_metadata_size_);
  if (!channel) {
    ALOGE("ProducerChannel::OnProducerDetach: Invalid buffer.");
    return ErrorStatus(EINVAL);
  }

  const auto channel_status =
      service()->SetChannel(channel_id, std::move(channel));
  if (!channel_status) {
    // Technically, this should never fail, as we just pushed the channel. Note
    // that LOG_FATAL will be stripped out in non-debug build.
    LOG_FATAL(
        "ProducerChannel::OnProducerDetach: Failed to set new detached buffer "
        "channel: %s.",
        channel_status.GetErrorMessage().c_str());
  }

  return status;
} */

Status<LocalFence> ProducerChannel::OnConsumerAcquire(Message& /*message*/) {
  ATRACE_NAME("ProducerChannel::OnConsumerAcquire");
  ALOGD_IF(TRACE, "ProducerChannel::OnConsumerAcquire: buffer_id=%d",
           buffer_id());
  if (producer_owns_) {
    ALOGE("ProducerChannel::OnConsumerAcquire: Not in posted state!");
    return ErrorStatus(EBUSY);
  }

  // Return a borrowed fd to avoid unnecessary duplication of the underlying fd.
  // Serialization just needs to read the handle.
  return {std::move(post_fence_)};
}

Status<void> ProducerChannel::OnConsumerRelease(Message&,
                                                LocalFence release_fence) {
  ATRACE_NAME("ProducerChannel::OnConsumerRelease");
  ALOGD_IF(TRACE, "ProducerChannel::OnConsumerRelease: buffer_id=%d",
           buffer_id());
  if (producer_owns_) {
    ALOGE("ProducerChannel::OnConsumerRelease: Not in acquired state!");
    return ErrorStatus(EBUSY);
  }

  // Attempt to merge the fences if necessary.
  if (release_fence) {
    if (returned_fence_) {
      LocalFence merged_fence(sync_merge("bufferhub_merged",
                                         returned_fence_.get_fd(),
                                         release_fence.get_fd()));
      const int error = errno;
      if (!merged_fence) {
        ALOGE("ProducerChannel::OnConsumerRelease: Failed to merge fences: %s",
              strerror(error));
        return ErrorStatus(error);
      }
      returned_fence_ = std::move(merged_fence);
    } else {
      returned_fence_ = std::move(release_fence);
    }
  }

  DecrementPendingConsumers();
  if (pending_consumers_ == 0) {
    // Clear the producer bit atomically to transit into released state. This
    // has to done by BufferHub as it requries synchronization among all
    // consumers.
    BufferHubDefs::ModifyBufferState(buffer_state_,
                                     BufferHubDefs::kFirstClientBitMask, 0ULL);
    ALOGD_IF(TRACE,
             "ProducerChannel::OnConsumerRelease: releasing last consumer: "
             "buffer_id=%d state=%" PRIx64 ".",
             buffer_id(), buffer_state_->load(std::memory_order_acquire));

    if (orphaned_consumer_bit_mask_) {
      ALOGW(
          "ProducerChannel::OnConsumerRelease: orphaned buffer detected "
          "during the this acquire/release cycle: id=%d orphaned=0x%" PRIx64
          " queue_index=%" PRIu64 ".",
          buffer_id(), orphaned_consumer_bit_mask_,
          metadata_header_->queue_index);
      orphaned_consumer_bit_mask_ = 0;
    }

    SignalAvailable();
  }

  ALOGE_IF(
      pending_consumers_ && BufferHubDefs::IsBufferReleased(
                                buffer_state_->load(std::memory_order_acquire)),
      "ProducerChannel::OnConsumerRelease: buffer state inconsistent: "
      "pending_consumers=%d, buffer buffer is in releaed state.",
      pending_consumers_);
  return {};
}

void ProducerChannel::DecrementPendingConsumers() {
  if (pending_consumers_ == 0) {
    ALOGE("ProducerChannel::DecrementPendingConsumers: no pending consumer.");
    return;
  }

  --pending_consumers_;
  ALOGD_IF(TRACE,
           "ProducerChannel::DecrementPendingConsumers: buffer_id=%d %d "
           "consumers left",
           buffer_id(), pending_consumers_);
}

void ProducerChannel::OnConsumerOrphaned(ConsumerChannel* channel) {
  // Ignore the orphaned consumer.
  DecrementPendingConsumers();

  const uint64_t client_state_mask = channel->client_state_mask();
  ALOGE_IF(orphaned_consumer_bit_mask_ & client_state_mask,
           "ProducerChannel::OnConsumerOrphaned: Consumer "
           "(client_state_mask=%" PRIx64 ") is already orphaned.",
           client_state_mask);
  orphaned_consumer_bit_mask_ |= client_state_mask;

  // Atomically clear the fence state bit as an orphaned consumer will never
  // signal a release fence. Also clear the buffer state as it won't be released
  // as well.
  fence_state_->fetch_and(~client_state_mask);
  BufferHubDefs::ModifyBufferState(buffer_state_, client_state_mask, 0ULL);

  ALOGW(
      "ProducerChannel::OnConsumerOrphaned: detected new orphaned consumer "
      "buffer_id=%d client_state_mask=%" PRIx64 " queue_index=%" PRIu64
      " buffer_state=%" PRIx64 " fence_state=%" PRIx64 ".",
      buffer_id(), client_state_mask, metadata_header_->queue_index,
      buffer_state_->load(std::memory_order_acquire),
      fence_state_->load(std::memory_order_acquire));
}

void ProducerChannel::AddConsumer(ConsumerChannel* channel) {
  consumer_channels_.push_back(channel);
}

void ProducerChannel::RemoveConsumer(ConsumerChannel* channel) {
  consumer_channels_.erase(
      std::find(consumer_channels_.begin(), consumer_channels_.end(), channel));
  // Restore the consumer state bit and make it visible in other threads that
  // acquire the active_clients_bit_mask_.
  active_clients_bit_mask_->fetch_and(~channel->client_state_mask(),
                                      std::memory_order_release);

  const uint64_t buffer_state = buffer_state_->load(std::memory_order_acquire);
  if (BufferHubDefs::IsBufferPosted(buffer_state) ||
      BufferHubDefs::IsBufferAcquired(buffer_state)) {
    // The consumer client is being destoryed without releasing. This could
    // happen in corner cases when the consumer crashes. Here we mark it
    // orphaned before remove it from producer.
    OnConsumerOrphaned(channel);
  }

  if (BufferHubDefs::IsBufferReleased(buffer_state) ||
      BufferHubDefs::IsBufferGained(buffer_state)) {
    // The consumer is being close while it is suppose to signal a release
    // fence. Signal the dummy fence here.
    if (fence_state_->load(std::memory_order_acquire) &
        channel->client_state_mask()) {
      epoll_event event;
      event.events = EPOLLIN;
      event.data.u64 = channel->client_state_mask();
      if (epoll_ctl(release_fence_fd_.Get(), EPOLL_CTL_MOD,
                    dummy_fence_fd_.Get(), &event) < 0) {
        ALOGE(
            "ProducerChannel::RemoveConsumer: Failed to modify the shared "
            "release fence to include the dummy fence: %s",
            strerror(errno));
        return;
      }
      ALOGW(
          "ProducerChannel::RemoveConsumer: signal dummy release fence "
          "buffer_id=%d",
          buffer_id());
      eventfd_write(dummy_fence_fd_.Get(), 1);
    }
  }
}

// Returns true if the given parameters match the underlying buffer parameters.
bool ProducerChannel::CheckParameters(uint32_t width, uint32_t height,
                                      uint32_t layer_count, uint32_t format,
                                      uint64_t usage,
                                      size_t user_metadata_size) {
  return user_metadata_size == user_metadata_size_ &&
         buffer_.width() == width && buffer_.height() == height &&
         buffer_.layer_count() == layer_count && buffer_.format() == format &&
         buffer_.usage() == usage;
}

}  // namespace dvr
}  // namespace android
