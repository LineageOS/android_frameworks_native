#include <private/dvr/producer_buffer.h>

using android::pdx::LocalChannelHandle;
using android::pdx::LocalHandle;
using android::pdx::Status;

namespace android {
namespace dvr {

ProducerBuffer::ProducerBuffer(uint32_t width, uint32_t height, uint32_t format,
                               uint64_t usage, size_t user_metadata_size)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("ProducerBuffer::ProducerBuffer");
  ALOGD_IF(TRACE,
           "ProducerBuffer::ProducerBuffer: fd=%d width=%u height=%u format=%u "
           "usage=%" PRIx64 " user_metadata_size=%zu",
           event_fd(), width, height, format, usage, user_metadata_size);

  auto status = InvokeRemoteMethod<BufferHubRPC::CreateBuffer>(
      width, height, format, usage, user_metadata_size);
  if (!status) {
    ALOGE(
        "ProducerBuffer::ProducerBuffer: Failed to create producer buffer: %s",
        status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "ProducerBuffer::ProducerBuffer: Failed to import producer buffer: %s",
        strerror(-ret));
    Close(ret);
  }
}

ProducerBuffer::ProducerBuffer(uint64_t usage, size_t size)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("ProducerBuffer::ProducerBuffer");
  ALOGD_IF(TRACE, "ProducerBuffer::ProducerBuffer: usage=%" PRIx64 " size=%zu",
           usage, size);
  const int width = static_cast<int>(size);
  const int height = 1;
  const int format = HAL_PIXEL_FORMAT_BLOB;
  const size_t user_metadata_size = 0;

  auto status = InvokeRemoteMethod<BufferHubRPC::CreateBuffer>(
      width, height, format, usage, user_metadata_size);
  if (!status) {
    ALOGE("ProducerBuffer::ProducerBuffer: Failed to create blob: %s",
          status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "ProducerBuffer::ProducerBuffer: Failed to import producer buffer: %s",
        strerror(-ret));
    Close(ret);
  }
}

ProducerBuffer::ProducerBuffer(LocalChannelHandle channel)
    : BASE(std::move(channel)) {
  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "ProducerBuffer::ProducerBuffer: Failed to import producer buffer: %s",
        strerror(-ret));
    Close(ret);
  }
}

int ProducerBuffer::LocalPost(const DvrNativeBufferMetadata* meta,
                              const LocalHandle& ready_fence) {
  if (const int error = CheckMetadata(meta->user_metadata_size))
    return error;

  // Check invalid state transition.
  uint64_t buffer_state = buffer_state_->load(std::memory_order_acquire);
  if (!BufferHubDefs::IsBufferGained(buffer_state)) {
    ALOGE("ProducerBuffer::LocalPost: not gained, id=%d state=%" PRIx64 ".",
          id(), buffer_state);
    return -EBUSY;
  }

  // Copy the canonical metadata.
  void* metadata_ptr = reinterpret_cast<void*>(&metadata_header_->metadata);
  memcpy(metadata_ptr, meta, sizeof(DvrNativeBufferMetadata));
  // Copy extra user requested metadata.
  if (meta->user_metadata_ptr && meta->user_metadata_size) {
    void* metadata_src = reinterpret_cast<void*>(meta->user_metadata_ptr);
    memcpy(user_metadata_ptr_, metadata_src, meta->user_metadata_size);
  }

  // Send out the acquire fence through the shared epoll fd. Note that during
  // posting no consumer is not expected to be polling on the fence.
  if (const int error = UpdateSharedFence(ready_fence, shared_acquire_fence_))
    return error;

  // Set the producer bit atomically to transit into posted state.
  // The producer state bit mask is kFirstClientBitMask for now.
  BufferHubDefs::ModifyBufferState(buffer_state_, 0ULL,
                                   BufferHubDefs::kFirstClientBitMask);
  return 0;
}

int ProducerBuffer::Post(const LocalHandle& ready_fence, const void* meta,
                         size_t user_metadata_size) {
  ATRACE_NAME("ProducerBuffer::Post");

  // Populate cononical metadata for posting.
  DvrNativeBufferMetadata canonical_meta;
  canonical_meta.user_metadata_ptr = reinterpret_cast<uint64_t>(meta);
  canonical_meta.user_metadata_size = user_metadata_size;

  if (const int error = LocalPost(&canonical_meta, ready_fence))
    return error;

  return ReturnStatusOrError(InvokeRemoteMethod<BufferHubRPC::ProducerPost>(
      BorrowedFence(ready_fence.Borrow())));
}

int ProducerBuffer::PostAsync(const DvrNativeBufferMetadata* meta,
                              const LocalHandle& ready_fence) {
  ATRACE_NAME("ProducerBuffer::PostAsync");

  if (const int error = LocalPost(meta, ready_fence))
    return error;

  return ReturnStatusOrError(SendImpulse(BufferHubRPC::ProducerPost::Opcode));
}

int ProducerBuffer::LocalGain(DvrNativeBufferMetadata* out_meta,
                              LocalHandle* out_fence, bool gain_posted_buffer) {
  uint64_t buffer_state = buffer_state_->load(std::memory_order_acquire);
  ALOGD_IF(TRACE, "ProducerBuffer::LocalGain: buffer=%d, state=%" PRIx64 ".",
           id(), buffer_state);

  if (!out_meta)
    return -EINVAL;

  if (BufferHubDefs::IsBufferGained(buffer_state)) {
    // We don't want to log error when gaining a newly allocated
    // buffer.
    ALOGI("ProducerBuffer::LocalGain: already gained id=%d.", id());
    return -EALREADY;
  }
  if (BufferHubDefs::IsBufferAcquired(buffer_state) ||
      (BufferHubDefs::IsBufferPosted(buffer_state) && !gain_posted_buffer)) {
    ALOGE("ProducerBuffer::LocalGain: not released id=%d state=%" PRIx64 ".",
          id(), buffer_state);
    return -EBUSY;
  }

  // Canonical metadata is undefined on Gain. Except for user_metadata and
  // release_fence_mask. Fill in the user_metadata_ptr in address space of the
  // local process.
  if (metadata_header_->metadata.user_metadata_size && user_metadata_ptr_) {
    out_meta->user_metadata_size =
        metadata_header_->metadata.user_metadata_size;
    out_meta->user_metadata_ptr =
        reinterpret_cast<uint64_t>(user_metadata_ptr_);
  } else {
    out_meta->user_metadata_size = 0;
    out_meta->user_metadata_ptr = 0;
  }

  uint64_t fence_state = fence_state_->load(std::memory_order_acquire);
  // If there is an release fence from consumer, we need to return it.
  if (fence_state & BufferHubDefs::kConsumerStateMask) {
    *out_fence = shared_release_fence_.Duplicate();
    out_meta->release_fence_mask =
        fence_state & BufferHubDefs::kConsumerStateMask;
  }

  // Clear out all bits and the buffer is now back to gained state.
  buffer_state_->store(0ULL);
  return 0;
}

int ProducerBuffer::Gain(LocalHandle* release_fence, bool gain_posted_buffer) {
  ATRACE_NAME("ProducerBuffer::Gain");

  DvrNativeBufferMetadata meta;
  if (const int error = LocalGain(&meta, release_fence, gain_posted_buffer))
    return error;

  auto status = InvokeRemoteMethod<BufferHubRPC::ProducerGain>();
  if (!status)
    return -status.error();
  return 0;
}

int ProducerBuffer::GainAsync(DvrNativeBufferMetadata* out_meta,
                              LocalHandle* release_fence,
                              bool gain_posted_buffer) {
  ATRACE_NAME("ProducerBuffer::GainAsync");

  if (const int error = LocalGain(out_meta, release_fence, gain_posted_buffer))
    return error;

  return ReturnStatusOrError(SendImpulse(BufferHubRPC::ProducerGain::Opcode));
}

int ProducerBuffer::GainAsync() {
  DvrNativeBufferMetadata meta;
  LocalHandle fence;
  return GainAsync(&meta, &fence);
}

std::unique_ptr<ProducerBuffer> ProducerBuffer::Import(
    LocalChannelHandle channel) {
  ALOGD_IF(TRACE, "ProducerBuffer::Import: channel=%d", channel.value());
  return ProducerBuffer::Create(std::move(channel));
}

std::unique_ptr<ProducerBuffer> ProducerBuffer::Import(
    Status<LocalChannelHandle> status) {
  return Import(status ? status.take()
                       : LocalChannelHandle{nullptr, -status.error()});
}

Status<LocalChannelHandle> ProducerBuffer::Detach() {
  // TODO(b/112338294) remove after migrate producer buffer to binder
  ALOGW("ProducerBuffer::Detach: not supported operation during migration");
  return {};

  // TODO(b/112338294) Keep here for reference. Remove it after new logic is
  // written.
  /* uint64_t buffer_state = buffer_state_->load(std::memory_order_acquire);
  if (!BufferHubDefs::IsBufferGained(buffer_state)) {
    // Can only detach a ProducerBuffer when it's in gained state.
    ALOGW("ProducerBuffer::Detach: The buffer (id=%d, state=0x%" PRIx64
          ") is not in gained state.",
          id(), buffer_state);
    return {};
  }

  Status<LocalChannelHandle> status =
      InvokeRemoteMethod<BufferHubRPC::ProducerBufferDetach>();
  ALOGE_IF(!status,
           "ProducerBuffer::Detach: Failed to detach buffer (id=%d): %s.", id(),
           status.GetErrorMessage().c_str());
  return status; */
}

}  // namespace dvr
}  // namespace android
