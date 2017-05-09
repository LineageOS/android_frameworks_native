#include "include/private/dvr/native_buffer_queue.h"

#include <log/log.h>
#include <sys/epoll.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <array>

#include <dvr/dvr_display_types.h>

namespace android {
namespace dvr {
namespace display {

NativeBufferQueue::NativeBufferQueue(
    EGLDisplay display, const std::shared_ptr<ProducerQueue>& producer_queue,
    uint32_t width, uint32_t height, uint32_t format, uint64_t usage,
    size_t capacity)
    : display_(display),
      width_(width),
      height_(height),
      format_(format),
      usage_(usage),
      producer_queue_(producer_queue),
      buffers_(capacity) {
  for (size_t i = 0; i < capacity; i++) {
    size_t slot;
    // TODO(jwcai) Should change to use BufferViewPort's spec to config.
    const int ret = producer_queue_->AllocateBuffer(width_, height_, 1, format_,
                                                    usage_, &slot);
    if (ret < 0) {
      ALOGE(
          "NativeBufferQueue::NativeBufferQueue: Failed to allocate buffer: %s",
          strerror(-ret));
      return;
    }

    ALOGD_IF(TRACE, "NativeBufferQueue::NativeBufferQueue: slot=%zu", slot);
  }
}

NativeBufferProducer* NativeBufferQueue::Dequeue() {
  ATRACE_NAME("NativeBufferQueue::Dequeue");
  size_t slot;
  pdx::LocalHandle fence;
  auto buffer_status = producer_queue_->Dequeue(-1, &slot, &fence);
  if (!buffer_status) {
    ALOGE("NativeBufferQueue::Dequeue: Failed to dequeue buffer: %s",
          buffer_status.GetErrorMessage().c_str());
    return nullptr;
  }

  if (buffers_[slot] == nullptr)
    buffers_[slot] =
        new NativeBufferProducer(buffer_status.take(), display_, slot);

  ALOGD_IF(TRACE, "NativeBufferQueue::Dequeue: slot=%zu buffer=%p", slot,
           buffers_[slot].get());
  return buffers_[slot].get();
}

}  // namespace display
}  // namespace dvr
}  // namespace android
