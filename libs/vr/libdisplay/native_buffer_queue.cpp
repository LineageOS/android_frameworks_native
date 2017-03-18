#include "include/private/dvr/native_buffer_queue.h"

#include <log/log.h>
#include <sys/epoll.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <array>

#include <private/dvr/display_types.h>

namespace android {
namespace dvr {

NativeBufferQueue::NativeBufferQueue(
    EGLDisplay display, const std::shared_ptr<DisplaySurfaceClient>& surface,
    size_t capacity)
    : display_(display), buffers_(capacity) {
  std::shared_ptr<ProducerQueue> queue = surface->GetProducerQueue();

  for (size_t i = 0; i < capacity; i++) {
    size_t slot;
    // TODO(jwcai) Should change to use BufferViewPort's spec to config.
    int ret =
        queue->AllocateBuffer(surface->width(), surface->height(),
                              surface->format(), surface->usage(), 1, &slot);
    if (ret < 0) {
      ALOGE(
          "NativeBufferQueue::NativeBufferQueue: Failed to allocate buffer, "
          "error=%d",
          ret);
      return;
    }

    ALOGD_IF(TRACE,
             "NativeBufferQueue::NativeBufferQueue: New buffer allocated at "
             "slot=%zu",
             slot);
  }

  producer_queue_ = std::move(queue);
}

NativeBufferProducer* NativeBufferQueue::Dequeue() {
  ATRACE_NAME("NativeBufferQueue::Dequeue");

  // This never times out.
  size_t slot;
  pdx::LocalHandle fence;
  std::shared_ptr<BufferProducer> buffer =
      producer_queue_->Dequeue(-1, &slot, &fence);

  if (buffers_[slot] == nullptr) {
    buffers_[slot] = new NativeBufferProducer(buffer, display_, slot);
  }

  ALOGD_IF(TRACE,
           "NativeBufferQueue::Dequeue: dequeue buffer at slot=%zu, buffer=%p",
           slot, buffers_[slot].get());
  return buffers_[slot].get();
}

}  // namespace dvr
}  // namespace android
