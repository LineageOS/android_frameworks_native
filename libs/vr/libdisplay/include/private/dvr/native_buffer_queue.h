#ifndef ANDROID_DVR_NATIVE_BUFFER_QUEUE_H_
#define ANDROID_DVR_NATIVE_BUFFER_QUEUE_H_

#include <semaphore.h>

#include <mutex>
#include <vector>

#include <private/dvr/native_buffer.h>
#include <private/dvr/ring_buffer.h>

#include "display_client.h"

namespace android {
namespace dvr {
namespace display {

// A wrapper over dvr::ProducerQueue that caches EGLImage.
class NativeBufferQueue {
 public:
  NativeBufferQueue(EGLDisplay display,
                    const std::shared_ptr<ProducerQueue>& producer_queue,
                    uint32_t width, uint32_t height, uint32_t format,
                    uint64_t usage, size_t capacity);

  uint32_t width() const { return width_; }
  uint32_t height() const { return height_; }
  uint32_t format() const { return format_; }
  uint64_t usage() const { return usage_; }
  size_t capacity() const { return producer_queue_->capacity(); }

  // Dequeue a buffer from the free queue, blocking until one is available.
  NativeBufferProducer* Dequeue();

  // An noop here to keep Vulkan path in GraphicsContext happy.
  // TODO(jwcai, cort) Move Vulkan path into GVR/Google3.
  void Enqueue(NativeBufferProducer* /*buffer*/) {}

 private:
  EGLDisplay display_;
  uint32_t width_;
  uint32_t height_;
  uint32_t format_;
  uint64_t usage_;
  std::shared_ptr<ProducerQueue> producer_queue_;
  std::vector<sp<NativeBufferProducer>> buffers_;

  NativeBufferQueue(const NativeBufferQueue&) = delete;
  void operator=(const NativeBufferQueue&) = delete;
};

}  // namespace display
}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_NATIVE_BUFFER_QUEUE_H_
