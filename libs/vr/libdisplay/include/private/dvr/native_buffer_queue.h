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

// A wrapper over dvr::ProducerQueue that caches EGLImage.
class NativeBufferQueue {
 public:
  // Create a queue with the given number of free buffers.
  NativeBufferQueue(EGLDisplay display,
                    const std::shared_ptr<DisplaySurfaceClient>& surface,
                    size_t capacity);

  size_t GetQueueCapacity() const { return producer_queue_->capacity(); }

  // Dequeue a buffer from the free queue, blocking until one is available.
  NativeBufferProducer* Dequeue();

  // An noop here to keep Vulkan path in GraphicsContext happy.
  // TODO(jwcai, cort) Move Vulkan path into GVR/Google3.
  void Enqueue(NativeBufferProducer* buffer) {}

 private:
  EGLDisplay display_;
  std::shared_ptr<ProducerQueue> producer_queue_;
  std::vector<sp<NativeBufferProducer>> buffers_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_NATIVE_BUFFER_QUEUE_H_
