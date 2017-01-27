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

// NativeBufferQueue manages a queue of NativeBufferProducers allocated from a
// DisplaySurfaceClient. Buffers are automatically re-enqueued when released by
// the consumer side.
class NativeBufferQueue {
 public:
  // Create a queue with the given number of free buffers.
  NativeBufferQueue(const std::shared_ptr<DisplaySurfaceClient>& surface,
                    size_t capacity);
  NativeBufferQueue(EGLDisplay display,
                    const std::shared_ptr<DisplaySurfaceClient>& surface,
                    size_t capacity);
  ~NativeBufferQueue();

  std::shared_ptr<DisplaySurfaceClient> surface() const { return surface_; }

  // Dequeue a buffer from the free queue, blocking until one is available.
  NativeBufferProducer* Dequeue();

  // Enqueue a buffer at the end of the free queue.
  void Enqueue(NativeBufferProducer* buf);

  // Get the number of free buffers in the queue.
  size_t GetFreeBufferCount() const;

  // Get the total number of buffers managed by this queue.
  size_t GetQueueCapacity() const;

  // Accessors for display surface buffer attributes.
  int width() const { return surface_->width(); }
  int height() const { return surface_->height(); }
  int format() const { return surface_->format(); }
  int usage() const { return surface_->usage(); }

 private:
  // Wait for buffers to be released and enqueue them.
  bool WaitForBuffers();

  std::shared_ptr<DisplaySurfaceClient> surface_;

  // A list of strong pointers to the buffers, used for managing buffer
  // lifetime.
  std::vector<android::sp<NativeBufferProducer>> buffers_;

  // Used to implement queue semantics.
  RingBuffer<NativeBufferProducer*> buffer_queue_;

  // Epoll fd used to wait for BufferHub events.
  int epoll_fd_;

  NativeBufferQueue(const NativeBufferQueue&) = delete;
  void operator=(NativeBufferQueue&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_NATIVE_BUFFER_QUEUE_H_
