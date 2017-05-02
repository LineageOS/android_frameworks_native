#include "include/dvr/dvr_api.h"
#include "include/dvr/dvr_buffer_queue.h"

#include <android/native_window.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_client.h>
#include <private/dvr/buffer_hub_queue_producer.h>

#define CHECK_PARAM(param)                                               \
  LOG_ALWAYS_FATAL_IF(param == nullptr, "%s: " #param "cannot be NULL.", \
                      __FUNCTION__)

using namespace android;

extern "C" {

void dvrWriteBufferQueueDestroy(DvrWriteBufferQueue* write_queue) {
  if (write_queue != nullptr && write_queue->native_window_ != nullptr) {
    ANativeWindow_release(write_queue->native_window_);
  }
  delete write_queue;
}

size_t dvrWriteBufferQueueGetCapacity(DvrWriteBufferQueue* write_queue) {
  CHECK_PARAM(write_queue);
  return write_queue->producer_queue_->capacity();
}

int dvrWriteBufferQueueGetExternalSurface(DvrWriteBufferQueue* write_queue,
                                          ANativeWindow** out_window) {
  CHECK_PARAM(write_queue);
  CHECK_PARAM(out_window);

  if (write_queue->producer_queue_->metadata_size() !=
      sizeof(DvrNativeBufferMetadata)) {
    ALOGE(
        "The size of buffer metadata (%u) of the write queue does not match of "
        "size of DvrNativeBufferMetadata (%u).",
        write_queue->producer_queue_->metadata_size(),
        sizeof(DvrNativeBufferMetadata));
    return -EINVAL;
  }

  // Lazy creation of |native_window_|.
  if (write_queue->native_window_ == nullptr) {
    std::shared_ptr<dvr::BufferHubQueueCore> core =
        dvr::BufferHubQueueCore::Create(write_queue->producer_queue_);
    if (core == nullptr) {
      ALOGE(
          "dvrWriteBufferQueueGetExternalSurface: Failed to create native "
          "window.");
      return -ENOMEM;
    }

    sp<IGraphicBufferProducer> gbp = new dvr::BufferHubQueueProducer(core);
    sp<Surface> surface = new Surface(gbp, true);
    write_queue->native_window_ = static_cast<ANativeWindow*>(surface.get());
    ANativeWindow_acquire(write_queue->native_window_);
  }

  *out_window = write_queue->native_window_;
  return 0;
}

int dvrWriteBufferQueueCreateReadQueue(DvrWriteBufferQueue* write_queue,
                                       DvrReadBufferQueue** out_read_queue) {
  CHECK_PARAM(write_queue);
  CHECK_PARAM(write_queue->producer_queue_);
  CHECK_PARAM(out_read_queue);

  auto read_queue = std::make_unique<DvrReadBufferQueue>();
  read_queue->consumer_queue_ =
      write_queue->producer_queue_->CreateConsumerQueue();
  if (read_queue->consumer_queue_ == nullptr) {
    ALOGE(
        "dvrWriteBufferQueueCreateReadQueue: Failed to create consumer queue "
        "from DvrWriteBufferQueue[%p].",
        write_queue);
    return -ENOMEM;
  }

  *out_read_queue = read_queue.release();
  return 0;
}

int dvrWriteBufferQueueDequeue(DvrWriteBufferQueue* write_queue, int timeout,
                                  DvrWriteBuffer** out_buffer,
                                  int* out_fence_fd) {
  CHECK_PARAM(write_queue);
  CHECK_PARAM(write_queue->producer_queue_);
  CHECK_PARAM(out_buffer);
  CHECK_PARAM(out_fence_fd);

  size_t slot;
  pdx::LocalHandle release_fence;
  std::shared_ptr<dvr::BufferProducer> buffer =
      write_queue->producer_queue_->Dequeue(timeout, &slot, &release_fence);
  if (buffer == nullptr) {
    ALOGE("dvrWriteBufferQueueDequeue: Failed to dequeue buffer.");
    return -ENOMEM;
  }

  *out_buffer = CreateDvrWriteBufferFromBufferProducer(buffer);
  *out_fence_fd = release_fence.Release();
  return 0;
}

// ReadBufferQueue
void dvrReadBufferQueueDestroy(DvrReadBufferQueue* read_queue) {
  delete read_queue;
}

size_t dvrReadBufferQueueGetCapacity(DvrReadBufferQueue* read_queue) {
  CHECK_PARAM(read_queue);

  return read_queue->consumer_queue_->capacity();
}

int dvrReadBufferQueueCreateReadQueue(DvrReadBufferQueue* read_queue,
                                      DvrReadBufferQueue** out_read_queue) {
  CHECK_PARAM(read_queue);
  CHECK_PARAM(read_queue->consumer_queue_);
  CHECK_PARAM(out_read_queue);

  auto new_read_queue = std::make_unique<DvrReadBufferQueue>();
  new_read_queue->consumer_queue_ =
      read_queue->consumer_queue_->CreateConsumerQueue();
  if (new_read_queue->consumer_queue_ == nullptr) {
    ALOGE(
        "dvrReadBufferQueueCreateReadQueue: Failed to create consumer queue "
        "from DvrReadBufferQueue[%p].",
        read_queue);
    return -ENOMEM;
  }

  *out_read_queue = new_read_queue.release();
  return 0;
}

int dvrReadBufferQueueDequeue(DvrReadBufferQueue* read_queue, int timeout,
                              DvrReadBuffer** out_buffer, int* out_fence_fd,
                              void* out_meta, size_t meta_size_bytes) {
  CHECK_PARAM(read_queue);
  CHECK_PARAM(read_queue->consumer_queue_);
  CHECK_PARAM(out_buffer);
  CHECK_PARAM(out_fence_fd);
  CHECK_PARAM(out_meta);

  if (meta_size_bytes != read_queue->consumer_queue_->metadata_size()) {
    ALOGE(
        "dvrReadBufferQueueDequeue: Invalid metadata size, expected (%zu), "
        "but actual (%zu).",
        read_queue->consumer_queue_->metadata_size(), meta_size_bytes);
    return -EINVAL;
  }

  size_t slot;
  pdx::LocalHandle acquire_fence;
  std::shared_ptr<dvr::BufferConsumer> buffer =
      read_queue->consumer_queue_->Dequeue(timeout, &slot, out_meta,
                                           meta_size_bytes, &acquire_fence);

  if (buffer == nullptr) {
    ALOGE("dvrReadBufferQueueGainBuffer: Failed to dequeue buffer.");
    return -ENOMEM;
  }

  *out_buffer = CreateDvrReadBufferFromBufferConsumer(buffer);
  *out_fence_fd = acquire_fence.Release();
  return 0;
}

}  // extern "C"
