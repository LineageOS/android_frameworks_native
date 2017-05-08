#include "include/dvr/dvr_api.h"
#include "include/dvr/dvr_buffer_queue.h"

#include <android/native_window.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_client.h>
#include <private/dvr/buffer_hub_queue_producer.h>

#include "dvr_internal.h"

#define CHECK_PARAM(param)                                               \
  LOG_ALWAYS_FATAL_IF(param == nullptr, "%s: " #param "cannot be NULL.", \
                      __FUNCTION__)

using namespace android;

namespace android {
namespace dvr {

DvrWriteBufferQueue* CreateDvrWriteBufferQueueFromProducerQueue(
    const std::shared_ptr<dvr::ProducerQueue>& producer_queue) {
  return new DvrWriteBufferQueue{std::move(producer_queue)};
}

DvrReadBufferQueue* CreateDvrReadBufferQueueFromConsumerQueue(
    const std::shared_ptr<dvr::ConsumerQueue>& consumer_queue) {
  return new DvrReadBufferQueue{std::move(consumer_queue)};
}

dvr::ProducerQueue* GetProducerQueueFromDvrWriteBufferQueue(
    DvrWriteBufferQueue* write_queue) {
  return write_queue->producer_queue.get();
}

}  // namespace dvr
}  // namespace android

extern "C" {

void dvrWriteBufferQueueDestroy(DvrWriteBufferQueue* write_queue) {
  if (write_queue != nullptr && write_queue->native_window != nullptr)
    ANativeWindow_release(write_queue->native_window);

  delete write_queue;
}

ssize_t dvrWriteBufferQueueGetCapacity(DvrWriteBufferQueue* write_queue) {
  if (!write_queue || !write_queue->producer_queue)
    return -EINVAL;

  return write_queue->producer_queue->capacity();
}

int dvrWriteBufferQueueGetId(DvrWriteBufferQueue* write_queue) {
  if (!write_queue)
    return -EINVAL;

  return write_queue->producer_queue->id();
}

int dvrWriteBufferQueueGetExternalSurface(DvrWriteBufferQueue* write_queue,
                                          ANativeWindow** out_window) {
  if (!write_queue || !out_window)
    return -EINVAL;

  if (write_queue->producer_queue->metadata_size() !=
      sizeof(DvrNativeBufferMetadata)) {
    ALOGE(
        "The size of buffer metadata (%zu) of the write queue does not match "
        "of size of DvrNativeBufferMetadata (%zu).",
        write_queue->producer_queue->metadata_size(),
        sizeof(DvrNativeBufferMetadata));
    return -EINVAL;
  }

  // Lazy creation of |native_window|.
  if (write_queue->native_window == nullptr) {
    sp<IGraphicBufferProducer> gbp =
        dvr::BufferHubQueueProducer::Create(write_queue->producer_queue);
    sp<Surface> surface = new Surface(gbp, true);
    write_queue->native_window = static_cast<ANativeWindow*>(surface.get());
    ANativeWindow_acquire(write_queue->native_window);
  }

  *out_window = write_queue->native_window;
  return 0;
}

int dvrWriteBufferQueueCreateReadQueue(DvrWriteBufferQueue* write_queue,
                                       DvrReadBufferQueue** out_read_queue) {
  if (!write_queue || !write_queue->producer_queue || !out_read_queue)
    return -EINVAL;

  auto read_queue = std::make_unique<DvrReadBufferQueue>();
  read_queue->consumer_queue =
      write_queue->producer_queue->CreateConsumerQueue();
  if (read_queue->consumer_queue == nullptr) {
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
                               DvrWriteBuffer* write_buffer,
                               int* out_fence_fd) {
  if (!write_queue || !write_queue->producer_queue || !write_buffer ||
      !out_fence_fd) {
    return -EINVAL;
  }

  size_t slot;
  pdx::LocalHandle release_fence;
  auto buffer_status =
      write_queue->producer_queue->Dequeue(timeout, &slot, &release_fence);
  if (!buffer_status) {
    ALOGE_IF(buffer_status.error() != ETIMEDOUT,
             "dvrWriteBufferQueueDequeue: Failed to dequeue buffer: %s",
             buffer_status.GetErrorMessage().c_str());
    return -buffer_status.error();
  }

  write_buffer->write_buffer = buffer_status.take();
  *out_fence_fd = release_fence.Release();
  return 0;
}

// ReadBufferQueue
void dvrReadBufferQueueDestroy(DvrReadBufferQueue* read_queue) {
  delete read_queue;
}

ssize_t dvrReadBufferQueueGetCapacity(DvrReadBufferQueue* read_queue) {
  if (!read_queue)
    return -EINVAL;

  return read_queue->consumer_queue->capacity();
}

int dvrReadBufferQueueGetId(DvrReadBufferQueue* read_queue) {
  if (!read_queue)
    return -EINVAL;

  return read_queue->consumer_queue->id();
}

int dvrReadBufferQueueCreateReadQueue(DvrReadBufferQueue* read_queue,
                                      DvrReadBufferQueue** out_read_queue) {
  if (!read_queue || !read_queue->consumer_queue || !out_read_queue)
    return -EINVAL;

  auto new_read_queue = std::make_unique<DvrReadBufferQueue>();
  new_read_queue->consumer_queue =
      read_queue->consumer_queue->CreateConsumerQueue();
  if (new_read_queue->consumer_queue == nullptr) {
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
                              DvrReadBuffer* read_buffer, int* out_fence_fd,
                              void* out_meta, size_t meta_size_bytes) {
  if (!read_queue || !read_queue->consumer_queue || !read_buffer ||
      !out_fence_fd || !out_meta) {
    return -EINVAL;
  }

  if (meta_size_bytes != read_queue->consumer_queue->metadata_size()) {
    ALOGE(
        "dvrReadBufferQueueDequeue: Invalid metadata size, expected (%zu), "
        "but actual (%zu).",
        read_queue->consumer_queue->metadata_size(), meta_size_bytes);
    return -EINVAL;
  }

  size_t slot;
  pdx::LocalHandle acquire_fence;
  auto buffer_status = read_queue->consumer_queue->Dequeue(
      timeout, &slot, out_meta, meta_size_bytes, &acquire_fence);
  if (!buffer_status) {
    ALOGE_IF(buffer_status.error() != ETIMEDOUT,
             "dvrReadBufferQueueDequeue: Failed to dequeue buffer: %s",
             buffer_status.GetErrorMessage().c_str());
    return -buffer_status.error();
  }

  read_buffer->read_buffer = buffer_status.take();
  *out_fence_fd = acquire_fence.Release();
  return 0;
}

}  // extern "C"
