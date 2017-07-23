#include "include/dvr/dvr_api.h"
#include "include/dvr/dvr_buffer_queue.h"

#include <android/native_window.h>
#include <private/dvr/buffer_hub_queue_producer.h>

#include "dvr_internal.h"
#include "dvr_buffer_queue_internal.h"

using namespace android;
using android::dvr::BufferConsumer;
using android::dvr::BufferHubBuffer;
using android::dvr::BufferHubQueueProducer;
using android::dvr::BufferProducer;
using android::dvr::ConsumerQueue;
using android::dvr::ProducerQueue;

extern "C" {

DvrWriteBufferQueue::DvrWriteBufferQueue(
    const std::shared_ptr<ProducerQueue>& producer_queue)
    : producer_queue_(producer_queue),
      width_(producer_queue->default_width()),
      height_(producer_queue->default_height()),
      format_(producer_queue->default_format()) {}

int DvrWriteBufferQueue::GetNativeWindow(ANativeWindow** out_window) {
  if (producer_queue_->metadata_size() != sizeof(DvrNativeBufferMetadata)) {
    ALOGE(
        "DvrWriteBufferQueue::GetNativeWindow: The size of buffer metadata "
        "(%zu) of the write queue does not match  of size of "
        "DvrNativeBufferMetadata (%zu).",
        producer_queue_->metadata_size(), sizeof(DvrNativeBufferMetadata));
    return -EINVAL;
  }

  if (native_window_ == nullptr) {
    // Lazy creation of |native_window|, as not everyone is using
    // DvrWriteBufferQueue as an external surface.
    sp<IGraphicBufferProducer> gbp =
        BufferHubQueueProducer::Create(producer_queue_);
    native_window_ = new Surface(gbp, true);
  }

  *out_window = static_cast<ANativeWindow*>(native_window_.get());
  return 0;
}

int DvrWriteBufferQueue::CreateReadQueue(DvrReadBufferQueue** out_read_queue) {
  std::unique_ptr<ConsumerQueue> consumer_queue =
      producer_queue_->CreateConsumerQueue();
  if (consumer_queue == nullptr) {
    ALOGE(
        "DvrWriteBufferQueue::CreateReadQueue: Failed to create consumer queue "
        "from producer queue: queue_id=%d.", producer_queue_->id());
    return -ENOMEM;
  }

  *out_read_queue = new DvrReadBufferQueue(std::move(consumer_queue));
  return 0;
}

int DvrWriteBufferQueue::Dequeue(int timeout, DvrWriteBuffer* write_buffer,
                                 int* out_fence_fd) {
  size_t slot;
  pdx::LocalHandle fence;
  std::shared_ptr<BufferProducer> buffer_producer;

  // Need to retry N+1 times, where N is total number of buffers in the queue.
  // As in the worst case, we will dequeue all N buffers and reallocate them, on
  // the {N+1}th dequeue, we are guaranteed to get a buffer with new dimension.
  size_t max_retries = 1 + producer_queue_->capacity();
  size_t retry = 0;

  for (; retry < max_retries; retry++) {
    auto buffer_status = producer_queue_->Dequeue(timeout, &slot, &fence);
    if (!buffer_status) {
      ALOGE_IF(buffer_status.error() != ETIMEDOUT,
               "DvrWriteBufferQueue::Dequeue: Failed to dequeue buffer: %s",
               buffer_status.GetErrorMessage().c_str());
      return -buffer_status.error();
    }

    buffer_producer = buffer_status.take();
    if (!buffer_producer)
      return -ENOMEM;

    if (width_ == buffer_producer->width() &&
        height_ == buffer_producer->height() &&
        format_ == buffer_producer->format()) {
      // Producer queue returns a buffer matches the current request.
      break;
    }

    // Needs reallocation. Note that if there are already multiple available
    // buffers in the queue, the next one returned from |queue_->Dequeue| may
    // still have the old buffer dimension or format. Retry up to N+1 times or
    // until we dequeued a buffer with new configuration.
    ALOGD_IF(TRACE,
             "DvrWriteBufferQueue::Dequeue: requested buffer at slot: %zu "
             "(w=%u, h=%u, fmt=%u) is different from the buffer returned "
             "(w=%u, h=%u, fmt=%u). Need re-allocation.",
             slot, width_, height_, format_, buffer_producer->width(),
             buffer_producer->height(), buffer_producer->format());

    // Currently, we are not storing |layer_count| and |usage| in queue
    // configuration. Copy those setup from the last buffer dequeued before we
    // remove it.
    uint32_t old_layer_count = buffer_producer->layer_count();
    uint64_t old_usage = buffer_producer->usage();

    // Allocate a new producer buffer with new buffer configs. Note that if
    // there are already multiple available buffers in the queue, the next one
    // returned from |queue_->Dequeue| may still have the old buffer dimension
    // or format. Retry up to BufferHubQueue::kMaxQueueCapacity times or until
    // we dequeued a buffer with new configuration.
    auto remove_status = producer_queue_->RemoveBuffer(slot);
    if (!remove_status) {
      ALOGE("DvrWriteBufferQueue::Dequeue: Failed to remove buffer: %s",
            remove_status.GetErrorMessage().c_str());
      return -remove_status.error();
    }

    auto allocate_status = producer_queue_->AllocateBuffer(
        width_, height_, old_layer_count, format_, old_usage);
    if (!allocate_status) {
      ALOGE("DvrWriteBufferQueue::Dequeue: Failed to allocate buffer: %s",
            allocate_status.GetErrorMessage().c_str());
      return -allocate_status.error();
    }
  }

  if (retry >= max_retries) {
    ALOGE(
        "DvrWriteBufferQueue::Dequeue: Failed to re-allocate buffer after "
        "resizing.");
    return -ENOMEM;
  }

  write_buffer->write_buffer = std::move(buffer_producer);
  *out_fence_fd = fence.Release();
  return 0;
}

int DvrWriteBufferQueue::ResizeBuffer(uint32_t width, uint32_t height) {
  if (width == 0 || height == 0) {
    ALOGE(
        "DvrWriteBufferQueue::ResizeBuffer: invalid buffer dimension: w=%u, "
        "h=%u.",
        width, height);
    return -EINVAL;
  }

  width_ = width;
  height_ = height;
  return 0;
}

void dvrWriteBufferQueueDestroy(DvrWriteBufferQueue* write_queue) {
  delete write_queue;
}

ssize_t dvrWriteBufferQueueGetCapacity(DvrWriteBufferQueue* write_queue) {
  if (!write_queue)
    return -EINVAL;

  return write_queue->capacity();
}

int dvrWriteBufferQueueGetId(DvrWriteBufferQueue* write_queue) {
  if (!write_queue)
    return -EINVAL;

  return write_queue->id();
}

int dvrWriteBufferQueueGetExternalSurface(DvrWriteBufferQueue* write_queue,
                                          ANativeWindow** out_window) {
  if (!write_queue || !out_window)
    return -EINVAL;

  return write_queue->GetNativeWindow(out_window);
}

int dvrWriteBufferQueueCreateReadQueue(DvrWriteBufferQueue* write_queue,
                                       DvrReadBufferQueue** out_read_queue) {
  if (!write_queue || !out_read_queue)
    return -EINVAL;

  return write_queue->CreateReadQueue(out_read_queue);
}

int dvrWriteBufferQueueDequeue(DvrWriteBufferQueue* write_queue, int timeout,
                               DvrWriteBuffer* write_buffer,
                               int* out_fence_fd) {
  if (!write_queue || !write_buffer || !out_fence_fd)
    return -EINVAL;

  return write_queue->Dequeue(timeout, write_buffer, out_fence_fd);
}

int dvrWriteBufferQueueResizeBuffer(DvrWriteBufferQueue* write_queue,
                                    uint32_t width, uint32_t height) {
  if (!write_queue)
    return -EINVAL;

  return write_queue->ResizeBuffer(width, height);
}

// ReadBufferQueue

DvrReadBufferQueue::DvrReadBufferQueue(
    const std::shared_ptr<ConsumerQueue>& consumer_queue)
    : consumer_queue_(consumer_queue) {}

int DvrReadBufferQueue::CreateReadQueue(DvrReadBufferQueue** out_read_queue) {
  std::unique_ptr<ConsumerQueue> consumer_queue =
      consumer_queue_->CreateConsumerQueue();
  if (consumer_queue == nullptr) {
    ALOGE(
        "DvrReadBufferQueue::CreateReadQueue: Failed to create consumer queue "
        "from producer queue: queue_id=%d.", consumer_queue_->id());
    return -ENOMEM;
  }

  *out_read_queue = new DvrReadBufferQueue(std::move(consumer_queue));
  return 0;
}

int DvrReadBufferQueue::Dequeue(int timeout, DvrReadBuffer* read_buffer,
                                int* out_fence_fd, void* out_meta,
                                size_t meta_size_bytes) {
  if (meta_size_bytes != consumer_queue_->metadata_size()) {
    ALOGE(
        "DvrReadBufferQueue::Dequeue: Invalid metadata size, expected (%zu), "
        "but actual (%zu).",
        consumer_queue_->metadata_size(), meta_size_bytes);
    return -EINVAL;
  }

  size_t slot;
  pdx::LocalHandle acquire_fence;
  auto buffer_status = consumer_queue_->Dequeue(
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

void DvrReadBufferQueue::SetBufferAvailableCallback(
    DvrReadBufferQueueBufferAvailableCallback callback, void* context) {
  if (callback == nullptr) {
    consumer_queue_->SetBufferAvailableCallback(nullptr);
  } else {
    consumer_queue_->SetBufferAvailableCallback(
        [callback, context]() { callback(context); });
  }
}

void DvrReadBufferQueue::SetBufferRemovedCallback(
    DvrReadBufferQueueBufferRemovedCallback callback, void* context) {
  if (callback == nullptr) {
    consumer_queue_->SetBufferRemovedCallback(nullptr);
  } else {
    consumer_queue_->SetBufferRemovedCallback(
        [callback, context](const std::shared_ptr<BufferHubBuffer>& buffer) {
          DvrReadBuffer read_buffer{
              std::static_pointer_cast<BufferConsumer>(buffer)};
          callback(&read_buffer, context);
        });
  }
}

int DvrReadBufferQueue::HandleEvents() {
  // TODO(jwcai) Probably should change HandleQueueEvents to return Status.
  consumer_queue_->HandleQueueEvents();
  return 0;
}

void dvrReadBufferQueueDestroy(DvrReadBufferQueue* read_queue) {
  delete read_queue;
}

ssize_t dvrReadBufferQueueGetCapacity(DvrReadBufferQueue* read_queue) {
  if (!read_queue)
    return -EINVAL;

  return read_queue->capacity();
}

int dvrReadBufferQueueGetId(DvrReadBufferQueue* read_queue) {
  if (!read_queue)
    return -EINVAL;

  return read_queue->id();
}

int dvrReadBufferQueueGetEventFd(DvrReadBufferQueue* read_queue) {
  if (!read_queue)
    return -EINVAL;

  return read_queue->event_fd();
}

int dvrReadBufferQueueCreateReadQueue(DvrReadBufferQueue* read_queue,
                                      DvrReadBufferQueue** out_read_queue) {
  if (!read_queue || !out_read_queue)
    return -EINVAL;

  return read_queue->CreateReadQueue(out_read_queue);
}

int dvrReadBufferQueueDequeue(DvrReadBufferQueue* read_queue, int timeout,
                              DvrReadBuffer* read_buffer, int* out_fence_fd,
                              void* out_meta, size_t meta_size_bytes) {
  if (!read_queue || !read_buffer || !out_fence_fd)
    return -EINVAL;

  if (meta_size_bytes != 0 && !out_meta)
    return -EINVAL;

  return read_queue->Dequeue(timeout, read_buffer, out_fence_fd, out_meta,
                             meta_size_bytes);
}

int dvrReadBufferQueueSetBufferAvailableCallback(
    DvrReadBufferQueue* read_queue,
    DvrReadBufferQueueBufferAvailableCallback callback, void* context) {
  if (!read_queue)
    return -EINVAL;

  read_queue->SetBufferAvailableCallback(callback, context);
  return 0;
}

int dvrReadBufferQueueSetBufferRemovedCallback(
    DvrReadBufferQueue* read_queue,
    DvrReadBufferQueueBufferRemovedCallback callback, void* context) {
  if (!read_queue)
    return -EINVAL;

  read_queue->SetBufferRemovedCallback(callback, context);
  return 0;
}

int dvrReadBufferQueueHandleEvents(DvrReadBufferQueue* read_queue) {
  if (!read_queue)
    return -EINVAL;

  return read_queue->HandleEvents();
}

}  // extern "C"
