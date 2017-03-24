#ifndef ANDROID_DVR_BUFFER_HUB_QUEUE_CORE_H_
#define ANDROID_DVR_BUFFER_HUB_QUEUE_CORE_H_

#include <private/dvr/buffer_hub_queue_client.h>

#include <gui/BufferSlot.h>
#include <utils/Atomic.h>
#include <utils/String8.h>

#include <mutex>

namespace android {
namespace dvr {

class BufferHubQueueCore {
 private:
  friend class BufferHubQueueProducer;

 public:
  static constexpr int kNoConnectedApi = -1;

  // Create a BufferHubQueueCore instance by creating a new producer queue.
  static std::shared_ptr<BufferHubQueueCore> Create();

  // Create a BufferHubQueueCore instance by importing an existing prodcuer queue.
  static std::shared_ptr<BufferHubQueueCore> Create(
      const std::shared_ptr<ProducerQueue>& producer);

  struct BufferMetadata {
    // Timestamp of the frame.
    int64_t timestamp;
  };

  class NativeBuffer
      : public ANativeObjectBase<ANativeWindowBuffer, NativeBuffer, RefBase> {
   public:
    explicit NativeBuffer(const std::shared_ptr<BufferHubBuffer>& buffer)
        : buffer_(buffer) {
      ANativeWindowBuffer::width = buffer_->width();
      ANativeWindowBuffer::height = buffer_->height();
      ANativeWindowBuffer::stride = buffer_->stride();
      ANativeWindowBuffer::format = buffer_->format();
      ANativeWindowBuffer::usage = buffer_->usage();
      ANativeWindowBuffer::handle = buffer_->buffer()->handle();
    }

    std::shared_ptr<BufferHubBuffer> buffer() { return buffer_; }

   private:
    std::shared_ptr<BufferHubBuffer> buffer_;
  };

  // Get the unique buffer producer queue backing this BufferHubQueue.
  std::shared_ptr<ProducerQueue> GetProducerQueue() { return producer_; }

 private:
  using LocalHandle = pdx::LocalHandle;

  struct BufferHubSlot : public BufferSlot {
    BufferHubSlot() : mBufferProducer(nullptr), mIsReallocating(false) {}
    // BufferSlot comes from android framework, using m prefix to comply with
    // the name convention with the reset of data fields from BufferSlot.
    std::shared_ptr<BufferProducer> mBufferProducer;
    bool mIsReallocating;
  };

  static String8 getUniqueName() {
    static volatile int32_t counter = 0;
    return String8::format("unnamed-%d-%d", getpid(),
                           android_atomic_inc(&counter));
  }

  static uint64_t getUniqueId() {
    static std::atomic<uint32_t> counter{0};
    static uint64_t id = static_cast<uint64_t>(getpid()) << 32;
    return id | counter++;
  }

  // Private constructor to force use of |Create|.
  BufferHubQueueCore();

  // Allocate a new buffer producer through BufferHub.
  int AllocateBuffer(uint32_t width, uint32_t height, PixelFormat format,
                     uint32_t usage, size_t slice_count);

  // Detach a buffer producer through BufferHub.
  int DetachBuffer(size_t slot);

  // Mutex for thread safety.
  std::mutex mutex_;

  // Connect client API, should be one of the NATIVE_WINDOW_API_* flags.
  int connected_api_{kNoConnectedApi};

  // |buffers_| stores the buffers that have been dequeued from
  // |dvr::BufferHubQueue|, It is initialized to invalid buffers, and gets
  // filled in with the result of |Dequeue|.
  // TODO(jwcai) The buffer allocated to a slot will also be replaced if the
  // requested buffer usage or geometry differs from that of the buffer
  // allocated to a slot.
  BufferHubSlot buffers_[BufferHubQueue::kMaxQueueCapacity];

  // Concreate implementation backed by BufferHubBuffer.
  std::shared_ptr<ProducerQueue> producer_;

  // |generation_number_| stores the current generation number of the attached
  // producer. Any attempt to attach a buffer with a different generation
  // number will fail.
  uint32_t generation_number_;

  // Sets how long dequeueBuffer or attachBuffer will block if a buffer or
  // slot is not yet available. The timeout is stored in milliseconds.
  int dequeue_timeout_ms_;

  const uint64_t unique_id_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_QUEUE_CORE_H_
