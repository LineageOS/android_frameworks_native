#ifndef ANDROID_DVR_BUFFER_HUB_QUEUE_PRODUCER_H_
#define ANDROID_DVR_BUFFER_HUB_QUEUE_PRODUCER_H_

#include <private/dvr/buffer_hub_queue_core.h>

#include <gui/IGraphicBufferProducer.h>

namespace android {
namespace dvr {

class BufferHubQueueProducer : public BnInterface<IGraphicBufferProducer> {
 public:
  BufferHubQueueProducer(const std::shared_ptr<BufferHubQueueCore>& core);

  // See |IGraphicBufferProducer::requestBuffer|
  status_t requestBuffer(int slot, sp<GraphicBuffer>* buf) override;

  // For the BufferHub based implementation. All buffers in the queue are
  // allowed to be dequeued from the consumer side. It call always returns
  // 0 for |NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS| query. Thus setting
  // |max_dequeued_buffers| here can be considered the same as setting queue
  // capacity.
  //
  // See |IGraphicBufferProducer::setMaxDequeuedBufferCount| for more info
  status_t setMaxDequeuedBufferCount(int max_dequeued_buffers) override;

  // See |IGraphicBufferProducer::setAsyncMode|
  status_t setAsyncMode(bool async) override;

  // See |IGraphicBufferProducer::dequeueBuffer|
  status_t dequeueBuffer(int* out_slot, sp<Fence>* out_fence, uint32_t width,
                         uint32_t height, PixelFormat format,
                         uint32_t usage,
                         FrameEventHistoryDelta* outTimestamps) override;

  // See |IGraphicBufferProducer::detachBuffer|
  status_t detachBuffer(int slot) override;

  // See |IGraphicBufferProducer::detachNextBuffer|
  status_t detachNextBuffer(sp<GraphicBuffer>* out_buffer,
                            sp<Fence>* out_fence) override;

  // See |IGraphicBufferProducer::attachBuffer|
  status_t attachBuffer(int* out_slot, const sp<GraphicBuffer>& buffer) override;

  // See |IGraphicBufferProducer::queueBuffer|
  status_t queueBuffer(int slot, const QueueBufferInput& input,
                       QueueBufferOutput* output) override;

  // See |IGraphicBufferProducer::cancelBuffer|
  status_t cancelBuffer(int slot, const sp<Fence>& fence) override;

  // See |IGraphicBufferProducer::query|
  status_t query(int what, int* out_value) override;

  // See |IGraphicBufferProducer::connect|
  status_t connect(const sp<IProducerListener>& listener, int api,
                   bool producer_controlled_by_app,
                   QueueBufferOutput* output) override;

  // See |IGraphicBufferProducer::disconnect|
  status_t disconnect(int api, DisconnectMode mode = DisconnectMode::Api) override;

  // See |IGraphicBufferProducer::setSidebandStream|
  status_t setSidebandStream(const sp<NativeHandle>& stream) override;

  // See |IGraphicBufferProducer::allocateBuffers|
  void allocateBuffers(uint32_t width, uint32_t height, PixelFormat format,
                       uint32_t usage) override;

  // See |IGraphicBufferProducer::allowAllocation|
  status_t allowAllocation(bool allow) override;

  // See |IGraphicBufferProducer::setGenerationNumber|
  status_t setGenerationNumber(uint32_t generation_number) override;

  // See |IGraphicBufferProducer::getConsumerName|
  String8 getConsumerName() const override;

  // See |IGraphicBufferProducer::setSharedBufferMode|
  status_t setSharedBufferMode(bool shared_buffer_mode) override;

  // See |IGraphicBufferProducer::setAutoRefresh|
  status_t setAutoRefresh(bool auto_refresh) override;

  // See |IGraphicBufferProducer::setDequeueTimeout|
  status_t setDequeueTimeout(nsecs_t timeout) override;

  // See |IGraphicBufferProducer::getLastQueuedBuffer|
  status_t getLastQueuedBuffer(sp<GraphicBuffer>* out_buffer,
                               sp<Fence>* out_fence,
                               float out_transform_matrix[16]) override;

  // See |IGraphicBufferProducer::getFrameTimestamps|
  void getFrameTimestamps(FrameEventHistoryDelta* /*outDelta*/) override;

  // See |IGraphicBufferProducer::getUniqueId|
  status_t getUniqueId(uint64_t* out_id) const override;

 protected:
  IBinder* onAsBinder() override;

 private:
  using LocalHandle = pdx::LocalHandle;

  // |core_| holds the actually buffer slots.
  std::shared_ptr<BufferHubQueueCore> core_;

  // |max_buffer_count_| sets the capacity of the underlying buffer queue.
  int32_t max_buffer_count_{BufferHubQueue::kMaxQueueCapacity};

  // |max_dequeued_buffer_count_| set the maximum number of buffers that can
  // be dequeued at the same momment.
  int32_t max_dequeued_buffer_count_{1};
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_QUEUE_PRODUCER_H_
