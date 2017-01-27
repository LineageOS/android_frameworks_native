#ifndef ANDROID_DVR_BUFFERHUBD_PRODUCER_QUEUE_CHANNEL_H_
#define ANDROID_DVR_BUFFERHUBD_PRODUCER_QUEUE_CHANNEL_H_

#include "buffer_hub.h"

#include <private/dvr/bufferhub_rpc.h>

namespace android {
namespace dvr {

class ProducerQueueChannel : public BufferHubChannel {
 public:
  using Message = pdx::Message;
  using RemoteChannelHandle = pdx::RemoteChannelHandle;

  static std::shared_ptr<ProducerQueueChannel> Create(
      BufferHubService* service, int channel_id, size_t meta_size_bytes,
      int usage_set_mask, int usage_clear_mask, int usage_deny_set_mask,
      int usage_deny_clear_mask, int* error);
  ~ProducerQueueChannel() override;

  bool HandleMessage(Message& message) override;
  void HandleImpulse(Message& message) override;

  BufferInfo GetBufferInfo() const override;

  // Handles client request to create a new consumer queue attached to current
  // producer queue.
  // Returns a handle for the service channel, as well as the size of the
  // metadata associated with the queue.
  std::pair<RemoteChannelHandle, size_t> OnCreateConsumerQueue(
      Message& message);

  // Allocate a new BufferHubProducer according to the input spec. Client may
  // handle this as if a new producer is created through kOpCreateBuffer.
  std::vector<std::pair<RemoteChannelHandle, size_t>>
  OnProducerQueueAllocateBuffers(Message& message, int width, int height,
                                 int format, int usage, size_t slice_count,
                                 size_t buffer_count);

  // Detach a BufferHubProducer indicated by |slot|. Note that the buffer must
  // be in Gain'ed state for the producer queue to detach.
  int OnProducerQueueDetachBuffer(Message& message, size_t slot);

  void AddConsumer(ConsumerQueueChannel* channel);
  void RemoveConsumer(ConsumerQueueChannel* channel);

 private:
  ProducerQueueChannel(BufferHubService* service, int channel_id,
                       size_t meta_size_bytes, int usage_set_mask,
                       int usage_clear_mask, int usage_deny_set_mask,
                       int usage_deny_clear_mask, int* error);

  // Allocate one single producer buffer by |OnProducerQueueAllocateBuffers|.
  // Note that the newly created buffer's file handle will be pushed to client
  // and our return type is a RemoteChannelHandle.
  // Returns the remote channdel handle and the slot number for the newly
  // allocated buffer.
  std::pair<RemoteChannelHandle, size_t> AllocateBuffer(Message& message,
                                                        int width, int height,
                                                        int format, int usage,
                                                        size_t slice_count);

  // Size of the meta data associated with all the buffers allocated from the
  // queue. Now we assume the metadata size is immutable once the queue is
  // created.
  size_t meta_size_bytes_;

  // A set of variables to control what |usage| bits can this ProducerQueue
  // allocate.
  int usage_set_mask_;
  int usage_clear_mask_;
  int usage_deny_set_mask_;
  int usage_deny_clear_mask_;

  // Provides access to the |channel_id| of all consumer channels associated
  // with this producer.
  std::vector<ConsumerQueueChannel*> consumer_channels_;

  // Tracks how many buffers have this queue allocated.
  size_t capacity_;

  // Tracks of all buffer producer allocated through this buffer queue. Once
  // a buffer get allocated, it will take a logical slot in the |buffers_| array
  // and the slot number will stay unchanged during the entire life cycle of the
  // queue.
  std::weak_ptr<ProducerChannel> buffers_[BufferHubRPC::kMaxQueueCapacity];

  ProducerQueueChannel(const ProducerQueueChannel&) = delete;
  void operator=(const ProducerQueueChannel&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_PRODUCER_QUEUE_CHANNEL_H_
