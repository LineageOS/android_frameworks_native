#ifndef ANDROID_DVR_BUFFERHUBD_CONSUMER_CHANNEL_H_
#define ANDROID_DVR_BUFFERHUBD_CONSUMER_CHANNEL_H_

#include "buffer_hub.h"

#include <pdx/rpc/buffer_wrapper.h>
#include <private/dvr/bufferhub_rpc.h>

namespace android {
namespace dvr {

// Consumer channels are attached to a Producer channel
class ConsumerChannel : public BufferHubChannel {
 public:
  using Channel = pdx::Channel;
  using Message = pdx::Message;

  ConsumerChannel(BufferHubService* service, int buffer_id, int channel_id,
                  const std::shared_ptr<Channel> producer);
  ~ConsumerChannel() override;

  bool HandleMessage(Message& message) override;
  void HandleImpulse(Message& message) override;

  BufferInfo GetBufferInfo() const override;

  bool OnProducerPosted();
  void OnProducerClosed();

 private:
  using MetaData = pdx::rpc::BufferWrapper<std::uint8_t*>;

  std::shared_ptr<ProducerChannel> GetProducer() const;

  pdx::Status<std::pair<BorrowedFence, MetaData>> OnConsumerAcquire(
      Message& message, std::size_t metadata_size);
  pdx::Status<void> OnConsumerRelease(Message& message,
                                      LocalFence release_fence);
  pdx::Status<void> OnConsumerSetIgnore(Message& message, bool ignore);

  bool handled_;  // True if we have processed RELEASE.
  bool ignored_;  // True if we are ignoring events.
  std::weak_ptr<Channel> producer_;

  ConsumerChannel(const ConsumerChannel&) = delete;
  void operator=(const ConsumerChannel&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_CONSUMER_CHANNEL_H_
