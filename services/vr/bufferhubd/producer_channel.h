#ifndef ANDROID_DVR_BUFFERHUBD_PRODUCER_CHANNEL_H_
#define ANDROID_DVR_BUFFERHUBD_PRODUCER_CHANNEL_H_

#include "buffer_hub.h"

#include <functional>
#include <memory>
#include <vector>

#include <pdx/channel_handle.h>
#include <pdx/file_handle.h>
#include <pdx/rpc/buffer_wrapper.h>
#include <private/dvr/bufferhub_rpc.h>
#include <private/dvr/ion_buffer.h>

namespace android {
namespace dvr {

// The buffer changes ownership according to the following sequence:
// POST -> ACQUIRE/RELEASE (all consumers) -> GAIN (producer acquires) -> POST

// The producer channel is owned by a single app that writes into buffers and
// calls POST when drawing is complete. This channel has a set of consumer
// channels associated with it that are waiting for notifications.
class ProducerChannel : public BufferHubChannel {
 public:
  using Message = pdx::Message;
  using BorrowedHandle = pdx::BorrowedHandle;
  using RemoteChannelHandle = pdx::RemoteChannelHandle;
  template <typename T>
  using BufferWrapper = pdx::rpc::BufferWrapper<T>;

  static std::shared_ptr<ProducerChannel> Create(
      BufferHubService* service, int channel_id, int width, int height,
      int format, int usage, size_t meta_size_bytes, size_t slice_count,
      int* error);

  ~ProducerChannel() override;

  bool HandleMessage(Message& message) override;
  void HandleImpulse(Message& message) override;

  BufferInfo GetBufferInfo() const override;

  NativeBufferHandle<BorrowedHandle> OnGetBuffer(Message& message,
                                                 unsigned index);
  std::vector<NativeBufferHandle<BorrowedHandle>> OnGetBuffers(
      Message& message);

  RemoteChannelHandle CreateConsumer(Message& message);
  RemoteChannelHandle OnNewConsumer(Message& message);

  std::pair<BorrowedFence, BufferWrapper<std::uint8_t*>> OnConsumerAcquire(
      Message& message, std::size_t metadata_size);
  int OnConsumerRelease(Message& message, LocalFence release_fence);

  void OnConsumerIgnored();

  void AddConsumer(ConsumerChannel* channel);
  void RemoveConsumer(ConsumerChannel* channel);

  bool CheckAccess(int euid, int egid);
  bool CheckParameters(int width, int height, int format, int usage,
                       size_t meta_size_bytes, size_t slice_count);

  int OnProducerMakePersistent(Message& message, const std::string& name,
                               int user_id, int group_id);
  int OnRemovePersistence(Message& message);

 private:
  std::vector<ConsumerChannel*> consumer_channels_;
  // This counts the number of consumers left to process this buffer. If this is
  // zero then the producer can re-acquire ownership.
  int pending_consumers_;

  std::vector<IonBuffer> slices_;

  bool producer_owns_;
  LocalFence post_fence_;
  LocalFence returned_fence_;
  size_t meta_size_bytes_;
  std::unique_ptr<uint8_t[]> meta_;

  static constexpr int kNoCheckId = -1;
  static constexpr int kUseCallerId = 0;
  static constexpr int kRootId = 0;

  // User and group id to check when obtaining a persistent buffer.
  int owner_user_id_ = kNoCheckId;
  int owner_group_id_ = kNoCheckId;

  std::string name_;

  ProducerChannel(BufferHubService* service, int channel, int width, int height,
                  int format, int usage, size_t meta_size_bytes,
                  size_t slice_count, int* error);

  int OnProducerPost(Message& message, LocalFence acquire_fence,
                     BufferWrapper<std::vector<std::uint8_t>> metadata);
  LocalFence OnProducerGain(Message& message);

  ProducerChannel(const ProducerChannel&) = delete;
  void operator=(const ProducerChannel&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_PRODUCER_CHANNEL_H_
