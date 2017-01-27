#ifndef ANDROID_DVR_BUFFERHUBD_BUFFER_HUB_H_
#define ANDROID_DVR_BUFFERHUBD_BUFFER_HUB_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <hardware/gralloc.h>
#include <pdx/service.h>

namespace android {
namespace dvr {

class BufferHubService;
class ConsumerChannel;
class ProducerChannel;
class ConsumerQueueChannel;
class ProducerQueueChannel;

class BufferHubChannel : public pdx::Channel {
 public:
  enum ChannelType {
    kProducerType,
    kConsumerType,
    kProducerQueueType,
    kConsumerQueueType,
  };

  enum : int { kDetachedId = -1 };

  BufferHubChannel(BufferHubService* service, int buffer_id, int channel_id,
                   ChannelType channel_type)
      : service_(service),
        buffer_id_(buffer_id),
        channel_id_(channel_id),
        channel_type_(channel_type) {}
  virtual ~BufferHubChannel() {}

  virtual bool HandleMessage(pdx::Message& message) = 0;
  virtual void HandleImpulse(pdx::Message& message) = 0;

  // Captures buffer info for use by BufferHubService::DumpState().
  struct BufferInfo {
    // Common data field shared by BufferProducer and ProducerQueue.
    int id = -1;
    int type = -1;
    size_t consumer_count = 0;

    // Data field for buffer producer.
    int width = 0;
    int height = 0;
    int format = 0;
    int usage = 0;
    size_t slice_count = 0;
    std::string name;

    // Data filed for producer queue.
    size_t capacity = 0;
    int usage_set_mask = 0;
    int usage_clear_mask = 0;
    int usage_deny_set_mask = 0;
    int usage_deny_clear_mask = 0;

    BufferInfo(int id, size_t consumer_count, int width, int height, int format,
               int usage, size_t slice_count, const std::string& name)
        : id(id),
          type(kProducerType),
          consumer_count(consumer_count),
          width(width),
          height(height),
          format(format),
          usage(usage),
          slice_count(slice_count),
          name(name) {}

    BufferInfo(int id, size_t consumer_count, size_t capacity, int usage_set_mask,
               int usage_clear_mask, int usage_deny_set_mask,
               int usage_deny_clear_mask)
        : id(id),
          type(kProducerQueueType),
          consumer_count(consumer_count),
          capacity(capacity),
          usage_set_mask(usage_set_mask),
          usage_clear_mask(usage_clear_mask),
          usage_deny_set_mask(usage_deny_set_mask),
          usage_deny_clear_mask(usage_deny_clear_mask) {}

    BufferInfo() {}
  };

  // Returns the buffer info for this buffer.
  virtual BufferInfo GetBufferInfo() const = 0;

  // Signal the client fd that an ownership change occurred using POLLIN.
  void SignalAvailable();

  // Clear the ownership change event.
  void ClearAvailable();

  // Signal hangup event.
  void Hangup();

  BufferHubService* service() const { return service_; }
  ChannelType channel_type() const { return channel_type_; }
  int buffer_id() const { return buffer_id_; }

  int channel_id() const { return channel_id_; }
  bool IsDetached() const { return channel_id_ == kDetachedId; }

  void Detach() {
    if (channel_type_ == kProducerType)
      channel_id_ = kDetachedId;
  }
  void Attach(int channel_id) {
    if (channel_type_ == kProducerType && channel_id_ == kDetachedId)
      channel_id_ = channel_id;
  }

 private:
  BufferHubService* service_;

  // Static id of the buffer for logging and informational purposes. This id
  // does not change for the life of the buffer.
  // TODO(eieio): Consider using an id allocator instead of the originating
  // channel id; channel ids wrap after 2^31 ids, but this is not a problem in
  // general because channel ids are not used for any lookup in this service.
  int buffer_id_;

  // The channel id of the buffer. This may change for a persistent producer
  // buffer if it is detached and re-attached to another channel.
  int channel_id_;

  ChannelType channel_type_;

  BufferHubChannel(const BufferHubChannel&) = delete;
  void operator=(const BufferHubChannel&) = delete;
};

class BufferHubService : public pdx::ServiceBase<BufferHubService> {
 public:
  BufferHubService();
  ~BufferHubService() override;

  int HandleMessage(pdx::Message& message) override;
  void HandleImpulse(pdx::Message& message) override;

  void OnChannelClose(pdx::Message& message,
                      const std::shared_ptr<pdx::Channel>& channel) override;

  bool IsInitialized() const override;
  std::string DumpState(size_t max_length) override;

  bool AddNamedBuffer(const std::string& name,
                      const std::shared_ptr<ProducerChannel>& buffer);
  std::shared_ptr<ProducerChannel> GetNamedBuffer(const std::string& name);
  bool RemoveNamedBuffer(const ProducerChannel& buffer);

 private:
  friend BASE;

  std::unordered_map<std::string, std::shared_ptr<ProducerChannel>>
      named_buffers_;

  int OnCreateBuffer(pdx::Message& message, int width, int height, int format,
                     int usage, size_t meta_size_bytes, size_t slice_count);
  int OnCreatePersistentBuffer(pdx::Message& message, const std::string& name,
                               int user_id, int group_id, int width, int height,
                               int format, int usage, size_t meta_size_bytes,
                               size_t slice_count);
  int OnGetPersistentBuffer(pdx::Message& message, const std::string& name);
  int OnCreateProducerQueue(pdx::Message& message, size_t meta_size_bytes,
                            int usage_set_mask, int usage_clear_mask,
                            int usage_deny_set_mask, int usage_deny_clear_mask);

  BufferHubService(const BufferHubService&) = delete;
  void operator=(const BufferHubService&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_BUFFER_HUB_H_
