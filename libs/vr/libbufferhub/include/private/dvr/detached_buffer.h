#ifndef ANDROID_DVR_DETACHED_BUFFER_H_
#define ANDROID_DVR_DETACHED_BUFFER_H_

#include <private/dvr/buffer_hub_client.h>

namespace android {
namespace dvr {

class DetachedBuffer {
 public:
  using LocalChannelHandle = pdx::LocalChannelHandle;

  // Allocates a standalone DetachedBuffer not associated with any producer
  // consumer set.
  static std::unique_ptr<DetachedBuffer> Create(uint32_t width, uint32_t height,
                                                uint32_t layer_count,
                                                uint32_t format, uint64_t usage,
                                                size_t user_metadata_size) {
    return std::unique_ptr<DetachedBuffer>(new DetachedBuffer(
        width, height, layer_count, format, usage, user_metadata_size));
  }

  // Imports the given channel handle to a DetachedBuffer, taking ownership.
  static std::unique_ptr<DetachedBuffer> Import(
      LocalChannelHandle channel_handle) {
    return std::unique_ptr<DetachedBuffer>(
        new DetachedBuffer(std::move(channel_handle)));
  }

  DetachedBuffer(const DetachedBuffer&) = delete;
  void operator=(const DetachedBuffer&) = delete;

  const sp<GraphicBuffer>& buffer() const { return buffer_.buffer(); }

  int id() const { return id_; }
  bool IsValid() const { return client_.IsValid(); }

  // Promotes a DetachedBuffer to become a ProducerBuffer. Once promoted the
  // DetachedBuffer channel will be closed automatically on successful IPC
  // return. Further IPCs towards this channel will return error.
  std::unique_ptr<BufferProducer> Promote();

  // Takes the underlying graphic buffer out of this DetachedBuffer. This call
  // immediately invalidates this DetachedBuffer object and transfers the
  // underlying pdx::LocalChannelHandle into the GraphicBuffer.
  sp<GraphicBuffer> TakeGraphicBuffer();

 private:
  DetachedBuffer(uint32_t width, uint32_t height, uint32_t layer_count,
                 uint32_t format, uint64_t usage, size_t user_metadata_size);

  DetachedBuffer(LocalChannelHandle channel_handle);

  int ImportGraphicBuffer();

  // Global id for the buffer that is consistent across processes.
  int id_;
  IonBuffer buffer_;
  BufferHubClient client_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DETACHED_BUFFER_H_
