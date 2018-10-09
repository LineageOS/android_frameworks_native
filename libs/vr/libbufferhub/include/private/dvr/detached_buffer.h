#ifndef ANDROID_DVR_DETACHED_BUFFER_H_
#define ANDROID_DVR_DETACHED_BUFFER_H_

#include <pdx/client.h>
#include <private/dvr/buffer_hub_defs.h>
#include <private/dvr/buffer_hub_metadata.h>
#include <private/dvr/ion_buffer.h>

namespace android {
namespace dvr {

class BufferHubClient : public pdx::Client {
 public:
  BufferHubClient();
  explicit BufferHubClient(pdx::LocalChannelHandle channel_handle);

  bool IsValid() const;
  pdx::LocalChannelHandle TakeChannelHandle();

  using pdx::Client::Close;
  using pdx::Client::event_fd;
  using pdx::Client::GetChannel;
  using pdx::Client::InvokeRemoteMethod;
};

class DetachedBuffer {
 public:
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
      pdx::LocalChannelHandle channel_handle) {
    return std::unique_ptr<DetachedBuffer>(
        new DetachedBuffer(std::move(channel_handle)));
  }

  DetachedBuffer(const DetachedBuffer&) = delete;
  void operator=(const DetachedBuffer&) = delete;

  // Gets ID of the buffer client. All DetachedBuffer clients derived from the
  // same buffer in bufferhubd share the same buffer id.
  int id() const { return id_; }

  // Returns the current value of MetadataHeader::buffer_state.
  uint64_t buffer_state() { return metadata_header_->buffer_state.load(); }

  // A state mask which is unique to a buffer hub client among all its siblings
  // sharing the same concrete graphic buffer.
  uint64_t buffer_state_bit() const { return buffer_state_bit_; }

  // Returns true if the buffer holds an open PDX channels towards bufferhubd.
  bool IsConnected() const { return client_.IsValid(); }

  // Returns true if the buffer holds an valid gralloc buffer handle that's
  // availble for the client to read from and/or write into.
  bool IsValid() const { return buffer_.IsValid(); }

  // Returns the event mask for all the events that are pending on this buffer
  // (see sys/poll.h for all possible bits).
  pdx::Status<int> GetEventMask(int events) {
    if (auto* channel = client_.GetChannel()) {
      return channel->GetEventMask(events);
    } else {
      return pdx::ErrorStatus(EINVAL);
    }
  }

  // Polls the fd for |timeout_ms| milliseconds (-1 for infinity).
  int Poll(int timeout_ms);

  // Promotes a DetachedBuffer to become a ProducerBuffer. Once promoted the
  // DetachedBuffer channel will be closed automatically on successful IPC
  // return. Further IPCs towards this channel will return error.
  pdx::Status<pdx::LocalChannelHandle> Promote();

  // Creates a DetachedBuffer from an existing one.
  pdx::Status<pdx::LocalChannelHandle> Duplicate();

 private:
  DetachedBuffer(uint32_t width, uint32_t height, uint32_t layer_count,
                 uint32_t format, uint64_t usage, size_t user_metadata_size);

  DetachedBuffer(pdx::LocalChannelHandle channel_handle);

  int ImportGraphicBuffer();

  // Global id for the buffer that is consistent across processes.
  int id_;
  uint64_t buffer_state_bit_;

  // The concrete Ion buffers.
  IonBuffer buffer_;
  IonBuffer metadata_buffer_;

  // buffer metadata.
  size_t user_metadata_size_ = 0;
  BufferHubDefs::MetadataHeader* metadata_header_ = nullptr;
  void* user_metadata_ptr_ = nullptr;

  // PDX backend.
  BufferHubClient client_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DETACHED_BUFFER_H_
