#ifndef ANDROID_DVR_DETACHED_BUFFER_H_
#define ANDROID_DVR_DETACHED_BUFFER_H_

// We would eliminate the clang warnings introduced by libdpx.
// TODO(b/112338294): Remove those once BufferHub moved to use Binder
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wdouble-promotion"
#pragma clang diagnostic ignored "-Wgnu-case-range"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Winconsistent-missing-destructor-override"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wpacked"
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wswitch-enum"
#pragma clang diagnostic ignored "-Wundefined-func-template"
#pragma clang diagnostic ignored "-Wunused-template"
#pragma clang diagnostic ignored "-Wweak-vtables"
#include <pdx/client.h>
#include <private/dvr/buffer_hub_defs.h>
#include <private/dvr/native_handle_wrapper.h>
#include <pdx/client.h>
#pragma clang diagnostic pop

#include <ui/BufferHubMetadata.h>

namespace android {

class BufferHubClient : public pdx::Client {
 public:
  BufferHubClient();
  virtual ~BufferHubClient();
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

  const native_handle_t* DuplicateHandle() {
    return buffer_handle_.DuplicateHandle();
  }

  // Returns the current value of MetadataHeader::buffer_state.
  uint64_t buffer_state() {
    return metadata_.metadata_header()->buffer_state.load(
        std::memory_order_acquire);
  }

  // A state mask which is unique to a buffer hub client among all its siblings
  // sharing the same concrete graphic buffer.
  uint64_t buffer_state_bit() const { return buffer_state_bit_; }

  size_t user_metadata_size() const { return metadata_.user_metadata_size(); }

  // Returns true if the buffer holds an open PDX channels towards bufferhubd.
  bool IsConnected() const { return client_.IsValid(); }

  // Returns true if the buffer holds an valid native buffer handle that's
  // availble for the client to read from and/or write into.
  bool IsValid() const { return buffer_handle_.IsValid(); }

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

  // Creates a DetachedBuffer client from an existing one. The new client will
  // share the same underlying gralloc buffer and ashmem region for metadata.
  pdx::Status<pdx::LocalChannelHandle> Duplicate();

 private:
  DetachedBuffer(uint32_t width, uint32_t height, uint32_t layer_count,
                 uint32_t format, uint64_t usage, size_t user_metadata_size);

  DetachedBuffer(pdx::LocalChannelHandle channel_handle);

  int ImportGraphicBuffer();

  // Global id for the buffer that is consistent across processes.
  int id_;
  uint64_t buffer_state_bit_;

  // Wrapps the gralloc buffer handle of this buffer.
  dvr::NativeHandleWrapper<pdx::LocalHandle> buffer_handle_;

  // An ashmem-based metadata object. The same shared memory are mapped to the
  // bufferhubd daemon and all buffer clients.
  dvr::BufferHubMetadata metadata_;

  // PDX backend.
  BufferHubClient client_;
};

}  // namespace android

#endif  // ANDROID_DVR_DETACHED_BUFFER_H_
