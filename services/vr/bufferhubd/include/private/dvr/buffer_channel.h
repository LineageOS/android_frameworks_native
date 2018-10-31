#ifndef ANDROID_DVR_BUFFERHUBD_BUFFER_CHANNEL_H_
#define ANDROID_DVR_BUFFERHUBD_BUFFER_CHANNEL_H_

#include <pdx/channel_handle.h>
#include <pdx/file_handle.h>
#include <private/dvr/buffer_hub.h>
#include <private/dvr/buffer_hub_defs.h>
#include <private/dvr/buffer_node.h>

namespace android {
namespace dvr {

class BufferChannel : public BufferHubChannel {
 public:
  ~BufferChannel() override;

  template <typename... Args>
  static std::unique_ptr<BufferChannel> Create(Args&&... args) {
    auto buffer = std::unique_ptr<BufferChannel>(
        new BufferChannel(std::forward<Args>(args)...));
    return buffer->IsValid() ? std::move(buffer) : nullptr;
  }

  // Returns whether the object holds a valid graphic buffer.
  bool IsValid() const {
    return buffer_node_ != nullptr && buffer_node_->IsValid();
  }

  // Captures buffer info for use by BufferHubService::DumpState().
  BufferInfo GetBufferInfo() const override;

  bool HandleMessage(pdx::Message& message) override;
  void HandleImpulse(pdx::Message& message) override;

 private:

  // Allocates a new detached buffer.
  BufferChannel(BufferHubService* service, int buffer_id, uint32_t width,
                uint32_t height, uint32_t layer_count, uint32_t format,
                uint64_t usage, size_t user_metadata_size);

  // Creates a detached buffer from an existing BufferNode. This method is used
  // in OnDuplicate method.
  BufferChannel(BufferHubService* service, int buffer_id, int channel_id,
                std::shared_ptr<BufferNode> buffer_node);

  pdx::Status<BufferTraits<pdx::BorrowedHandle>> OnImport(
      pdx::Message& message);
  pdx::Status<pdx::RemoteChannelHandle> OnDuplicate(pdx::Message& message);

  // The concrete implementation of the Buffer object.
  std::shared_ptr<BufferNode> buffer_node_ = nullptr;

  // The state bit of this buffer. Must be one the lower 63 bits.
  uint64_t client_state_mask_ = 0ULL;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_BUFFER_CHANNEL_H_
