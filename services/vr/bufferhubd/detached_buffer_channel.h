#ifndef ANDROID_DVR_BUFFERHUBD_DETACHED_BUFFER_CHANNEL_H_
#define ANDROID_DVR_BUFFERHUBD_DETACHED_BUFFER_CHANNEL_H_

#include "buffer_hub.h"

// #include <pdx/channel_handle.h>
// #include <pdx/file_handle.h>
// #include <pdx/rpc/buffer_wrapper.h>
// #include <private/dvr/ion_buffer.h>

namespace android {
namespace dvr {

class DetachedBufferChannel : public BufferHubChannel {
 public:
  // Creates a detached buffer.
  DetachedBufferChannel(BufferHubService* service, int buffer_id,
                        int channel_id, IonBuffer buffer,
                        IonBuffer metadata_buffer, size_t user_metadata_size);

  size_t user_metadata_size() const { return user_metadata_size_; }

  // Captures buffer info for use by BufferHubService::DumpState().
  BufferInfo GetBufferInfo() const override;

  bool HandleMessage(pdx::Message& message) override;
  void HandleImpulse(pdx::Message& message) override;

 private:
  pdx::Status<pdx::RemoteChannelHandle> OnPromote(pdx::Message& message);

  // Gralloc buffer handles.
  IonBuffer buffer_;
  IonBuffer metadata_buffer_;

  // Size of user requested metadata.
  const size_t user_metadata_size_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_DETACHED_BUFFER_CHANNEL_H_
