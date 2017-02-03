#ifndef ANDROID_DVR_SERVICES_DISPLAYD_SURFACE_CHANNEL_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_SURFACE_CHANNEL_H_

#include <pdx/service.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/display_rpc.h>

namespace android {
namespace dvr {

class DisplayService;

class SurfaceChannel : public pdx::Channel {
 public:
  SurfaceChannel(DisplayService* service, int channel_id, SurfaceType type,
                 size_t metadata_size)
      : service_(service),
        surface_id_(channel_id),
        type_(type),
        metadata_size_(metadata_size) {}

  ~SurfaceChannel() override = default;

  DisplayService* service() const { return service_; }
  int surface_id() const { return surface_id_; }
  SurfaceType type() const { return type_; }
  size_t metadata_size() const { return metadata_size_; }

  pdx::LocalHandle GetMetadataBufferFd() {
    return EnsureMetadataBuffer() ? metadata_buffer_->GetBlobFd()
                                  : pdx::LocalHandle{};
  }

  // Dispatches surface channel messages to the appropriate handlers. This
  // handler runs on the displayd message dispatch thread.
  virtual int HandleMessage(pdx::Message& message);

 protected:
  // Contains the surface metadata.
  std::shared_ptr<BufferProducer> metadata_buffer_;

  // Returns the metadata buffer for this surface. The first call allocates the
  // buffer, while subsequent calls return the same buffer.
  pdx::BorrowedChannelHandle OnGetMetadataBuffer(pdx::Message& message);

  // Allocates the single metadata buffer for this surface unless it is already
  // allocated. Idempotent when called multiple times.
  bool EnsureMetadataBuffer();

 private:
  DisplayService* service_;
  int surface_id_;
  SurfaceType type_;
  size_t metadata_size_;

  SurfaceChannel(const SurfaceChannel&) = delete;
  void operator=(const SurfaceChannel&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_SURFACE_CHANNEL_H_
