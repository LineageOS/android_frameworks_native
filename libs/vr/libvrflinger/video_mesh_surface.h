#ifndef ANDROID_DVR_SERVICES_DISPLAYD_VIDEO_MESH_SURFACE_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_VIDEO_MESH_SURFACE_H_

#include <private/dvr/buffer_hub_queue_client.h>

#include "surface_channel.h"

namespace android {
namespace dvr {

class DisplayService;

// VideoMeshSurface takes three inputs: 1) buffers filled by Android system
// components (e.g. MediaCodec or camera stack) other than applications' GL
// context; 2) a 3D mesh choosen by application to define the shape of the
// surface; 3) a transformation matrix from application to define the rotation,
// position, and scaling of the video surface.
class VideoMeshSurface : public SurfaceChannel {
 public:
  using Message = pdx::Message;
  using LocalChannelHandle = pdx::LocalChannelHandle;

  VideoMeshSurface(DisplayService* service, int channel_id);
  ~VideoMeshSurface() override;

  volatile const VideoMeshSurfaceMetadata* GetMetadataBufferPtr() {
    if (EnsureMetadataBuffer()) {
      void* addr = nullptr;
      metadata_buffer_->GetBlobReadWritePointer(metadata_size(), &addr);
      return static_cast<const volatile VideoMeshSurfaceMetadata*>(addr);
    } else {
      return nullptr;
    }
  }

  int HandleMessage(Message& message) override;

  std::shared_ptr<ConsumerQueue> GetConsumerQueue();

 private:
  LocalChannelHandle OnCreateProducerQueue(Message& message);

  std::shared_ptr<ConsumerQueue> consumer_queue_;

  VideoMeshSurface(const VideoMeshSurface&) = delete;
  void operator=(const VideoMeshSurface&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_VIDEO_MESH_SURFACE_H_
