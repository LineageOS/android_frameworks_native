#ifndef ANDROID_DVR_VIDEO_MESH_SURFACE_CLIENT_H_
#define ANDROID_DVR_VIDEO_MESH_SURFACE_CLIENT_H_

#include <private/dvr/buffer_hub_queue_client.h>
#include <private/dvr/display_client.h>

namespace android {
namespace dvr {

class VideoMeshSurfaceClient
    : pdx::ClientBase<VideoMeshSurfaceClient, SurfaceClient> {
 public:
  using LocalChannelHandle = pdx::LocalChannelHandle;

  // This call assumes ownership of |handle|.
  static std::unique_ptr<VideoMeshSurfaceClient> Import(
      LocalChannelHandle handle);

  std::shared_ptr<ProducerQueue> GetProducerQueue();

  // Get the shared memory metadata buffer for this video mesh surface. If it is
  // not yet allocated, this will allocate it.
  volatile VideoMeshSurfaceMetadata* GetMetadataBufferPtr();

 private:
  friend BASE;

  std::shared_ptr<ProducerQueue> producer_queue_;
  VideoMeshSurfaceMetadata* mapped_metadata_buffer_;

  explicit VideoMeshSurfaceClient(LocalChannelHandle handle);
};

}  // namespace dvr
}  // namespace android

struct DvrVideoMeshSurface {
  std::shared_ptr<android::dvr::VideoMeshSurfaceClient> client;
};

#endif  // ANDROID_DVR_VIDEO_MESH_SURFACE_CLIENT_H_
