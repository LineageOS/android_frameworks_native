#include "include/private/dvr/video_mesh_surface_client.h"

using android::pdx::LocalChannelHandle;

namespace android {
namespace dvr {

/* static */
std::unique_ptr<VideoMeshSurfaceClient> VideoMeshSurfaceClient::Import(
    LocalChannelHandle handle) {
  return VideoMeshSurfaceClient::Create(std::move(handle));
}

VideoMeshSurfaceClient::VideoMeshSurfaceClient(LocalChannelHandle handle)
    : BASE(std::move(handle), SurfaceTypeEnum::VideoMesh),
      mapped_metadata_buffer_(nullptr) {
  // TODO(jwcai) import more data if needed.
}

std::shared_ptr<ProducerQueue> VideoMeshSurfaceClient::GetProducerQueue() {
  if (producer_queue_ == nullptr) {
    // Create producer queue through DisplayRPC
    auto status =
        InvokeRemoteMethod<DisplayRPC::VideoMeshSurfaceCreateProducerQueue>();
    if (!status) {
      ALOGE(
          "VideoMeshSurfaceClient::GetProducerQueue: failed to create producer "
          "queue: %s",
          status.GetErrorMessage().c_str());
      return nullptr;
    }

    producer_queue_ =
        ProducerQueue::Import<VideoMeshSurfaceBufferMetadata>(status.take());
  }
  return producer_queue_;
}

volatile VideoMeshSurfaceMetadata*
VideoMeshSurfaceClient::GetMetadataBufferPtr() {
  if (!mapped_metadata_buffer_) {
    if (auto buffer_producer = GetMetadataBuffer()) {
      void* addr = nullptr;
      const int ret = buffer_producer->GetBlobReadWritePointer(
          sizeof(VideoMeshSurfaceMetadata), &addr);
      if (ret < 0) {
        ALOGE(
            "VideoMeshSurfaceClient::GetMetadataBufferPtr: Failed to map "
            "surface metadata: %s",
            strerror(-ret));
        return nullptr;
      }
      mapped_metadata_buffer_ = static_cast<VideoMeshSurfaceMetadata*>(addr);
    }
  }

  return mapped_metadata_buffer_;
}

}  // namespace dvr
}  // namespace android
