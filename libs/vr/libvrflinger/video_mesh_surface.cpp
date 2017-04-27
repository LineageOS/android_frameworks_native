#include "video_mesh_surface.h"

#include <private/dvr/buffer_hub_queue_core.h>
#include <private/dvr/display_rpc.h>

using android::pdx::LocalChannelHandle;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

VideoMeshSurface::VideoMeshSurface(DisplayService* service, int surface_id)
    : SurfaceChannel(service, surface_id, SurfaceTypeEnum::VideoMesh,
                     sizeof(VideoMeshSurfaceMetadata)) {}

VideoMeshSurface::~VideoMeshSurface() {}

pdx::Status<void> VideoMeshSurface::HandleMessage(Message& message) {
  ATRACE_NAME("VideoMeshSurface::HandleMessage");

  switch (message.GetOp()) {
    case DisplayRPC::VideoMeshSurfaceCreateProducerQueue::Opcode:
      DispatchRemoteMethod<DisplayRPC::VideoMeshSurfaceCreateProducerQueue>(
          *this, &VideoMeshSurface::OnCreateProducerQueue, message);
      break;

    default:
      return SurfaceChannel::HandleMessage(message);
  }

  return {};
}

std::shared_ptr<ConsumerQueue> VideoMeshSurface::GetConsumerQueue() {
  if (!consumer_queue_) {
    ALOGE(
        "VideoMeshSurface::GetConsumerQueue: consumer_queue is uninitialized.");
  }

  return consumer_queue_;
}

LocalChannelHandle VideoMeshSurface::OnCreateProducerQueue(Message& message) {
  ATRACE_NAME("VideoMeshSurface::OnCreateProducerQueue");

  if (consumer_queue_ != nullptr) {
    ALOGE(
        "VideoMeshSurface::OnCreateProducerQueue: A ProdcuerQueue has already "
        "been created and transported to VideoMeshSurfaceClient.");
    REPLY_ERROR_RETURN(message, EALREADY, {});
  }

  auto producer =
      ProducerQueue::Create<BufferHubQueueCore::NativeBufferMetadata>();
  consumer_queue_ = producer->CreateConsumerQueue();

  return std::move(producer->GetChannelHandle());
}

}  // namespace dvr
}  // namespace android
