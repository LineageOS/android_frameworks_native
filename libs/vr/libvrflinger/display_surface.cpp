#include "display_surface.h"

#include <utils/Trace.h>

#include <private/dvr/platform_defines.h>

#include "display_service.h"
#include "hardware_composer.h"

#define LOCAL_TRACE 1

using android::pdx::BorrowedChannelHandle;
using android::pdx::LocalChannelHandle;
using android::pdx::Message;
using android::pdx::RemoteChannelHandle;
using android::pdx::Status;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::rpc::IfAnyOf;

namespace android {
namespace dvr {

DisplaySurface::DisplaySurface(DisplayService* service, int surface_id,
                               int process_id, int width, int height,
                               int format, int usage, int flags)
    : SurfaceChannel(service, surface_id, SurfaceTypeEnum::Normal,
                     sizeof(DisplaySurfaceMetadata)),
      process_id_(process_id),
      acquired_buffers_(kMaxPostedBuffers),
      video_mesh_surfaces_updated_(false),
      width_(width),
      height_(height),
      format_(format),
      usage_(usage),
      flags_(flags),
      client_visible_(false),
      client_z_order_(0),
      client_exclude_from_blur_(false),
      client_blur_behind_(false),
      manager_visible_(false),
      manager_z_order_(0),
      manager_blur_(0.0f),
      layer_order_(0),
      allocated_buffer_index_(0) {}

DisplaySurface::~DisplaySurface() {
  ALOGD_IF(LOCAL_TRACE,
           "DisplaySurface::~DisplaySurface: surface_id=%d process_id=%d",
           surface_id(), process_id_);
}

void DisplaySurface::ManagerSetVisible(bool visible) {
  std::lock_guard<std::mutex> autolock(lock_);
  manager_visible_ = visible;
}

void DisplaySurface::ManagerSetZOrder(int z_order) {
  std::lock_guard<std::mutex> autolock(lock_);
  manager_z_order_ = z_order;
}

void DisplaySurface::ManagerSetBlur(float blur) {
  std::lock_guard<std::mutex> autolock(lock_);
  manager_blur_ = blur;
}

void DisplaySurface::ClientSetVisible(bool visible) {
  std::lock_guard<std::mutex> autolock(lock_);
  client_visible_ = visible;
}

void DisplaySurface::ClientSetZOrder(int z_order) {
  std::lock_guard<std::mutex> autolock(lock_);
  client_z_order_ = z_order;
}

void DisplaySurface::ClientSetExcludeFromBlur(bool exclude_from_blur) {
  std::lock_guard<std::mutex> autolock(lock_);
  client_exclude_from_blur_ = exclude_from_blur;
}

void DisplaySurface::ClientSetBlurBehind(bool blur_behind) {
  std::lock_guard<std::mutex> autolock(lock_);
  client_blur_behind_ = blur_behind;
}

void DisplaySurface::DequeueBuffersLocked() {
  if (consumer_queue_ == nullptr) {
    ALOGE(
        "DisplaySurface::DequeueBuffersLocked: Consumer queue is not "
        "initialized.");
    return;
  }

  size_t slot;
  uint64_t sequence;
  while (true) {
    LocalHandle acquire_fence;
    auto buffer_consumer =
        consumer_queue_->Dequeue(0, &slot, &sequence, &acquire_fence);
    if (!buffer_consumer) {
      ALOGD_IF(TRACE,
               "DisplaySurface::DequeueBuffersLocked: We have dequeued all "
               "available buffers.");
      return;
    }

    // Save buffer index, associated with the buffer id so that it can be looked
    // up later.
    int buffer_id = buffer_consumer->id();
    if (buffer_id_to_index_.find(buffer_id) == buffer_id_to_index_.end()) {
      buffer_id_to_index_[buffer_id] = allocated_buffer_index_;
      ++allocated_buffer_index_;
    }

    if (!IsVisible()) {
      ATRACE_NAME("DropFrameOnInvisibleSurface");
      ALOGD_IF(TRACE,
               "DisplaySurface::DequeueBuffersLocked: Discarding buffer_id=%d "
               "on invisible surface.",
               buffer_consumer->id());
      buffer_consumer->Discard();
      continue;
    }

    if (acquired_buffers_.IsFull()) {
      ALOGE(
          "DisplaySurface::DequeueBuffersLocked: Posted buffers full, "
          "overwriting.");
      acquired_buffers_.PopBack();
    }

    acquired_buffers_.Append(
        AcquiredBuffer(buffer_consumer, std::move(acquire_fence), sequence));
  }
}

AcquiredBuffer DisplaySurface::AcquireCurrentBuffer() {
  std::lock_guard<std::mutex> autolock(lock_);
  DequeueBuffersLocked();

  if (acquired_buffers_.IsEmpty()) {
    ALOGE(
        "DisplaySurface::AcquireCurrentBuffer: attempt to acquire buffer when "
        "none are posted.");
    return AcquiredBuffer();
  }
  AcquiredBuffer buffer = std::move(acquired_buffers_.Front());
  acquired_buffers_.PopFront();
  ALOGD_IF(TRACE, "DisplaySurface::AcquireCurrentBuffer: buffer: %p",
           buffer.buffer().get());
  return buffer;
}

AcquiredBuffer DisplaySurface::AcquireNewestAvailableBuffer(
    AcquiredBuffer* skipped_buffer) {
  std::lock_guard<std::mutex> autolock(lock_);
  DequeueBuffersLocked();

  AcquiredBuffer buffer;
  int frames = 0;
  // Basic latency stopgap for when the application misses a frame:
  // If the application recovers on the 2nd or 3rd (etc) frame after
  // missing, this code will skip frames to catch up by checking if
  // the next frame is also available.
  while (!acquired_buffers_.IsEmpty() &&
         acquired_buffers_.Front().IsAvailable()) {
    // Capture the skipped buffer into the result parameter.
    // Note that this API only supports skipping one buffer per vsync.
    if (frames > 0 && skipped_buffer)
      *skipped_buffer = std::move(buffer);
    ++frames;
    buffer = std::move(acquired_buffers_.Front());
    acquired_buffers_.PopFront();
    if (frames == 2)
      break;
  }
  ALOGD_IF(TRACE, "DisplaySurface::AcquireNewestAvailableBuffer: buffer: %p",
           buffer.buffer().get());
  return buffer;
}

uint32_t DisplaySurface::GetRenderBufferIndex(int buffer_id) {
  std::lock_guard<std::mutex> autolock(lock_);

  if (buffer_id_to_index_.find(buffer_id) == buffer_id_to_index_.end()) {
    ALOGW("DisplaySurface::GetRenderBufferIndex: unknown buffer_id %d.",
          buffer_id);
    return 0;
  }
  return buffer_id_to_index_[buffer_id];
}

bool DisplaySurface::IsBufferAvailable() {
  std::lock_guard<std::mutex> autolock(lock_);
  DequeueBuffersLocked();

  return !acquired_buffers_.IsEmpty() &&
         acquired_buffers_.Front().IsAvailable();
}

bool DisplaySurface::IsBufferPosted() {
  std::lock_guard<std::mutex> autolock(lock_);
  DequeueBuffersLocked();

  return !acquired_buffers_.IsEmpty();
}

int DisplaySurface::HandleMessage(pdx::Message& message) {
  switch (message.GetOp()) {
    case DisplayRPC::SetAttributes::Opcode:
      DispatchRemoteMethod<DisplayRPC::SetAttributes>(
          *this, &DisplaySurface::OnClientSetAttributes, message);
      break;

    case DisplayRPC::CreateBufferQueue::Opcode:
      DispatchRemoteMethod<DisplayRPC::CreateBufferQueue>(
          *this, &DisplaySurface::OnCreateBufferQueue, message);
      break;

    case DisplayRPC::CreateVideoMeshSurface::Opcode:
      DispatchRemoteMethod<DisplayRPC::CreateVideoMeshSurface>(
          *this, &DisplaySurface::OnCreateVideoMeshSurface, message);
      break;

    default:
      return SurfaceChannel::HandleMessage(message);
  }

  return 0;
}

int DisplaySurface::OnClientSetAttributes(
    pdx::Message& /*message*/, const DisplaySurfaceAttributes& attributes) {
  for (const auto& attribute : attributes) {
    const auto& key = attribute.first;
    const auto* variant = &attribute.second;
    bool invalid_value = false;
    switch (key) {
      case DisplaySurfaceAttributeEnum::ZOrder:
        invalid_value = !IfAnyOf<int32_t, int64_t, float>::Call(
            variant, [this](const auto& value) {
              DisplaySurface::ClientSetZOrder(value);
            });
        break;
      case DisplaySurfaceAttributeEnum::Visible:
        invalid_value = !IfAnyOf<int32_t, int64_t, bool>::Call(
            variant, [this](const auto& value) {
              DisplaySurface::ClientSetVisible(value);
            });
        break;
      case DisplaySurfaceAttributeEnum::ExcludeFromBlur:
        invalid_value = !IfAnyOf<int32_t, int64_t, bool>::Call(
            variant, [this](const auto& value) {
              DisplaySurface::ClientSetExcludeFromBlur(value);
            });
        break;
      case DisplaySurfaceAttributeEnum::BlurBehind:
        invalid_value = !IfAnyOf<int32_t, int64_t, bool>::Call(
            variant, [this](const auto& value) {
              DisplaySurface::ClientSetBlurBehind(value);
            });
        break;
      default:
        ALOGW(
            "DisplaySurface::OnClientSetAttributes: Unrecognized attribute %d "
            "surface_id=%d",
            key, surface_id());
        break;
    }

    if (invalid_value) {
      ALOGW(
          "DisplaySurface::OnClientSetAttributes: Failed to set display "
          "surface attribute '%s' because of incompatible type: %d",
          DisplaySurfaceAttributeEnum::ToString(key).c_str(), variant->index());
    }
  }

  service()->NotifyDisplayConfigurationUpdate();
  return 0;
}

LocalChannelHandle DisplaySurface::OnCreateBufferQueue(Message& message) {
  ATRACE_NAME("DisplaySurface::OnCreateBufferQueue");

  if (consumer_queue_ != nullptr) {
    ALOGE(
        "DisplaySurface::OnCreateBufferQueue: A ProdcuerQueue has already been "
        "created and transported to DisplayClient.");
    REPLY_ERROR_RETURN(message, EALREADY, {});
  }

  auto producer = ProducerQueue::Create<uint64_t>();
  consumer_queue_ = producer->CreateConsumerQueue();

  return std::move(producer->GetChannelHandle());
}

RemoteChannelHandle DisplaySurface::OnCreateVideoMeshSurface(
    pdx::Message& message) {
  if (flags_ & DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION) {
    ALOGE(
        "DisplaySurface::OnCreateVideoMeshSurface: system distorion is "
        "disabled on this display surface, cannot create VideoMeshSurface on "
        "top of it.");
    REPLY_ERROR_RETURN(message, EINVAL, {});
  }

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);

  if (!status) {
    ALOGE(
        "DisplaySurface::OnCreateVideoMeshSurface: failed to push channel: %s",
        status.GetErrorMessage().c_str());
    REPLY_ERROR_RETURN(message, ENOMEM, {});
  }

  auto surface = std::make_shared<VideoMeshSurface>(service(), channel_id);
  const int ret = service()->SetChannel(channel_id, surface);
  if (ret < 0) {
    ALOGE(
        "DisplaySurface::OnCreateVideoMeshSurface: failed to set new video "
        "mesh surface channel: %s",
        strerror(-ret));
    REPLY_ERROR_RETURN(message, ENOMEM, {});
  }

  {
    std::lock_guard<std::mutex> autolock(lock_);
    pending_video_mesh_surfaces_.push_back(surface);
    video_mesh_surfaces_updated_ = true;
  }

  return status.take();
}

std::vector<std::shared_ptr<VideoMeshSurface>>
DisplaySurface::GetVideoMeshSurfaces() {
  std::lock_guard<std::mutex> autolock(lock_);
  std::vector<std::shared_ptr<VideoMeshSurface>> surfaces;

  for (auto& surface : pending_video_mesh_surfaces_) {
    if (auto video_surface = surface.lock()) {
      surfaces.push_back(video_surface);
    } else {
      ALOGE("Unable to lock video mesh surface.");
    }
  }

  pending_video_mesh_surfaces_.clear();
  video_mesh_surfaces_updated_ = false;
  return surfaces;
}

}  // namespace dvr
}  // namespace android
