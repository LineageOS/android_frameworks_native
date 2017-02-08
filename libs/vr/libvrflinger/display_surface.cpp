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
      posted_buffers_(kMaxPostedBuffers),
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
      allocated_buffer_index_(0),
      layer_order_(0) {}

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

size_t DisplaySurface::GetBufferCount() const {
  std::lock_guard<std::mutex> autolock(lock_);
  return buffers_.size();
}

std::vector<std::shared_ptr<BufferConsumer>> DisplaySurface::GetBuffers() {
  std::lock_guard<std::mutex> autolock(lock_);
  std::vector<std::shared_ptr<BufferConsumer>> return_vector(buffers_.size());

  for (const auto pair : buffers_) {
    return_vector.push_back(pair.second);
  }

  return return_vector;
}

AcquiredBuffer DisplaySurface::AcquireNewestAvailableBuffer(
    AcquiredBuffer* skipped_buffer) {
  std::lock_guard<std::mutex> autolock(lock_);
  AcquiredBuffer buffer;
  int frames = 0;
  // Basic latency stopgap for when the application misses a frame:
  // If the application recovers on the 2nd or 3rd (etc) frame after
  // missing, this code will skip frames to catch up by checking if
  // the next frame is also available.
  while (!posted_buffers_.IsEmpty() && posted_buffers_.Front().IsAvailable()) {
    // Capture the skipped buffer into the result parameter.
    // Note that this API only supports skipping one buffer per vsync.
    if (frames > 0 && skipped_buffer)
      *skipped_buffer = std::move(buffer);
    ++frames;
    buffer = std::move(posted_buffers_.Front());
    posted_buffers_.PopFront();
    if (frames == 2)
      break;
  }
  return buffer;
}

bool DisplaySurface::IsBufferAvailable() const {
  std::lock_guard<std::mutex> autolock(lock_);
  return !posted_buffers_.IsEmpty() && posted_buffers_.Front().IsAvailable();
}

bool DisplaySurface::IsBufferPosted() const {
  std::lock_guard<std::mutex> autolock(lock_);
  return !posted_buffers_.IsEmpty();
}

AcquiredBuffer DisplaySurface::AcquireCurrentBuffer() {
  std::lock_guard<std::mutex> autolock(lock_);
  if (posted_buffers_.IsEmpty()) {
    ALOGE("Error: attempt to acquire buffer when none are posted.");
    return AcquiredBuffer();
  }
  AcquiredBuffer buffer = std::move(posted_buffers_.Front());
  posted_buffers_.PopFront();
  return buffer;
}

int DisplaySurface::GetConsumers(std::vector<LocalChannelHandle>* consumers) {
  std::lock_guard<std::mutex> autolock(lock_);
  std::vector<LocalChannelHandle> items;

  for (auto pair : buffers_) {
    const auto& buffer = pair.second;

    Status<LocalChannelHandle> consumer_channel = buffer->CreateConsumer();
    if (!consumer_channel) {
      ALOGE(
          "DisplaySurface::GetConsumers: Failed to get a new consumer for "
          "buffer %d: %s",
          buffer->id(), consumer_channel.GetErrorMessage().c_str());
      return -consumer_channel.error();
    }

    items.push_back(consumer_channel.take());
  }

  *consumers = std::move(items);
  return 0;
}

int DisplaySurface::HandleMessage(pdx::Message& message) {
  switch (message.GetOp()) {
    case DisplayRPC::SetAttributes::Opcode:
      DispatchRemoteMethod<DisplayRPC::SetAttributes>(
          *this, &DisplaySurface::OnClientSetAttributes, message);
      break;

    case DisplayRPC::AllocateBuffer::Opcode:
      DispatchRemoteMethod<DisplayRPC::AllocateBuffer>(
          *this, &DisplaySurface::OnAllocateBuffer, message);
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

// Allocates a new buffer for the DisplaySurface associated with this channel.
std::pair<uint32_t, LocalChannelHandle> DisplaySurface::OnAllocateBuffer(
    pdx::Message& message) {
  // Inject flag to enable framebuffer compression for the application buffers.
  // TODO(eieio,jbates): Make this configurable per hardware platform.
  const int usage = usage_ | GRALLOC_USAGE_QCOM_FRAMEBUFFER_COMPRESSION;
  const int slice_count =
      (flags_ & static_cast<int>(DisplaySurfaceFlagsEnum::SeparateGeometry))
          ? 2
          : 1;

  ALOGI_IF(
      TRACE,
      "DisplaySurface::OnAllocateBuffer: width=%d height=%d format=%x usage=%x "
      "slice_count=%d",
      width_, height_, format_, usage, slice_count);

  // Create a producer buffer to hand back to the sender.
  auto producer = BufferProducer::Create(width_, height_, format_, usage,
                                         sizeof(uint64_t), slice_count);
  if (!producer)
    REPLY_ERROR_RETURN(message, EINVAL, {});

  // Create and import a consumer attached to the producer.
  Status<LocalChannelHandle> consumer_channel = producer->CreateConsumer();
  if (!consumer_channel)
    REPLY_ERROR_RETURN(message, consumer_channel.error(), {});

  std::shared_ptr<BufferConsumer> consumer =
      BufferConsumer::Import(consumer_channel.take());
  if (!consumer)
    REPLY_ERROR_RETURN(message, ENOMEM, {});

  // Add the consumer to this surface.
  int err = AddConsumer(consumer);
  if (err < 0) {
    ALOGE("DisplaySurface::OnAllocateBuffer: failed to add consumer: buffer=%d",
          consumer->id());
    REPLY_ERROR_RETURN(message, -err, {});
  }

  // Move the channel handle so that it doesn't get closed when the producer
  // goes out of scope.
  std::pair<uint32_t, LocalChannelHandle> return_value(
      allocated_buffer_index_, std::move(producer->GetChannelHandle()));

  // Save buffer index, associated with the buffer id so that it can be looked
  // up later.
  buffer_id_to_index_[consumer->id()] = allocated_buffer_index_;
  ++allocated_buffer_index_;

  return return_value;
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

int DisplaySurface::AddConsumer(
    const std::shared_ptr<BufferConsumer>& consumer) {
  ALOGD_IF(TRACE, "DisplaySurface::AddConsumer: buffer_id=%d", consumer->id());
  // Add the consumer to the epoll dispatcher, edge-triggered.
  int err = service()->dispatcher_.AddEventHandler(
      consumer->event_fd(), EPOLLET | EPOLLIN | EPOLLHUP,
      std::bind(&DisplaySurface::HandleConsumerEvents,
                std::static_pointer_cast<DisplaySurface>(shared_from_this()),
                consumer, std::placeholders::_1));
  if (err) {
    ALOGE(
        "DisplaySurface::AddConsumer: failed to add epoll event handler for "
        "consumer: %s",
        strerror(-err));
    return err;
  }

  // Add the consumer to the list of buffers for this surface.
  std::lock_guard<std::mutex> autolock(lock_);
  buffers_.insert(std::make_pair(consumer->id(), consumer));
  return 0;
}

void DisplaySurface::RemoveConsumer(
    const std::shared_ptr<BufferConsumer>& consumer) {
  ALOGD_IF(TRACE, "DisplaySurface::RemoveConsumer: buffer_id=%d",
           consumer->id());
  service()->dispatcher_.RemoveEventHandler(consumer->event_fd());

  std::lock_guard<std::mutex> autolock(lock_);
  buffers_.erase(consumer->id());
}

void DisplaySurface::RemoveConsumerUnlocked(
    const std::shared_ptr<BufferConsumer>& consumer) {
  ALOGD_IF(TRACE, "DisplaySurface::RemoveConsumerUnlocked: buffer_id=%d",
           consumer->id());
  service()->dispatcher_.RemoveEventHandler(consumer->event_fd());
  buffers_.erase(consumer->id());
}

void DisplaySurface::OnPostConsumer(
    const std::shared_ptr<BufferConsumer>& consumer) {
  ATRACE_NAME("DisplaySurface::OnPostConsumer");
  std::lock_guard<std::mutex> autolock(lock_);

  if (!IsVisible()) {
    ALOGD_IF(TRACE,
             "DisplaySurface::OnPostConsumer: Discarding buffer_id=%d on "
             "invisible surface.",
             consumer->id());
    consumer->Discard();
    return;
  }

  if (posted_buffers_.IsFull()) {
    ALOGE("Error: posted buffers full, overwriting");
    posted_buffers_.PopBack();
  }

  int error;
  posted_buffers_.Append(AcquiredBuffer(consumer, &error));

  // Remove the consumer if the other end was closed.
  if (posted_buffers_.Back().IsEmpty() && error == -EPIPE)
    RemoveConsumerUnlocked(consumer);
}

void DisplaySurface::HandleConsumerEvents(
    const std::shared_ptr<BufferConsumer>& consumer, int events) {
  auto status = consumer->GetEventMask(events);
  if (!status) {
    ALOGW(
        "DisplaySurface::HandleConsumerEvents: Failed to get event mask for "
        "consumer: %s",
        status.GetErrorMessage().c_str());
    return;
  }

  events = status.get();
  if (events & EPOLLHUP) {
    ALOGD_IF(TRACE,
             "DisplaySurface::HandleConsumerEvents: removing event handler for "
             "buffer=%d",
             consumer->id());
    RemoveConsumer(consumer);
  } else if (events & EPOLLIN) {
    // BufferHub uses EPOLLIN to signal consumer ownership.
    ALOGD_IF(TRACE,
             "DisplaySurface::HandleConsumerEvents: posting buffer=%d for "
             "process=%d",
             consumer->id(), process_id_);

    OnPostConsumer(consumer);
  }
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
