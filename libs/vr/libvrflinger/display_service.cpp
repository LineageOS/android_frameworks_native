#include "display_service.h"

#include <unistd.h>
#include <vector>

#include <dvr/dvr_display_types.h>
#include <pdx/default_transport/service_endpoint.h>
#include <pdx/rpc/remote_method.h>
#include <private/dvr/display_protocol.h>
#include <private/dvr/numeric.h>
#include <private/dvr/types.h>

using android::dvr::display::DisplayProtocol;
using android::pdx::Channel;
using android::pdx::ErrorStatus;
using android::pdx::Message;
using android::pdx::Status;
using android::pdx::default_transport::Endpoint;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

DisplayService::DisplayService(Hwc2::Composer* hidl,
                               RequestDisplayCallback request_display_callback)
    : BASE("DisplayService",
           Endpoint::Create(display::DisplayProtocol::kClientPath)),
      hardware_composer_(hidl, request_display_callback),
      request_display_callback_(request_display_callback) {
  hardware_composer_.Initialize();
}

bool DisplayService::IsInitialized() const {
  return BASE::IsInitialized() && hardware_composer_.IsInitialized();
}

std::string DisplayService::DumpState(size_t /*max_length*/) {
  return hardware_composer_.Dump();
}

void DisplayService::OnChannelClose(pdx::Message& message,
                                    const std::shared_ptr<Channel>& channel) {
  if (auto surface = std::static_pointer_cast<DisplaySurface>(channel)) {
    surface->OnSetAttributes(message,
                             {{display::SurfaceAttribute::Visible,
                               display::SurfaceAttributeValue{false}}});
    SurfaceUpdated(surface->surface_type(),
                   display::SurfaceUpdateFlags::VisibilityChanged);
  }
}

// First-level dispatch for display service messages. Directly handles messages
// that are independent of the display surface (metrics, creation) and routes
// surface-specific messages to the per-instance handlers.
Status<void> DisplayService::HandleMessage(pdx::Message& message) {
  ALOGD_IF(TRACE, "DisplayService::HandleMessage: opcode=%d", message.GetOp());
  switch (message.GetOp()) {
    case DisplayProtocol::GetMetrics::Opcode:
      DispatchRemoteMethod<DisplayProtocol::GetMetrics>(
          *this, &DisplayService::OnGetMetrics, message);
      return {};

    case DisplayProtocol::CreateSurface::Opcode:
      DispatchRemoteMethod<DisplayProtocol::CreateSurface>(
          *this, &DisplayService::OnCreateSurface, message);
      return {};

    case DisplayProtocol::GetNamedBuffer::Opcode:
      DispatchRemoteMethod<DisplayProtocol::GetNamedBuffer>(
          *this, &DisplayService::OnGetNamedBuffer, message);
      return {};

    case DisplayProtocol::IsVrAppRunning::Opcode:
      DispatchRemoteMethod<DisplayProtocol::IsVrAppRunning>(
          *this, &DisplayService::IsVrAppRunning, message);
      return {};

    // Direct the surface specific messages to the surface instance.
    case DisplayProtocol::SetAttributes::Opcode:
    case DisplayProtocol::CreateQueue::Opcode:
    case DisplayProtocol::GetSurfaceInfo::Opcode:
      return HandleSurfaceMessage(message);

    default:
      return Service::HandleMessage(message);
  }
}

Status<display::Metrics> DisplayService::OnGetMetrics(
    pdx::Message& /*message*/) {
  return {{static_cast<uint32_t>(GetDisplayMetrics().width),
           static_cast<uint32_t>(GetDisplayMetrics().height),
           static_cast<uint32_t>(GetDisplayMetrics().dpi.x),
           static_cast<uint32_t>(GetDisplayMetrics().dpi.y),
           static_cast<uint32_t>(
               hardware_composer_.native_display_metrics().vsync_period_ns),
           0,
           0,
           0,
           0.0,
           {},
           {}}};
}

// Creates a new DisplaySurface and associates it with this channel. This may
// only be done once per channel.
Status<display::SurfaceInfo> DisplayService::OnCreateSurface(
    pdx::Message& message, const display::SurfaceAttributes& attributes) {
  // A surface may only be created once per channel.
  if (message.GetChannel())
    return ErrorStatus(EINVAL);

  ALOGI_IF(TRACE, "DisplayService::OnCreateSurface: cid=%d",
           message.GetChannelId());

  // Use the channel id as the unique surface id.
  const int surface_id = message.GetChannelId();
  const int process_id = message.GetProcessId();
  const int user_id = message.GetEffectiveUserId();

  ALOGI_IF(TRACE,
           "DisplayService::OnCreateSurface: surface_id=%d process_id=%d",
           surface_id, process_id);

  auto surface_status =
      DisplaySurface::Create(this, surface_id, process_id, user_id, attributes);
  if (!surface_status) {
    ALOGE("DisplayService::OnCreateSurface: Failed to create surface: %s",
          surface_status.GetErrorMessage().c_str());
    return ErrorStatus(surface_status.error());
  }

  SurfaceType surface_type = surface_status.get()->surface_type();
  display::SurfaceUpdateFlags update_flags =
      surface_status.get()->update_flags();
  display::SurfaceInfo surface_info{surface_status.get()->surface_id(),
                                    surface_status.get()->visible(),
                                    surface_status.get()->z_order()};

  message.SetChannel(surface_status.take());

  SurfaceUpdated(surface_type, update_flags);
  return {surface_info};
}

void DisplayService::SurfaceUpdated(SurfaceType surface_type,
                                    display::SurfaceUpdateFlags update_flags) {
  ALOGD_IF(TRACE, "DisplayService::SurfaceUpdated: update_flags=%x",
           update_flags.value());
  if (update_flags.value() != 0) {
    if (surface_type == SurfaceType::Application)
      NotifyDisplayConfigurationUpdate();
    else
      UpdateActiveDisplaySurfaces();
  }
}

pdx::Status<BorrowedNativeBufferHandle> DisplayService::OnGetNamedBuffer(
    pdx::Message& /* message */, const std::string& name) {
  ALOGD_IF(TRACE, "displayService::OnGetNamedBuffer: name=%s", name.c_str());
  auto named_buffer = named_buffers_.find(name);
  if (named_buffer != named_buffers_.end())
    return {BorrowedNativeBufferHandle(*named_buffer->second, 0)};
  else
    return pdx::ErrorStatus(EINVAL);
}

// Calls the message handler for the DisplaySurface associated with this
// channel.
Status<void> DisplayService::HandleSurfaceMessage(pdx::Message& message) {
  auto surface = std::static_pointer_cast<DisplaySurface>(message.GetChannel());
  ALOGW_IF(!surface,
           "DisplayService::HandleSurfaceMessage: surface is nullptr!");

  if (surface)
    return surface->HandleMessage(message);
  else
    return ErrorStatus(EINVAL);
}

std::shared_ptr<DisplaySurface> DisplayService::GetDisplaySurface(
    int surface_id) const {
  return std::static_pointer_cast<DisplaySurface>(GetChannel(surface_id));
}

std::vector<std::shared_ptr<DisplaySurface>>
DisplayService::GetDisplaySurfaces() const {
  return GetChannels<DisplaySurface>();
}

std::vector<std::shared_ptr<DirectDisplaySurface>>
DisplayService::GetVisibleDisplaySurfaces() const {
  std::vector<std::shared_ptr<DirectDisplaySurface>> visible_surfaces;

  ForEachDisplaySurface(
      SurfaceType::Direct,
      [&](const std::shared_ptr<DisplaySurface>& surface) mutable {
        if (surface->visible()) {
          visible_surfaces.push_back(
              std::static_pointer_cast<DirectDisplaySurface>(surface));
          surface->ClearUpdate();
        }
      });

  return visible_surfaces;
}

void DisplayService::UpdateActiveDisplaySurfaces() {
  auto visible_surfaces = GetVisibleDisplaySurfaces();

  std::sort(visible_surfaces.begin(), visible_surfaces.end(),
            [](const std::shared_ptr<DisplaySurface>& a,
               const std::shared_ptr<DisplaySurface>& b) {
              return a->z_order() < b->z_order();
            });

  ALOGD_IF(TRACE,
           "DisplayService::UpdateActiveDisplaySurfaces: %zd visible surfaces",
           visible_surfaces.size());

  hardware_composer_.SetDisplaySurfaces(std::move(visible_surfaces));
}

pdx::Status<BorrowedNativeBufferHandle> DisplayService::SetupNamedBuffer(
    const std::string& name, size_t size, uint64_t usage) {
  auto named_buffer = named_buffers_.find(name);
  if (named_buffer == named_buffers_.end()) {
    auto ion_buffer = std::make_unique<IonBuffer>(static_cast<int>(size), 1,
                                                  HAL_PIXEL_FORMAT_BLOB, usage);
    named_buffer =
        named_buffers_.insert(std::make_pair(name, std::move(ion_buffer)))
            .first;
  }

  return {BorrowedNativeBufferHandle(*named_buffer->second, 0)};
}

void DisplayService::OnHardwareComposerRefresh() {
  hardware_composer_.OnHardwareComposerRefresh();
}

void DisplayService::SetDisplayConfigurationUpdateNotifier(
    DisplayConfigurationUpdateNotifier update_notifier) {
  update_notifier_ = update_notifier;
}

void DisplayService::NotifyDisplayConfigurationUpdate() {
  if (update_notifier_)
    update_notifier_();
}

Status<bool> DisplayService::IsVrAppRunning(pdx::Message& /*message*/) {
  bool visible = false;
  ForEachDisplaySurface(
      SurfaceType::Application,
      [&visible](const std::shared_ptr<DisplaySurface>& surface) {
        if (surface->visible())
          visible = true;
      });

  return {visible};
}

}  // namespace dvr
}  // namespace android
