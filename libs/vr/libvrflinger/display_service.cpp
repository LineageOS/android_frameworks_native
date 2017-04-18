#include "display_service.h"

#include <unistd.h>
#include <vector>

#include <pdx/default_transport/service_endpoint.h>
#include <pdx/rpc/remote_method.h>
#include <private/dvr/composite_hmd.h>
#include <private/dvr/device_metrics.h>
#include <private/dvr/display_rpc.h>
#include <private/dvr/display_types.h>
#include <private/dvr/numeric.h>
#include <private/dvr/polynomial_radial_distortion.h>
#include <private/dvr/types.h>

using android::pdx::Channel;
using android::pdx::Message;
using android::pdx::default_transport::Endpoint;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::rpc::WrapBuffer;

namespace android {
namespace dvr {

DisplayService::DisplayService() : DisplayService(nullptr) {}

DisplayService::DisplayService(Hwc2::Composer* hidl)
    : BASE("DisplayService", Endpoint::Create(DisplayRPC::kClientPath)),
      hardware_composer_(hidl) {
  hardware_composer_.Initialize();
}

bool DisplayService::IsInitialized() const {
  return BASE::IsInitialized() && hardware_composer_.IsInitialized();
}

std::string DisplayService::DumpState(size_t max_length) {
  std::vector<char> buffer(max_length);
  uint32_t max_len_p = static_cast<uint32_t>(max_length);
  hardware_composer_.Dump(buffer.data(), &max_len_p);
  return std::string(buffer.data());
}

void DisplayService::OnChannelClose(pdx::Message& /*message*/,
                                    const std::shared_ptr<Channel>& channel) {
  auto surface = std::static_pointer_cast<SurfaceChannel>(channel);
  if (surface && surface->type() == SurfaceTypeEnum::Normal) {
    auto display_surface = std::static_pointer_cast<DisplaySurface>(surface);
    display_surface->ManagerSetVisible(false);
    display_surface->ClientSetVisible(false);
    NotifyDisplayConfigurationUpdate();
  }
  // TODO(jwcai) Handle ChannelClose of VideoMeshSurface.
}

// First-level dispatch for display service messages. Directly handles messages
// that are independent of the display surface (metrics, creation) and routes
// surface-specific messages to the per-instance handlers.
pdx::Status<void> DisplayService::HandleMessage(pdx::Message& message) {
  auto channel = message.GetChannel<SurfaceChannel>();

  switch (message.GetOp()) {
    case DisplayRPC::GetMetrics::Opcode:
      DispatchRemoteMethod<DisplayRPC::GetMetrics>(
          *this, &DisplayService::OnGetMetrics, message);
      return {};

    case DisplayRPC::GetEdsCapture::Opcode:
      DispatchRemoteMethod<DisplayRPC::GetEdsCapture>(
          *this, &DisplayService::OnGetEdsCapture, message);
      return {};

    case DisplayRPC::CreateSurface::Opcode:
      DispatchRemoteMethod<DisplayRPC::CreateSurface>(
          *this, &DisplayService::OnCreateSurface, message);
      return {};

    case DisplayRPC::SetViewerParams::Opcode:
      DispatchRemoteMethod<DisplayRPC::SetViewerParams>(
          *this, &DisplayService::OnSetViewerParams, message);
      return {};

    case DisplayRPC::GetNamedBuffer::Opcode:
      DispatchRemoteMethod<DisplayRPC::GetNamedBuffer>(
          *this, &DisplayService::OnGetNamedBuffer, message);
      return {};

    case DisplayRPC::IsVrAppRunning::Opcode:
      DispatchRemoteMethod<DisplayRPC::IsVrAppRunning>(
          *this, &DisplayService::IsVrAppRunning, message);
      return {};

    // Direct the surface specific messages to the surface instance.
    case DisplayRPC::CreateBufferQueue::Opcode:
    case DisplayRPC::SetAttributes::Opcode:
    case DisplayRPC::GetMetadataBuffer::Opcode:
    case DisplayRPC::CreateVideoMeshSurface::Opcode:
    case DisplayRPC::VideoMeshSurfaceCreateProducerQueue::Opcode:
      return HandleSurfaceMessage(message);

    default:
      return Service::HandleMessage(message);
  }
}

SystemDisplayMetrics DisplayService::OnGetMetrics(pdx::Message& message) {
  const Compositor* compositor = hardware_composer_.GetCompositor();
  if (compositor == nullptr)
    REPLY_ERROR_RETURN(message, EINVAL, {});

  HeadMountMetrics head_mount = compositor->head_mount_metrics();
  CompositeHmd hmd(head_mount, hardware_composer_.GetHmdDisplayMetrics());
  vec2i distorted_render_size = hmd.GetRecommendedRenderTargetSize();
  FieldOfView left_fov = hmd.GetEyeFov(kLeftEye);
  FieldOfView right_fov = hmd.GetEyeFov(kRightEye);

  SystemDisplayMetrics metrics;

  metrics.display_native_width = GetDisplayMetrics().width;
  metrics.display_native_height = GetDisplayMetrics().height;
  metrics.display_x_dpi = GetDisplayMetrics().dpi.x;
  metrics.display_y_dpi = GetDisplayMetrics().dpi.y;
  metrics.distorted_width = distorted_render_size[0];
  metrics.distorted_height = distorted_render_size[1];
  metrics.vsync_period_ns =
      hardware_composer_.native_display_metrics().vsync_period_ns;
  metrics.hmd_ipd_mm = 0;
  metrics.inter_lens_distance_m = head_mount.GetInterLensDistance();
  metrics.left_fov_lrbt[0] = left_fov.GetLeft();
  metrics.left_fov_lrbt[1] = left_fov.GetRight();
  metrics.left_fov_lrbt[2] = left_fov.GetBottom();
  metrics.left_fov_lrbt[3] = left_fov.GetTop();
  metrics.right_fov_lrbt[0] = right_fov.GetLeft();
  metrics.right_fov_lrbt[1] = right_fov.GetRight();
  metrics.right_fov_lrbt[2] = right_fov.GetBottom();
  metrics.right_fov_lrbt[3] = right_fov.GetTop();

  return metrics;
}

// Creates a new DisplaySurface and associates it with this channel. This may
// only be done once per channel.
int DisplayService::OnCreateSurface(pdx::Message& message, int width,
                                    int height, int format, int usage,
                                    DisplaySurfaceFlags flags) {
  // A surface may only be created once per channel.
  if (message.GetChannel())
    return -EINVAL;

  ALOGI_IF(TRACE, "DisplayService::OnCreateSurface: cid=%d",
           message.GetChannelId());

  // Use the channel id as the unique surface id.
  const int surface_id = message.GetChannelId();
  const int process_id = message.GetProcessId();

  ALOGI_IF(TRACE,
           "DisplayService::OnCreateSurface: surface_id=%d process_id=%d "
           "width=%d height=%d format=%x usage=%x flags=%x",
           surface_id, process_id, width, height, format, usage, flags);

  // TODO(eieio,jbates): Validate request parameters.
  auto channel = std::make_shared<DisplaySurface>(
      this, surface_id, process_id, width, height, format, usage, flags);

  message.SetChannel(channel);
  NotifyDisplayConfigurationUpdate();
  return 0;
}

DisplayRPC::ByteBuffer DisplayService::OnGetEdsCapture(pdx::Message& message) {
  Compositor* compositor = hardware_composer_.GetCompositor();
  if (compositor == nullptr)
    REPLY_ERROR_RETURN(message, EINVAL, {});

  std::vector<std::uint8_t> buffer(sizeof(LateLatchOutput));

  if (!compositor->GetLastEdsPose(
          reinterpret_cast<LateLatchOutput*>(buffer.data()))) {
    REPLY_ERROR_RETURN(message, EPERM, {});
  }

  return WrapBuffer(std::move(buffer));
}

void DisplayService::OnSetViewerParams(pdx::Message& message,
                                       const ViewerParams& view_params) {
  Compositor* compositor = hardware_composer_.GetCompositor();
  if (compositor == nullptr)
    REPLY_ERROR_RETURN(message, EINVAL);

  FieldOfView left(55.0f, 55.0f, 55.0f, 55.0f);
  FieldOfView right(55.0f, 55.0f, 55.0f, 55.0f);
  if (view_params.left_eye_field_of_view_angles.size() >= 4) {
    left = FieldOfView(ToRad(view_params.left_eye_field_of_view_angles[0]),
                       ToRad(view_params.left_eye_field_of_view_angles[1]),
                       ToRad(view_params.left_eye_field_of_view_angles[2]),
                       ToRad(view_params.left_eye_field_of_view_angles[3]));
    right = FieldOfView(ToRad(view_params.left_eye_field_of_view_angles[1]),
                        ToRad(view_params.left_eye_field_of_view_angles[0]),
                        ToRad(view_params.left_eye_field_of_view_angles[2]),
                        ToRad(view_params.left_eye_field_of_view_angles[3]));
  }

  std::shared_ptr<ColorChannelDistortion> red_distortion;
  std::shared_ptr<ColorChannelDistortion> green_distortion;
  std::shared_ptr<ColorChannelDistortion> blue_distortion;

  // We should always have a red distortion.
  LOG_FATAL_IF(view_params.distortion_coefficients_r.empty());
  red_distortion = std::make_shared<PolynomialRadialDistortion>(
      view_params.distortion_coefficients_r);

  if (!view_params.distortion_coefficients_g.empty()) {
    green_distortion = std::make_shared<PolynomialRadialDistortion>(
        view_params.distortion_coefficients_g);
  }

  if (!view_params.distortion_coefficients_b.empty()) {
    blue_distortion = std::make_shared<PolynomialRadialDistortion>(
        view_params.distortion_coefficients_b);
  }

  HeadMountMetrics::EyeOrientation left_orientation =
      HeadMountMetrics::EyeOrientation::kCCW0Degrees;
  HeadMountMetrics::EyeOrientation right_orientation =
      HeadMountMetrics::EyeOrientation::kCCW0Degrees;

  if (view_params.eye_orientations.size() > 1) {
    left_orientation = static_cast<HeadMountMetrics::EyeOrientation>(
        view_params.eye_orientations[0]);
    right_orientation = static_cast<HeadMountMetrics::EyeOrientation>(
        view_params.eye_orientations[1]);
  }

  HeadMountMetrics head_mount_metrics(
      view_params.inter_lens_distance, view_params.tray_to_lens_distance,
      view_params.screen_to_lens_distance,
      static_cast<HeadMountMetrics::VerticalAlignment>(
          view_params.vertical_alignment),
      left, right, red_distortion, green_distortion, blue_distortion,
      left_orientation, right_orientation,
      view_params.screen_center_to_lens_distance);

  compositor->UpdateHeadMountMetrics(head_mount_metrics);
}

pdx::Status<BorrowedNativeBufferHandle> DisplayService::OnGetNamedBuffer(
    pdx::Message& /* message */, const std::string& name) {
  auto named_buffer = named_buffers_.find(name);
  if (named_buffer != named_buffers_.end()) {
    return {BorrowedNativeBufferHandle(*named_buffer->second, 0)};
  }

  return pdx::ErrorStatus(EINVAL);
}

// Calls the message handler for the DisplaySurface associated with this
// channel.
pdx::Status<void> DisplayService::HandleSurfaceMessage(pdx::Message& message) {
  auto surface = std::static_pointer_cast<SurfaceChannel>(message.GetChannel());
  ALOGW_IF(!surface,
           "DisplayService::HandleSurfaceMessage: surface is nullptr!");

  if (surface)
    return surface->HandleMessage(message);
  else
    REPLY_ERROR_RETURN(message, EINVAL, {});
}

std::shared_ptr<DisplaySurface> DisplayService::GetDisplaySurface(
    int surface_id) const {
  return std::static_pointer_cast<DisplaySurface>(GetChannel(surface_id));
}

std::vector<std::shared_ptr<DisplaySurface>>
DisplayService::GetDisplaySurfaces() const {
  return GetChannels<DisplaySurface>();
}

std::vector<std::shared_ptr<DisplaySurface>>
DisplayService::GetVisibleDisplaySurfaces() const {
  std::vector<std::shared_ptr<DisplaySurface>> visible_surfaces;

  ForEachDisplaySurface(
      [&](const std::shared_ptr<DisplaySurface>& surface) mutable {
        if (surface->IsVisible())
          visible_surfaces.push_back(surface);
      });

  return visible_surfaces;
}

void DisplayService::UpdateActiveDisplaySurfaces() {
  auto visible_surfaces = GetVisibleDisplaySurfaces();

  // Sort the surfaces based on manager z order first, then client z order.
  std::sort(visible_surfaces.begin(), visible_surfaces.end(),
            [](const std::shared_ptr<DisplaySurface>& a,
               const std::shared_ptr<DisplaySurface>& b) {
              return a->manager_z_order() != b->manager_z_order()
                         ? a->manager_z_order() < b->manager_z_order()
                         : a->client_z_order() < b->client_z_order();
            });

  ALOGD_IF(TRACE,
           "DisplayService::UpdateActiveDisplaySurfaces: %zd visible surfaces",
           visible_surfaces.size());

  // TODO(jbates) Have the shell manage blurred layers.
  bool blur_requested = false;
  auto end = visible_surfaces.crend();
  for (auto it = visible_surfaces.crbegin(); it != end; ++it) {
    auto surface = *it;
    // Surfaces with exclude_from_blur==true are not blurred
    // and are excluded from blur computation of other layers.
    if (surface->client_exclude_from_blur()) {
      surface->ManagerSetBlur(0.0f);
      continue;
    }
    surface->ManagerSetBlur(blur_requested ? 1.0f : 0.0f);
    if (surface->client_blur_behind())
      blur_requested = true;
  }

  hardware_composer_.SetDisplaySurfaces(std::move(visible_surfaces));
}

pdx::Status<BorrowedNativeBufferHandle> DisplayService::SetupNamedBuffer(
    const std::string& name, size_t size, int producer_usage,
    int consumer_usage) {
  auto named_buffer = named_buffers_.find(name);
  if (named_buffer == named_buffers_.end()) {
    auto ion_buffer = std::make_unique<IonBuffer>(
        static_cast<int>(size), 1, HAL_PIXEL_FORMAT_BLOB, producer_usage,
        consumer_usage);
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

int DisplayService::IsVrAppRunning(pdx::Message& message) {
  bool visible = false;
  ForEachDisplaySurface(
      [&visible](const std::shared_ptr<DisplaySurface>& surface) {
        if (surface->client_z_order() == 0 && surface->IsVisible())
          visible = true;
      });

  REPLY_SUCCESS_RETURN(message, visible, 0);
}

}  // namespace dvr
}  // namespace android
