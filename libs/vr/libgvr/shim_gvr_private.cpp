#define LOG_TAG "libgvr_shim_private"

#include <log/log.h>
#include <private/dvr/display_rpc.h>
#include <private/dvr/internal_types.h>
#include <vr/gvr/capi/include/gvr.h>
#include <vr/gvr/capi/src/gvr_private.h>

#include <pdx/rpc/remote_method.h>
#include "deviceparams/CardboardDevice.nolite.pb.h"

bool gvr_set_async_reprojection_enabled(gvr_context* /* gvr */,
                                        bool /* enabled */) {
  return true;
}

void gvr_on_surface_created_reprojection_thread(gvr_context* /* gvr */) {}

void gvr_render_reprojection_thread(gvr_context* /* gvr */) {}

void gvr_on_pause_reprojection_thread(gvr_context* /* gvr */) {}

void gvr_update_surface_reprojection_thread(
    gvr_context* /* gvr */, int32_t /* surface_id */, int32_t /* texture_id */,
    gvr_clock_time_point /* timestamp */, gvr_mat4f /* surface_transform */) {
  ALOGE("gvr_update_surface_reprojection_thread not implemented");
}

void gvr_remove_all_surfaces_reprojection_thread(gvr_context* /* gvr */) {
  ALOGE("gvr_remove_all_surfaces_reprojection_thread not implemented");
}

void gvr_reconnect_sensors(gvr_context* /* gvr */) {
  ALOGE("gvr_reconnect_sensors not implemented");
}

bool gvr_set_viewer_params(gvr_context* gvr,
                           const void* serialized_viewer_params,
                           size_t serialized_viewer_params_size_bytes) {
  std::string serialized_device_params_string(
      reinterpret_cast<const char*>(serialized_viewer_params),
      serialized_viewer_params_size_bytes);
  std::unique_ptr<proto::DeviceParams> device_params(new proto::DeviceParams);
  if (!device_params->ParseFromString(serialized_device_params_string)) {
    ALOGE("Invalid serialized Cardboard DeviceParams");
    return false;
  }

  android::dvr::ViewerParams viewer_params;

  viewer_params.screen_to_lens_distance =
      device_params->screen_to_lens_distance();
  viewer_params.inter_lens_distance = device_params->inter_lens_distance();
  for (int i = 0; i < device_params->left_eye_field_of_view_angles_size();
       ++i) {
    viewer_params.left_eye_field_of_view_angles.push_back(
        device_params->left_eye_field_of_view_angles(i));
  }

  viewer_params.vertical_alignment =
      static_cast<android::dvr::ViewerParams::VerticalAlignmentType>(
          device_params->vertical_alignment());
  viewer_params.tray_to_lens_distance = device_params->tray_to_lens_distance();

  // TODO(hendrikw) Leave the g and b coefficients empty until we support
  // chromatic aberration correction.
  for (int i = 0; i < device_params->distortion_coefficients_size(); ++i) {
    viewer_params.distortion_coefficients_r.push_back(
        device_params->distortion_coefficients(i));
  }

  viewer_params.screen_center_to_lens_distance =
      viewer_params.inter_lens_distance / 2.0;
  if (device_params->has_internal()) {
    for (int i = 0; i < device_params->internal().eye_orientations_size();
         ++i) {
      viewer_params.eye_orientations.push_back(
          static_cast<android::dvr::ViewerParams::EyeOrientation>(
              device_params->internal().eye_orientations(i)));
    }

    if (device_params->internal().has_screen_center_to_lens_distance())
      viewer_params.screen_center_to_lens_distance =
          device_params->internal().screen_center_to_lens_distance();
  }

  if (device_params->has_daydream_internal()) {
    viewer_params.daydream_internal.version =
        device_params->daydream_internal().version();
    for (int i = 0;
         i < device_params->daydream_internal().alignment_markers_size(); ++i) {
      viewer_params.daydream_internal.alignment_markers.push_back(
          {device_params->daydream_internal().alignment_markers(i).horizontal(),
           device_params->daydream_internal().alignment_markers(i).vertical()});
    }
  }

  gvr->display_client_->SetViewerParams(viewer_params);
  return true;
}

void gvr_set_lens_offset(gvr_context* /* gvr */, gvr_vec2f /* offset */) {
  ALOGE("gvr_set_lens_offset not implemented");
}

void gvr_set_display_metrics(gvr_context* /* gvr */,
                             gvr_sizei /* size_pixels */,
                             gvr_vec2f /* meters_per_pixel */,
                             float /* border_size_meters */) {
  ALOGE("gvr_set_display_metrics not implemented");
}

void gvr_set_display_output_rotation(gvr_context* /* gvr */,
                                     int /* display_output_rotation */) {
  ALOGE("gvr_set_display_output_rotation not implemented");
}

float gvr_get_border_size_meters(const gvr_context* /* gvr */) {
  ALOGE("gvr_get_border_size_meters not implemented");
  return 0.0f;
}

bool gvr_check_surface_size_changed(gvr_context* /* gvr */) { return false; }

gvr_sizei gvr_get_surface_size(const gvr_context* /* gvr */) {
  ALOGE("gvr_get_surface_size not implemented");
  return {0, 0};
}

void gvr_set_back_gesture_event_handler(gvr_context* /* gvr */,
                                        event_handler /* handler */,
                                        void* /* user_data */) {
  ALOGE("gvr_set_back_gesture_event_handler not implemented");
}

gvr_tracker_state* gvr_pause_tracking_get_state(gvr_context* /* gvr */) {
  ALOGE("gvr_pause_tracking_get_state not implemented");
  return nullptr;
}

void gvr_resume_tracking_set_state(gvr_context* /* gvr */,
                                   gvr_tracker_state* /* tracker_state */) {
  ALOGE("gvr_resume_tracking_set_state not implemented");
}

void gvr_set_ignore_manual_tracker_pause_resume(gvr_context* /* gvr */,
                                                bool /* should_ignore */) {
  ALOGE("gvr_set_ignore_manual_tracker_pause_resume not implemented");
}

gvr_tracker_state* gvr_tracker_state_create(
    const char* /* tracker_state_buffer */, size_t /* buf_size */) {
  ALOGE("gvr_tracker_state_create not implemented");
  return nullptr;
}

size_t gvr_tracker_state_get_buffer_size(
    gvr_tracker_state* /* tracker_state */) {
  ALOGE("gvr_tracker_state_get_buffer_size not implemented");
  return 0;
}

const char* gvr_tracker_state_get_buffer(
    gvr_tracker_state* /* tracker_state */) {
  ALOGE("gvr_tracker_state_get_buffer not implemented");
  return nullptr;
}

void gvr_tracker_state_destroy(gvr_tracker_state** /* tracker_state */) {
  ALOGE("gvr_tracker_state_destroy not implemented");
}

gvr_display_synchronizer* gvr_display_synchronizer_create() {
  // We don't actually support (or need) any of the synchronizer functionality,
  // but if we return null here the gvr setup code in the app fails. Instead
  // return a dummy object that does nothing, which allows gvr apps to work.
  return new gvr_display_synchronizer;
}

void gvr_display_synchronizer_destroy(gvr_display_synchronizer** synchronizer) {
  if (synchronizer) {
    delete *synchronizer;
    *synchronizer = nullptr;
  }
}

void gvr_display_synchronizer_reset(
    gvr_display_synchronizer* /* synchronizer */,
    int64_t /* expected_interval_nanos */, int64_t /* vsync_offset_nanos */) {}

void gvr_display_synchronizer_update(
    gvr_display_synchronizer* /* synchronizer */,
    gvr_clock_time_point /* vsync_time */, int32_t /* rotation */) {}

void gvr_set_display_synchronizer(
    gvr_context* /* gvr */, gvr_display_synchronizer* /* synchronizer */) {}

void gvr_set_error(gvr_context* gvr, int32_t error_code) {
  if (gvr->last_error_ != GVR_ERROR_NONE) {
    ALOGW("Overwriting existing error code: %d (%s)", gvr->last_error_,
          gvr_get_error_string(gvr->last_error_));
  }
  gvr->last_error_ = error_code;
}

void gvr_pause(gvr_context* gvr) {
  if (gvr == nullptr) {
    ALOGW("gvr_pause called with a null gvr_context. This is a bug.");
    return;
  }
  for (gvr_swap_chain* swap_chain : gvr->swap_chains_) {
    if (swap_chain->graphics_context_)
      dvrGraphicsSurfaceSetVisible(swap_chain->graphics_context_, 0);
  }
}

void gvr_resume(gvr_context* gvr) {
  if (gvr == nullptr) {
    ALOGW("gvr_resume called with a null gvr_context. This is a bug.");
    return;
  }
  for (gvr_swap_chain* swap_chain : gvr->swap_chains_) {
    if (swap_chain->graphics_context_)
      dvrGraphicsSurfaceSetVisible(swap_chain->graphics_context_, 1);
  }
}

void gvr_dump_debug_data(gvr_context* /* gvr */) {}

bool gvr_using_vr_display_service(gvr_context* /* gvr */) { return true; }

void gvr_request_context_sharing(gvr_context* /* gvr */,
                                 gvr_egl_context_listener /* handler */,
                                 void* /* user_data */) {}
