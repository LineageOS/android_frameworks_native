#include "include/private/dvr/composite_hmd.h"

#include <log/log.h>

#include <private/dvr/numeric.h>

namespace android {
namespace dvr {

CompositeHmd::CompositeHmd(const HeadMountMetrics& head_mount_metrics,
                           const DisplayMetrics& display_metrics)
    : head_mount_metrics_(head_mount_metrics),
      display_metrics_(display_metrics) {
  MetricsChanged();
}

float CompositeHmd::GetTargetFrameDuration() const {
  return display_metrics_.GetFrameDurationSeconds();
}

vec2 CompositeHmd::ComputeDistortedPoint(EyeType eye, vec2 position,
                                         RgbColorChannel channel) const {
  position = TransformPoint(eye_tan_angle_from_norm_screen_matrix_[eye], position);
  vec2 distorted =
      head_mount_metrics_.GetColorChannelDistortion(channel).Distort(position);
  return TransformPoint(eye_norm_texture_from_tan_angle_matrix_[eye], distorted);
}

vec2 CompositeHmd::ComputeInverseDistortedPoint(EyeType eye, vec2 position,
                                                RgbColorChannel channel) const {
  position = TransformPoint(eye_norm_texture_from_tan_angle_inv_matrix_[eye], position);
  vec2 distorted =
      head_mount_metrics_.GetColorChannelDistortion(channel).DistortInverse(
          position);
  return TransformPoint(eye_tan_angle_from_norm_screen_inv_matrix_[eye], distorted);
}

void CompositeHmd::ComputeDistortedVertex(EyeType eye, vec2 uv_in,
                                          vec2* vertex_out,
                                          vec2* uv_out) const {
  // The mesh vertices holds the shape of the distortion.
  vec2 vertex_position = ComputeInverseDistortedPoint(eye, uv_in, kRed);
  *vertex_out = vec2(vertex_position.x() - 0.5f, vertex_position.y() - 0.5f);

  if (uv_out) {
    // Compute the texture coordinate for each vertex coordinate.
    // Red's is the inverse of the inverse, skip the calculation and use uv_in.
    uv_out[kRed] = uv_in;
    uv_out[kGreen] = ComputeDistortedPoint(eye, vertex_position, kGreen);
    uv_out[kBlue] = ComputeDistortedPoint(eye, vertex_position, kBlue);
  }
}

vec2i CompositeHmd::GetRecommendedRenderTargetSize() const {
  return recommended_render_target_size_;
}

Range2i CompositeHmd::GetDisplayRange() const { return display_range_; }

mat4 CompositeHmd::GetEyeFromHeadMatrix(EyeType eye) const {
  return eye_from_head_matrix_[eye];
}

FieldOfView CompositeHmd::GetEyeFov(EyeType eye) const { return eye_fov_[eye]; }

Range2i CompositeHmd::GetEyeViewportBounds(EyeType eye) const {
  return eye_viewport_range_[eye];
}

void CompositeHmd::SetHeadMountMetrics(
    const HeadMountMetrics& head_mount_metrics) {
  // Use the assignement operator to do memberwise copy.
  head_mount_metrics_ = head_mount_metrics;
  MetricsChanged();
}

const HeadMountMetrics& CompositeHmd::GetHeadMountMetrics() const {
  return head_mount_metrics_;
}

void CompositeHmd::SetDisplayMetrics(const DisplayMetrics& display_metrics) {
  // Use the assignment operator to do memberwise copy.
  display_metrics_ = display_metrics;
  MetricsChanged();
}

const DisplayMetrics& CompositeHmd::GetDisplayMetrics() const {
  return display_metrics_;
}

void CompositeHmd::MetricsChanged() {
  // Abbreviations in variable names:
  //   "vp": viewport
  //   "ta": tan-angle
  const HeadMountMetrics& mount = head_mount_metrics_;
  DisplayMetrics display = display_metrics_;

  if (display.IsPortrait()) {
    // If we're in portrait mode, toggle the orientation so that all
    // calculations are done in landscape mode.
    display.ToggleOrientation();
  }

  float display_width_meters = display.GetSizeMeters()[0];
  float display_height_meters = display.GetSizeMeters()[1];

  vec2 pixels_per_meter = vec2(1.0f / display.GetMetersPerPixel()[0],
                               1.0f / display.GetMetersPerPixel()[1]);

  // virtual_eye_to_screen_dist is the distance from the screen to the eye
  // after it has been projected through the lens.  This would normally be
  // slightly different from the distance to the actual eye.
  float virtual_eye_to_screen_dist = mount.GetVirtualEyeToScreenDistance();
  float meters_per_tan_angle = virtual_eye_to_screen_dist;
  vec2 pixels_per_tan_angle = pixels_per_meter * meters_per_tan_angle;

  LOG_ALWAYS_FATAL_IF(0.0f == display_width_meters);
  LOG_ALWAYS_FATAL_IF(0.0f == display_height_meters);
  LOG_ALWAYS_FATAL_IF(0.0f == virtual_eye_to_screen_dist);

  // Height of lenses from the bottom of the screen.
  float lens_y_center = 0;
  float bottom_dist = 0;
  float top_dist = 0;

  // bottom_display_dist and top_display_dist represent the distance from the
  // lens center to the edge of the display.
  float bottom_display_dist = 0;
  float top_display_dist = 0;
  switch (mount.GetVerticalAlignment()) {
    case HeadMountMetrics::kBottom:
      lens_y_center =
          mount.GetTrayToLensDistance() - display.GetBorderSizeMeters();
      bottom_dist = lens_y_center;
      top_dist = lens_y_center;
      bottom_display_dist = lens_y_center;
      top_display_dist = display_height_meters - lens_y_center;
      break;
    case HeadMountMetrics::kCenter:
      // TODO(hendrikw): This should respect the border size, but since we
      //                 currently hard code the border size, it would break
      //                 the distortion on some devices.  Revisit when border
      //                 size is fixed.
      lens_y_center = display_height_meters * 0.5f;
      bottom_dist = lens_y_center;
      top_dist = lens_y_center;
      bottom_display_dist = lens_y_center;
      top_display_dist = lens_y_center;
      break;
    case HeadMountMetrics::kTop:
      lens_y_center = display_height_meters - (mount.GetTrayToLensDistance() -
                                               display.GetBorderSizeMeters());
      bottom_dist =
          mount.GetTrayToLensDistance() - display.GetBorderSizeMeters();
      top_dist = bottom_dist;
      bottom_display_dist = lens_y_center;
      top_display_dist = display_height_meters - lens_y_center;
      break;
  }

  float inner_dist = mount.GetScreenCenterToLensDistance();
  float outer_dist = display_width_meters * 0.5f - inner_dist;

  // We don't take chromatic aberration into account yet for computing FOV,
  // viewport, etc, so we only use the green channel for now. Note the actual
  // Distort function *does* implement chromatic aberration.
  const ColorChannelDistortion& distortion =
      mount.GetColorChannelDistortion(kGreen);

  vec2 outer_point(outer_dist / virtual_eye_to_screen_dist, 0.0f);
  vec2 inner_point(inner_dist / virtual_eye_to_screen_dist, 0.0f);
  vec2 bottom_point(0.0f, bottom_dist / virtual_eye_to_screen_dist);
  vec2 top_point(0.0f, top_dist / virtual_eye_to_screen_dist);

  float outer_angle = atanf(distortion.Distort(outer_point)[0]);
  float inner_angle = atanf(distortion.Distort(inner_point)[0]);
  float bottom_angle = atanf(distortion.Distort(bottom_point)[1]);
  float top_angle = atanf(distortion.Distort(top_point)[1]);

  for (EyeType eye : {kLeftEye, kRightEye}) {
    const FieldOfView max_fov = mount.GetEyeMaxFov(eye);
    float left_angle = (eye == kLeftEye) ? outer_angle : inner_angle;
    float right_angle = (eye == kLeftEye) ? inner_angle : outer_angle;

    eye_fov_[eye] = FieldOfView(std::min(left_angle, max_fov.GetLeft()),
                                std::min(right_angle, max_fov.GetRight()),
                                std::min(bottom_angle, max_fov.GetBottom()),
                                std::min(top_angle, max_fov.GetTop()));

    vec2 texture_vp_ta_p1 =
        vec2(-tanf(eye_fov_[eye].GetLeft()), -tanf(eye_fov_[eye].GetBottom()));
    vec2 texture_vp_ta_p2 =
        vec2(tanf(eye_fov_[eye].GetRight()), tanf(eye_fov_[eye].GetTop()));
    vec2 texture_vp_size_ta = texture_vp_ta_p2 - texture_vp_ta_p1;

    vec2 texture_vp_sizef_pixels =
        texture_vp_size_ta.array() * pixels_per_tan_angle.array();

    vec2i texture_vp_size_pixels =
        vec2i(static_cast<int32_t>(roundf(texture_vp_sizef_pixels[0])),
              static_cast<int32_t>(roundf(texture_vp_sizef_pixels[1])));
    int vp_start_x =
        (eye == kLeftEye) ? 0 : eye_viewport_range_[kLeftEye].p2[0];

    eye_viewport_range_[eye] =
        Range2i::FromSize(vec2i(vp_start_x, 0), texture_vp_size_pixels);
    float left_dist = (eye == kLeftEye) ? outer_dist : inner_dist;
    float right_dist = (eye == kLeftEye) ? inner_dist : outer_dist;
    vec2 screen_ta_p1(-left_dist / virtual_eye_to_screen_dist,
                      -bottom_display_dist / virtual_eye_to_screen_dist);
    vec2 screen_ta_p2(right_dist / virtual_eye_to_screen_dist,
                      top_display_dist / virtual_eye_to_screen_dist);
    vec2 screen_ta_size = screen_ta_p2 - screen_ta_p1;

    // Align the tan angle coordinates to the nearest pixel.  This will ensure
    // that the optical center doesn't straddle multiple pixels.
    // TODO(hendrikw): verify that this works correctly for Daydream View.
    vec2 tan_angle_per_pixel(screen_ta_size.array() /
                             texture_vp_size_pixels.cast<float>().array());
    vec2 pixel_p1(screen_ta_p1.array() / tan_angle_per_pixel.array());
    vec2 pixel_shift(roundf(pixel_p1.x()) - pixel_p1.x(),
                     roundf(pixel_p1.y()) - pixel_p1.y());
    screen_ta_p1 +=
        (tan_angle_per_pixel.array() * pixel_shift.array()).matrix();
    screen_ta_p2 +=
        (tan_angle_per_pixel.array() * pixel_shift.array()).matrix();

    // Calculate the transformations needed for the distortions.
    eye_tan_angle_from_norm_screen_matrix_[eye] =
        TranslationMatrix(vec2(screen_ta_p1)) *
        ScaleMatrix(screen_ta_size);
    eye_tan_angle_from_norm_screen_inv_matrix_[eye] =
        eye_tan_angle_from_norm_screen_matrix_[eye].inverse();

    eye_norm_texture_from_tan_angle_inv_matrix_[eye] =
        TranslationMatrix(texture_vp_ta_p1) *
        ScaleMatrix(texture_vp_size_ta);
    eye_norm_texture_from_tan_angle_matrix_[eye] =
        eye_norm_texture_from_tan_angle_inv_matrix_[eye].inverse();
  }
  vec2i left_vp_size = eye_viewport_range_[kLeftEye].GetSize();
  vec2i right_vp_size = eye_viewport_range_[kRightEye].GetSize();

  recommended_render_target_size_ =
      vec2i(left_vp_size[0] + right_vp_size[0],
            std::max(left_vp_size[1], right_vp_size[1]));

  display_range_ = Range2i::FromSize(vec2i(0, 0), display.GetSizePixels());

  eye_from_head_matrix_[kLeftEye] = Eigen::Translation3f(
      vec3(mount.GetScreenCenterToLensDistance(), 0.0f, 0.0f));
  eye_from_head_matrix_[kRightEye] = Eigen::Translation3f(
      vec3(-mount.GetScreenCenterToLensDistance(), 0.0f, 0.0f));
}

}  // namespace dvr
}  // namespace android
