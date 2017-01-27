#ifndef ANDROID_DVR_COMPOSITE_HMD_H_
#define ANDROID_DVR_COMPOSITE_HMD_H_

#include <private/dvr/display_metrics.h>
#include <private/dvr/head_mount_metrics.h>
#include <private/dvr/types.h>

namespace android {
namespace dvr {

// An intermediate structure composed of a head mount (described by
// HeadMountMetrics) and a display (described by DisplayMetrics).
class CompositeHmd {
 public:
  // Constructs a new CompositeHmd given a HeadMountMetrics and a
  // DisplayMetrics.
  CompositeHmd(const HeadMountMetrics& head_mount_metrics,
               const DisplayMetrics& display_metrics);

  CompositeHmd(CompositeHmd&& composite_hmd) = delete;
  CompositeHmd(const CompositeHmd& composite_hmd) = delete;
  CompositeHmd& operator=(CompositeHmd&& composite_hmd) = delete;
  CompositeHmd& operator=(const CompositeHmd& composite_hmd) = delete;

  // Headset metadata.
  float GetTargetFrameDuration() const;
  void ComputeDistortedVertex(EyeType eye, vec2 uv_in, vec2* vertex_out,
                              vec2* uv_out) const;

  // Eye-unspecific view accessors.
  vec2i GetRecommendedRenderTargetSize() const;
  Range2i GetDisplayRange() const;

  // Eye-specific view accessors.
  mat4 GetEyeFromHeadMatrix(EyeType eye) const;
  FieldOfView GetEyeFov(EyeType eye) const;
  Range2i GetEyeViewportBounds(EyeType eye) const;

  // Set HeadMountMetrics and recompute everything that depends on
  // HeadMountMetrics.
  void SetHeadMountMetrics(const HeadMountMetrics& head_mount_metrics);

  // Returns a reference to the |head_mount_metrics_| member.
  const HeadMountMetrics& GetHeadMountMetrics() const;

  // Set DisplayMetrics and recompute everything that depends on DisplayMetrics.
  void SetDisplayMetrics(const DisplayMetrics& display_metrics);

  // Returns a reference to the current display metrics.
  const DisplayMetrics& GetDisplayMetrics() const;

  // Compute the distorted point for a single channel.
  vec2 ComputeDistortedPoint(EyeType eye, vec2 position,
                             RgbColorChannel channel) const;

  // Compute the inverse distorted point for a single channel.
  vec2 ComputeInverseDistortedPoint(EyeType eye, vec2 position,
                                    RgbColorChannel channel) const;

 private:
  FieldOfView eye_fov_[2];
  Range2i eye_viewport_range_[2];
  mat4 eye_from_head_matrix_[2];
  Range2i display_range_;
  vec2i recommended_render_target_size_;

  // Per-eye scale and translation to convert from normalized Screen Space
  // ([0:1]x[0:1]) to tan-angle space.
  mat3 eye_tan_angle_from_norm_screen_matrix_[2];
  mat3 eye_tan_angle_from_norm_screen_inv_matrix_[2];

  // Per-eye scale and translation to convert from tan-angle space to normalized
  // Texture Space ([0:1]x[0:1]).
  mat3 eye_norm_texture_from_tan_angle_matrix_[2];
  mat3 eye_norm_texture_from_tan_angle_inv_matrix_[2];

  HeadMountMetrics head_mount_metrics_;
  DisplayMetrics display_metrics_;

  // Called by SetHeadMountMetrics/SetDisplayMetrics after metrics get changed.
  // This function will update head_mount_metrics_/display_metrics_ based on the
  // metrics supplied in the above two methods.
  void MetricsChanged();
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_COMPOSITE_HMD_H_
