#ifndef ANDROID_DVR_RENDER_TEXTURE_PARAMS_H_
#define ANDROID_DVR_RENDER_TEXTURE_PARAMS_H_

#include <private/dvr/types.h>

namespace android {
namespace dvr {

// Encapsulates information about the render texture, includes the size
// of the render texture, and the left/right viewport which define the
// portion each eye is rendering onto. This struct will be passed to
// PresentFrame every frame before the client actually drawing the scene.
struct RenderTextureParams {
  RenderTextureParams() {}

  RenderTextureParams(vec2i target_texture_size,
                      const Range2i& eye_viewport_bounds_left,
                      const Range2i& eye_viewport_bounds_right,
                      const FieldOfView& eye_fov_left,
                      const FieldOfView& eye_fov_right)
      : texture_size(target_texture_size) {
    eye_viewport_bounds[kLeftEye] = eye_viewport_bounds_left;
    eye_viewport_bounds[kRightEye] = eye_viewport_bounds_right;
    eye_fov[kLeftEye] = eye_fov_left;
    eye_fov[kRightEye] = eye_fov_right;
  }

  explicit RenderTextureParams(vec2i target_texture_size,
                               const FieldOfView& eye_fov_left,
                               const FieldOfView& eye_fov_right) {
    texture_size = target_texture_size;
    eye_viewport_bounds[0] = Range2i::FromSize(
        vec2i(0, 0), vec2i(texture_size[0] / 2, texture_size[1]));
    eye_viewport_bounds[1] =
        Range2i::FromSize(vec2i(texture_size[0] / 2, 0),
                          vec2i(texture_size[0] / 2, texture_size[1]));

    eye_fov[kLeftEye] = eye_fov_left;
    eye_fov[kRightEye] = eye_fov_right;
  }

  // The render texture size.
  vec2i texture_size;

  // The viewport bounds on the render texture for each eye.
  Range2i eye_viewport_bounds[2];

  // The field of view for each eye in degrees.
  FieldOfView eye_fov[2];
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_RENDER_TEXTURE_PARAMS_H_
