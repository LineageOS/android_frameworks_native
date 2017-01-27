#ifndef ANDROID_DVR_GRAPHICS_FPS_GRAPH_H
#define ANDROID_DVR_GRAPHICS_FPS_GRAPH_H

#include <private/dvr/graphics/mesh.h>
#include <private/dvr/graphics/shader_program.h>

namespace android {
namespace dvr {

// Debug text class that draws small text with Open GL.
class DebugText {
 public:
  DebugText(int max_digits, int viewport_width, int viewport_height);
  ~DebugText();

  void SetViewportSize(int viewport_width, int viewport_height);

  // Draw text at given screen-space location, scale and color.
  // A |scale| of 1.0 means 1:1 pixel mapping with current viewport size.
  // If |stereo_offset| is not zero, the string will be rendered again
  // with the given offset for stereo rendering. The stereo axis can be on
  // screenspace x or y axis, which is given by |axis| as 0 or 1,
  // respectively. |axis| also determines the direction that text is rendered.
  void Draw(float x, float y, float scale, float r, float g, float b, float a,
            const char* str, float stereo_offset, uint8_t axis);

  // Helper that draws green text at render target resolution.
  void Draw(float x, float y, const char* str, float stereo_offset,
            uint8_t axis) {
    Draw(x, y, 1.0f, 0, 1, 0, 1, str, stereo_offset, axis);
  }

 private:
  int max_digits_;
  vec2 pixel_size_screen_space_;
  ShaderProgram shader_;
  GLuint texture_;
  Mesh<vec2, vec2> mesh_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_FPS_GRAPH_H
