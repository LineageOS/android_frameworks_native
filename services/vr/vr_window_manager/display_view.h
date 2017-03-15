#ifndef VR_WINDOW_MANAGER_DISPLAY_VIEW_H_
#define VR_WINDOW_MANAGER_DISPLAY_VIEW_H_

#include <private/dvr/graphics/mesh.h>
#include <private/dvr/graphics/shader_program.h>

#include "hwc_callback.h"
#include "surface_flinger_view.h"

namespace android {
namespace dvr {

enum class ViewMode {
  Hidden,
  VR,
  App,
};

class DisplayView {
 public:
  DisplayView(uint32_t id, int touchpad_id);
  ~DisplayView();

  // Calls to these 3 functions must be synchronized.
  base::unique_fd OnFrame(std::unique_ptr<HwcCallback::Frame> frame,
                          bool debug_mode, bool* showing);
  void AdvanceFrame();
  void UpdateReleaseFence();

  void OnDrawFrame(SurfaceFlingerView* surface_flinger_view, bool debug_mode);
  void DrawEye(EyeType eye, const mat4& perspective, const mat4& eye_matrix,
               const mat4& head_matrix, const vec2& size, float fade_value);

  void Recenter(const mat4& initial);

  bool UpdateHitInfo(const vec3& view_location, const vec3& view_direction,
                     vec3* hit_location);

  void SetPrograms(ShaderProgram* program, ShaderProgram* overlay_program);

  bool visible() const { return current_frame_.visibility != ViewMode::Hidden; }
  bool allow_input() const { return allow_input_; }
  const vec2& hit_location() const { return hit_location_in_window_coord_; }
  uint32_t id() const { return id_; }
  int touchpad_id() const { return touchpad_id_; }

 private:
  bool IsHit(const vec3& view_location, const vec3& view_direction,
             vec3* hit_location, vec2* hit_location_in_window_coord,
             bool test_ime);
  bool IsImeHit(const vec3& view_location, const vec3& view_direction,
                vec3* hit_location);
  void DrawOverlays(const mat4& perspective, const mat4& eye_matrix,
                    const mat4& head_matrix, float fade_value);
  void DrawIme();
  void DrawDimOverlay(const mat4& mvp, const TextureLayer& layer,
                      const vec2& top_left, const vec2& bottom_right);
  void DrawWithTransform(const mat4& transform, const ShaderProgram& program);

  uint32_t id_;
  int touchpad_id_;

  uint32_t current_vr_app_;

  ShaderProgram* program_;
  ShaderProgram* overlay_program_;

  mat4 initial_head_matrix_;
  mat4 scale_;
  mat4 translate_;
  mat4 ime_translate_;
  vec2 size_;

  std::vector<TextureLayer> textures_;
  TextureLayer ime_texture_;

  bool allow_input_ = false;
  vec2 hit_location_in_window_coord_;
  vec2 ime_top_left_;
  vec2 ime_size_;
  bool has_ime_ = false;

  struct PendingFrame {
    PendingFrame() = default;
    PendingFrame(std::unique_ptr<HwcCallback::Frame>&& frame,
                 ViewMode visibility)
        : frame(std::move(frame)), visibility(visibility) {}
    PendingFrame(PendingFrame&& r)
        : frame(std::move(r.frame)), visibility(r.visibility) {}

    void operator=(PendingFrame&& r) {
      frame.reset(r.frame.release());
      visibility = r.visibility;
    }

    std::unique_ptr<HwcCallback::Frame> frame;
    ViewMode visibility = ViewMode::Hidden;
  };
  std::deque<PendingFrame> pending_frames_;
  PendingFrame current_frame_;
  base::unique_fd release_fence_;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_DISPLAY_VIEW_H_
