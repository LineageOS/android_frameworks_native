#ifndef VR_WINDOW_MANAGER_SHELL_VIEW_H_
#define VR_WINDOW_MANAGER_SHELL_VIEW_H_

#include <private/dvr/graphics/mesh.h>
#include <private/dvr/graphics/shader_program.h>
#include <android/dvr/IVirtualTouchpadService.h>

#include <deque>

#include "application.h"
#include "reticle.h"
#include "shell_view_binder_interface.h"
#include "surface_flinger_view.h"

namespace android {
namespace dvr {

enum class ViewMode {
  Hidden,
  VR,
  App,
};

class ShellView : public Application,
                  public android::dvr::ShellViewBinderInterface,
                  public HwcCallback::Client {
 public:
  ShellView();
  virtual ~ShellView();

  int Initialize(JNIEnv* env, jobject app_context,
                 jobject class_loader) override;

  int AllocateResources() override;
  void DeallocateResources() override;

  // ShellViewBinderInterface:
  void EnableDebug(bool debug) override;
  void VrMode(bool mode) override;
  void dumpInternal(String8& result) override;

 protected:
  void DrawEye(EyeType eye, const mat4& perspective, const mat4& eye_matrix,
               const mat4& head_matrix) override;
  void OnVisibilityChanged(bool visible) override;

  void DrawOverlays(const mat4& perspective, const mat4& eye_matrix,
                    const mat4& head_matrix);
  void DrawReticle(const mat4& perspective, const mat4& eye_matrix,
                   const mat4& head_matrix);
  void DrawIme();
  void DrawDimOverlay(const mat4& mvp, const TextureLayer& layer,
                      const vec2& top_left, const vec2& bottom_right);
  void DrawController(const mat4& perspective, const mat4& eye_matrix,
                      const mat4& head_matrix);

  bool IsHit(const vec3& view_location, const vec3& view_direction,
             vec3* hit_location, vec2* hit_location_in_window_coord,
             bool test_ime);
  bool IsImeHit(const vec3& view_location, const vec3& view_direction,
                vec3 *hit_location);
  bool InitializeTouch();
  void Touch();
  bool OnTouchpadButton(bool down, int button);

  void OnDrawFrame() override;
  void DrawWithTransform(const mat4& transform, const ShaderProgram& program);

  bool OnClick(bool down);

  void AdvanceFrame();

  // HwcCallback::Client:
  void OnFrame(std::unique_ptr<HwcCallback::Frame> frame) override;

  std::unique_ptr<ShaderProgram> program_;
  std::unique_ptr<ShaderProgram> overlay_program_;
  std::unique_ptr<ShaderProgram> controller_program_;

  // This starts at -1 so we don't call ReleaseFrame for the first frame.
  int skipped_frame_count_ = -1;

  uint32_t current_vr_app_;

  // Used to center the scene when the shell becomes visible.
  bool should_recenter_ = true;
  mat4 initial_head_matrix_;
  mat4 scale_;
  mat4 translate_;
  mat4 ime_translate_;
  vec2 size_;

  std::unique_ptr<SurfaceFlingerView> surface_flinger_view_;
  std::unique_ptr<Reticle> reticle_;
  sp<IVirtualTouchpadService> virtual_touchpad_;
  std::vector<TextureLayer> textures_;
  TextureLayer ime_texture_;

  bool is_touching_ = false;
  bool allow_input_ = false;
  int touchpad_buttons_ = 0;
  vec2 hit_location_in_window_coord_;
  vec2 ime_top_left_;
  vec2 ime_size_;
  bool has_ime_ = false;

  std::unique_ptr<Mesh<vec3, vec3, vec2>> controller_mesh_;

  struct PendingFrame {
    PendingFrame() = default;
    PendingFrame(std::unique_ptr<HwcCallback::Frame>&& frame, ViewMode visibility)
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
  std::mutex pending_frame_mutex_;
  PendingFrame current_frame_;

  mat4 controller_translate_;

  ShellView(const ShellView&) = delete;
  void operator=(const ShellView&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_SHELL_VIEW_H_
