#ifndef VR_WINDOW_MANAGER_SHELL_VIEW_H_
#define VR_WINDOW_MANAGER_SHELL_VIEW_H_

#include <dvr/virtual_touchpad_client.h>
#include <private/dvr/graphics/mesh.h>
#include <private/dvr/graphics/shader_program.h>

#include <deque>

#include "application.h"
#include "display_view.h"
#include "reticle.h"
#include "shell_view_binder_interface.h"
#include "surface_flinger_view.h"

namespace android {
namespace dvr {

class ShellView : public Application,
                  public android::dvr::ShellViewBinderInterface,
                  public HwcCallback::Client {
 public:
  ShellView();
  virtual ~ShellView();

  int Initialize() override;

  int AllocateResources() override;
  void DeallocateResources() override;

  // ShellViewBinderInterface:
  void EnableDebug(bool debug) override;
  void VrMode(bool mode) override;
  void dumpInternal(String8& result) override;
  void Set2DMode(bool mode) override;


 protected:
  void DrawEye(EyeType eye, const mat4& perspective, const mat4& eye_matrix,
               const mat4& head_matrix) override;
  void OnDrawFrame() override;
  void OnEndFrame() override;
  void OnVisibilityChanged(bool visible) override;

  void DrawReticle(const mat4& perspective, const mat4& eye_matrix,
                   const mat4& head_matrix);
  void DrawController(const mat4& perspective, const mat4& eye_matrix,
                      const mat4& head_matrix);

  void Touch();
  bool OnTouchpadButton(bool down, int button);

  bool OnClick(bool down);

  DisplayView* FindActiveDisplay(const vec3& position, const quat& quaternion,
                                 vec3* hit_location);

  // HwcCallback::Client:
  base::unique_fd OnFrame(std::unique_ptr<HwcCallback::Frame> frame) override;
  DisplayView* FindOrCreateDisplay(uint32_t id);

  std::unique_ptr<ShaderProgram> program_;
  std::unique_ptr<ShaderProgram> overlay_program_;
  std::unique_ptr<ShaderProgram> controller_program_;

  std::unique_ptr<SurfaceFlingerView> surface_flinger_view_;
  std::unique_ptr<Reticle> reticle_;

  struct DvrVirtualTouchpadDeleter {
    void operator()(DvrVirtualTouchpad* p) {
      dvrVirtualTouchpadDetach(p);
      dvrVirtualTouchpadDestroy(p);
    }
  };
  std::unique_ptr<DvrVirtualTouchpad, DvrVirtualTouchpadDeleter>
      virtual_touchpad_;

  std::unique_ptr<Mesh<vec3, vec3, vec2>> controller_mesh_;

  bool is_touching_ = false;
  int touchpad_buttons_ = 0;
  vec2 size_;

  // Used to center the scene when the shell becomes visible.
  bool should_recenter_ = true;

  std::mutex display_frame_mutex_;

  std::vector<std::unique_ptr<DisplayView>> displays_;
  std::vector<std::unique_ptr<DisplayView>> new_displays_;
  std::vector<DisplayView*> removed_displays_;
  DisplayView* active_display_ = nullptr;

  mat4 controller_translate_;

  ShellView(const ShellView&) = delete;
  void operator=(const ShellView&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_SHELL_VIEW_H_
