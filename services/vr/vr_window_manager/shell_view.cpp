#include "shell_view.h"

#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <android/input.h>
#include <binder/IServiceManager.h>
#include <dvr/graphics.h>
#include <hardware/hwcomposer2.h>
#include <inttypes.h>
#include <log/log.h>

#include "controller_mesh.h"
#include "texture.h"

namespace android {
namespace dvr {

namespace {

constexpr uint32_t kPrimaryDisplayId = 1;

const std::string kVertexShader = SHADER0([]() {
  layout(location = 0) in vec4 aPosition;
  layout(location = 1) in vec4 aTexCoord;
  uniform mat4 uViewProjection;
  uniform mat4 uTransform;

  out vec2 vTexCoord;
  void main() {
    gl_Position = uViewProjection * uTransform * aPosition;
    vTexCoord = aTexCoord.xy;
  }
});

const std::string kFragmentShader = SHADER0([]() {
  precision mediump float;

  in vec2 vTexCoord;
  uniform sampler2D tex;
  uniform float uAlpha;

  out vec4 fragColor;
  void main() {
    fragColor = texture(tex, vTexCoord);
    fragColor.a *= uAlpha;
  }
});

// This shader provides a dim layer in a given rect. This is intended
// to indicate the non-interactive region.
// Texture coordinates between [uCoords.xy, uCoords.zw] are dim, otherwise
// transparent.
const std::string kOverlayFragmentShader = SHADER0([]() {
  precision highp float;

  in vec2 vTexCoord;
  uniform sampler2D tex;
  uniform vec4 uCoords;

  out vec4 fragColor;
  void main() {
    vec4 color = vec4(0, 0, 0, 0);
    if (all(greaterThan(vTexCoord, uCoords.xy)) &&
        all(lessThan(vTexCoord, uCoords.zw))) {
      color = vec4(0, 0, 0, 0.5);
    }
    fragColor = color;
  }
});

const std::string kControllerFragmentShader = SHADER0([]() {
  precision mediump float;

  in vec2 vTexCoord;

  out vec4 fragColor;
  void main() { fragColor = vec4(0.8, 0.2, 0.2, 1.0); }
});

mat4 GetHorizontallyAlignedMatrixFromPose(const Posef& pose) {
  vec3 position = pose.GetPosition();
  quat view_quaternion = pose.GetRotation();

  vec3 z = vec3(view_quaternion * vec3(0.0f, 0.0f, 1.0f));
  vec3 y(0.0f, 1.0f, 0.0f);
  vec3 x = y.cross(z);
  x.normalize();
  y = z.cross(x);

  mat4 m;
  // clang-format off
  m(0, 0) = x[0]; m(0, 1) = y[0]; m(0, 2) = z[0]; m(0, 3) = position[0];
  m(1, 0) = x[1]; m(1, 1) = y[1]; m(1, 2) = z[1]; m(1, 3) = position[1];
  m(2, 0) = x[2]; m(2, 1) = y[2]; m(2, 2) = z[2]; m(2, 3) = position[2];
  m(3, 0) = 0.0f; m(3, 1) = 0.0f; m(3, 2) = 0.0f; m(3, 3) = 1.0f;
  // clang-format on

  return m;
}

int GetTouchIdForDisplay(uint32_t display) {
  return display == kPrimaryDisplayId ? DVR_VIRTUAL_TOUCHPAD_PRIMARY
                                      : DVR_VIRTUAL_TOUCHPAD_VIRTUAL;
}

}  // namespace

ShellView::ShellView() {}

ShellView::~ShellView() {}

int ShellView::Initialize() {
  int ret = Application::Initialize();
  if (ret)
    return ret;

  virtual_touchpad_.reset(dvrVirtualTouchpadCreate());
  const status_t touchpad_status =
      dvrVirtualTouchpadAttach(virtual_touchpad_.get());
  if (touchpad_status != OK) {
    ALOGE("Failed to connect to virtual touchpad");
    return touchpad_status;
  }

  surface_flinger_view_.reset(new SurfaceFlingerView);
  if (!surface_flinger_view_->Initialize(this))
    return 1;

  return 0;
}

int ShellView::AllocateResources() {
  int ret = Application::AllocateResources();
  if (ret)
    return ret;

  program_.reset(new ShaderProgram);
  program_->Link(kVertexShader, kFragmentShader);
  overlay_program_.reset(new ShaderProgram);
  overlay_program_->Link(kVertexShader, kOverlayFragmentShader);
  controller_program_.reset(new ShaderProgram);
  controller_program_->Link(kVertexShader, kControllerFragmentShader);
  if (!program_ || !overlay_program_ || !controller_program_)
    return 1;

  reticle_.reset(new Reticle());
  if (!reticle_->Initialize())
    return 1;

  controller_mesh_.reset(new Mesh<vec3, vec3, vec2>());
  controller_mesh_->SetVertices(kNumControllerMeshVertices,
                                kControllerMeshVertices);

  for (auto& display : displays_)
    display->SetPrograms(program_.get(), overlay_program_.get());

  initialized_ = true;

  return 0;
}

void ShellView::DeallocateResources() {
  {
    std::unique_lock<std::mutex> l(display_frame_mutex_);
    removed_displays_.clear();
    new_displays_.clear();
    displays_.clear();
  }

  display_client_.reset();
  reticle_.reset();
  controller_mesh_.reset();
  program_.reset(new ShaderProgram);
  overlay_program_.reset(new ShaderProgram);
  controller_program_.reset(new ShaderProgram);
  Application::DeallocateResources();
}

void ShellView::EnableDebug(bool debug) {
  QueueTask(debug ? MainThreadTask::EnableDebugMode
                  : MainThreadTask::DisableDebugMode);
}

void ShellView::VrMode(bool mode) {
  QueueTask(mode ? MainThreadTask::EnteringVrMode
                 : MainThreadTask::ExitingVrMode);
}

void ShellView::dumpInternal(String8& result) {
  result.append("[shell]\n");
  result.appendFormat("initialized = %s\n", initialized_ ? "true" : "false");
  result.appendFormat("is_visible = %s\n", is_visible_ ? "true" : "false");
  result.appendFormat("debug_mode = %s\n\n", debug_mode_ ? "true" : "false");

  result.append("[displays]\n");
  result.appendFormat("count = %zu\n", displays_.size());
  for (size_t i = 0; i < displays_.size(); ++i) {
    result.appendFormat("  display_id = %" PRId32 "\n", displays_[i]->id());
    result.appendFormat("    size=%fx%f\n",
                        displays_[i]->size().x(), displays_[i]->size().y());
  }

  result.append("\n");
}

void ShellView::Set2DMode(bool mode) {
  if (!displays_.empty())
    displays_[0]->set_2dmode(mode);
}

void ShellView::SetRotation(int angle) {
  mat4 m(Eigen::AngleAxisf(M_PI * -0.5f * angle, vec3::UnitZ()));
  for (auto& d: displays_)
    d->set_rotation(m);
}

void ShellView::OnDrawFrame() {
  bool visible = false;

  {
    std::unique_lock<std::mutex> l(display_frame_mutex_);

    // Move any new displays into the list.
    if (!new_displays_.empty()) {
      for (auto& display : new_displays_) {
        display->Recenter(GetHorizontallyAlignedMatrixFromPose(last_pose_));
        display->SetPrograms(program_.get(), overlay_program_.get());
        displays_.emplace_back(display.release());
      }
      new_displays_.clear();
    }

    // Remove any old displays from the list now.
    if (!removed_displays_.empty()) {
      for (auto& display : removed_displays_) {
        displays_.erase(std::find_if(
            displays_.begin(), displays_.end(),
            [display](auto& ptr) { return display == ptr.get(); }));
      }
      removed_displays_.clear();
    }

    for (auto& display : displays_) {
      display->AdvanceFrame();
      visible = visible || display->visible();
    }
  }

  if (!debug_mode_ && visible != is_visible_) {
    SetVisibility(visible);
  }

  for (auto& display : displays_) {
    display->OnDrawFrame(surface_flinger_view_.get(), debug_mode_);
  }
}

void ShellView::OnEndFrame() {
  std::unique_lock<std::mutex> l(display_frame_mutex_);
  for (auto& display : displays_) {
    display->UpdateReleaseFence();
  }
}

DisplayView* ShellView::FindOrCreateDisplay(uint32_t id) {
  for (auto& display : displays_) {
    if (display->id() == id) {
      return display.get();
    }
  }

  // It might be pending addition.
  for (auto& display : new_displays_) {
    if (display->id() == id) {
      return display.get();
    }
  }

  auto display = new DisplayView(id, GetTouchIdForDisplay(id));
  // Virtual displays only ever have 2D apps so force it.
  if (id != kPrimaryDisplayId)
    display->set_always_2d(true);
  new_displays_.emplace_back(display);
  return display;
}

base::unique_fd ShellView::OnFrame(std::unique_ptr<HwcCallback::Frame> frame) {
  std::unique_lock<std::mutex> l(display_frame_mutex_);
  DisplayView* display = FindOrCreateDisplay(frame->display_id());

  if (frame->removed()) {
    removed_displays_.push_back(display);
    return base::unique_fd();
  }

  bool showing = false;

  // This is a temporary fix for now. These APIs will be changed when everything
  // is moved into vrcore.
  // Do this on demand in case vr_flinger crashed and we are reconnecting.
  if (!display_client_.get()) {
    int error = 0;
    display_client_ = DisplayClient::Create(&error);

    if (error) {
      ALOGE("Could not connect to display service : %s(%d)", strerror(error),
            error);
      return base::unique_fd();
    }
  }

  // TODO(achaulk): change when moved into vrcore.
  bool vr_running = display_client_->IsVrAppRunning();

  base::unique_fd fd(
      display->OnFrame(std::move(frame), debug_mode_, vr_running, &showing));

  if (showing)
    QueueTask(MainThreadTask::Show);

  return fd;
}

void ShellView::DrawEye(EyeType eye, const mat4& perspective,
                        const mat4& eye_matrix, const mat4& head_matrix) {
  if (should_recenter_ && !displays_.empty()) {
    // Position the quad horizontally aligned in the direction the user
    // is facing, effectively taking out head roll.
    displays_[0]->Recenter(GetHorizontallyAlignedMatrixFromPose(last_pose_));
  }

  for (auto& display : displays_) {
    if (display->visible()) {
      display->DrawEye(eye, perspective, eye_matrix, head_matrix, fade_value_);
    }
  }

  // TODO(alexst): Replicate controller rendering from VR Home.
  // Current approach in the function below is a quick visualization.
  DrawController(perspective, eye_matrix, head_matrix);

  DrawReticle(perspective, eye_matrix, head_matrix);
}

void ShellView::OnVisibilityChanged(bool visible) {
  should_recenter_ = visible;
  Application::OnVisibilityChanged(visible);
}

bool ShellView::OnClick(bool down) {
  if (down) {
    if (!is_touching_ && active_display_ && active_display_->allow_input()) {
      is_touching_ = true;
    }
  } else {
    is_touching_ = false;
  }
  Touch();
  return true;
}

void ShellView::DrawReticle(const mat4& perspective, const mat4& eye_matrix,
                            const mat4& head_matrix) {
  reticle_->Hide();

  vec3 pointer_location = last_pose_.GetPosition();
  quat view_quaternion = last_pose_.GetRotation();

  if (shmem_controller_active_) {
    view_quaternion = controller_orientation_;
    vec4 controller_location = controller_translate_ * vec4(0, 0, 0, 1);
    pointer_location = vec3(controller_location.x(), controller_location.y(),
                            controller_location.z());

    if (shmem_controller_active_) {
      uint64_t buttons = shmem_controller_buttons_;
      shmem_controller_buttons_ = 0;
      while (buttons) {
        switch (buttons & 0xF) {
          case 0x1:
            OnClick(false);
            break;
          case 0x3:
            OnTouchpadButton(false, AMOTION_EVENT_BUTTON_BACK);
            break;
          case 0x4:
            should_recenter_ = true;
            break;
          case 0x9:
            OnClick(true);
            break;
          case 0xB:
            OnTouchpadButton(true, AMOTION_EVENT_BUTTON_BACK);
            break;
          default:
            break;
        }
        buttons >>= 4;
      }
    }
  }

  vec3 hit_location;
  active_display_ =
      FindActiveDisplay(pointer_location, view_quaternion, &hit_location);

  if (active_display_) {
    reticle_->ShowAt(
        Eigen::Translation3f(hit_location) * view_quaternion.matrix(),
        active_display_->allow_input() ? vec3(1, 0, 0) : vec3(0, 0, 0));
    Touch();
  }

  reticle_->Draw(perspective, eye_matrix, head_matrix);
}

DisplayView* ShellView::FindActiveDisplay(const vec3& position,
                                          const quat& quaternion,
                                          vec3* hit_location) {
  vec3 direction = vec3(quaternion * vec3(0, 0, -1));
  vec3 temp_hit;

  DisplayView* best_display = nullptr;
  vec3 best_hit;

  auto is_better = [&best_hit, &position](DisplayView*, const vec3& hit) {
    return (hit - position).squaredNorm() < (best_hit - position).squaredNorm();
  };

  for (auto& display : displays_) {
    if (display->UpdateHitInfo(position, direction, &temp_hit)) {
      if (!best_display || is_better(display.get(), temp_hit)) {
        best_display = display.get();
        best_hit = temp_hit;
      }
    }
  }

  if (best_display)
    *hit_location = best_hit;
  return best_display;
}

void ShellView::DrawController(const mat4& perspective, const mat4& eye_matrix,
                               const mat4& head_matrix) {
  if (!shmem_controller_active_)
    return;

  controller_program_->Use();
  mat4 mvp = perspective * eye_matrix * head_matrix;

  GLint view_projection_location = glGetUniformLocation(
      controller_program_->GetProgram(), "uViewProjection");
  glUniformMatrix4fv(view_projection_location, 1, 0, mvp.data());

  quat view_quaternion = controller_orientation_;
  view_quaternion.toRotationMatrix();

  vec3 world_pos = last_pose_.GetPosition() + controller_position_;

  controller_translate_ =
      Eigen::Translation3f(world_pos.x(), world_pos.y(), world_pos.z());

  mat4 transform = controller_translate_ * view_quaternion *
                   mat4(Eigen::Scaling<float>(1, 1, 3.0));
  GLint transform_location =
      glGetUniformLocation(controller_program_->GetProgram(), "uTransform");
  glUniformMatrix4fv(transform_location, 1, 0, transform.data());

  controller_mesh_->Draw();
}

void ShellView::Touch() {
  if (!virtual_touchpad_) {
    ALOGE("missing virtual touchpad");
    return;
  }

  if (!active_display_)
    return;

  const vec2& hit_location = active_display_->hit_location();
  const vec2 size = active_display_->size();

  float x = hit_location.x() / size.x();
  float y = hit_location.y() / size.y();

  // Device is portrait, but in landscape when in VR.
  // Rotate touch input appropriately.
  const android::status_t status = dvrVirtualTouchpadTouch(
      virtual_touchpad_.get(), active_display_->touchpad_id(),
      x, y, is_touching_ ? 1.0f : 0.0f);
  if (status != OK) {
    ALOGE("touch failed: %d", status);
  }
}

bool ShellView::OnTouchpadButton(bool down, int button) {
  int buttons = touchpad_buttons_;
  if (down) {
    if (active_display_ && active_display_->allow_input()) {
      buttons |= button;
    }
  } else {
    buttons &= ~button;
  }
  if (buttons == touchpad_buttons_) {
    return true;
  }
  touchpad_buttons_ = buttons;
  if (!virtual_touchpad_) {
    ALOGE("missing virtual touchpad");
    return false;
  }

  if (!active_display_)
    return true;

  const android::status_t status = dvrVirtualTouchpadButtonState(
      virtual_touchpad_.get(), active_display_->touchpad_id(),
      touchpad_buttons_);
  if (status != OK) {
    ALOGE("touchpad button failed: %d %d", touchpad_buttons_, status);
  }
  return true;
}

}  // namespace dvr
}  // namespace android
