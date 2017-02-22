#include "shell_view.h"

#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <android/input.h>
#include <binder/IServiceManager.h>
#include <hardware/hwcomposer2.h>
#include <log/log.h>

#include "controller_mesh.h"
#include "texture.h"

namespace android {
namespace dvr {

namespace {

constexpr float kLayerScaleFactor = 4.0f;

constexpr unsigned int kVRAppLayerCount = 2;

constexpr unsigned int kMaximumPendingFrames = 8;

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

const GLfloat kVertices[] = {
  -1, -1, 0,
   1, -1, 0,
  -1,  1, 0,
   1,  1, 0,
};

const GLfloat kTextureVertices[] = {
  0, 1,
  1, 1,
  0, 0,
  1, 0,
};

// Returns true if the given point is inside the given rect.
bool IsInside(const vec2& pt, const vec2& tl, const vec2& br) {
  return pt.x() >= tl.x() && pt.x() <= br.x() &&
    pt.y() >= tl.y() && pt.y() <= br.y();
}

mat4 GetScalingMatrix(float width, float height) {
  float xscale = 1, yscale = 1;
  float ar = width / height;
  if (ar > 1)
    yscale = 1.0 / ar;
  else
    xscale = ar;

  xscale *= kLayerScaleFactor;
  yscale *= kLayerScaleFactor;

  return mat4(Eigen::Scaling<float>(xscale, yscale, 1.0));
}

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

  return m * Eigen::AngleAxisf(M_PI * 0.5f, vec3::UnitZ());
}

// Helper function that applies the crop transform to the texture layer and
// positions (and scales) the texture layer in the appropriate location in the
// display space.
mat4 GetLayerTransform(const TextureLayer& texture_layer, float display_width,
                       float display_height) {
  // Map from vertex coordinates to [0, 1] coordinates:
  //  1) Flip y since in vertex coordinates (-1, -1) is at the bottom left and
  //     in texture coordinates (0, 0) is at the top left.
  //  2) Translate by (1, 1) to map vertex coordinates to [0, 2] on x and y.
  //  3) Scale by 1 / 2 to map coordinates to [0, 1] on x  and y.
  mat4 unit_space(
      Eigen::AlignedScaling3f(0.5f, 0.5f, 1.0f) *
      Eigen::Translation3f(1.0f, 1.0f, 0.0f) *
      Eigen::AlignedScaling3f(1.0f, -1.0f, 1.0f));

  mat4 texture_space(Eigen::AlignedScaling3f(
      texture_layer.texture->width(), texture_layer.texture->height(), 1.0f));

  // 1) Translate the layer to crop the left and top edge.
  // 2) Scale the layer such that the cropped right and bottom edges map outside
  //    the exture region.
  float crop_width = texture_layer.crop.right - texture_layer.crop.left;
  float crop_height = texture_layer.crop.bottom - texture_layer.crop.top;
  mat4 texture_crop(
      Eigen::AlignedScaling3f(
          texture_layer.texture->width() / crop_width,
          texture_layer.texture->height() / crop_height,
          1.0f) *
      Eigen::Translation3f(
          -texture_layer.crop.left, -texture_layer.crop.top, 0.0f));

  mat4 display_space(
      Eigen::AlignedScaling3f(display_width, display_height, 1.0f));

  // 1) Scale the texture to fit the display frame.
  // 2) Translate the texture in the display frame location.
  float display_frame_width = texture_layer.display_frame.right -
      texture_layer.display_frame.left;
  float display_frame_height = texture_layer.display_frame.bottom -
      texture_layer.display_frame.top;
  mat4 display_frame(
      Eigen::Translation3f(
          texture_layer.display_frame.left,
          texture_layer.display_frame.top,
          0.0f) *
      Eigen::AlignedScaling3f(
          display_frame_width / display_width,
          display_frame_height / display_height,
          1.0f));

  mat4 layer_transform = unit_space.inverse() * display_space.inverse() *
      display_frame * display_space * texture_space.inverse() * texture_crop *
      texture_space * unit_space;
  return layer_transform;
}

// Determine if ths frame should be shown or hidden.
ViewMode CalculateVisibilityFromLayerConfig(const HwcCallback::Frame& frame,
                                            uint32_t vr_app) {
  auto& layers = frame.layers();

  // We assume the first two layers are the VR app.
  if (layers.size() < kVRAppLayerCount)
    return ViewMode::Hidden;

  if (vr_app != layers[0].appid || layers[0].appid == 0 ||
      layers[1].appid != layers[0].appid) {
    if (layers[1].appid != layers[0].appid && layers[0].appid) {
      // This might be a 2D app.
      return ViewMode::App;
    }
    return ViewMode::Hidden;
  }

  // If a non-VR-app, non-skipped layer appears, show.
  size_t index = kVRAppLayerCount;
  // Now, find a dim layer if it exists.
  // If it does, ignore any layers behind it for visibility determination.
  for (size_t i = index; i < layers.size(); i++) {
    if (layers[i].appid == 0) {
      index = i + 1;
      break;
    }
  }

  // If any non-skipped layers exist now then we show, otherwise hide.
  for (size_t i = index; i < layers.size(); i++) {
    if (!layers[i].should_skip_layer())
      return ViewMode::VR;
  }
  return ViewMode::Hidden;
}


}  // namespace

ShellView::ShellView() {
  ime_translate_ = mat4(Eigen::Translation3f(0.0f, -0.5f, 0.25f));
  ime_top_left_ = vec2(0, 0);
  ime_size_ = vec2(0, 0);
}

ShellView::~ShellView() {}

int ShellView::Initialize() {
  int ret = Application::Initialize();
  if (ret)
    return ret;

  translate_ = Eigen::Translation3f(0, 0, -2.5f);

  if (!InitializeTouch())
    ALOGE("Failed to initialize virtual touchpad");

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

  initialized_ = true;

  return 0;
}

void ShellView::DeallocateResources() {
  surface_flinger_view_.reset();
  reticle_.reset();
  controller_mesh_.reset();
  program_.reset(new ShaderProgram);
  overlay_program_.reset(new ShaderProgram);
  controller_program_.reset(new ShaderProgram);
  Application::DeallocateResources();
}

void ShellView::EnableDebug(bool debug) {
  ALOGI("EnableDebug(%d)", (int)debug); // XXX TODO delete
  QueueTask(debug ? MainThreadTask::EnableDebugMode
                  : MainThreadTask::DisableDebugMode);
}

void ShellView::VrMode(bool mode) {
  ALOGI("VrMode(%d)", (int)mode); // XXX TODO delete
  QueueTask(mode ? MainThreadTask::EnteringVrMode
                 : MainThreadTask::ExitingVrMode);
}

void ShellView::dumpInternal(String8& result) {
  result.append("[shell]\n");
  result.appendFormat("initialized = %s\n", initialized_ ? "true" : "false");
  result.appendFormat("is_visible = %s\n", is_visible_ ? "true" : "false");
  result.appendFormat("debug_mode = %s\n\n", debug_mode_ ? "true" : "false");
}

void ShellView::AdvanceFrame() {
  if (!pending_frames_.empty()) {
    // Check if we should advance the frame.
    auto& frame = pending_frames_.front();
    if (frame.visibility == ViewMode::Hidden ||
        frame.frame->Finish() == HwcCallback::FrameStatus::kFinished) {
      current_frame_ = std::move(frame);
      pending_frames_.pop_front();
    }
  }
}

void ShellView::OnDrawFrame() {
  textures_.clear();
  has_ime_ = false;

  {
    std::unique_lock<std::mutex> l(pending_frame_mutex_);
    AdvanceFrame();
  }

  bool visible = current_frame_.visibility != ViewMode::Hidden;

  if (!debug_mode_ && visible != is_visible_) {
    SetVisibility(current_frame_.visibility != ViewMode::Hidden);
  }

  if (!debug_mode_ && !visible)
    return;

  ime_texture_ = TextureLayer();

  surface_flinger_view_->GetTextures(*current_frame_.frame.get(), &textures_,
                                     &ime_texture_, debug_mode_,
                                     current_frame_.visibility == ViewMode::VR);
  has_ime_ = ime_texture_.texture != nullptr;
}

void ShellView::DrawEye(EyeType /* eye */, const mat4& perspective,
                        const mat4& eye_matrix, const mat4& head_matrix) {
  if (should_recenter_) {
    // Position the quad horizontally aligned in the direction the user
    // is facing, effectively taking out head roll.
    initial_head_matrix_ = GetHorizontallyAlignedMatrixFromPose(last_pose_);
    should_recenter_ = false;
  }

  size_ = vec2(surface_flinger_view_->width(), surface_flinger_view_->height());
  scale_ = GetScalingMatrix(size_.x(), size_.y());

  DrawOverlays(perspective, eye_matrix, head_matrix);

  // TODO(alexst): Replicate controller rendering from VR Home.
  // Current approach in the function below is a quick visualization.
  DrawController(perspective, eye_matrix, head_matrix);

  // TODO: Make sure reticle is shown only over visible overlays.
  DrawReticle(perspective, eye_matrix, head_matrix);
}

void ShellView::OnVisibilityChanged(bool visible) {
  should_recenter_ = visible;
  Application::OnVisibilityChanged(visible);
}

bool ShellView::OnClick(bool down) {
  if (down) {
    if (!is_touching_ && allow_input_) {
      is_touching_ = true;
    }
  } else {
    is_touching_ = false;
  }
  Touch();
  return true;
}

base::unique_fd ShellView::OnFrame(std::unique_ptr<HwcCallback::Frame> frame) {
  ViewMode visibility =
      CalculateVisibilityFromLayerConfig(*frame.get(), current_vr_app_);

  if (visibility == ViewMode::Hidden && debug_mode_)
    visibility = ViewMode::VR;

  if (frame->layers().empty())
    current_vr_app_ = 0;
  else
    current_vr_app_ = frame->layers().front().appid;

  std::unique_lock<std::mutex> l(pending_frame_mutex_);

  pending_frames_.emplace_back(std::move(frame), visibility);

  if (pending_frames_.size() > kMaximumPendingFrames) {
    pending_frames_.pop_front();
  }

  if (visibility == ViewMode::Hidden &&
      current_frame_.visibility == ViewMode::Hidden) {
    // Consume all frames while hidden.
    while (!pending_frames_.empty())
      AdvanceFrame();
  }

  // If we are showing ourselves the main thread is not processing anything,
  // so give it a kick.
  if (visibility != ViewMode::Hidden &&
      current_frame_.visibility == ViewMode::Hidden) {
    QueueTask(MainThreadTask::EnteringVrMode);
    QueueTask(MainThreadTask::Show);
  }

  return base::unique_fd(dup(release_fence_.get()));
}

bool ShellView::IsHit(const vec3& view_location, const vec3& view_direction,
                      vec3* hit_location, vec2* hit_location_in_window_coord,
                      bool test_ime) {
  mat4 m = initial_head_matrix_ * translate_;
  if (test_ime)
    m = m * ime_translate_;
  mat4 inverse = (m * scale_).inverse();
  vec4 transformed_loc =
      inverse * vec4(view_location[0], view_location[1], view_location[2], 1);
  vec4 transformed_dir = inverse * vec4(view_direction[0], view_direction[1],
                                        view_direction[2], 0);

  if (transformed_dir.z() >= 0 || transformed_loc.z() <= 0)
    return false;

  float distance = -transformed_loc.z() / transformed_dir.z();
  vec4 transformed_hit_loc = transformed_loc + transformed_dir * distance;
  if (transformed_hit_loc.x() < -1 || transformed_hit_loc.x() > 1)
    return false;
  if (transformed_hit_loc.y() < -1 || transformed_hit_loc.y() > 1)
    return false;

  hit_location_in_window_coord->x() =
      (1 + transformed_hit_loc.x()) / 2 * size_.x();
  hit_location_in_window_coord->y() =
      (1 - transformed_hit_loc.y()) / 2 * size_.y();

  *hit_location = view_location + view_direction * distance;
  return true;
}

void ShellView::DrawOverlays(const mat4& perspective, const mat4& eye_matrix,
                             const mat4& head_matrix) {
  if (textures_.empty())
    return;

  program_->Use();
  mat4 mvp = perspective * eye_matrix * head_matrix;
  GLint view_projection_location =
      glGetUniformLocation(program_->GetProgram(), "uViewProjection");
  glUniformMatrix4fv(view_projection_location, 1, 0, mvp.data());

  GLint alpha_location =
      glGetUniformLocation(program_->GetProgram(), "uAlpha");

  GLint tex_location = glGetUniformLocation(program_->GetProgram(), "tex");
  glUniform1i(tex_location, 0);
  glActiveTexture(GL_TEXTURE0);

  for (const auto& texture_layer : textures_) {
    switch (texture_layer.blending) {
      case HWC2_BLEND_MODE_PREMULTIPLIED:
        glEnable(GL_BLEND);
        glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
        break;
      case HWC2_BLEND_MODE_COVERAGE:
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        break;
      default:
        break;
    }

    glUniform1f(alpha_location, fade_value_ * texture_layer.alpha);

    glBindTexture(GL_TEXTURE_2D, texture_layer.texture->id());

    mat4 layer_transform = GetLayerTransform(texture_layer, size_.x(),
                                             size_.y());

    mat4 transform = initial_head_matrix_ * translate_ * scale_ *
        layer_transform;
    DrawWithTransform(transform, *program_);

    glDisable(GL_BLEND);
  }

  if (has_ime_) {
    ime_top_left_ = vec2(static_cast<float>(ime_texture_.display_frame.left),
                         static_cast<float>(ime_texture_.display_frame.top));
    ime_size_ = vec2(static_cast<float>(ime_texture_.display_frame.right -
                                        ime_texture_.display_frame.left),
                     static_cast<float>(ime_texture_.display_frame.bottom -
                                        ime_texture_.display_frame.top));

    DrawDimOverlay(mvp, textures_[0], ime_top_left_, ime_top_left_ + ime_size_);

    DrawIme();
  }

  EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  EGLSyncKHR sync = eglCreateSyncKHR(display, EGL_SYNC_NATIVE_FENCE_ANDROID,
                                     nullptr);
  if (sync != EGL_NO_SYNC_KHR) {
    // Need to flush in order to get the fence FD.
    glFlush();
    base::unique_fd fence(eglDupNativeFenceFDANDROID(display, sync));
    eglDestroySyncKHR(display, sync);
    UpdateReleaseFence(std::move(fence));
  } else {
    ALOGE("Failed to create sync fence");
    UpdateReleaseFence(base::unique_fd());
  }
}

void ShellView::DrawIme() {
  program_->Use();
  glBindTexture(GL_TEXTURE_2D, ime_texture_.texture->id());

  mat4 layer_transform = GetLayerTransform(ime_texture_, size_.x(), size_.y());

  mat4 transform = initial_head_matrix_ * translate_ * ime_translate_ * scale_ *
              layer_transform;

  DrawWithTransform(transform, *program_);
}

void ShellView::DrawDimOverlay(const mat4& mvp, const TextureLayer& layer, const vec2& top_left,
                    const vec2& bottom_right) {
  overlay_program_->Use();
  glUniformMatrix4fv(
      glGetUniformLocation(overlay_program_->GetProgram(), "uViewProjection"),
      1, 0, mvp.data());
  glUniform4f(glGetUniformLocation(overlay_program_->GetProgram(), "uCoords"),
              top_left.x() / size_.x(), top_left.y() / size_.y(),
              bottom_right.x() / size_.x(), bottom_right.y() / size_.y());
  glEnable(GL_BLEND);
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
  mat4 layer_transform =
      GetLayerTransform(layer, size_.x(), size_.y());

  mat4 transform =
      initial_head_matrix_ * translate_ * scale_ * layer_transform;
  DrawWithTransform(transform, *overlay_program_);
  glDisable(GL_BLEND);
}

void ShellView::DrawWithTransform(const mat4& transform,
                                  const ShaderProgram& program) {
  GLint transform_location =
      glGetUniformLocation(program.GetProgram(), "uTransform");
  glUniformMatrix4fv(transform_location, 1, 0, transform.data());

  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, kVertices);
  glEnableVertexAttribArray(1);
  glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 0, kTextureVertices);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}

bool ShellView::IsImeHit(const vec3& view_location, const vec3& view_direction,
                vec3 *hit_location) {
  // First, check if the IME window is hit.
  bool is_hit = IsHit(view_location, view_direction, hit_location,
                      &hit_location_in_window_coord_, true);
  if (is_hit) {
    // If it is, check if the window coordinate is in the IME region;
    // if so then we are done.
    if (IsInside(hit_location_in_window_coord_, ime_top_left_,
                 ime_top_left_ + ime_size_)) {
      allow_input_ = true;
      return true;
    }
  }

  allow_input_ = false;
  // Check if we have hit the main window.
  is_hit = IsHit(view_location, view_direction, hit_location,
                 &hit_location_in_window_coord_, false);
  if (is_hit) {
    // Only allow input if we are not hitting the region hidden by the IME.
    // Allowing input here would cause clicks on the main window to actually
    // be clicks on the IME.
    if (!IsInside(hit_location_in_window_coord_, ime_top_left_,
                  ime_top_left_ + ime_size_)) {
      allow_input_ = true;
    }
  }
  return is_hit;
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

  vec3 view_direction = vec3(view_quaternion * vec3(0, 0, -1));

  vec3 hit_location;

  bool is_hit;
  if(has_ime_) {
    // This will set allow_input_ and hit_location_in_window_coord_.
    is_hit = IsImeHit(pointer_location, view_direction, &hit_location);
  } else {
    is_hit = IsHit(pointer_location, view_direction, &hit_location,
                   &hit_location_in_window_coord_, false);
    allow_input_ = is_hit;
  }

  if (is_hit) {
    reticle_->ShowAt(
        Eigen::Translation3f(hit_location) * view_quaternion.matrix(),
        allow_input_ ? vec3(1, 0, 0) : vec3(0, 0, 0));
    Touch();
  }

  reticle_->Draw(perspective, eye_matrix, head_matrix);
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

bool ShellView::InitializeTouch() {
  virtual_touchpad_ =
      android::interface_cast<android::dvr::IVirtualTouchpadService>(
          android::defaultServiceManager()->getService(
              android::String16("virtual_touchpad")));
  if (!virtual_touchpad_.get()) {
    ALOGE("Failed to connect to virtual touchpad");
    return false;
  }
  return true;
}

void ShellView::Touch() {
  if (!virtual_touchpad_.get()) {
    ALOGE("missing virtual touchpad");
    // Try to reconnect; useful in development.
    if (!InitializeTouch()) {
      return;
    }
  }

  const android::binder::Status status = virtual_touchpad_->touch(
      hit_location_in_window_coord_.x() / size_.x(),
      hit_location_in_window_coord_.y() / size_.y(),
      is_touching_ ? 1.0f : 0.0f);
  if (!status.isOk()) {
    ALOGE("touch failed: %s", status.toString8().string());
  }
}

bool ShellView::OnTouchpadButton(bool down, int button) {
  int buttons = touchpad_buttons_;
  if (down) {
    if (allow_input_) {
      buttons |= button;
    }
  } else {
    buttons &= ~button;
  }
  if (buttons == touchpad_buttons_) {
    return true;
  }
  touchpad_buttons_ = buttons;
  if (!virtual_touchpad_.get()) {
    ALOGE("missing virtual touchpad");
    return false;
  }

  const android::binder::Status status =
      virtual_touchpad_->buttonState(touchpad_buttons_);
  if (!status.isOk()) {
    ALOGE("touchpad button failed: %d %s", touchpad_buttons_,
          status.toString8().string());
  }
  return true;
}

void ShellView::UpdateReleaseFence(base::unique_fd fence) {
  std::lock_guard<std::mutex> guard(pending_frame_mutex_);
  release_fence_ = std::move(fence);
}

}  // namespace dvr
}  // namespace android
