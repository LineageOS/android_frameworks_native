#include "display_view.h"

#include "texture.h"

namespace android {
namespace dvr {

namespace {

constexpr float kLayerScaleFactor = 3.0f;
constexpr unsigned int kMaximumPendingFrames = 8;
constexpr uint32_t kSystemId = 1000;

// clang-format off
const GLfloat kVertices[] = {
  -1, -1, 0,
   1, -1, 0,
  -1, 1, 0,
   1, 1, 0,
};

const GLfloat kTextureVertices[] = {
  0, 1,
  1, 1,
  0, 0,
  1, 0,
};
// clang-format on

// Returns true if the given point is inside the given rect.
bool IsInside(const vec2& pt, const vec2& tl, const vec2& br) {
  return pt.x() >= tl.x() && pt.x() <= br.x() && pt.y() >= tl.y() &&
         pt.y() <= br.y();
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
  mat4 unit_space(Eigen::AlignedScaling3f(0.5f, 0.5f, 1.0f) *
                  Eigen::Translation3f(1.0f, 1.0f, 0.0f) *
                  Eigen::AlignedScaling3f(1.0f, -1.0f, 1.0f));

  mat4 texture_space(Eigen::AlignedScaling3f(
      texture_layer.texture->width(), texture_layer.texture->height(), 1.0f));

  // 1) Translate the layer to crop the left and top edge.
  // 2) Scale the layer such that the cropped right and bottom edges map outside
  //    the exture region.
  float crop_width = texture_layer.crop.right - texture_layer.crop.left;
  float crop_height = texture_layer.crop.bottom - texture_layer.crop.top;
  mat4 texture_crop(Eigen::AlignedScaling3f(
                        texture_layer.texture->width() / crop_width,
                        texture_layer.texture->height() / crop_height, 1.0f) *
                    Eigen::Translation3f(-texture_layer.crop.left,
                                         -texture_layer.crop.top, 0.0f));

  mat4 display_space(
      Eigen::AlignedScaling3f(display_width, display_height, 1.0f));

  // 1) Scale the texture to fit the display frame.
  // 2) Translate the texture in the display frame location.
  float display_frame_width =
      texture_layer.display_frame.right - texture_layer.display_frame.left;
  float display_frame_height =
      texture_layer.display_frame.bottom - texture_layer.display_frame.top;
  mat4 display_frame(
      Eigen::Translation3f(texture_layer.display_frame.left,
                           texture_layer.display_frame.top, 0.0f) *
      Eigen::AlignedScaling3f(display_frame_width / display_width,
                              display_frame_height / display_height, 1.0f));

  mat4 layer_transform = unit_space.inverse() * display_space.inverse() *
                         display_frame * display_space *
                         texture_space.inverse() * texture_crop *
                         texture_space * unit_space;
  return layer_transform;
}

// Determine if ths frame should be shown or hidden.
ViewMode CalculateVisibilityFromLayerConfig(const HwcCallback::Frame& frame,
                                            uint32_t* appid) {
  auto& layers = frame.layers();

  size_t index;
  // Skip all layers that we don't know about.
  for (index = 0; index < layers.size(); index++) {
    if (layers[index].type != 0xFFFFFFFF && layers[index].type != 0)
      break;
  }

  if (index == layers.size())
    return ViewMode::Hidden;

  if (layers[index].type != 1) {
    // We don't have a VR app layer? Abort.
    return ViewMode::Hidden;
  }

  if (layers[index].appid != *appid) {
    *appid = layers[index].appid;
    return ViewMode::App;
  }

  // This is the VR app, ignore it.
  index++;

  // Now, find a dim layer if it exists.
  // If it does, ignore any layers behind it for visibility determination.
  for (size_t i = index; i < layers.size(); i++) {
    if (layers[i].appid == HwcCallback::HwcLayer::kSurfaceFlingerLayer) {
      index = i + 1;
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

DisplayView::DisplayView(uint32_t id, int touchpad_id)
    : id_(id), touchpad_id_(touchpad_id) {
  translate_ = Eigen::Translation3f(0, 0, -5.0f);
  ime_translate_ = mat4(Eigen::Translation3f(0.0f, -0.5f, 0.25f));
  ime_top_left_ = vec2(0, 0);
  ime_size_ = vec2(0, 0);
  rotation_ = mat4::Identity();
}

DisplayView::~DisplayView() {}

void DisplayView::Recenter(const mat4& initial) {
  initial_head_matrix_ =
      initial * Eigen::AngleAxisf(M_PI * 0.5f, vec3::UnitZ());
}

void DisplayView::SetPrograms(ShaderProgram* program,
                              ShaderProgram* overlay_program) {
  program_ = program;
  overlay_program_ = overlay_program;
}

void DisplayView::DrawEye(EyeType /* eye */, const mat4& perspective,
                          const mat4& eye_matrix, const mat4& head_matrix,
                          float fade_value) {
  scale_ = GetScalingMatrix(size_.x(), size_.y());

  DrawOverlays(perspective, eye_matrix, head_matrix, fade_value);
}

void DisplayView::AdvanceFrame() {
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

void DisplayView::OnDrawFrame(SurfaceFlingerView* surface_flinger_view,
                              bool debug_mode) {
  textures_.clear();
  has_ime_ = false;

  if (!visible())
    return;

  surface_flinger_view->GetTextures(*current_frame_.frame.get(), &textures_,
                                    &ime_texture_, debug_mode,
                                    current_frame_.visibility == ViewMode::VR);
  has_ime_ = ime_texture_.texture != nullptr;
}

base::unique_fd DisplayView::OnFrame(std::unique_ptr<HwcCallback::Frame> frame,
                                     bool debug_mode, bool is_vr_active,
                                     bool* showing) {
  size_ = vec2(frame->display_width(), frame->display_height());
  uint32_t app = current_vr_app_;
  ViewMode visibility = CalculateVisibilityFromLayerConfig(*frame.get(), &app);

  if (visibility == ViewMode::Hidden && debug_mode)
    visibility = ViewMode::VR;

  if (frame->layers().empty()) {
    current_vr_app_ = 0;
  } else if (visibility == ViewMode::App) {
    // This is either a VR app switch or a 2D app launching.
    // If we can have VR apps, update if it's 0.
    if (!always_2d_ && is_vr_active && !use_2dmode_ && app != kSystemId) {
      visibility = ViewMode::Hidden;
      current_vr_app_ = app;
    }
  } else if (!current_vr_app_) {
    // The VR app is running.
    current_vr_app_ = app;
  }

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
    *showing = true;
  }

  return base::unique_fd(dup(release_fence_.get()));
}

bool DisplayView::IsHit(const vec3& view_location, const vec3& view_direction,
                        vec3* hit_location, vec2* hit_location_in_window_coord,
                        bool test_ime) {
  mat4 m = GetStandardTransform();
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

void DisplayView::DrawOverlays(const mat4& perspective, const mat4& eye_matrix,
                               const mat4& head_matrix, float fade_value) {
  if (textures_.empty())
    return;

  program_->Use();
  mat4 mvp = perspective * eye_matrix * head_matrix;
  GLint view_projection_location =
      glGetUniformLocation(program_->GetProgram(), "uViewProjection");
  glUniformMatrix4fv(view_projection_location, 1, 0, mvp.data());

  GLint alpha_location = glGetUniformLocation(program_->GetProgram(), "uAlpha");

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

    glUniform1f(alpha_location, fade_value * texture_layer.alpha);

    glBindTexture(GL_TEXTURE_2D, texture_layer.texture->id());

    mat4 layer_transform =
        GetLayerTransform(texture_layer, size_.x(), size_.y());

    mat4 transform = GetStandardTransform() * scale_ * layer_transform;
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
}

void DisplayView::UpdateReleaseFence() {
  EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  EGLSyncKHR sync =
      eglCreateSyncKHR(display, EGL_SYNC_NATIVE_FENCE_ANDROID, nullptr);
  if (sync != EGL_NO_SYNC_KHR) {
    // Need to flush in order to get the fence FD.
    glFlush();
    base::unique_fd fence(eglDupNativeFenceFDANDROID(display, sync));
    eglDestroySyncKHR(display, sync);
    release_fence_ = std::move(fence);
  } else {
    ALOGE("Failed to create sync fence");
    release_fence_ = base::unique_fd();
  }
}

mat4 DisplayView::GetStandardTransform() {
  mat4 m = initial_head_matrix_ * rotation_ * translate_;
  if (current_frame_.visibility == ViewMode::App)
    m *= Eigen::AngleAxisf(M_PI * -0.5f, vec3::UnitZ());
  return m;
}

void DisplayView::DrawIme() {
  program_->Use();
  glBindTexture(GL_TEXTURE_2D, ime_texture_.texture->id());

  mat4 layer_transform = GetLayerTransform(ime_texture_, size_.x(), size_.y());

  mat4 transform =
      GetStandardTransform() * ime_translate_ * scale_ * layer_transform;

  DrawWithTransform(transform, *program_);
}

void DisplayView::DrawDimOverlay(const mat4& mvp, const TextureLayer& layer,
                                 const vec2& top_left,
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
  mat4 layer_transform = GetLayerTransform(layer, size_.x(), size_.y());

  mat4 transform = GetStandardTransform() * scale_ * layer_transform;
  DrawWithTransform(transform, *overlay_program_);
  glDisable(GL_BLEND);
}

void DisplayView::DrawWithTransform(const mat4& transform,
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

bool DisplayView::UpdateHitInfo(const vec3& view_location,
                                const vec3& view_direction,
                                vec3* hit_location) {
  bool is_hit = false;
  if (has_ime_) {
    // This will set allow_input_ and hit_location_in_window_coord_.
    is_hit = IsImeHit(view_location, view_direction, hit_location);
  } else {
    is_hit = IsHit(view_location, view_direction, hit_location,
                   &hit_location_in_window_coord_, false);
    allow_input_ = is_hit;
  }
  return is_hit;
}

bool DisplayView::IsImeHit(const vec3& view_location,
                           const vec3& view_direction, vec3* hit_location) {
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

}  // namespace dvr
}  // namespace android
