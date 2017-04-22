#include "compositor.h"

#include <EGL/eglext.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>

#include <memory>

#include <cutils/properties.h>

#include <dvr/graphics.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/debug.h>
#include <private/dvr/device_metrics.h>
#include <private/dvr/display_types.h>
#include <private/dvr/dummy_native_window.h>
#include <private/dvr/gl_fenced_flush.h>
#include <private/dvr/graphics/blur.h>
#include <private/dvr/graphics/gpu_profiler.h>
#include <private/dvr/native_buffer.h>
#include <private/dvr/platform_defines.h>
#include <utils/Log.h>
#include <utils/Trace.h>

#include "debug_hud_data.h"
#include "debug_hud_view.h"
#include "display_surface.h"

#define BINNING_CONTROL_HINT_QCOM 0x8FB0

// Accepted by the <hint> parameter of glHint:
#define BINNING_QCOM 0x8FB1
#define VISIBILITY_OPTIMIZED_BINNING_QCOM 0x8FB2
#define RENDER_DIRECT_TO_FRAMEBUFFER_QCOM 0x8FB3

#ifndef EGL_CONTEXT_MAJOR_VERSION
#define EGL_CONTEXT_MAJOR_VERSION 0x3098
#define EGL_CONTEXT_MINOR_VERSION 0x30FB
#endif

using android::pdx::LocalHandle;

static const int kDistortionMeshResolution = 40;

static std::shared_ptr<int64_t> eds_gpu_duration_ns =
    std::make_shared<int64_t>(0);

static constexpr char kDisableLensDistortionProp[] =
    "persist.dvr.disable_distort";

static constexpr char kEnableEdsPoseSaveProp[] =
    "persist.dvr.save_eds_pose";

namespace android {
namespace dvr {

namespace {

// An implementation of ANativeWindowBuffer backed by a temporary IonBuffer.
// Do not hold on to this kind of object, because the IonBuffer may become
// invalid in other scopes.
class TemporaryNativeBuffer
    : public ANativeObjectBase<ANativeWindowBuffer, TemporaryNativeBuffer,
                               LightRefBase<TemporaryNativeBuffer>> {
 public:
  explicit TemporaryNativeBuffer(const IonBuffer* buffer) : BASE() {
    ANativeWindowBuffer::width = buffer->width();
    ANativeWindowBuffer::height = buffer->height();
    ANativeWindowBuffer::stride = buffer->stride();
    ANativeWindowBuffer::format = buffer->format();
    ANativeWindowBuffer::usage = buffer->usage();
    // TODO(eieio): Update NYC to support layer_count.
    // ANativeWindowBuffer::layer_count = 1;
    handle = buffer->handle();
  }

 private:
  friend class android::LightRefBase<TemporaryNativeBuffer>;

  TemporaryNativeBuffer(const TemporaryNativeBuffer&) = delete;
  void operator=(TemporaryNativeBuffer&) = delete;
};

std::vector<uint8_t> ReadTextureRGBA(GLuint texture_id, int width, int height) {
  std::vector<uint8_t> data(width * height * 4);
  GLuint fbo;
  glGenFramebuffers(1, &fbo);
  glBindFramebuffer(GL_FRAMEBUFFER, fbo);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         texture_id, 0);
  // Using default GL_PACK_ALIGNMENT of 4 for the 4 byte source data.
  glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, data.data());
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
  glDeleteFramebuffers(1, &fbo);
  CHECK_GL();
  return data;
}

}  // namespace

class Compositor::Texture {
 public:
  Texture(std::shared_ptr<BufferConsumer> consumer, EGLDisplay display,
          int index);
  ~Texture();

  std::shared_ptr<BufferConsumer> consumer() const { return consumer_; }
  GLuint texture_id() const { return texture_id_; }
  vec2i size() const {
    return vec2i(native_buffer_.get()->width, native_buffer_.get()->height);
  }
  int index() const { return index_; }

  bool Initialize();

 private:
  Texture(const Texture&) = delete;
  void operator=(const Texture&) = delete;

  std::shared_ptr<BufferConsumer> consumer_;

  android::sp<NativeBufferConsumer> native_buffer_;

  EGLDisplay display_;
  EGLImageKHR image_;
  GLuint texture_id_;
  int index_;
};

Compositor::Texture::Texture(std::shared_ptr<BufferConsumer> consumer,
                             EGLDisplay display, int index)
    : consumer_(consumer),
      display_(display),
      image_(nullptr),
      texture_id_(0),
      index_(index) {}

Compositor::Texture::~Texture() {
  glDeleteTextures(1, &texture_id_);
  eglDestroyImageKHR(display_, image_);
}

bool Compositor::Texture::Initialize() {
  native_buffer_ = new NativeBufferConsumer(consumer_, index_);

  CHECK_GL();
  image_ = eglCreateImageKHR(
      display_, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
      static_cast<ANativeWindowBuffer*>(native_buffer_.get()), nullptr);
  if (!image_) {
    ALOGE("Failed to create EGLImage\n");
    return false;
  }

  glGenTextures(1, &texture_id_);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, texture_id_);
  glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, image_);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  CHECK_GL();
  return true;
}

Compositor::RenderTarget::RenderTarget()
    : buffer_texture_id_(0),
      buffer_framebuffer_id_(0),
      buffer_image_(nullptr) {}

Compositor::RenderTarget::~RenderTarget() { Destroy(); }

void Compositor::RenderTarget::Destroy() {
  glDeleteFramebuffers(1, &buffer_framebuffer_id_);
  glDeleteTextures(1, &buffer_texture_id_);
  eglDestroyImageKHR(eglGetDisplay(EGL_DEFAULT_DISPLAY), buffer_image_);
  buffer_texture_id_ = 0;
  buffer_framebuffer_id_ = 0;
  buffer_image_ = nullptr;
}

void Compositor::RenderTarget::Initialize(int width, int height) {
  LOG_ALWAYS_FATAL_IF(buffer_texture_id_ || buffer_framebuffer_id_ ||
                      buffer_image_);
  constexpr int usage = GRALLOC_USAGE_HW_FB | GRALLOC_USAGE_HW_COMPOSER |
                        GRALLOC_USAGE_HW_RENDER |
                        GRALLOC_USAGE_QCOM_FRAMEBUFFER_COMPRESSION;
  buffer_ = std::make_shared<IonBuffer>(width, height,
                                        HAL_PIXEL_FORMAT_RGBA_8888, usage);

  native_buffer_ = new NativeBuffer(buffer_);

  buffer_image_ = eglCreateImageKHR(
      eglGetDisplay(EGL_DEFAULT_DISPLAY), EGL_NO_CONTEXT,
      EGL_NATIVE_BUFFER_ANDROID,
      static_cast<ANativeWindowBuffer*>(native_buffer_.get()), nullptr);

  glGenTextures(1, &buffer_texture_id_);
  glBindTexture(GL_TEXTURE_2D, buffer_texture_id_);
  CHECK_GL();

  glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, buffer_image_);
  CHECK_GL();

  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glBindTexture(GL_TEXTURE_2D, 0);

  // Generate a framebuffer.
  glGenFramebuffers(1, &buffer_framebuffer_id_);
  glBindFramebuffer(GL_FRAMEBUFFER, buffer_framebuffer_id_);
  CHECK_GL();

  // Attach the color buffer
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         buffer_texture_id_, 0);
  CHECK_GL();
  GLenum result = glCheckFramebufferStatus(GL_FRAMEBUFFER);
  CHECK_GL();
  if (result != GL_FRAMEBUFFER_COMPLETE) {
    ALOGE("Framebuffer incomplete: %d", result);
  }

  // Clear the render target to black once. In direct render mode we never draw
  // the corner pixels.
  glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
  glClear(GL_COLOR_BUFFER_BIT);
  glFlush();

  glBindFramebuffer(GL_FRAMEBUFFER, 0);
  CHECK_GL();
}

void Compositor::RenderTarget::BindFramebuffer() {
  glBindFramebuffer(GL_FRAMEBUFFER, buffer_framebuffer_id_);
}

void Compositor::RenderTarget::DiscardColorAttachment() {
  GLenum attachment = GL_COLOR_ATTACHMENT0;
  glDiscardFramebufferEXT(GL_FRAMEBUFFER, 1, &attachment);
  CHECK_GL();
}

class Compositor::RenderPoseBufferObject {
 public:
  RenderPoseBufferObject(LocalHandle&& render_pose_buffer_fd) :
      fd_(std::move(render_pose_buffer_fd)) {
    // Create new pose tracking buffer for this surface.
    glGenBuffers(1, &render_pose_buffer_object_);
    glBindBuffer(GL_UNIFORM_BUFFER, render_pose_buffer_object_);
    if (fd_) {
      LOG_ALWAYS_FATAL_IF(!glBindSharedBufferQCOM);
      if (glBindSharedBufferQCOM)
        glBindSharedBufferQCOM(GL_UNIFORM_BUFFER,
                               sizeof(DisplaySurfaceMetadata),
                               fd_.Get());
      else
        ALOGE("Error: Missing gralloc buffer extension");
      CHECK_GL();
    }
    glBindBuffer(GL_UNIFORM_BUFFER, 0);
  }

  ~RenderPoseBufferObject() { glDeleteBuffers(1, &render_pose_buffer_object_); }

  GLuint object_id() const { return render_pose_buffer_object_; }

 private:
  // Render pose buffer object. This contains an array of poses that corresponds
  // with the surface buffers.
  GLuint render_pose_buffer_object_;
  LocalHandle fd_;

  RenderPoseBufferObject(const RenderPoseBufferObject&) = delete;
  void operator=(const RenderPoseBufferObject&) = delete;
};

HeadMountMetrics CreateDefaultHeadMountMetrics() {
  const bool enable_distortion =
      property_get_bool(kDisableLensDistortionProp, 0) == 0;
  return enable_distortion ? CreateHeadMountMetrics()
                           : CreateUndistortedHeadMountMetrics();
}

Compositor::Compositor()
    : head_mount_metrics_(CreateDefaultHeadMountMetrics()),
      display_(0),
      config_(0),
      surface_(0),
      context_(0),
      active_render_target_(0),
      is_render_direct_(false),
      compute_fbo_(0),
      compute_fbo_texture_(0),
      hmd_metrics_requires_update_(false),
      eds_pose_capture_enabled_(false) {}

Compositor::~Compositor() {}

bool Compositor::Initialize(const DisplayMetrics& display_metrics) {
  ATRACE_NAME("Compositor::Initialize");
  if (!InitializeEGL())
    return false;

  display_metrics_ = display_metrics;
  const int width = display_metrics_.GetSizePixels().x();
  const int height = display_metrics_.GetSizePixels().y();

  render_target_[0].Initialize(width, height);
  render_target_[1].Initialize(width, height);

  // EDS:
  GpuProfiler::Get()->SetEnableGpuTracing(true);

  eds_pose_capture_enabled_ = property_get_bool(kEnableEdsPoseSaveProp, 0) == 1;

  CheckAndUpdateHeadMountMetrics(true);

  debug_hud_.reset(new DebugHudView(*composite_hmd_.get()));
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

  return true;
}

void Compositor::UpdateHeadMountMetrics(
    const HeadMountMetrics& head_mount_metrics) {
  // Recalculating the mesh must be done in the draw loop, defer until then.
  std::lock_guard<std::mutex> _lock(mutex_);
  head_mount_metrics_ = head_mount_metrics;
  hmd_metrics_requires_update_ = true;
}

void Compositor::CheckAndUpdateHeadMountMetrics(bool force_update) {
  std::lock_guard<std::mutex> _lock(mutex_);
  if (hmd_metrics_requires_update_ || force_update) {
    hmd_metrics_requires_update_ = false;
    composite_hmd_.reset(
        new CompositeHmd(head_mount_metrics_, display_metrics_));
    CHECK_GL();
    eds_renderer_.reset(new DistortionRenderer(
        *composite_hmd_.get(), display_metrics_.GetSizePixels(),
        kDistortionMeshResolution, true, false, false, true, true));
  }
}

bool Compositor::InitializeEGL() {
  ATRACE_NAME("Compositor::InitializeEGL");
  display_ = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (!display_) {
    ALOGE("Failed to get egl display\n");
    return false;
  }

  eglInitialize(display_, nullptr, nullptr);

  EGLint attribs[] = {
      EGL_BUFFER_SIZE,
      32,
      EGL_ALPHA_SIZE,
      0,
      EGL_BLUE_SIZE,
      8,
      EGL_RED_SIZE,
      8,
      EGL_GREEN_SIZE,
      8,
      EGL_DEPTH_SIZE,
      0,
      EGL_SURFACE_TYPE,
      EGL_WINDOW_BIT,
      EGL_RENDERABLE_TYPE,
      EGL_OPENGL_ES2_BIT,
      EGL_NONE,
  };

  EGLint num_configs;
  if (!eglChooseConfig(display_, attribs, &config_, 1, &num_configs)) {
    ALOGE("Couldn't find config");
    return false;
  }

  std::unique_ptr<DummyNativeWindow> window(new DummyNativeWindow());

  surface_ = eglCreateWindowSurface(display_, config_, window.get(), nullptr);
  if (surface_ == EGL_NO_SURFACE) {
    ALOGE("Failed to create egl surface");
    return false;
  }
  window.release();

  EGLint context_attribs[] = {EGL_CONTEXT_MAJOR_VERSION,
                              3,
                              EGL_CONTEXT_MINOR_VERSION,
                              1,
                              EGL_CONTEXT_PRIORITY_LEVEL_IMG,
                              EGL_CONTEXT_PRIORITY_HIGH_IMG,
                              EGL_NONE};
  context_ = eglCreateContext(display_, config_, nullptr, context_attribs);
  if (!eglMakeCurrent(display_, surface_, surface_, context_)) {
    ALOGE("Unable to create GLESv2 context");
    return false;
  }

  load_gl_extensions();
  GpuProfiler::Get()->OnGlContextCreated();

  glEnable(BINNING_CONTROL_HINT_QCOM);
  glHint(BINNING_CONTROL_HINT_QCOM, RENDER_DIRECT_TO_FRAMEBUFFER_QCOM);
  is_render_direct_ = true;
  CHECK_GL();

  // Initialize the placeholder 1x1 framebuffer that we bind during compute
  // shader instances to avoid accesses to other framebuffers.
  glGenFramebuffers(1, &compute_fbo_);
  glGenTextures(1, &compute_fbo_texture_);
  glBindFramebuffer(GL_FRAMEBUFFER, compute_fbo_);
  glBindTexture(GL_TEXTURE_2D, compute_fbo_texture_);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE,
               nullptr);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         compute_fbo_texture_, 0);
  CHECK_GL();
  CHECK_GL_FBO();
  glBindTexture(GL_TEXTURE_2D, 0);
  glBindFramebuffer(GL_FRAMEBUFFER, 0);

  return true;
}

void Compositor::Shutdown() {
  glFinish();
  render_target_[0].Destroy();
  render_target_[1].Destroy();
  layers_.clear();
  glDeleteFramebuffers(1, &compute_fbo_);
  glDeleteTextures(1, &compute_fbo_texture_);

  debug_hud_.reset();
  eds_renderer_.reset();

  if (context_) {
    GpuProfiler::Get()->OnGlContextDestroyed();
    eglDestroyContext(display_, context_);
    context_ = 0;
  }

  if (surface_ != EGL_NO_SURFACE) {
    eglDestroySurface(display_, surface_);
    surface_ = EGL_NO_SURFACE;
  }
}

void Compositor::RemoveAllBuffers() { layers_.clear(); }

void Compositor::UpdateSurfaces(
    const std::vector<std::shared_ptr<DisplaySurface>>& surfaces) {
  // Delete the removed surfaces.
  layers_.erase(
      std::remove_if(layers_.begin(), layers_.end(),
                     [&surfaces](const AppFrame& layer) {
                       for (const auto& surface : surfaces)
                         if (surface->surface_id() == layer.surface_id())
                           return false;
                       return true;
                     }),
      layers_.end());
  // New surfaces are added on-demand as buffers are posted.
}

Compositor::AppFrame::AppFrame()
    : surface_id_(-1),
      blur_(0.0f),
      z_order_(0),
      vertical_flip_(false),
      enable_cac_(true),
      render_buffer_index_(0) {}

Compositor::AppFrame::~AppFrame() {}

const Compositor::Texture* Compositor::AppFrame::GetGlTextureId(
    EGLDisplay display, int index) {
  auto buffer_consumer = buffer_.buffer();
  if (!buffer_consumer) {
    return nullptr;
  }
  auto texture_it = std::find_if(
      textures_.begin(), textures_.end(),
      [buffer_consumer, index](const std::shared_ptr<Texture>& t) {
        return t->consumer() == buffer_consumer && t->index() == index;
      });

  if (texture_it != textures_.end()) {
    return (*texture_it).get();
  }

  textures_.push_back(
      std::make_shared<Texture>(buffer_consumer, display, index));
  if (!textures_.back()->Initialize()) {
    textures_.pop_back();
    return nullptr;
  }
  return textures_.back().get();
}

bool Compositor::AppFrame::UpdateSurface(
    const std::shared_ptr<DisplaySurface>& surface) {
  int surface_id = surface->surface_id();
  float blur = surface->manager_blur();
  bool need_sort = false;
  if (z_order_ != surface->layer_order()) {
    need_sort = true;
    z_order_ = surface->layer_order();
  }

  surface_id_ = surface_id;
  if (!render_pose_buffer_object_) {
    render_pose_buffer_object_.reset(
        new RenderPoseBufferObject(surface->GetMetadataBufferFd()));
  }

  blur_ = blur;
  vertical_flip_ =
      !!(surface->flags() & DVR_DISPLAY_SURFACE_FLAGS_VERTICAL_FLIP);
  enable_cac_ =
      !(surface->flags() & DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_CAC);

  AcquiredBuffer skipped_buffer;
  AcquiredBuffer buffer =
      surface->AcquireNewestAvailableBuffer(&skipped_buffer);
  if (!skipped_buffer.IsEmpty()) {
    DebugHudData::data.SkipLayerFrame(z_order_);
    ATRACE_NAME("DropToCatchUp");
    ATRACE_ASYNC_END("BufferPost", skipped_buffer.buffer()->id());
  }
  if (!buffer.IsEmpty()) {
    DebugHudData::data.AddLayerFrame(z_order_);
    // Buffer was already ready, so we don't need to wait on the fence.
    buffer.ClaimAcquireFence().Close();
    ATRACE_ASYNC_END("BufferPost", buffer.buffer()->id());

    render_buffer_index_ = surface->GetRenderBufferIndex(buffer.buffer()->id());

#ifdef TRACE
    const volatile DisplaySurfaceMetadata* data =
        surface->GetMetadataBufferPtr();
#endif
    ALOGE_IF(TRACE, "read pose index %d %f %f", render_buffer_index_,
             data->orientation[render_buffer_index_][0],
             data->orientation[render_buffer_index_][1]);

    // Move the new buffer over the old. AcquiredBuffer releases the old one.
    buffer_ = std::move(buffer);
  }
  return need_sort;
}

void Compositor::AppFrame::UpdateVideoMeshSurface(
    const std::shared_ptr<DisplaySurface>& surface) {
  // Update |video_compositors_| with |video_surface|. Note that
  // |UpdateVideoMeshSurface| should only be called on the PostThread before
  // |DrawFrame| is called. Thus, no synchronization is required for
  // |video_compositors_|.
  if (!surface->video_mesh_surfaces_updated())
    return;

  // TODO(jwcai) The following loop handles adding new surfaces; video mesh
  // removal logic shall be handled by listening to |OnChannelClose| event from
  // DisplayService.
  for (const auto& video_surface : surface->GetVideoMeshSurfaces()) {
    // Here we assume number of |video_surface|s is relatively small, thus, the
    // merge should be efficient enough.
    auto video_compositor_it = std::find_if(
        video_compositors_.begin(), video_compositors_.end(),
        [video_surface](const std::shared_ptr<VideoCompositor>& c) {
          return c->surface_id() == video_surface->surface_id();
        });

    if (video_compositor_it == video_compositors_.end()) {
      // This video surface is new, create a new VideoCompositor.
      video_compositors_.push_back(std::make_shared<VideoCompositor>(
          video_surface, surface->GetMetadataBufferPtr()));
    } else {
      // There is a compositor in |video_compositors_| is already set up for
      // this |video_surface|.
      ALOGW("Duplicated video_mesh_surface: surface_id=%d",
            video_surface->surface_id());
    }
  }
}

void Compositor::AppFrame::ResetBlurrers() { blurrers_.clear(); }

void Compositor::AppFrame::AddBlurrer(Blur* blurrer) {
  blurrers_.emplace_back(blurrer);
}

void Compositor::PostBuffer(const std::shared_ptr<DisplaySurface>& surface) {
  int surface_id = surface->surface_id();

  ALOGD_IF(TRACE, "Post surface %d", surface_id);

  auto layer_it = std::find_if(layers_.begin(), layers_.end(),
                               [surface_id](const AppFrame& frame) {
                                 return frame.surface_id() == surface_id;
                               });

  bool need_sort = false;
  if (layer_it == layers_.end()) {
    layers_.push_back(AppFrame());
    layer_it = layers_.end() - 1;
    need_sort = true;
  }

  need_sort |= layer_it->UpdateSurface(surface);
  layer_it->UpdateVideoMeshSurface(surface);

  if (need_sort) {
    std::stable_sort(layers_.begin(), layers_.end());
  }
}

std::vector<uint8_t> Compositor::ReadLayerPixels(size_t index, int* width,
                                                 int* height) {
  if (index >= layers_.size()) {
    return {};
  }

  const Texture* texture = layers_[index].GetGlTextureId(display_, 0);
  if (!texture) {
    return {};
  }

  *width = texture->size()[0];
  *height = texture->size()[1];
  return ReadTextureRGBA(texture->texture_id(), *width, *height);
}

std::vector<uint8_t> Compositor::ReadBufferPixels(const IonBuffer* buffer) {
  android::sp<TemporaryNativeBuffer> native_buffer =
      new TemporaryNativeBuffer(buffer);

  // Finish to make sure the GL driver has completed drawing of prior FBOs.
  // Since we are creating an EGL image here, the driver will not know that
  // there is a dependency on earlier GL draws.
  glFinish();

  EGLImageKHR image = eglCreateImageKHR(
      display_, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
      static_cast<ANativeWindowBuffer*>(native_buffer.get()), nullptr);
  if (!image) {
    ALOGE("Failed to create EGLImage\n");
    return {};
  }

  GLuint texture_id;
  glGenTextures(1, &texture_id);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, texture_id);
  glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, image);

  int width = buffer->width();
  int height = buffer->height();
  std::vector<uint8_t> data = ReadTextureRGBA(texture_id, width, height);

  glBindTexture(GL_TEXTURE_2D, 0);
  glDeleteTextures(1, &texture_id);
  eglDestroyImageKHR(display_, image);
  return data;
}

bool Compositor::DrawFrame(uint32_t target_vsync_count,
                           LocalHandle* buffer_fence_fd) {
  CheckAndUpdateHeadMountMetrics(false);

  ATRACE_NAME("Compositor::DrawFrame");
  GpuProfiler::Get()->PollGlTimerQueries();

  if (buffer_fence_fd)
    buffer_fence_fd->Close();

  int num_layers = 0;
  const int kMaxLayers = 4;
  GLuint texture_id[2][kMaxLayers] = {{0}};
  GLuint render_pose_buffer_id[kMaxLayers] = {0};
  uint32_t render_buffer_index[kMaxLayers] = {0};
  bool vertical_flip[kMaxLayers] = {false};
  bool separate_eye_textures[kMaxLayers] = {false};
  bool enable_cac[kMaxLayers] = {};
  CHECK_GL();
  for (auto& layer : layers_) {
    if (!layer.buffer().buffer()) {
      ATRACE_NAME("no_buffer");
      continue;
    }

    // Extract surface parameters.
    render_buffer_index[num_layers] = layer.render_buffer_index();
    render_pose_buffer_id[num_layers] =
        layer.render_pose_buffer_object()->object_id();
    vertical_flip[num_layers] = layer.vertical_flip();
    enable_cac[num_layers] =
        head_mount_metrics_.supports_chromatic_aberration_correction() &&
        layer.enable_cac();

    // Extract per-eye textures. These may be separate or joined (atlased).
    vec2i size(0, 0);
    int view_count = layer.buffer().buffer()->slice_count();
    ALOGE_IF(view_count > 2, "Error: more than 2 views not supported");
    view_count = std::min(2, view_count);
    separate_eye_textures[num_layers] = (view_count > 1);
    bool is_missing_texture = false;
    for (int eye = 0; eye < 2; ++eye) {
      // If view_count is 1, each eye texture is the 0th.
      int view_index = (view_count == 2) ? eye : 0;
      const Texture* texture = layer.GetGlTextureId(display_, view_index);
      // Texture will be null if the EGL image creation fails (hopefully never).
      if (!texture) {
        is_missing_texture = true;
        break;
      }
      // All views are currently expected to have the same size.
      size = texture->size();
      texture_id[eye][num_layers] = texture->texture_id();
    }
    if (is_missing_texture) {
      continue;
    }

    // Perform blur if requested.
    if (fabs(layer.blur()) > 0.001f) {
      // No need for CAC on blurred layers.
      enable_cac[num_layers] = false;
      if (layer.blurrer_count() < 1 || layer.blurrer(0)->width() != size[0] ||
          layer.blurrer(0)->height() != size[1]) {
        // Blur is created with the left eye texture, but the same instance
        // can be used for the right eye as well.
        layer.ResetBlurrers();
        layer.AddBlurrer(new Blur(size[0], size[1], texture_id[0][num_layers],
                                  GL_TEXTURE_2D, GL_TEXTURE_2D, true, display_,
                                  view_count));
      }
      // Reset blur instances to prepare for drawing.
      layer.blurrer(0)->StartFrame();
      layer.blurrer(0)->set_scale(layer.blur());
      // Perform blur and replace source texture with blurred output texture.
      if (view_count == 1) {
        // Single wide buffer for both eyes, blur both eyes in one operation.
        texture_id[0][num_layers] = texture_id[1][num_layers] =
            layer.blurrer(0)->DrawBlur(texture_id[0][num_layers]);
      } else {
        // Split eye buffers in a single frame, blur each framebuffer.
        texture_id[0][num_layers] =
            layer.blurrer(0)->DrawBlur(texture_id[0][num_layers]);
        texture_id[1][num_layers] =
            layer.blurrer(0)->DrawBlur(texture_id[1][num_layers]);
      }
    }

    ++num_layers;
    if (num_layers >= kMaxLayers)
      break;
  }

  CHECK_GL();
  // Set appropriate binning mode for the number of layers.
  if (num_layers > 1 && is_render_direct_) {
    is_render_direct_ = false;
    glDisable(BINNING_CONTROL_HINT_QCOM);
  } else if (num_layers <= 1 && !is_render_direct_) {
    is_render_direct_ = true;
    glEnable(BINNING_CONTROL_HINT_QCOM);
    glHint(BINNING_CONTROL_HINT_QCOM, RENDER_DIRECT_TO_FRAMEBUFFER_QCOM);
  }

  // Workaround for GL driver bug that causes the currently bound FBO to be
  // accessed during a compute shader pass (DoLateLatch below). Based on an
  // analysis with systrace, the best pattern here was to run the compute shader
  // with a *different* FBO than what will be drawn to afterward. So we bind
  // a dummy 1x1 FBO here and discard it. If instead, the current render target
  // is bound during the compute shader, the following draw calls will be forced
  // into direct mode rendering.
  glBindFramebuffer(GL_FRAMEBUFFER, compute_fbo_);
  GLenum attachment = GL_COLOR_ATTACHMENT0;
  glDiscardFramebufferEXT(GL_FRAMEBUFFER, 1, &attachment);

  // Double buffer the render target.  Get the render target we're drawing into,
  // and update the active buffer to the next buffer.
  RenderTarget& render_target = GetRenderTarget();
  SetNextRenderTarget();

  if (num_layers > 0) {
    // This trace prints the EDS+Warp GPU overhead and prints every 5 seconds:
    TRACE_GPU_PRINT("GPU EDS+Warp", 5 * 60);
    CHECK_GL();
    eds_renderer_->DoLateLatch(target_vsync_count, render_buffer_index,
                               render_pose_buffer_id, vertical_flip,
                               separate_eye_textures, num_layers);

    render_target.BindFramebuffer();

    // Discard to avoid unresolving the framebuffer during tiled rendering.
    render_target.DiscardColorAttachment();

    // For tiled mode rendering, we clear every frame to avoid garbage showing
    // up in the parts of tiles that are not rendered.
    if (!is_render_direct_) {
      glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
      glClear(GL_COLOR_BUFFER_BIT);
    }

    for (int eye = kLeftEye; eye <= kRightEye; ++eye) {
      eds_renderer_->PrepGlState(static_cast<EyeType>(eye));
      for (int layer_i = 0; layer_i < num_layers; ++layer_i) {
        bool blend_with_previous = layer_i > 0;
        uint32_t current_buffer_index = render_buffer_index[layer_i];

        // Render video mesh in the background of each graphics layer.
        layers_[layer_i].ForEachVideoCompositor([this, eye, layer_i,
                                                 current_buffer_index,
                                                 &blend_with_previous](
            const std::shared_ptr<VideoCompositor>& video_compositor) mutable {
          eds_renderer_->DrawVideoQuad(
              static_cast<EyeType>(eye), layer_i,
              video_compositor->GetActiveTextureId(display_),
              video_compositor->GetTransform(eye, current_buffer_index));
          blend_with_previous = true;
        });

        // Apply distortion to frame submitted from the app's GL context.
        eds_renderer_->SetChromaticAberrationCorrectionEnabled(
            enable_cac[layer_i]);
        eds_renderer_->ApplyDistortionCorrectionToTexture(
            static_cast<EyeType>(eye), &texture_id[eye][layer_i],
            &vertical_flip[layer_i], &separate_eye_textures[layer_i], &layer_i,
            1, blend_with_previous, false);
      }
    }
    eds_renderer_->ResetGlState(1);
    CHECK_GL();
  } else {
    ALOGI("No buffers for compositing, clearing to black.");
    render_target.BindFramebuffer();
    glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
    glClear(GL_COLOR_BUFFER_BIT);
  }

  debug_hud_->Update();
  debug_hud_->Draw();

  LocalHandle fence_fd = CreateGLSyncAndFlush(display_);

  if (buffer_fence_fd)
    *buffer_fence_fd = std::move(fence_fd);

  if (eds_pose_capture_enabled_) {
    std::lock_guard<std::mutex> _lock(mutex_);
    eds_renderer_->GetLastEdsPose(&eds_pose_capture_);
  }

  return true;
}

bool Compositor::GetLastEdsPose(LateLatchOutput* out_data) {
  if (eds_pose_capture_enabled_) {
    std::lock_guard<std::mutex> _lock(mutex_);
    *out_data = eds_pose_capture_;
    return true;
  } else {
    ALOGE("Eds pose capture is not enabled.");
    return false;
  }
}

}  // namespace dvr
}  // namespace android
