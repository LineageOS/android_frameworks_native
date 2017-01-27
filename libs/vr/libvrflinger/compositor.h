#ifndef ANDROID_DVR_SERVICES_DISPLAYD_COMPOSITOR_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_COMPOSITOR_H_

#include <EGL/egl.h>
#include <log/log.h>
#include <utils/StrongPointer.h>

#include <memory>
#include <mutex>
#include <queue>
#include <vector>

#include <pdx/file_handle.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/composite_hmd.h>
#include <private/dvr/display_metrics.h>
#include <private/dvr/distortion_renderer.h>
#include <private/dvr/frame_time_history.h>
#include <private/dvr/ion_buffer.h>
#include <private/dvr/native_buffer.h>

#include "acquired_buffer.h"
#include "video_compositor.h"
struct DvrPose;

namespace android {
namespace dvr {

class Blur;
class BufferConsumer;
class CompositeHmd;
class DebugHudView;
class DisplaySurface;

// This is a GPU compositor for software EDS and lens warp on buffers provided
// by HardwareComposer.
class Compositor {
 public:
  Compositor();
  ~Compositor();

  bool Initialize(const DisplayMetrics& display_metrics);
  void UpdateHeadMountMetrics(const HeadMountMetrics& head_mount_metrics);
  void Shutdown();

  // Renders a frame with the latest buffers with EDS and warp applied.
  // buffer_fence_fd can be used to get a fence for the rendered frame. It can
  // be set to null if the fence isn't needed.
  bool DrawFrame(uint32_t target_vsync_count,
                 pdx::LocalHandle* buffer_fence_fd);

  // Remove all buffers.
  void RemoveAllBuffers();

  // Synchronize compositor layers with in given surfaces.
  void UpdateSurfaces(
      const std::vector<std::shared_ptr<DisplaySurface>>& surfaces);

  // This must be called for each surface before DrawFrame is called.
  void PostBuffer(const std::shared_ptr<DisplaySurface>& surface);

  std::shared_ptr<IonBuffer> GetBuffer() const {
    return render_target_[active_render_target_].buffer();
  }

  // Returns the number of layers being rendered by the compositor.
  size_t GetLayerCount() const { return layers_.size(); }

  // Returns the source buffer at the given layer index or nullptr if none is
  // available.
  std::shared_ptr<BufferConsumer> PeekAtLayer(size_t index) const {
    if (index >= GetLayerCount())
      return nullptr;
    return layers_[index].buffer().buffer();
  }

  // Expensive operation to transfer the pixels of the given layer index into
  // unformatted memory and return as a RGBA buffer.
  // On success, returns non-zero sized vector and sets width and height.
  // On failure, returns empty vector.
  std::vector<uint8_t> ReadLayerPixels(size_t index, int* width, int* height);

  // Expensive operation to transfer the pixels of the given buffer into
  // unformatted memory and return as a RGBA buffer.
  // On success, returns non-zero sized vector.
  // On failure, returns empty vector.
  std::vector<uint8_t> ReadBufferPixels(const IonBuffer* buffer);

  bool GetLastEdsPose(LateLatchOutput* out_data);

  const HeadMountMetrics& head_mount_metrics() const {
    return head_mount_metrics_;
  }

 private:
  class Texture;
  class RenderPoseBufferObject;

  // A rendered frame from an application.
  class AppFrame {
   public:
    AppFrame();
    ~AppFrame();

    AppFrame(AppFrame&& other) = default;
    AppFrame& operator=(AppFrame&&) = default;

    // Gets a GL texture object for the current buffer. The resulting texture
    // object will be cached for future calls. Returns a pointer for temporary
    // access - not meant to hold on to.
    const Texture* GetGlTextureId(EGLDisplay display, int index);

    bool operator<(const AppFrame& rhs) const {
      return z_order_ < rhs.z_order_;
    }
    int z_order() const { return z_order_; }
    // Return true if this surface z order has been changed.
    bool UpdateSurface(const std::shared_ptr<DisplaySurface>& surface);
    void UpdateVideoMeshSurface(const std::shared_ptr<DisplaySurface>& surface);
    void ResetBlurrers();
    void AddBlurrer(Blur* blurrer);

    const AcquiredBuffer& buffer() const { return buffer_; }
    int surface_id() const { return surface_id_; }
    float blur() const { return blur_; }
    bool vertical_flip() const { return vertical_flip_; }
    bool enable_cac() const { return enable_cac_; }
    size_t blurrer_count() const { return blurrers_.size(); }
    Blur* blurrer(size_t i) {
      return blurrers_.size() < i ? nullptr : blurrers_[i].get();
    }
    uint32_t render_buffer_index() const { return render_buffer_index_; }
    const RenderPoseBufferObject* render_pose_buffer_object() const {
      return render_pose_buffer_object_.get();
    }

    template <class A>
    void ForEachVideoCompositor(A action) const {
      for (auto& c : video_compositors_) {
        action(c);
      }
    }

   private:
    int surface_id_;
    float blur_;
    int z_order_;
    bool vertical_flip_;
    bool enable_cac_;
    std::vector<std::unique_ptr<Blur>> blurrers_;
    AcquiredBuffer buffer_;
    std::vector<std::shared_ptr<Texture>> textures_;
    uint32_t render_buffer_index_;
    std::unique_ptr<RenderPoseBufferObject> render_pose_buffer_object_;

    // Active video mesh compositors
    std::vector<std::shared_ptr<VideoCompositor>> video_compositors_;

    AppFrame(const AppFrame& other) = delete;
    AppFrame& operator=(const AppFrame&) = delete;
  };

  class RenderTarget {
   public:
    RenderTarget();
    ~RenderTarget();

    void Initialize(int width, int height);
    void Destroy();
    void BindFramebuffer();
    void DiscardColorAttachment();

    std::shared_ptr<IonBuffer> buffer() const { return buffer_; }

   private:
    std::shared_ptr<IonBuffer> buffer_;
    android::sp<NativeBuffer> native_buffer_;

    GLuint buffer_texture_id_;
    GLuint buffer_framebuffer_id_;
    EGLImageKHR buffer_image_;
  };

  Compositor(const Compositor&) = delete;
  void operator=(const Compositor&) = delete;

  bool InitializeEGL();

  void UpdateHudToggle();
  void PrintStatsHud();
  void CheckAndUpdateHeadMountMetrics(bool force_update);

  RenderTarget& GetRenderTarget() {
    return render_target_[active_render_target_];
  }

  void SetNextRenderTarget() {
    active_render_target_ = (active_render_target_ + 1) & 1;
  }

  std::vector<AppFrame> layers_;

  DisplayMetrics display_metrics_;
  HeadMountMetrics head_mount_metrics_;

  EGLDisplay display_;
  EGLConfig config_;
  EGLSurface surface_;
  EGLContext context_;
  int active_render_target_;
  RenderTarget render_target_[2];
  bool is_render_direct_;

  // FBO for compute shader.
  GLuint compute_fbo_;
  GLuint compute_fbo_texture_;

  std::unique_ptr<DebugHudView> debug_hud_;

  // EDS:
  std::unique_ptr<CompositeHmd> composite_hmd_;
  bool hmd_metrics_requires_update_;
  std::unique_ptr<DistortionRenderer> eds_renderer_;

  bool eds_pose_capture_enabled_;
  std::mutex mutex_;
  LateLatchOutput eds_pose_capture_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_COMPOSITOR_H_
