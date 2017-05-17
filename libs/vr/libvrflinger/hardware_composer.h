#ifndef ANDROID_DVR_SERVICES_DISPLAYD_HARDWARE_COMPOSER_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_HARDWARE_COMPOSER_H_

#include <ui/GraphicBuffer.h>
#include "DisplayHardware/ComposerHal.h"
#include "hwc_types.h"

#include <hardware/gralloc.h>
#include <log/log.h>

#include <array>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <tuple>
#include <vector>

#include <dvr/pose_client.h>
#include <pdx/file_handle.h>
#include <pdx/rpc/variant.h>
#include <private/dvr/buffer_hub_client.h>

#include "acquired_buffer.h"
#include "display_surface.h"

// Hardware composer HAL doesn't define HWC_TRANSFORM_NONE as of this writing.
#ifndef HWC_TRANSFORM_NONE
#define HWC_TRANSFORM_NONE static_cast<hwc_transform_t>(0)
#endif

namespace android {
namespace dvr {

// Basic display metrics for physical displays. Dimensions and densities are
// relative to the physical display orientation, which may be different from the
// logical display orientation exposed to applications.
struct HWCDisplayMetrics {
  int width;
  int height;
  struct {
    int x;
    int y;
  } dpi;
  int vsync_period_ns;
};

// Layer represents the connection between a hardware composer layer and the
// source supplying buffers for the layer's contents.
class Layer {
 public:
  Layer() {}

  // Sets up the global state used by all Layer instances. This must be called
  // before using any Layer methods.
  static void InitializeGlobals(Hwc2::Composer* hwc2_hidl,
                                const HWCDisplayMetrics* metrics);

  // Releases any shared pointers and fence handles held by this instance.
  void Reset();

  // Sets up the layer to use a display surface as its content source. The Layer
  // automatically handles ACQUIRE/RELEASE phases for the surface's buffer train
  // every frame.
  //
  // |blending| receives HWC_BLENDING_* values.
  // |transform| receives HWC_TRANSFORM_* values.
  // |composition_type| receives either HWC_FRAMEBUFFER for most layers or
  // HWC_FRAMEBUFFER_TARGET (unless you know what you are doing).
  // |index| is the index of this surface in the DirectDisplaySurface array.
  void Setup(const std::shared_ptr<DirectDisplaySurface>& surface,
             HWC::BlendMode blending, HWC::Transform transform,
             HWC::Composition composition_type, size_t z_roder);

  // Sets up the layer to use a direct buffer as its content source. No special
  // handling of the buffer is performed; responsibility for updating or
  // changing the buffer each frame is on the caller.
  //
  // |blending| receives HWC_BLENDING_* values.
  // |transform| receives HWC_TRANSFORM_* values.
  // |composition_type| receives either HWC_FRAMEBUFFER for most layers or
  // HWC_FRAMEBUFFER_TARGET (unless you know what you are doing).
  void Setup(const std::shared_ptr<IonBuffer>& buffer, HWC::BlendMode blending,
             HWC::Transform transform, HWC::Composition composition_type,
             size_t z_order);

  // Layers that use a direct IonBuffer should call this each frame to update
  // which buffer will be used for the next PostLayers.
  void UpdateBuffer(const std::shared_ptr<IonBuffer>& buffer);

  // Sets up the hardware composer layer for the next frame. When the layer is
  // associated with a display surface, this method automatically ACQUIRES a new
  // buffer if one is available.
  void Prepare();

  // After calling prepare, if this frame is to be dropped instead of passing
  // along to the HWC, call Drop to close the contained fence(s).
  void Drop();

  // Performs fence bookkeeping after the frame has been posted to hardware
  // composer.
  void Finish(int release_fence_fd);

  // Sets the blending for the layer. |blending| receives HWC_BLENDING_* values.
  void SetBlending(HWC::BlendMode blending);

  // Sets the z-order of this layer
  void SetZOrder(size_t z_order);

  // Gets the current IonBuffer associated with this layer. Ownership of the
  // buffer DOES NOT pass to the caller and the pointer is not guaranteed to
  // remain valid across calls to Layer::Setup(), Layer::Prepare(), or
  // Layer::Reset(). YOU HAVE BEEN WARNED.
  IonBuffer* GetBuffer();

  HWC::Composition GetCompositionType() const { return composition_type_; }
  HWC::Layer GetLayerHandle() const { return hardware_composer_layer_; }
  bool IsLayerSetup() const { return !source_.empty(); }

  // Applies all of the settings to this layer using the hwc functions
  void UpdateLayerSettings();

  int GetSurfaceId() const {
    int surface_id = -1;
    pdx::rpc::IfAnyOf<SourceSurface>::Call(
        &source_, [&surface_id](const SourceSurface& surface_source) {
          surface_id = surface_source.surface->surface_id();
        });
    return surface_id;
  }

 private:
  void CommonLayerSetup();

  static Hwc2::Composer* hwc2_hidl_;
  static const HWCDisplayMetrics* display_metrics_;

  // The hardware composer layer and metrics to use during the prepare cycle.
  hwc2_layer_t hardware_composer_layer_ = 0;

  // Layer properties used to setup the hardware composer layer during the
  // Prepare phase.
  size_t z_order_ = 0;
  HWC::BlendMode blending_ = HWC::BlendMode::None;
  HWC::Transform transform_ = HWC::Transform::None;
  HWC::Composition composition_type_ = HWC::Composition::Invalid;
  HWC::Composition target_composition_type_ = HWC::Composition::Device;

  // State when the layer is connected to a surface. Provides the same interface
  // as SourceBuffer to simplify internal use by Layer.
  struct SourceSurface {
    std::shared_ptr<DirectDisplaySurface> surface;
    AcquiredBuffer acquired_buffer;
    pdx::LocalHandle release_fence;

    SourceSurface(const std::shared_ptr<DirectDisplaySurface>& surface)
        : surface(surface) {}

    // Attempts to acquire a new buffer from the surface and return a tuple with
    // width, height, buffer handle, and fence. If a new buffer is not available
    // the previous buffer is returned or an empty value if no buffer has ever
    // been posted. When a new buffer is acquired the previous buffer's release
    // fence is passed out automatically.
    std::tuple<int, int, sp<GraphicBuffer>, pdx::LocalHandle> Acquire() {
      if (surface->IsBufferAvailable()) {
        acquired_buffer.Release(std::move(release_fence));
        acquired_buffer = surface->AcquireCurrentBuffer();
        ATRACE_ASYNC_END("BufferPost", acquired_buffer.buffer()->id());
      }
      if (!acquired_buffer.IsEmpty()) {
        return std::make_tuple(acquired_buffer.buffer()->width(),
                               acquired_buffer.buffer()->height(),
                               acquired_buffer.buffer()->buffer()->buffer(),
                               acquired_buffer.ClaimAcquireFence());
      } else {
        return std::make_tuple(0, 0, nullptr, pdx::LocalHandle{});
      }
    }

    void Finish(pdx::LocalHandle fence) { release_fence = std::move(fence); }

    // Gets a pointer to the current acquired buffer or returns nullptr if there
    // isn't one.
    IonBuffer* GetBuffer() {
      if (acquired_buffer.IsAvailable())
        return acquired_buffer.buffer()->buffer();
      else
        return nullptr;
    }

    // Returns the surface id of the surface.
    int GetSurfaceId() { return surface->surface_id(); }
  };

  // State when the layer is connected to a buffer. Provides the same interface
  // as SourceSurface to simplify internal use by Layer.
  struct SourceBuffer {
    std::shared_ptr<IonBuffer> buffer;

    std::tuple<int, int, sp<GraphicBuffer>, pdx::LocalHandle> Acquire() {
      if (buffer)
        return std::make_tuple(buffer->width(), buffer->height(),
                               buffer->buffer(), pdx::LocalHandle{});
      else
        return std::make_tuple(0, 0, nullptr, pdx::LocalHandle{});
    }

    void Finish(pdx::LocalHandle /*fence*/) {}

    IonBuffer* GetBuffer() { return buffer.get(); }

    int GetSurfaceId() const { return -1; }
  };

  // The underlying hardware composer layer is supplied buffers either from a
  // surface buffer train or from a buffer directly.
  pdx::rpc::Variant<SourceSurface, SourceBuffer> source_;

  pdx::LocalHandle acquire_fence_;
  bool surface_rect_functions_applied_ = false;

  Layer(const Layer&) = delete;
  void operator=(const Layer&) = delete;
};

// HardwareComposer encapsulates the hardware composer HAL, exposing a
// simplified API to post buffers to the display.
//
// HardwareComposer is accessed by both the vr flinger dispatcher thread and the
// surface flinger main thread, in addition to internally running a separate
// thread for compositing/EDS and posting layers to the HAL. When changing how
// variables are used or adding new state think carefully about which threads
// will access the state and whether it needs to be synchronized.
class HardwareComposer {
 public:
  // Type for vsync callback.
  using VSyncCallback = std::function<void(int, int64_t, int64_t, uint32_t)>;
  using RequestDisplayCallback = std::function<void(bool)>;

  // Since there is no universal way to query the number of hardware layers,
  // just set it to 4 for now.
  static constexpr size_t kMaxHardwareLayers = 4;

  HardwareComposer();
  HardwareComposer(Hwc2::Composer* hidl,
                   RequestDisplayCallback request_display_callback);
  ~HardwareComposer();

  bool Initialize();

  bool IsInitialized() const { return initialized_; }

  // Start the post thread if there's work to do (i.e. visible layers). This
  // should only be called from surface flinger's main thread.
  void Enable();
  // Pause the post thread, blocking until the post thread has signaled that
  // it's paused. This should only be called from surface flinger's main thread.
  void Disable();

  // Get the HMD display metrics for the current display.
  display::Metrics GetHmdDisplayMetrics() const;

  HWC::Error GetDisplayAttribute(hwc2_display_t display, hwc2_config_t config,
                                 hwc2_attribute_t attributes,
                                 int32_t* out_value) const;
  HWC::Error GetDisplayMetrics(hwc2_display_t display, hwc2_config_t config,
                               HWCDisplayMetrics* out_metrics) const;
  std::string Dump();

  void SetVSyncCallback(VSyncCallback callback);

  // Metrics of the logical display, which is always landscape.
  int DisplayWidth() const { return display_metrics_.width; }
  int DisplayHeight() const { return display_metrics_.height; }
  HWCDisplayMetrics display_metrics() const { return display_metrics_; }

  // Metrics of the native display, which depends on the specific hardware
  // implementation of the display.
  HWCDisplayMetrics native_display_metrics() const {
    return native_display_metrics_;
  }

  // Sets the display surfaces to compose the hardware layer stack.
  void SetDisplaySurfaces(
      std::vector<std::shared_ptr<DirectDisplaySurface>> surfaces);

  void OnHardwareComposerRefresh();

 private:
  int32_t EnableVsync(bool enabled);

  class ComposerCallback : public Hwc2::IComposerCallback {
   public:
    ComposerCallback() {}

    hardware::Return<void> onHotplug(Hwc2::Display /*display*/,
                                     Connection /*connected*/) override {
      // TODO(skiazyk): depending on how the server is implemented, we might
      // have to set it up to synchronize with receiving this event, as it can
      // potentially be a critical event for setting up state within the
      // hwc2 module. That is, we (technically) should not call any other hwc
      // methods until this method has been called after registering the
      // callbacks.
      return hardware::Void();
    }

    hardware::Return<void> onRefresh(Hwc2::Display /*display*/) override {
      return hardware::Void();
    }

    hardware::Return<void> onVsync(Hwc2::Display /*display*/,
                                   int64_t /*timestamp*/) override {
      return hardware::Void();
    }
  };

  HWC::Error Validate(hwc2_display_t display);
  HWC::Error Present(hwc2_display_t display);

  void SetBacklightBrightness(int brightness);

  void PostLayers();
  void PostThread();

  // The post thread has two controlling states:
  // 1. Idle: no work to do (no visible surfaces).
  // 2. Suspended: explicitly halted (system is not in VR mode).
  // When either #1 or #2 is true then the post thread is quiescent, otherwise
  // it is active.
  using PostThreadStateType = uint32_t;
  struct PostThreadState {
    enum : PostThreadStateType {
      Active = 0,
      Idle = (1 << 0),
      Suspended = (1 << 1),
      Quit = (1 << 2),
    };
  };

  void UpdatePostThreadState(uint32_t state, bool suspend);

  // Blocks until either event_fd becomes readable, or we're interrupted by a
  // control thread. Any errors are returned as negative errno values. If we're
  // interrupted, kPostThreadInterrupted will be returned.
  int PostThreadPollInterruptible(const pdx::LocalHandle& event_fd,
                                  int requested_events);

  // BlockUntilVSync, WaitForVSync, and SleepUntil are all blocking calls made
  // on the post thread that can be interrupted by a control thread. If
  // interrupted, these calls return kPostThreadInterrupted.
  int ReadWaitPPState();
  int BlockUntilVSync();
  int ReadVSyncTimestamp(int64_t* timestamp);
  int WaitForVSync(int64_t* timestamp);
  int SleepUntil(int64_t wakeup_timestamp);

  bool IsFramePendingInDriver() { return ReadWaitPPState() == 1; }

  // Reconfigures the layer stack if the display surfaces changed since the last
  // frame. Called only from the post thread.
  bool UpdateLayerConfig();

  // Called on the post thread when the post thread is resumed.
  void OnPostThreadResumed();
  // Called on the post thread when the post thread is paused or quits.
  void OnPostThreadPaused();

  bool initialized_;

  // Hardware composer HAL device from SurfaceFlinger. VrFlinger does not own
  // this pointer.
  Hwc2::Composer* hwc2_hidl_;
  RequestDisplayCallback request_display_callback_;
  sp<ComposerCallback> callbacks_;

  // Display metrics of the physical display.
  HWCDisplayMetrics native_display_metrics_;
  // Display metrics of the logical display, adjusted so that orientation is
  // landscape.
  HWCDisplayMetrics display_metrics_;
  // Transform required to get from native to logical display orientation.
  HWC::Transform display_transform_ = HWC::Transform::None;

  // Pending surface list. Set by the display service when DirectSurfaces are
  // added, removed, or change visibility. Written by the message dispatch
  // thread and read by the post thread.
  std::vector<std::shared_ptr<DirectDisplaySurface>> pending_surfaces_;

  // The surfaces displayed by the post thread. Used exclusively by the post
  // thread.
  std::vector<std::shared_ptr<DirectDisplaySurface>> display_surfaces_;

  // Layer array for handling buffer flow into hardware composer layers.
  std::array<Layer, kMaxHardwareLayers> layers_;
  size_t active_layer_count_ = 0;

  // Handler to hook vsync events outside of this class.
  VSyncCallback vsync_callback_;

  // The layer posting thread. This thread wakes up a short time before vsync to
  // hand buffers to hardware composer.
  std::thread post_thread_;

  // Post thread state machine and synchronization primitives.
  PostThreadStateType post_thread_state_{PostThreadState::Idle};
  std::atomic<bool> post_thread_quiescent_{true};
  bool post_thread_resumed_{false};
  pdx::LocalHandle post_thread_event_fd_;
  std::mutex post_thread_mutex_;
  std::condition_variable post_thread_wait_;
  std::condition_variable post_thread_ready_;

  // Backlight LED brightness sysfs node.
  pdx::LocalHandle backlight_brightness_fd_;

  // Primary display vsync event sysfs node.
  pdx::LocalHandle primary_display_vsync_event_fd_;

  // Primary display wait_pingpong state sysfs node.
  pdx::LocalHandle primary_display_wait_pp_fd_;

  // VSync sleep timerfd.
  pdx::LocalHandle vsync_sleep_timer_fd_;

  // The timestamp of the last vsync.
  int64_t last_vsync_timestamp_ = 0;

  // Vsync count since display on.
  uint32_t vsync_count_ = 0;

  // Counter tracking the number of skipped frames.
  int frame_skip_count_ = 0;

  // Fd array for tracking retire fences that are returned by hwc. This allows
  // us to detect when the display driver begins queuing frames.
  std::vector<pdx::LocalHandle> retire_fence_fds_;

  // Pose client for frame count notifications. Pose client predicts poses
  // out to display frame boundaries, so we need to tell it about vsyncs.
  DvrPose* pose_client_ = nullptr;

  static constexpr int kPostThreadInterrupted = 1;

  static void HwcRefresh(hwc2_callback_data_t data, hwc2_display_t display);
  static void HwcVSync(hwc2_callback_data_t data, hwc2_display_t display,
                       int64_t timestamp);
  static void HwcHotplug(hwc2_callback_data_t callbackData,
                         hwc2_display_t display, hwc2_connection_t connected);

  HardwareComposer(const HardwareComposer&) = delete;
  void operator=(const HardwareComposer&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_HARDWARE_COMPOSER_H_
