#ifndef ANDROID_DVR_SERVICES_DISPLAYD_HARDWARE_COMPOSER_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_HARDWARE_COMPOSER_H_

#include <log/log.h>
#include <hardware/gralloc.h>
#include <hardware/hardware.h>
#include <hardware/hwcomposer2.h>

#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/sync_util.h>

#include <array>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <tuple>
#include <vector>

#include <pdx/file_handle.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/frame_time_history.h>
#include <private/dvr/sync_util.h>

#include "acquired_buffer.h"
#include "compositor.h"
#include "display_surface.h"

#include "DisplayHardware/ComposerHal.h"

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
  Layer();

  // Sets the hardware composer layer and display metrics that this Layer should
  // use each Prepare cycle. This class does not own either of these pointers,
  // which MUST remain valid for its lifetime. This method MUST be called once
  // in the life of the instance before any other method is valid to call.
  void Initialize(Hwc2::Composer* hwc2_hidl, HWCDisplayMetrics* metrics);

  // Releases any shared pointers and fence handles held by this instance.
  void Reset();

  // Sets up the layer to use a display surface as its content source. The Layer
  // will automatically handle ACQUIRE/RELEASE phases for the surface's buffer
  // train every frame.
  //
  // |blending| receives HWC_BLENDING_* values.
  // |transform| receives HWC_TRANSFORM_* values.
  // |composition_type| receives either HWC_FRAMEBUFFER for most layers or
  // HWC_FRAMEBUFFER_TARGET (unless you know what you are doing).
  // |index| is the index of this surface in the DisplaySurface array.
  void Setup(const std::shared_ptr<DisplaySurface>& surface,
             hwc2_blend_mode_t blending, hwc_transform_t transform,
             hwc2_composition_t composition_type, size_t index);

  // Sets up the layer to use a direct buffer as its content source. No special
  // handling of the buffer is performed; responsibility for updating or
  // changing the buffer each frame is on the caller.
  //
  // |blending| receives HWC_BLENDING_* values.
  // |transform| receives HWC_TRANSFORM_* values.
  // |composition_type| receives either HWC_FRAMEBUFFER for most layers or
  // HWC_FRAMEBUFFER_TARGET (unless you know what you are doing).
  void Setup(const std::shared_ptr<IonBuffer>& buffer,
             hwc2_blend_mode_t blending, hwc_transform_t transform,
             hwc2_composition_t composition_type, size_t z_order);

  // Layers that use a direct IonBuffer should call this each frame to update
  // which buffer will be used for the next PostLayers.
  void UpdateDirectBuffer(const std::shared_ptr<IonBuffer>& buffer);

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
  void SetBlending(hwc2_blend_mode_t blending);

  // Sets the Z-order of this layer
  void SetZOrderIndex(int surface_index);

  // Gets the current IonBuffer associated with this layer. Ownership of the
  // buffer DOES NOT pass to the caller and the pointer is not guaranteed to
  // remain valid across calls to Layer::Setup(), Layer::Prepare(), or
  // Layer::Reset(). YOU HAVE BEEN WARNED.
  IonBuffer* GetBuffer();

  hwc2_composition_t GetCompositionType() const { return composition_type_; }

  hwc2_layer_t GetLayerHandle() const { return hardware_composer_layer_; }

  bool UsesDirectBuffer() const { return direct_buffer_ != nullptr; }

  bool IsLayerSetup() const {
    return direct_buffer_ != nullptr || surface_ != nullptr;
  }

  // Applies all of the settings to this layer using the hwc functions
  void UpdateLayerSettings();

  int GetSurfaceId() const {
    if (surface_ != nullptr) {
      return surface_->surface_id();
    } else {
      return -1;
    }
  }

 private:
  void CommonLayerSetup();

  Hwc2::Composer* hwc2_hidl_;

  // Original display surface array index for tracking purposes.
  size_t surface_index_;

  // The hardware composer layer and metrics to use during the prepare cycle.
  hwc2_layer_t hardware_composer_layer_;
  HWCDisplayMetrics* display_metrics_;

  // Layer properties used to setup the hardware composer layer during the
  // Prepare phase.
  hwc2_blend_mode_t blending_;
  hwc_transform_t transform_;
  hwc2_composition_t composition_type_;

  // These two members are mutually exclusive. When direct_buffer_ is set the
  // Layer gets its contents directly from that buffer; when surface_ is set the
  // Layer gets it contents from the surface's buffer train.
  std::shared_ptr<IonBuffer> direct_buffer_;
  std::shared_ptr<DisplaySurface> surface_;

  // State when associated with a display surface.
  AcquiredBuffer acquired_buffer_;
  pdx::LocalHandle release_fence_;

  pdx::LocalHandle acquire_fence_fd_;
  bool surface_rect_functions_applied_;

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

  // Since there is no universal way to query the number of hardware layers,
  // just set it to 4 for now.
  static constexpr int kMaxHardwareLayers = 4;

  HardwareComposer();
  HardwareComposer(Hwc2::Composer* hidl);
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
  DisplayMetrics GetHmdDisplayMetrics() const;

  int32_t GetDisplayAttribute(hwc2_display_t display, hwc2_config_t config,
                              hwc2_attribute_t attributes,
                              int32_t* out_value) const;
  int32_t GetDisplayMetrics(hwc2_display_t display, hwc2_config_t config,
                            HWCDisplayMetrics* out_metrics) const;
  void Dump(char* buffer, uint32_t* out_size);

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

  // Set the display surface stack to compose to the display each frame.
  void SetDisplaySurfaces(
      std::vector<std::shared_ptr<DisplaySurface>> surfaces);

  Compositor* GetCompositor() { return &compositor_; }

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

  int32_t Validate(hwc2_display_t display);
  int32_t Present(hwc2_display_t display);

  void SetBacklightBrightness(int brightness);

  void PostLayers(bool is_geometry_changed);
  void PostThread();

  // Check to see if we have a value written to post_thread_interrupt_event_fd_,
  // indicating a control thread interrupted the post thread. This clears the
  // post_thread_interrupt_event_fd_ state in the process. Returns true if an
  // interrupt was requested.
  bool CheckPostThreadInterruptEventFd();
  // Blocks until either event_fd becomes readable, or we're interrupted by a
  // control thread. Any errors are returned as negative errno values. If we're
  // interrupted, kPostThreadInterrupted will be returned.
  int PostThreadPollInterruptible(int event_fd, int requested_events);

  // BlockUntilVSync, WaitForVSync, and SleepUntil are all blocking calls made
  // on the post thread that can be interrupted by a control thread. If
  // interrupted, these calls return kPostThreadInterrupted.
  int ReadWaitPPState();
  int BlockUntilVSync();
  int ReadVSyncTimestamp(int64_t* timestamp);
  int WaitForVSync(int64_t* timestamp);
  int SleepUntil(int64_t wakeup_timestamp);

  bool IsFramePendingInDriver() { return ReadWaitPPState() == 1; }

  // Returns true if the layer config changed, false otherwise
  bool UpdateLayerConfig();
  void PostCompositorBuffers();

  // Return true if the post thread has work to do (i.e. there are visible
  // surfaces to post to the screen). Must be called with post_thread_mutex_
  // locked. Called only from the post thread.
  bool PostThreadHasWork();

  // Called on the post thread when the post thread is resumed.
  void OnPostThreadResumed();
  // Called on the post thread when the post thread is paused or quits.
  void OnPostThreadPaused();

  struct FrameTimeMeasurementRecord {
    int64_t start_time;
    pdx::LocalHandle fence;

    FrameTimeMeasurementRecord(FrameTimeMeasurementRecord&&) = default;
    FrameTimeMeasurementRecord& operator=(FrameTimeMeasurementRecord&&) =
        default;
    FrameTimeMeasurementRecord(const FrameTimeMeasurementRecord&) = delete;
    FrameTimeMeasurementRecord& operator=(const FrameTimeMeasurementRecord&) =
        delete;
  };

  void UpdateFrameTimeHistory(std::vector<FrameTimeMeasurementRecord>* backlog,
                              int backlog_max,
                              FenceInfoBuffer* fence_info_buffer,
                              FrameTimeHistory* history);

  // Returns true if the frame finished rendering, false otherwise. If the frame
  // finished the frame end time is stored in timestamp. Doesn't block.
  bool CheckFrameFinished(int frame_fence_fd,
                          FenceInfoBuffer* fence_info_buffer,
                          int64_t* timestamp);

  void HandlePendingScreenshots();

  bool initialized_;

  // Hardware composer HAL device.
  std::unique_ptr<Hwc2::Composer> hwc2_hidl_;
  sp<ComposerCallback> callbacks_;

  // Display metrics of the physical display.
  HWCDisplayMetrics native_display_metrics_;
  // Display metrics of the logical display, adjusted so that orientation is
  // landscape.
  HWCDisplayMetrics display_metrics_;
  // Transform required to get from native to logical display orientation.
  hwc_transform_t display_transform_;

  // Buffer for the background layer required by hardware composer.
  std::shared_ptr<IonBuffer> framebuffer_target_;

  // Protects access to variables used by the post thread and one of the control
  // threads (either the vr flinger dispatcher thread or the surface flinger
  // main thread). This includes active_surfaces_, active_surfaces_updated_,
  // post_thread_enabled_, post_thread_running_, and
  // post_thread_quit_requested_.
  std::mutex post_thread_mutex_;

  // Surfaces configured by the display manager. Written by the vr flinger
  // dispatcher thread, read by the post thread.
  std::vector<std::shared_ptr<DisplaySurface>> active_surfaces_;
  // active_surfaces_updated_ is set to true by the vr flinger dispatcher thread
  // when the list of active surfaces changes. active_surfaces_updated_ will be
  // set back to false by the post thread when it processes the update.
  bool active_surfaces_updated_;

  // The surfaces displayed by the post thread. Used exclusively by the post
  // thread.
  std::vector<std::shared_ptr<DisplaySurface>> display_surfaces_;

  // The surfaces rendered by the compositor. Used exclusively by the post
  // thread.
  std::vector<std::shared_ptr<DisplaySurface>> compositor_surfaces_;

  // Layer array for handling buffer flow into hardware composer layers.
  // Note that the first array is the actual storage for the layer objects,
  // and the latter is an array of pointers, which can be freely re-arranged
  // without messing up the underlying objects.
  std::array<Layer, kMaxHardwareLayers> layer_storage_;
  std::array<Layer*, kMaxHardwareLayers> layers_;
  size_t active_layer_count_;

  // Set by the Post thread to the index of the GPU compositing output
  // buffer in the layers_ array.
  Layer* gpu_layer_;

  // Handler to hook vsync events outside of this class.
  VSyncCallback vsync_callback_;

  // The layer posting thread. This thread wakes up a short time before vsync to
  // hand buffers to post processing and the results to hardware composer.
  std::thread post_thread_;

  // Set to true if the post thread is allowed to run. Surface flinger and vr
  // flinger share access to the display, and vr flinger shouldn't use the
  // display while surface flinger is using it. While surface flinger owns the
  // display, post_thread_enabled_ will be set to false to indicate the post
  // thread shouldn't run.
  bool post_thread_enabled_;
  // Set to true by the post thread if it's currently running.
  bool post_thread_running_;
  // Set to true if the post thread should quit. Only set when destroying the
  // HardwareComposer instance.
  bool post_thread_quit_requested_;
  // Used to wake the post thread up while it's waiting for vsync or sleeping
  // until EDS preemption, for faster transition to the paused state.
  pdx::LocalHandle post_thread_interrupt_event_fd_;
  // Used to communicate between the control thread and the post thread.
  std::condition_variable post_thread_cond_var_;

  // Backlight LED brightness sysfs node.
  pdx::LocalHandle backlight_brightness_fd_;

  // Primary display vsync event sysfs node.
  pdx::LocalHandle primary_display_vsync_event_fd_;

  // Primary display wait_pingpong state sysfs node.
  pdx::LocalHandle primary_display_wait_pp_fd_;

  // VSync sleep timerfd.
  pdx::LocalHandle vsync_sleep_timer_fd_;

  // The timestamp of the last vsync.
  int64_t last_vsync_timestamp_;

  // Vsync count since display on.
  uint32_t vsync_count_;

  // Counter tracking the number of skipped frames.
  int frame_skip_count_;

  // After construction, only accessed on post_thread_.
  Compositor compositor_;

  // Fd array for tracking retire fences that are returned by hwc. This allows
  // us to detect when the display driver begins queuing frames.
  std::vector<pdx::LocalHandle> retire_fence_fds_;

  // Pose client for frame count notifications. Pose client predicts poses
  // out to display frame boundaries, so we need to tell it about vsyncs.
  DvrPose* pose_client_;

  // Our history of frame times. This is used to get a better estimate of how
  // long the next frame will take, to set a schedule for EDS.
  FrameTimeHistory frame_time_history_;

  // The backlog is used to allow us to start rendering the next frame before
  // the previous frame has finished, and still get an accurate measurement of
  // frame duration.
  std::vector<FrameTimeMeasurementRecord> frame_time_backlog_;

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
