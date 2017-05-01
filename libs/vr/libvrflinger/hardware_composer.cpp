#include "hardware_composer.h"

#include <log/log.h>
#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <fcntl.h>
#include <poll.h>
#include <sync/sync.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/system_properties.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <utils/Trace.h>

#include <algorithm>
#include <functional>
#include <map>

#include <dvr/performance_client_api.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/display_types.h>
#include <private/dvr/pose_client_internal.h>
#include <private/dvr/sync_util.h>

#include "debug_hud_data.h"
#include "screenshot_service.h"

using android::pdx::LocalHandle;

namespace android {
namespace dvr {

namespace {

// If the number of pending fences goes over this count at the point when we
// are about to submit a new frame to HWC, we will drop the frame. This should
// be a signal that the display driver has begun queuing frames. Note that with
// smart displays (with RAM), the fence is signaled earlier than the next vsync,
// at the point when the DMA to the display completes. Currently we use a smart
// display and the EDS timing coincides with zero pending fences, so this is 0.
constexpr int kAllowedPendingFenceCount = 0;

// If we think we're going to miss vsync by more than this amount, skip the
// frame.
constexpr int64_t kFrameSkipThresholdNs = 4000000;  // 4ms

// Counter PostLayers() deficiency by requiring apps to produce a frame at least
// 2.5ms before vsync. See b/28881672.
constexpr int64_t kFrameTimeEstimateMin = 2500000;  // 2.5ms

constexpr size_t kDefaultDisplayConfigCount = 32;

constexpr float kMetersPerInch = 0.0254f;

const char kBacklightBrightnessSysFile[] =
    "/sys/class/leds/lcd-backlight/brightness";

const char kPrimaryDisplayVSyncEventFile[] =
    "/sys/class/graphics/fb0/vsync_event";

const char kPrimaryDisplayWaitPPEventFile[] = "/sys/class/graphics/fb0/wait_pp";

const char kDvrPerformanceProperty[] = "sys.dvr.performance";

const char kRightEyeOffsetProperty[] = "dvr.right_eye_offset_ns";

// Returns our best guess for the time the compositor will spend rendering the
// next frame.
int64_t GuessFrameTime(int compositor_visible_layer_count) {
  // The cost of asynchronous EDS and lens warp is currently measured at 2.5ms
  // for one layer and 7ms for two layers, but guess a higher frame time to
  // account for CPU overhead. This guess is only used before we've measured the
  // actual time to render a frame for the current compositor configuration.
  switch (compositor_visible_layer_count) {
    case 0:
      return 500000;  // .5ms
    case 1:
      return 5000000;  // 5ms
    default:
      return 10500000;  // 10.5ms
  }
}

// Get time offset from a vsync to when the pose for that vsync should be
// predicted out to. For example, if scanout gets halfway through the frame
// at the halfway point between vsyncs, then this could be half the period.
// With global shutter displays, this should be changed to the offset to when
// illumination begins. Low persistence adds a frame of latency, so we predict
// to the center of the next frame.
inline int64_t GetPosePredictionTimeOffset(int64_t vsync_period_ns) {
  return (vsync_period_ns * 150) / 100;
}

}  // anonymous namespace

HardwareComposer::HardwareComposer()
  : HardwareComposer(nullptr) {
}

HardwareComposer::HardwareComposer(Hwc2::Composer* hwc2_hidl)
    : initialized_(false),
      hwc2_hidl_(hwc2_hidl),
      display_transform_(HWC_TRANSFORM_NONE),
      active_surfaces_updated_(false),
      active_layer_count_(0),
      gpu_layer_(nullptr),
      post_thread_enabled_(false),
      post_thread_running_(false),
      post_thread_quit_requested_(false),
      post_thread_interrupt_event_fd_(-1),
      backlight_brightness_fd_(-1),
      primary_display_vsync_event_fd_(-1),
      primary_display_wait_pp_fd_(-1),
      vsync_sleep_timer_fd_(-1),
      last_vsync_timestamp_(0),
      vsync_count_(0),
      frame_skip_count_(0),
      pose_client_(nullptr) {
  std::transform(layer_storage_.begin(), layer_storage_.end(), layers_.begin(),
                 [](auto& layer) { return &layer; });

  callbacks_ = new ComposerCallback;
}

HardwareComposer::~HardwareComposer(void) {
  std::unique_lock<std::mutex> lock(post_thread_mutex_);
  if (post_thread_.joinable()) {
    post_thread_quit_requested_ = true;
    post_thread_cond_var_.notify_all();
    post_thread_.join();
  }
}

bool HardwareComposer::Initialize() {
  if (initialized_) {
    ALOGE("HardwareComposer::Initialize: already initialized.");
    return false;
  }

  int32_t ret = HWC2_ERROR_NONE;

  Hwc2::Config config;
  ret = (int32_t)hwc2_hidl_->getActiveConfig(HWC_DISPLAY_PRIMARY, &config);

  if (ret != HWC2_ERROR_NONE) {
    ALOGE("HardwareComposer: Failed to get current display config : %d",
          config);
    return false;
  }

  ret =
      GetDisplayMetrics(HWC_DISPLAY_PRIMARY, config, &native_display_metrics_);

  if (ret != HWC2_ERROR_NONE) {
    ALOGE(
        "HardwareComposer: Failed to get display attributes for current "
        "configuration : %d",
        ret);
    return false;
  }

  ALOGI(
      "HardwareComposer: primary display attributes: width=%d height=%d "
      "vsync_period_ns=%d DPI=%dx%d",
      native_display_metrics_.width, native_display_metrics_.height,
      native_display_metrics_.vsync_period_ns, native_display_metrics_.dpi.x,
      native_display_metrics_.dpi.y);

  // Set the display metrics but never use rotation to avoid the long latency of
  // rotation processing in hwc.
  display_transform_ = HWC_TRANSFORM_NONE;
  display_metrics_ = native_display_metrics_;

  post_thread_interrupt_event_fd_.Reset(
      eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
  LOG_ALWAYS_FATAL_IF(
      !post_thread_interrupt_event_fd_,
      "HardwareComposer: Failed to create interrupt event fd : %s",
      strerror(errno));

  post_thread_ = std::thread(&HardwareComposer::PostThread, this);

  initialized_ = true;

  return initialized_;
}

void HardwareComposer::Enable() {
  std::lock_guard<std::mutex> lock(post_thread_mutex_);
  post_thread_enabled_ = true;
  post_thread_cond_var_.notify_all();
}

void HardwareComposer::Disable() {
  std::unique_lock<std::mutex> lock(post_thread_mutex_);
  post_thread_enabled_ = false;
  if (post_thread_running_) {
    // Write to the interrupt fd to get fast interrupt of the post thread
    int error = eventfd_write(post_thread_interrupt_event_fd_.Get(), 1);
    ALOGW_IF(error,
             "HardwareComposer::Disable: could not write post "
             "thread interrupt event fd : %s",
             strerror(errno));

    post_thread_cond_var_.wait(lock, [this] { return !post_thread_running_; });

    // Read the interrupt fd to clear its state
    uint64_t interrupt_count= 0;
    error = eventfd_read(post_thread_interrupt_event_fd_.Get(),
                         &interrupt_count);
    ALOGW_IF(error,
             "HardwareComposer::Disable: could not read post "
             "thread interrupt event fd : %s",
             strerror(errno));
  }
}

bool HardwareComposer::PostThreadHasWork() {
  return !display_surfaces_.empty() ||
      (active_surfaces_updated_ && !active_surfaces_.empty());
}

void HardwareComposer::OnPostThreadResumed() {
  constexpr int format = HAL_PIXEL_FORMAT_RGBA_8888;
  constexpr int usage =
      GRALLOC_USAGE_HW_FB | GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_RENDER;

  framebuffer_target_ = std::make_shared<IonBuffer>(
      native_display_metrics_.width, native_display_metrics_.height, format,
      usage);

  hwc2_hidl_->resetCommands();

  // Associate each Layer instance with a hardware composer layer.
  for (auto layer : layers_) {
    layer->Initialize(hwc2_hidl_.get(), &native_display_metrics_);
  }

  // Connect to pose service.
  pose_client_ = dvrPoseCreate();
  ALOGE_IF(!pose_client_, "HardwareComposer: Failed to create pose client");

  EnableVsync(true);

  // TODO(skiazyk): We need to do something about accessing this directly,
  // supposedly there is a backlight service on the way.
  // TODO(steventhomas): When we change the backlight setting, will surface
  // flinger (or something else) set it back to its original value once we give
  // control of the display back to surface flinger?
  SetBacklightBrightness(255);

  // Initialize the GPU compositor.
  LOG_ALWAYS_FATAL_IF(!compositor_.Initialize(GetHmdDisplayMetrics()),
                      "Failed to initialize the compositor");

  // Trigger target-specific performance mode change.
  property_set(kDvrPerformanceProperty, "performance");
}

void HardwareComposer::OnPostThreadPaused() {
  retire_fence_fds_.clear();
  gpu_layer_ = nullptr;

  // We have to destroy the layers to fully clear hwc device state before
  // handing off back to surface flinger
  for (size_t i = 0; i < kMaxHardwareLayers; ++i) {
    layers_[i]->Reset();
  }

  active_layer_count_ = 0;

  framebuffer_target_.reset();

  display_surfaces_.clear();
  compositor_surfaces_.clear();

  // Since we're clearing display_surfaces_ we'll need an update.
  active_surfaces_updated_ = true;

  if (pose_client_) {
    dvrPoseDestroy(pose_client_);
    pose_client_ = nullptr;
  }

  EnableVsync(false);

  frame_time_history_.ResetWithSeed(GuessFrameTime(0));
  frame_time_backlog_.clear();

  compositor_.Shutdown();

  hwc2_hidl_->resetCommands();

  // Trigger target-specific performance mode change.
  property_set(kDvrPerformanceProperty, "idle");
}

DisplayMetrics HardwareComposer::GetHmdDisplayMetrics() const {
  vec2i screen_size(display_metrics_.width, display_metrics_.height);
  DisplayOrientation orientation =
      (display_metrics_.width > display_metrics_.height
           ? DisplayOrientation::kLandscape
           : DisplayOrientation::kPortrait);
  float dpi_x = static_cast<float>(display_metrics_.dpi.x) / 1000.0f;
  float dpi_y = static_cast<float>(display_metrics_.dpi.y) / 1000.0f;
  float meters_per_pixel_x = kMetersPerInch / dpi_x;
  float meters_per_pixel_y = kMetersPerInch / dpi_y;
  vec2 meters_per_pixel(meters_per_pixel_x, meters_per_pixel_y);
  double frame_duration_s =
      static_cast<double>(display_metrics_.vsync_period_ns) / 1000000000.0;
  // TODO(hendrikw): Hard coding to 3mm.  The Pixel is actually 4mm, but it
  //                 seems that their tray to lens distance is wrong too, which
  //                 offsets this, at least for the pixel.
  float border_size = 0.003f;
  return DisplayMetrics(screen_size, meters_per_pixel, border_size,
                        static_cast<float>(frame_duration_s), orientation);
}

int32_t HardwareComposer::Validate(hwc2_display_t display) {
  uint32_t num_types;
  uint32_t num_requests;
  int32_t error =
      (int32_t)hwc2_hidl_->validateDisplay(display, &num_types, &num_requests);

  if (error == HWC2_ERROR_HAS_CHANGES) {
    // TODO(skiazyk): We might need to inspect the requested changes first, but
    // so far it seems like we shouldn't ever hit a bad state.
    // error = hwc2_funcs_.accept_display_changes_fn_(hardware_composer_device_,
    //                                               display);
    error = (int32_t)hwc2_hidl_->acceptDisplayChanges(display);
  }

  return error;
}

int32_t HardwareComposer::EnableVsync(bool enabled) {
  return (int32_t)hwc2_hidl_->setVsyncEnabled(
      HWC_DISPLAY_PRIMARY,
      (Hwc2::IComposerClient::Vsync)(enabled ? HWC2_VSYNC_ENABLE
                                             : HWC2_VSYNC_DISABLE));
}

int32_t HardwareComposer::Present(hwc2_display_t display) {
  int32_t present_fence;
  int32_t error = (int32_t)hwc2_hidl_->presentDisplay(display, &present_fence);

  // According to the documentation, this fence is signaled at the time of
  // vsync/DMA for physical displays.
  if (error == HWC2_ERROR_NONE) {
    ATRACE_INT("HardwareComposer: VsyncFence", present_fence);
    retire_fence_fds_.emplace_back(present_fence);
  } else {
    ATRACE_INT("HardwareComposer: PresentResult", error);
  }

  return error;
}

int32_t HardwareComposer::GetDisplayAttribute(hwc2_display_t display,
                                              hwc2_config_t config,
                                              hwc2_attribute_t attribute,
                                              int32_t* out_value) const {
  return (int32_t)hwc2_hidl_->getDisplayAttribute(
      display, config, (Hwc2::IComposerClient::Attribute)attribute, out_value);
}

int32_t HardwareComposer::GetDisplayMetrics(
    hwc2_display_t display, hwc2_config_t config,
    HWCDisplayMetrics* out_metrics) const {
  int32_t ret = HWC2_ERROR_NONE;

  ret = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_WIDTH,
                            &out_metrics->width);
  if (ret != HWC2_ERROR_NONE) {
    ALOGE("HardwareComposer: Failed to get display width");
    return ret;
  }

  ret = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_HEIGHT,
                            &out_metrics->height);
  if (ret != HWC2_ERROR_NONE) {
    ALOGE("HardwareComposer: Failed to get display height");
    return ret;
  }

  ret = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_VSYNC_PERIOD,
                            &out_metrics->vsync_period_ns);
  if (ret != HWC2_ERROR_NONE) {
    ALOGE("HardwareComposer: Failed to get display height");
    return ret;
  }

  ret = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_DPI_X,
                            &out_metrics->dpi.x);
  if (ret != HWC2_ERROR_NONE) {
    ALOGE("HardwareComposer: Failed to get display DPI X");
    return ret;
  }

  ret = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_DPI_Y,
                            &out_metrics->dpi.y);
  if (ret != HWC2_ERROR_NONE) {
    ALOGE("HardwareComposer: Failed to get display DPI Y");
    return ret;
  }

  return HWC2_ERROR_NONE;
}

void HardwareComposer::Dump(char* buffer, uint32_t* out_size) {
  std::string debug_str = hwc2_hidl_->dumpDebugInfo();
  ALOGI("%s", debug_str.c_str());

  if (buffer == nullptr) {
    *out_size = debug_str.size();
  } else {
    std::copy(debug_str.begin(), debug_str.begin() + *out_size, buffer);
  }
}

// TODO(skiazyk): Figure out what to do with `is_geometry_changed`. There does
// not seem to be any equivalent in the HWC2 API, but that doesn't mean its not
// there.
void HardwareComposer::PostLayers(bool /*is_geometry_changed*/) {
  ATRACE_NAME("HardwareComposer::PostLayers");

  // Setup the hardware composer layers with current buffers.
  for (size_t i = 0; i < active_layer_count_; i++) {
    layers_[i]->Prepare();
  }

  int32_t ret = Validate(HWC_DISPLAY_PRIMARY);
  if (ret) {
    ALOGE("HardwareComposer::Validate failed; ret=%d", ret);
    return;
  }

  // Now that we have taken in a frame from the application, we have a chance
  // to drop the frame before passing the frame along to HWC.
  // If the display driver has become backed up, we detect it here and then
  // react by skipping this frame to catch up latency.
  while (!retire_fence_fds_.empty() &&
         (!retire_fence_fds_.front() ||
          sync_wait(retire_fence_fds_.front().Get(), 0) == 0)) {
    // There are only 2 fences in here, no performance problem to shift the
    // array of ints.
    retire_fence_fds_.erase(retire_fence_fds_.begin());
  }

  const bool is_frame_pending = IsFramePendingInDriver();
  const bool is_fence_pending =
      retire_fence_fds_.size() > kAllowedPendingFenceCount;

  if (is_fence_pending || is_frame_pending) {
    ATRACE_INT("frame_skip_count", ++frame_skip_count_);

    ALOGW_IF(is_frame_pending, "Warning: frame already queued, dropping frame");
    ALOGW_IF(is_fence_pending,
             "Warning: dropping a frame to catch up with HWC (pending = %zd)",
             retire_fence_fds_.size());

    for (size_t i = 0; i < active_layer_count_; i++) {
      layers_[i]->Drop();
    }
    return;
  } else {
    // Make the transition more obvious in systrace when the frame skip happens
    // above.
    ATRACE_INT("frame_skip_count", 0);
  }

#if TRACE
  for (size_t i = 0; i < active_layer_count_; i++)
    ALOGI("HardwareComposer::PostLayers: dl[%zu] ctype=0x%08x", i,
          layers_[i]->GetCompositionType());
#endif

  ret = Present(HWC_DISPLAY_PRIMARY);
  if (ret) {
    ALOGE("HardwareComposer::Present failed; ret=%d", ret);
    return;
  }

  std::vector<Hwc2::Layer> out_layers;
  std::vector<int> out_fences;
  ret = (int32_t)hwc2_hidl_->getReleaseFences(HWC_DISPLAY_PRIMARY, &out_layers,
                                              &out_fences);
  uint32_t num_elements = out_layers.size();

  ALOGE_IF(ret, "HardwareComposer: GetReleaseFences failed; ret=%d", ret);

  // Perform post-frame bookkeeping. Unused layers are a no-op.
  for (size_t i = 0; i < num_elements; ++i) {
    for (size_t j = 0; j < active_layer_count_; ++j) {
      if (layers_[j]->GetLayerHandle() == out_layers[i]) {
        layers_[j]->Finish(out_fences[i]);
      }
    }
  }
}

void HardwareComposer::SetDisplaySurfaces(
    std::vector<std::shared_ptr<DisplaySurface>> surfaces) {
  ALOGI("HardwareComposer::SetDisplaySurfaces: surface count=%zd",
        surfaces.size());
  std::unique_lock<std::mutex> lock(post_thread_mutex_);
  active_surfaces_ = std::move(surfaces);
  active_surfaces_updated_ = true;
  if (post_thread_enabled_)
    post_thread_cond_var_.notify_all();
}

int HardwareComposer::PostThreadPollInterruptible(int event_fd,
                                                  int requested_events) {
  pollfd pfd[2] = {
      {
          .fd = event_fd,
          .events = static_cast<short>(requested_events),
          .revents = 0,
      },
      {
          .fd = post_thread_interrupt_event_fd_.Get(),
          .events = POLLPRI | POLLIN,
          .revents = 0,
      },
  };
  int ret, error;
  do {
    ret = poll(pfd, 2, -1);
    error = errno;
    ALOGW_IF(ret < 0,
             "HardwareComposer::PostThreadPollInterruptible: Error during "
             "poll(): %s (%d)",
             strerror(error), error);
  } while (ret < 0 && error == EINTR);

  if (ret < 0) {
    return -error;
  } else if (pfd[0].revents != 0) {
    return 0;
  } else if (pfd[1].revents != 0) {
    ALOGI("VrHwcPost thread interrupted");
    return kPostThreadInterrupted;
  } else {
    return 0;
  }
}

// Reads the value of the display driver wait_pingpong state. Returns 0 or 1
// (the value of the state) on success or a negative error otherwise.
// TODO(eieio): This is pretty driver specific, this should be moved to a
// separate class eventually.
int HardwareComposer::ReadWaitPPState() {
  // Gracefully handle when the kernel does not support this feature.
  if (!primary_display_wait_pp_fd_)
    return 0;

  const int wait_pp_fd = primary_display_wait_pp_fd_.Get();
  int ret, error;

  ret = lseek(wait_pp_fd, 0, SEEK_SET);
  if (ret < 0) {
    error = errno;
    ALOGE("HardwareComposer::ReadWaitPPState: Failed to seek wait_pp fd: %s",
          strerror(error));
    return -error;
  }

  char data = -1;
  ret = read(wait_pp_fd, &data, sizeof(data));
  if (ret < 0) {
    error = errno;
    ALOGE("HardwareComposer::ReadWaitPPState: Failed to read wait_pp state: %s",
          strerror(error));
    return -error;
  }

  switch (data) {
    case '0':
      return 0;
    case '1':
      return 1;
    default:
      ALOGE(
          "HardwareComposer::ReadWaitPPState: Unexpected value for wait_pp: %d",
          data);
      return -EINVAL;
  }
}

// Reads the timestamp of the last vsync from the display driver.
// TODO(eieio): This is pretty driver specific, this should be moved to a
// separate class eventually.
int HardwareComposer::ReadVSyncTimestamp(int64_t* timestamp) {
  const int event_fd = primary_display_vsync_event_fd_.Get();
  int ret, error;

  // The driver returns data in the form "VSYNC=<timestamp ns>".
  std::array<char, 32> data;
  data.fill('\0');

  // Seek back to the beginning of the event file.
  ret = lseek(event_fd, 0, SEEK_SET);
  if (ret < 0) {
    error = errno;
    ALOGE(
        "HardwareComposer::ReadVSyncTimestamp: Failed to seek vsync event fd: "
        "%s",
        strerror(error));
    return -error;
  }

  // Read the vsync event timestamp.
  ret = read(event_fd, data.data(), data.size());
  if (ret < 0) {
    error = errno;
    ALOGE_IF(
        error != EAGAIN,
        "HardwareComposer::ReadVSyncTimestamp: Error while reading timestamp: "
        "%s",
        strerror(error));
    return -error;
  }

  ret = sscanf(data.data(), "VSYNC=%" PRIu64,
               reinterpret_cast<uint64_t*>(timestamp));
  if (ret < 0) {
    error = errno;
    ALOGE(
        "HardwareComposer::ReadVSyncTimestamp: Error while parsing timestamp: "
        "%s",
        strerror(error));
    return -error;
  }

  return 0;
}

// Blocks until the next vsync event is signaled by the display driver.
// TODO(eieio): This is pretty driver specific, this should be moved to a
// separate class eventually.
int HardwareComposer::BlockUntilVSync() {
  return PostThreadPollInterruptible(primary_display_vsync_event_fd_.Get(),
                                     // There will be a POLLPRI event on vsync
                                     POLLPRI);
}

// Waits for the next vsync and returns the timestamp of the vsync event. If
// vsync already passed since the last call, returns the latest vsync timestamp
// instead of blocking. This method updates the last_vsync_timeout_ in the
// process.
//
// TODO(eieio): This is pretty driver specific, this should be moved to a
// separate class eventually.
int HardwareComposer::WaitForVSync(int64_t* timestamp) {
  int error;

  // Get the current timestamp and decide what to do.
  while (true) {
    int64_t current_vsync_timestamp;
    error = ReadVSyncTimestamp(&current_vsync_timestamp);
    if (error < 0 && error != -EAGAIN)
      return error;

    if (error == -EAGAIN) {
      // Vsync was turned off, wait for the next vsync event.
      error = BlockUntilVSync();
      if (error < 0 || error == kPostThreadInterrupted)
        return error;

      // Try again to get the timestamp for this new vsync interval.
      continue;
    }

    // Check that we advanced to a later vsync interval.
    if (TimestampGT(current_vsync_timestamp, last_vsync_timestamp_)) {
      *timestamp = last_vsync_timestamp_ = current_vsync_timestamp;
      return 0;
    }

    // See how close we are to the next expected vsync. If we're within 1ms,
    // sleep for 1ms and try again.
    const int64_t ns_per_frame = display_metrics_.vsync_period_ns;
    const int64_t threshold_ns = 1000000;

    const int64_t next_vsync_est = last_vsync_timestamp_ + ns_per_frame;
    const int64_t distance_to_vsync_est = next_vsync_est - GetSystemClockNs();

    if (distance_to_vsync_est > threshold_ns) {
      // Wait for vsync event notification.
      error = BlockUntilVSync();
      if (error < 0 || error == kPostThreadInterrupted)
        return error;
    } else {
      // Sleep for a short time (1 millisecond) before retrying.
      error = SleepUntil(GetSystemClockNs() + 1000000);
      if (error < 0 || error == kPostThreadInterrupted)
        return error;
    }
  }
}

int HardwareComposer::SleepUntil(int64_t wakeup_timestamp) {
  const int timer_fd = vsync_sleep_timer_fd_.Get();
  const itimerspec wakeup_itimerspec = {
      .it_interval = {.tv_sec = 0, .tv_nsec = 0},
      .it_value = NsToTimespec(wakeup_timestamp),
  };
  int ret =
      timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &wakeup_itimerspec, nullptr);
  int error = errno;
  if (ret < 0) {
    ALOGE("HardwareComposer::SleepUntil: Failed to set timerfd: %s",
          strerror(error));
    return -error;
  }

  return PostThreadPollInterruptible(timer_fd, POLLIN);
}

void HardwareComposer::PostThread() {
  // NOLINTNEXTLINE(runtime/int)
  prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("VrHwcPost"), 0, 0, 0);

  // Set the scheduler to SCHED_FIFO with high priority.
  int error = dvrSetSchedulerClass(0, "graphics:high");
  LOG_ALWAYS_FATAL_IF(
      error < 0,
      "HardwareComposer::PostThread: Failed to set scheduler class: %s",
      strerror(-error));
  error = dvrSetCpuPartition(0, "/system/performance");
  LOG_ALWAYS_FATAL_IF(
      error < 0,
      "HardwareComposer::PostThread: Failed to set cpu partition: %s",
      strerror(-error));

#if ENABLE_BACKLIGHT_BRIGHTNESS
  // TODO(hendrikw): This isn't required at the moment. It's possible that there
  //                 is another method to access this when needed.
  // Open the backlight brightness control sysfs node.
  backlight_brightness_fd_ = LocalHandle(kBacklightBrightnessSysFile, O_RDWR);
  ALOGW_IF(!backlight_brightness_fd_,
           "HardwareComposer: Failed to open backlight brightness control: %s",
           strerror(errno));
#endif // ENABLE_BACKLIGHT_BRIGHTNESS

  // Open the vsync event node for the primary display.
  // TODO(eieio): Move this into a platform-specific class.
  primary_display_vsync_event_fd_ =
      LocalHandle(kPrimaryDisplayVSyncEventFile, O_RDONLY);
  ALOGE_IF(!primary_display_vsync_event_fd_,
           "HardwareComposer: Failed to open vsync event node for primary "
           "display: %s",
           strerror(errno));

  // Open the wait pingpong status node for the primary display.
  // TODO(eieio): Move this into a platform-specific class.
  primary_display_wait_pp_fd_ =
      LocalHandle(kPrimaryDisplayWaitPPEventFile, O_RDONLY);
  ALOGW_IF(
      !primary_display_wait_pp_fd_,
      "HardwareComposer: Failed to open wait_pp node for primary display: %s",
      strerror(errno));

  // Create a timerfd based on CLOCK_MONOTINIC.
  vsync_sleep_timer_fd_.Reset(timerfd_create(CLOCK_MONOTONIC, 0));
  LOG_ALWAYS_FATAL_IF(
      !vsync_sleep_timer_fd_,
      "HardwareComposer: Failed to create vsync sleep timerfd: %s",
      strerror(errno));

  const int64_t ns_per_frame = display_metrics_.vsync_period_ns;
  const int64_t photon_offset_ns = GetPosePredictionTimeOffset(ns_per_frame);

  // TODO(jbates) Query vblank time from device, when such an API is available.
  // This value (6.3%) was measured on A00 in low persistence mode.
  int64_t vblank_ns = ns_per_frame * 63 / 1000;
  int64_t right_eye_photon_offset_ns = (ns_per_frame - vblank_ns) / 2;

  // Check property for overriding right eye offset value.
  right_eye_photon_offset_ns =
      property_get_int64(kRightEyeOffsetProperty, right_eye_photon_offset_ns);

  compositor_surfaces_.reserve(2);

  constexpr int kFrameTimeBacklogMax = 2;
  frame_time_backlog_.reserve(kFrameTimeBacklogMax);

  // Storage for retrieving fence info.
  FenceInfoBuffer fence_info_buffer;

  bool was_running = false;

  while (1) {
    ATRACE_NAME("HardwareComposer::PostThread");

    {
      std::unique_lock<std::mutex> lock(post_thread_mutex_);
      while (!post_thread_enabled_ || post_thread_quit_requested_ ||
             !PostThreadHasWork()) {
        if (was_running) {
          const char* pause_reason = "unknown";
          if (!post_thread_enabled_)
            pause_reason = "disabled";
          else if (post_thread_quit_requested_)
            pause_reason = "quit requested";
          else if (!PostThreadHasWork())
            pause_reason = "no work";
          ALOGI("VrHwcPost thread paused. Reason: %s.", pause_reason);
          OnPostThreadPaused();
          was_running = false;
        }
        post_thread_running_ = false;
        post_thread_cond_var_.notify_all();
        if (post_thread_quit_requested_)
          return;
        post_thread_cond_var_.wait(lock);
      }
      post_thread_running_ = true;
    }

    if (!was_running) {
      ALOGI("VrHwcPost thread resumed");
      OnPostThreadResumed();
      was_running = true;
    }

    int64_t vsync_timestamp = 0;
    {
      std::array<char, 128> buf;
      snprintf(buf.data(), buf.size(), "wait_vsync|vsync=%d|",
               vsync_count_ + 1);
      ATRACE_NAME(buf.data());

      error = WaitForVSync(&vsync_timestamp);
      ALOGE_IF(
          error < 0,
          "HardwareComposer::PostThread: Failed to wait for vsync event: %s",
          strerror(-error));
      // Don't bother processing this frame if a pause was requested
      if (error == kPostThreadInterrupted)
        continue;
    }

    ++vsync_count_;

    if (pose_client_) {
      // Signal the pose service with vsync info.
      // Display timestamp is in the middle of scanout.
      privateDvrPoseNotifyVsync(pose_client_, vsync_count_,
                                vsync_timestamp + photon_offset_ns,
                                ns_per_frame, right_eye_photon_offset_ns);
    }

    bool layer_config_changed = UpdateLayerConfig();

    if (!was_running || layer_config_changed) {
      frame_time_history_.ResetWithSeed(
          GuessFrameTime(compositor_surfaces_.size()));
      frame_time_backlog_.clear();
    } else {
      UpdateFrameTimeHistory(&frame_time_backlog_, kFrameTimeBacklogMax,
                             &fence_info_buffer, &frame_time_history_);
    }

    // Get our current best estimate at how long the next frame will take to
    // render, based on how long previous frames took to render. Use this
    // estimate to decide when to wake up for EDS.
    int64_t frame_time_estimate =
        frame_time_history_.GetSampleCount() == 0
            ? GuessFrameTime(compositor_surfaces_.size())
            : frame_time_history_.GetAverage();
    frame_time_estimate = std::max(frame_time_estimate, kFrameTimeEstimateMin);
    DebugHudData::data.hwc_latency = frame_time_estimate;

    // Signal all of the vsync clients. Because absolute time is used for the
    // wakeup time below, this can take a little time if necessary.
    if (vsync_callback_)
      vsync_callback_(HWC_DISPLAY_PRIMARY, vsync_timestamp, frame_time_estimate,
                      vsync_count_);

    {
      // Sleep until async EDS wakeup time.
      ATRACE_NAME("sleep");

      int64_t display_time_est = vsync_timestamp + ns_per_frame;
      int64_t now = GetSystemClockNs();
      int64_t frame_finish_time_est = now + frame_time_estimate;
      int64_t sleep_time_ns = display_time_est - now - frame_time_estimate;

      ATRACE_INT64("sleep_time_ns", sleep_time_ns);
      if (frame_finish_time_est - display_time_est >= kFrameSkipThresholdNs) {
        ATRACE_INT("frame_skip_count", ++frame_skip_count_);
        ALOGE(
            "HardwareComposer::PostThread: Missed frame schedule, drop "
            "frame. Expected frame miss: %.1fms",
            static_cast<double>(frame_finish_time_est - display_time_est) /
                1000000);

        // There are several reasons we might skip a frame, but one possibility
        // is we mispredicted the frame time. Clear out the frame time history.
        frame_time_history_.ResetWithSeed(
            GuessFrameTime(compositor_surfaces_.size()));
        frame_time_backlog_.clear();
        DebugHudData::data.hwc_frame_stats.SkipFrame();

        if (layer_config_changed) {
          // If the layer config changed we need to validateDisplay() even if
          // we're going to drop the frame, to flush the Composer object's
          // internal command buffer and apply our layer changes.
          Validate(HWC_DISPLAY_PRIMARY);
        }

        continue;
      } else {
        // Make the transition more obvious in systrace when the frame skip
        // happens above.
        ATRACE_INT("frame_skip_count", 0);
      }

      if (sleep_time_ns > 0) {
        error = SleepUntil(display_time_est - frame_time_estimate);
        ALOGE_IF(error < 0, "HardwareComposer::PostThread: Failed to sleep: %s",
                 strerror(-error));
        if (error == kPostThreadInterrupted) {
          if (layer_config_changed) {
            // If the layer config changed we need to validateDisplay() even if
            // we're going to drop the frame, to flush the Composer object's
            // internal command buffer and apply our layer changes.
            Validate(HWC_DISPLAY_PRIMARY);
          }
          continue;
        }
      }
    }

    DebugHudData::data.hwc_frame_stats.AddFrame();

    int64_t frame_start_time = GetSystemClockNs();

    // Setup the output buffer for the compositor. This needs to happen before
    // you draw with the compositor.
    if (gpu_layer_ != nullptr) {
      gpu_layer_->UpdateDirectBuffer(compositor_.GetBuffer());
    }

    // Call PostLayers now before performing the GL code for the compositor to
    // avoid missing the deadline that can cause the lower-level hwc to get
    // permanently backed up.
    PostLayers(layer_config_changed);

    PostCompositorBuffers();

    if (gpu_layer_ != nullptr) {
      // Note, with scanline racing, this draw is timed along with the post
      // layers to finish just in time.
      LocalHandle frame_fence_fd;
      compositor_.DrawFrame(vsync_count_ + 1, &frame_fence_fd);
      if (frame_fence_fd) {
        LOG_ALWAYS_FATAL_IF(frame_time_backlog_.size() >= kFrameTimeBacklogMax,
                            "Frame time backlog exceeds capacity");
        frame_time_backlog_.push_back(
            {frame_start_time, std::move(frame_fence_fd)});
      }
    } else if (!layer_config_changed) {
      frame_time_history_.AddSample(GetSystemClockNs() - frame_start_time);
    }

    HandlePendingScreenshots();
  }
}

bool HardwareComposer::UpdateLayerConfig() {
  std::vector<std::shared_ptr<DisplaySurface>> old_display_surfaces;
  {
    std::lock_guard<std::mutex> lock(post_thread_mutex_);
    if (!active_surfaces_updated_)
      return false;
    old_display_surfaces = display_surfaces_;
    display_surfaces_ = active_surfaces_;
    active_surfaces_updated_ = false;
  }

  DebugHudData::data.ResetLayers();

  // Figure out whether we need to update hardware layers. If this surface
  // change does not add or remove hardware layers we can avoid display hiccups
  // by gracefully updating only the GPU compositor layers.
  int old_gpu_layer_count = 0;
  int new_gpu_layer_count = 0;
  bool hardware_layers_need_update = false;
  // Look for new hardware layers and count new GPU layers.
  for (const auto& surface : display_surfaces_) {
    if (!(surface->flags() &
          DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION))
      ++new_gpu_layer_count;
    else if (std::find(old_display_surfaces.begin(), old_display_surfaces.end(),
                       surface) == old_display_surfaces.end())
      // This is a new hardware layer, we need to update.
      hardware_layers_need_update = true;
  }
  // Look for deleted hardware layers or compositor layers.
  for (const auto& surface : old_display_surfaces) {
    if (!(surface->flags() &
          DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION))
      ++old_gpu_layer_count;
    else if (std::find(display_surfaces_.begin(), display_surfaces_.end(),
                       surface) == display_surfaces_.end())
      // This is a deleted hardware layer, we need to update.
      hardware_layers_need_update = true;
  }
  // Check for compositor hardware layer transition.
  if ((!old_gpu_layer_count && new_gpu_layer_count) ||
      (old_gpu_layer_count && !new_gpu_layer_count))
    hardware_layers_need_update = true;

  // Set the chosen layer order for all surfaces.
  for (size_t i = 0; i < display_surfaces_.size(); ++i) {
    display_surfaces_[i]->SetLayerOrder(static_cast<int>(i));
  }

  // Update compositor layers.
  {
    ATRACE_NAME("UpdateLayerConfig_GpuLayers");
    compositor_.UpdateSurfaces(display_surfaces_);
    compositor_surfaces_.clear();
    for (size_t i = 0; i < display_surfaces_.size(); ++i) {
      const auto& surface = display_surfaces_[i];
      if (!(surface->flags() &
            DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION)) {
        compositor_surfaces_.push_back(surface);
      }
    }
  }

  if (!hardware_layers_need_update)
    return true;

  // Update hardware layers.

  ATRACE_NAME("UpdateLayerConfig_HwLayers");

  // Update the display layers in a non-destructive fashion.

  // Create a map from surface id to hardware layer
  std::map<int, Layer*> display_surface_layers;

  for (size_t i = 0; i < active_layer_count_; ++i) {
    auto layer = layers_[i];
    int surface_id = layer->GetSurfaceId();

    auto found =
        std::find_if(display_surfaces_.begin(), display_surfaces_.end(),
                     [surface_id](const auto& surface) {
                       return surface->surface_id() == surface_id;
                     });

    if (found != display_surfaces_.end()) {
      display_surface_layers[surface_id] = layer;
    }
  }

  bool has_gpu_layer = std::any_of(
      display_surfaces_.begin(), display_surfaces_.end(),
      [](const auto& surface) {
        return !(surface->flags() &
                 DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION);
      });

  if (!has_gpu_layer) {
    gpu_layer_ = nullptr;
  }

  auto is_layer_active = [&display_surface_layers, has_gpu_layer](auto layer) {
    int surface_id = layer->GetSurfaceId();
    if (surface_id >= 0) {
      return display_surface_layers.count(surface_id) > 0;
    } else {
      return has_gpu_layer;
    }
  };

  // Compress the in-use layers to the top of the list
  auto part = std::partition(
      layers_.begin(), layers_.begin() + active_layer_count_, is_layer_active);

  size_t new_active_layer_count = part - layers_.begin();

  // Clear any unused layers
  for (size_t i = new_active_layer_count; i < active_layer_count_; ++i) {
    layers_[i]->Reset();
  }

  active_layer_count_ = new_active_layer_count;

  bool gpu_layer_applied = false;

  // Create/update all of the hardware layers
  for (size_t i = 0; i < display_surfaces_.size(); ++i) {
    const auto& surface = display_surfaces_[i];
    bool is_hw_surface =
        surface->flags() & DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION;
    hwc2_blend_mode_t blending =
        i == 0 ? HWC2_BLEND_MODE_NONE : HWC2_BLEND_MODE_COVERAGE;

    DebugHudData::data.SetLayerInfo(
        i, surface->width(), surface->height(),
        !!(surface->flags() & DVR_DISPLAY_SURFACE_FLAGS_GEOMETRY_SEPARATE_2));

    if (!is_hw_surface && gpu_layer_applied) {
      continue;
    }

    Layer* target_layer;
    bool existing_layer = false;

    if (is_hw_surface) {
      auto it = display_surface_layers.find(surface->surface_id());

      if (it != display_surface_layers.end()) {
        target_layer = it->second;
        existing_layer = true;
      }
    } else if (gpu_layer_ != nullptr) {
      target_layer = gpu_layer_;
      existing_layer = true;
    }

    if (!existing_layer) {
      if (active_layer_count_ >= kMaxHardwareLayers) {
        ALOGI("HardwareComposer: More than %d hardware layers requested.",
              kMaxHardwareLayers);
        break;
      } else {
        target_layer = layers_[active_layer_count_];
        ++active_layer_count_;
      }

      ALOGD_IF(TRACE,
               "HardwareComposer::UpdateLayerConfig: (new) surface_id=%d -> "
               "layer=%zd",
               surface->surface_id(), i);

      if (is_hw_surface) {
        target_layer->Setup(surface, blending, display_transform_,
                            HWC2_COMPOSITION_DEVICE, i);
      } else {
        gpu_layer_ = target_layer;
        target_layer->Setup(compositor_.GetBuffer(), blending,
                            display_transform_, HWC2_COMPOSITION_DEVICE, i);
      }
    } else {
      ALOGD_IF(TRACE,
               "HardwareComposer::UpdateLayerConfig: (retained) surface_id=%d "
               "-> layer=%zd",
               surface->surface_id(), i);

      target_layer->SetBlending(blending);
      target_layer->SetZOrderIndex(i);
      target_layer->UpdateLayerSettings();
    }

    gpu_layer_applied = !is_hw_surface;
  }

  ALOGD_IF(TRACE, "HardwareComposer::UpdateLayerConfig: %zd active layers",
           active_layer_count_);

  return true;
}

void HardwareComposer::PostCompositorBuffers() {
  ATRACE_NAME("PostCompositorBuffers");
  for (const auto& surface : compositor_surfaces_) {
    compositor_.PostBuffer(surface);
  }
}

void HardwareComposer::UpdateFrameTimeHistory(
    std::vector<FrameTimeMeasurementRecord>* backlog, int backlog_max,
    FenceInfoBuffer* fence_info_buffer, FrameTimeHistory* history) {
  while (!backlog->empty()) {
    const auto& frame_time_record = backlog->front();
    int64_t end_time = 0;
    bool frame_finished = CheckFrameFinished(frame_time_record.fence.Get(),
                                             fence_info_buffer, &end_time);
    if (frame_finished) {
      int64_t frame_duration = end_time - frame_time_record.start_time;
      history->AddSample(frame_duration);
      // Our backlog is tiny (2 elements), so erasing from the front is ok
      backlog->erase(backlog->begin());
    } else {
      break;
    }
  }

  if (backlog->size() == static_cast<size_t>(backlog_max)) {
    // Yikes, something must've gone wrong if our oldest frame hasn't finished
    // yet. Give up on waiting for it.
    const auto& stale_frame_time_record = backlog->front();
    int64_t frame_duration =
        GetSystemClockNs() - stale_frame_time_record.start_time;
    backlog->erase(backlog->begin());
    history->AddSample(frame_duration);
    ALOGW("Frame didn't finish after %.1fms",
          static_cast<double>(frame_duration) / 1000000);
  }
}

bool HardwareComposer::CheckFrameFinished(int frame_fence_fd,
                                          FenceInfoBuffer* fence_info_buffer,
                                          int64_t* timestamp) {
  int result = -1;
  int sync_result = sync_wait(frame_fence_fd, 0);
  if (sync_result == 0) {
    result =
        GetFenceSignaledTimestamp(frame_fence_fd, fence_info_buffer, timestamp);
    if (result < 0) {
      ALOGE("Failed getting signaled timestamp from fence");
    }
  } else if (errno != ETIME) {
    ALOGE("sync_wait on frame fence failed");
  }
  return result >= 0;
}

void HardwareComposer::HandlePendingScreenshots() {
  // Take a screenshot of the requested layer, if available.
  // TODO(eieio): Look into using virtual displays to composite the layer stack
  // into a single output buffer that can be returned to the screenshot clients.
  if (active_layer_count_ > 0) {
    if (auto screenshot_service = ScreenshotService::GetInstance()) {
      if (screenshot_service->IsScreenshotRequestPending()) {
        ATRACE_NAME("screenshot");
        screenshot_service->TakeIfNeeded(layers_, compositor_);
      }
    } else {
      ALOGW(
          "HardwareComposer::HandlePendingScreenshots: Failed to get "
          "screenshot service!");
    }
  }
}

void HardwareComposer::SetVSyncCallback(VSyncCallback callback) {
  vsync_callback_ = callback;
}

void HardwareComposer::HwcRefresh(hwc2_callback_data_t /*data*/,
                                  hwc2_display_t /*display*/) {
  // TODO(eieio): implement invalidate callbacks.
}

void HardwareComposer::HwcVSync(hwc2_callback_data_t /*data*/,
                                hwc2_display_t /*display*/,
                                int64_t /*timestamp*/) {
  ATRACE_NAME(__PRETTY_FUNCTION__);
  // Intentionally empty. HWC may require a callback to be set to enable vsync
  // signals. We bypass this callback thread by monitoring the vsync event
  // directly, but signals still need to be enabled.
}

void HardwareComposer::HwcHotplug(hwc2_callback_data_t /*callbackData*/,
                                  hwc2_display_t /*display*/,
                                  hwc2_connection_t /*connected*/) {
  // TODO(eieio): implement display hotplug callbacks.
}

void HardwareComposer::OnHardwareComposerRefresh() {
  // TODO(steventhomas): Handle refresh.
}

void HardwareComposer::SetBacklightBrightness(int brightness) {
  if (backlight_brightness_fd_) {
    std::array<char, 32> text;
    const int length = snprintf(text.data(), text.size(), "%d", brightness);
    write(backlight_brightness_fd_.Get(), text.data(), length);
  }
}

Layer::Layer()
    : hwc2_hidl_(nullptr),
      surface_index_(-1),
      hardware_composer_layer_(0),
      display_metrics_(nullptr),
      blending_(HWC2_BLEND_MODE_NONE),
      transform_(HWC_TRANSFORM_NONE),
      composition_type_(HWC2_COMPOSITION_DEVICE),
      surface_rect_functions_applied_(false) {}

void Layer::Initialize(Hwc2::Composer* hwc2_hidl, HWCDisplayMetrics* metrics) {
  hwc2_hidl_ = hwc2_hidl;
  display_metrics_ = metrics;
}

void Layer::Reset() {
  const int ret = acquired_buffer_.Release(std::move(release_fence_));
  ALOGE_IF(ret < 0, "Layer::Reset: failed to release buffer: %s",
           strerror(-ret));

  if (hwc2_hidl_ != nullptr && hardware_composer_layer_) {
    hwc2_hidl_->destroyLayer(HWC_DISPLAY_PRIMARY, hardware_composer_layer_);
    hardware_composer_layer_ = 0;
  }

  surface_index_ = static_cast<size_t>(-1);
  blending_ = HWC2_BLEND_MODE_NONE;
  transform_ = HWC_TRANSFORM_NONE;
  composition_type_ = HWC2_COMPOSITION_DEVICE;
  direct_buffer_ = nullptr;
  surface_ = nullptr;
  acquire_fence_fd_.Close();
  surface_rect_functions_applied_ = false;
}

void Layer::Setup(const std::shared_ptr<DisplaySurface>& surface,
                  hwc2_blend_mode_t blending, hwc_transform_t transform,
                  hwc2_composition_t composition_type, size_t index) {
  Reset();
  surface_index_ = index;
  surface_ = surface;
  blending_ = blending;
  transform_ = transform;
  composition_type_ = composition_type;
  CommonLayerSetup();
}

void Layer::Setup(const std::shared_ptr<IonBuffer>& buffer,
                  hwc2_blend_mode_t blending, hwc_transform_t transform,
                  hwc2_composition_t composition_type, size_t z_order) {
  Reset();
  surface_index_ = z_order;
  direct_buffer_ = buffer;
  blending_ = blending;
  transform_ = transform;
  composition_type_ = composition_type;
  CommonLayerSetup();
}

void Layer::UpdateDirectBuffer(const std::shared_ptr<IonBuffer>& buffer) {
  direct_buffer_ = buffer;
}

void Layer::SetBlending(hwc2_blend_mode_t blending) { blending_ = blending; }

void Layer::SetZOrderIndex(int z_index) { surface_index_ = z_index; }

IonBuffer* Layer::GetBuffer() {
  if (direct_buffer_)
    return direct_buffer_.get();
  else if (acquired_buffer_.IsAvailable())
    return acquired_buffer_.buffer()->buffer();
  else
    return nullptr;
}

void Layer::UpdateLayerSettings() {
  if (!IsLayerSetup()) {
    ALOGE("HardwareComposer: Trying to update layers data on an unused layer.");
    return;
  }

  int32_t ret = HWC2_ERROR_NONE;

  hwc2_display_t display = HWC_DISPLAY_PRIMARY;

  ret = (int32_t)hwc2_hidl_->setLayerCompositionType(
      display, hardware_composer_layer_,
      (Hwc2::IComposerClient::Composition)composition_type_);
  ALOGE_IF(ret, "HardwareComposer: Error setting layer composition type : %d",
           ret);
  // ret = (int32_t) hwc2_hidl_->setLayerTransform(display,
  // hardware_composer_layer_,
  //                                    (Hwc2::IComposerClient::Transform)
  //                                    transform_);
  // ALOGE_IF(ret, "HardwareComposer: Error setting layer transform : %d", ret);

  // ret = hwc2_funcs_->set_layer_blend_mode_fn_(
  //    hardware_composer_device_, display, hardware_composer_layer_,
  //    blending_);
  ret = (int32_t)hwc2_hidl_->setLayerBlendMode(
      display, hardware_composer_layer_,
      (Hwc2::IComposerClient::BlendMode)blending_);
  ALOGE_IF(ret, "HardwareComposer: Error setting layer blend mode : %d", ret);

  Hwc2::IComposerClient::Rect display_frame;
  display_frame.left = 0;
  display_frame.top = 0;
  display_frame.right = display_metrics_->width;
  display_frame.bottom = display_metrics_->height;
  ret = (int32_t)hwc2_hidl_->setLayerDisplayFrame(
      display, hardware_composer_layer_, display_frame);
  ALOGE_IF(ret, "HardwareComposer: Error setting layer display frame : %d",
           ret);

  std::vector<Hwc2::IComposerClient::Rect> visible_region(1);
  visible_region[0] = display_frame;
  ret = (int32_t)hwc2_hidl_->setLayerVisibleRegion(
      display, hardware_composer_layer_, visible_region);
  ALOGE_IF(ret, "HardwareComposer: Error setting layer visible region : %d",
           ret);

  ret = (int32_t)hwc2_hidl_->setLayerPlaneAlpha(display,
                                                hardware_composer_layer_, 1.0f);
  ALOGE_IF(ret, "HardwareComposer: Error setting layer plane alpha : %d", ret);

  ret = (int32_t)hwc2_hidl_->setLayerZOrder(display, hardware_composer_layer_,
                                            surface_index_);
  ALOGE_IF(ret, "HardwareComposer: Error, setting z order index : %d", ret);
}

void Layer::CommonLayerSetup() {
  int32_t ret = (int32_t)hwc2_hidl_->createLayer(HWC_DISPLAY_PRIMARY,
                                                 &hardware_composer_layer_);

  ALOGE_IF(ret,
           "HardwareComposer: Failed to create layer on primary display : %d",
           ret);

  UpdateLayerSettings();
}

void Layer::Prepare() {
  int right, bottom;
  sp<GraphicBuffer> handle;

  if (surface_) {
    // Only update the acquired buffer when one is either available or this is
    // the first time through.
    if (surface_->IsBufferAvailable()) {
      // If we previously set this to a solid color layer to stall for time,
      // revert it to a device layer.
      if (acquired_buffer_.IsEmpty() &&
          composition_type_ != HWC2_COMPOSITION_DEVICE) {
        composition_type_ = HWC2_COMPOSITION_DEVICE;
        hwc2_hidl_->setLayerCompositionType(
            HWC_DISPLAY_PRIMARY, hardware_composer_layer_,
            (Hwc2::IComposerClient::Composition)HWC2_COMPOSITION_DEVICE);
      }

      DebugHudData::data.AddLayerFrame(surface_index_);
      acquired_buffer_.Release(std::move(release_fence_));
      acquired_buffer_ = surface_->AcquireCurrentBuffer();

      // Basic latency stopgap for when the application misses a frame:
      // If the application recovers on the 2nd or 3rd (etc) frame after
      // missing, this code will skip a frame to catch up by checking if
      // the next frame is also available.
      if (surface_->IsBufferAvailable()) {
        DebugHudData::data.SkipLayerFrame(surface_index_);
        ATRACE_NAME("DropToCatchUp");
        ATRACE_ASYNC_END("BufferPost", acquired_buffer_.buffer()->id());
        acquired_buffer_ = surface_->AcquireCurrentBuffer();
      }
      ATRACE_ASYNC_END("BufferPost", acquired_buffer_.buffer()->id());
    } else if (acquired_buffer_.IsEmpty()) {
      // While we are waiting for a buffer, set this to be an empty layer
      if (composition_type_ != HWC2_COMPOSITION_SOLID_COLOR) {
        composition_type_ = HWC2_COMPOSITION_SOLID_COLOR;
        hwc2_hidl_->setLayerCompositionType(
            HWC_DISPLAY_PRIMARY, hardware_composer_layer_,
            (Hwc2::IComposerClient::Composition)HWC2_COMPOSITION_SOLID_COLOR);

        Hwc2::IComposerClient::Color layer_color = {
            0, 0, 0, 0,
        };
        hwc2_hidl_->setLayerColor(HWC_DISPLAY_PRIMARY, hardware_composer_layer_,
                                  layer_color);
      }
      return;
    }
    right = acquired_buffer_.buffer()->width();
    bottom = acquired_buffer_.buffer()->height();
    handle = acquired_buffer_.buffer()->buffer()->buffer();
    acquire_fence_fd_.Reset(acquired_buffer_.ClaimAcquireFence().Release());
  } else {
    // TODO(jwcai) Note: this is the GPU compositor's layer, and we need the
    // mechanism to accept distorted layers from VrCore.
    right = direct_buffer_->width();
    bottom = direct_buffer_->height();
    handle = direct_buffer_->buffer();
    acquire_fence_fd_.Close();
  }

  int32_t ret = HWC2_ERROR_NONE;

  if (composition_type_ == HWC2_COMPOSITION_DEVICE) {
    ret = (int32_t)hwc2_hidl_->setLayerBuffer(HWC_DISPLAY_PRIMARY,
                                              hardware_composer_layer_, 0,
                                              handle,
                                              acquire_fence_fd_.Get());

    ALOGE_IF(ret, "HardwareComposer: Error setting layer buffer : %d", ret);
  }

  if (!surface_rect_functions_applied_) {
    Hwc2::IComposerClient::FRect crop_rect = {
        0, 0, static_cast<float>(right), static_cast<float>(bottom),
    };
    hwc2_hidl_->setLayerSourceCrop(HWC_DISPLAY_PRIMARY,
                                   hardware_composer_layer_, crop_rect);

    ALOGE_IF(ret, "HardwareComposer: Error setting layer source crop : %d",
             ret);

// TODO(skiazyk): why is this ifdef'd out. Is if a driver-specific issue where
// it must/cannot be called?
#ifdef QCOM_BSP
    hwc_rect_t damage_rect = {
        0, 0, right, bottom,
    };
    hwc_region_t damage = {
        1, &damage_rect,
    };
    // ret = hwc2_funcs_->set_layer_surface_damage(
    //    hardware_composer_device_, HWC_DISPLAY_PRIMARY,
    //    hardware_composer_layer_, damage);
    // uses a std::vector as the listing
    // hwc2_hidl_->setLayerSurfaceDamage(HWC_DISPLAY_PRIMARY,
    // hardware_composer_layer_, vector here);

    ALOGE_IF(ret, "HardwareComposer: Error settings layer surface damage : %d",
             ret);
#endif

    surface_rect_functions_applied_ = true;
  }
}

void Layer::Finish(int release_fence_fd) {
  release_fence_.Reset(release_fence_fd);
}

void Layer::Drop() { acquire_fence_fd_.Close(); }

}  // namespace dvr
}  // namespace android
