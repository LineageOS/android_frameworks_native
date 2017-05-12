#include "hardware_composer.h"

#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <fcntl.h>
#include <log/log.h>
#include <poll.h>
#include <sync/sync.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/system_properties.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <utils/Trace.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>

#include <dvr/dvr_display_types.h>
#include <dvr/performance_client_api.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/ion_buffer.h>
#include <private/dvr/pose_client_internal.h>

using android::pdx::LocalHandle;
using android::pdx::rpc::EmptyVariant;
using android::pdx::rpc::IfAnyOf;

using namespace std::chrono_literals;

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

// Offset before vsync to submit frames to hardware composer.
constexpr int64_t kFramePostOffsetNs = 4000000;  // 4ms

const char kBacklightBrightnessSysFile[] =
    "/sys/class/leds/lcd-backlight/brightness";

const char kPrimaryDisplayVSyncEventFile[] =
    "/sys/class/graphics/fb0/vsync_event";

const char kPrimaryDisplayWaitPPEventFile[] = "/sys/class/graphics/fb0/wait_pp";

const char kDvrPerformanceProperty[] = "sys.dvr.performance";

const char kRightEyeOffsetProperty[] = "dvr.right_eye_offset_ns";

// Get time offset from a vsync to when the pose for that vsync should be
// predicted out to. For example, if scanout gets halfway through the frame
// at the halfway point between vsyncs, then this could be half the period.
// With global shutter displays, this should be changed to the offset to when
// illumination begins. Low persistence adds a frame of latency, so we predict
// to the center of the next frame.
inline int64_t GetPosePredictionTimeOffset(int64_t vsync_period_ns) {
  return (vsync_period_ns * 150) / 100;
}

// Attempts to set the scheduler class and partiton for the current thread.
// Returns true on success or false on failure.
bool SetThreadPolicy(const std::string& scheduler_class,
                     const std::string& partition) {
  int error = dvrSetSchedulerClass(0, scheduler_class.c_str());
  if (error < 0) {
    ALOGE(
        "SetThreadPolicy: Failed to set scheduler class \"%s\" for "
        "thread_id=%d: %s",
        scheduler_class.c_str(), gettid(), strerror(-error));
    return false;
  }
  error = dvrSetCpuPartition(0, partition.c_str());
  if (error < 0) {
    ALOGE(
        "SetThreadPolicy: Failed to set cpu partiton \"%s\" for thread_id=%d: "
        "%s",
        partition.c_str(), gettid(), strerror(-error));
    return false;
  }
  return true;
}

}  // anonymous namespace

// Layer static data.
Hwc2::Composer* Layer::hwc2_hidl_;
const HWCDisplayMetrics* Layer::display_metrics_;

// HardwareComposer static data;
constexpr size_t HardwareComposer::kMaxHardwareLayers;

HardwareComposer::HardwareComposer()
    : HardwareComposer(nullptr, RequestDisplayCallback()) {}

HardwareComposer::HardwareComposer(
    Hwc2::Composer* hwc2_hidl, RequestDisplayCallback request_display_callback)
    : initialized_(false),
      hwc2_hidl_(hwc2_hidl),
      request_display_callback_(request_display_callback),
      callbacks_(new ComposerCallback) {}

HardwareComposer::~HardwareComposer(void) {
  UpdatePostThreadState(PostThreadState::Quit, true);
  if (post_thread_.joinable())
    post_thread_.join();
}

bool HardwareComposer::Initialize() {
  if (initialized_) {
    ALOGE("HardwareComposer::Initialize: already initialized.");
    return false;
  }

  HWC::Error error = HWC::Error::None;

  Hwc2::Config config;
  error = hwc2_hidl_->getActiveConfig(HWC_DISPLAY_PRIMARY, &config);

  if (error != HWC::Error::None) {
    ALOGE("HardwareComposer: Failed to get current display config : %d",
          config);
    return false;
  }

  error =
      GetDisplayMetrics(HWC_DISPLAY_PRIMARY, config, &native_display_metrics_);

  if (error != HWC::Error::None) {
    ALOGE(
        "HardwareComposer: Failed to get display attributes for current "
        "configuration : %d",
        error.value);
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

  // Pass hwc instance and metrics to setup globals for Layer.
  Layer::InitializeGlobals(hwc2_hidl_, &native_display_metrics_);

  post_thread_event_fd_.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
  LOG_ALWAYS_FATAL_IF(
      !post_thread_event_fd_,
      "HardwareComposer: Failed to create interrupt event fd : %s",
      strerror(errno));

  post_thread_ = std::thread(&HardwareComposer::PostThread, this);

  initialized_ = true;

  return initialized_;
}

void HardwareComposer::Enable() {
  UpdatePostThreadState(PostThreadState::Suspended, false);
}

void HardwareComposer::Disable() {
  UpdatePostThreadState(PostThreadState::Suspended, true);
}

// Update the post thread quiescent state based on idle and suspended inputs.
void HardwareComposer::UpdatePostThreadState(PostThreadStateType state,
                                             bool suspend) {
  std::unique_lock<std::mutex> lock(post_thread_mutex_);

  // Update the votes in the state variable before evaluating the effective
  // quiescent state. Any bits set in post_thread_state_ indicate that the post
  // thread should be suspended.
  if (suspend) {
    post_thread_state_ |= state;
  } else {
    post_thread_state_ &= ~state;
  }

  const bool quit = post_thread_state_ & PostThreadState::Quit;
  const bool effective_suspend = post_thread_state_ != PostThreadState::Active;
  if (quit) {
    post_thread_quiescent_ = true;
    eventfd_write(post_thread_event_fd_.Get(), 1);
    post_thread_wait_.notify_one();
  } else if (effective_suspend && !post_thread_quiescent_) {
    post_thread_quiescent_ = true;
    eventfd_write(post_thread_event_fd_.Get(), 1);
  } else if (!effective_suspend && post_thread_quiescent_) {
    post_thread_quiescent_ = false;
    eventfd_t value;
    eventfd_read(post_thread_event_fd_.Get(), &value);
    post_thread_wait_.notify_one();
  }

  // Wait until the post thread is in the requested state.
  post_thread_ready_.wait(lock, [this, effective_suspend] {
    return effective_suspend != post_thread_resumed_;
  });
}

void HardwareComposer::OnPostThreadResumed() {
  hwc2_hidl_->resetCommands();

  // Connect to pose service.
  pose_client_ = dvrPoseCreate();
  ALOGE_IF(!pose_client_, "HardwareComposer: Failed to create pose client");

  // HIDL HWC seems to have an internal race condition. If we submit a frame too
  // soon after turning on VSync we don't get any VSync signals. Give poor HWC
  // implementations a chance to enable VSync before we continue.
  EnableVsync(false);
  std::this_thread::sleep_for(100ms);
  EnableVsync(true);
  std::this_thread::sleep_for(100ms);

  // TODO(skiazyk): We need to do something about accessing this directly,
  // supposedly there is a backlight service on the way.
  // TODO(steventhomas): When we change the backlight setting, will surface
  // flinger (or something else) set it back to its original value once we give
  // control of the display back to surface flinger?
  SetBacklightBrightness(255);

  // Trigger target-specific performance mode change.
  property_set(kDvrPerformanceProperty, "performance");
}

void HardwareComposer::OnPostThreadPaused() {
  retire_fence_fds_.clear();
  display_surfaces_.clear();

  for (size_t i = 0; i < kMaxHardwareLayers; ++i) {
    layers_[i].Reset();
  }
  active_layer_count_ = 0;

  if (pose_client_) {
    dvrPoseDestroy(pose_client_);
    pose_client_ = nullptr;
  }

  EnableVsync(false);

  hwc2_hidl_->resetCommands();

  // Trigger target-specific performance mode change.
  property_set(kDvrPerformanceProperty, "idle");
}

HWC::Error HardwareComposer::Validate(hwc2_display_t display) {
  uint32_t num_types;
  uint32_t num_requests;
  HWC::Error error =
      hwc2_hidl_->validateDisplay(display, &num_types, &num_requests);

  if (error == HWC2_ERROR_HAS_CHANGES) {
    // TODO(skiazyk): We might need to inspect the requested changes first, but
    // so far it seems like we shouldn't ever hit a bad state.
    // error = hwc2_funcs_.accept_display_changes_fn_(hardware_composer_device_,
    //                                               display);
    error = hwc2_hidl_->acceptDisplayChanges(display);
  }

  return error;
}

int32_t HardwareComposer::EnableVsync(bool enabled) {
  return (int32_t)hwc2_hidl_->setVsyncEnabled(
      HWC_DISPLAY_PRIMARY,
      (Hwc2::IComposerClient::Vsync)(enabled ? HWC2_VSYNC_ENABLE
                                             : HWC2_VSYNC_DISABLE));
}

HWC::Error HardwareComposer::Present(hwc2_display_t display) {
  int32_t present_fence;
  HWC::Error error = hwc2_hidl_->presentDisplay(display, &present_fence);

  // According to the documentation, this fence is signaled at the time of
  // vsync/DMA for physical displays.
  if (error == HWC::Error::None) {
    ATRACE_INT("HardwareComposer: VsyncFence", present_fence);
    retire_fence_fds_.emplace_back(present_fence);
  } else {
    ATRACE_INT("HardwareComposer: PresentResult", error);
  }

  return error;
}

HWC::Error HardwareComposer::GetDisplayAttribute(hwc2_display_t display,
                                                 hwc2_config_t config,
                                                 hwc2_attribute_t attribute,
                                                 int32_t* out_value) const {
  return hwc2_hidl_->getDisplayAttribute(
      display, config, (Hwc2::IComposerClient::Attribute)attribute, out_value);
}

HWC::Error HardwareComposer::GetDisplayMetrics(
    hwc2_display_t display, hwc2_config_t config,
    HWCDisplayMetrics* out_metrics) const {
  HWC::Error error;

  error = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_WIDTH,
                              &out_metrics->width);
  if (error != HWC::Error::None) {
    ALOGE(
        "HardwareComposer::GetDisplayMetrics: Failed to get display width: %s",
        error.to_string().c_str());
    return error;
  }

  error = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_HEIGHT,
                              &out_metrics->height);
  if (error != HWC::Error::None) {
    ALOGE(
        "HardwareComposer::GetDisplayMetrics: Failed to get display height: %s",
        error.to_string().c_str());
    return error;
  }

  error = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_VSYNC_PERIOD,
                              &out_metrics->vsync_period_ns);
  if (error != HWC::Error::None) {
    ALOGE(
        "HardwareComposer::GetDisplayMetrics: Failed to get display height: %s",
        error.to_string().c_str());
    return error;
  }

  error = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_DPI_X,
                              &out_metrics->dpi.x);
  if (error != HWC::Error::None) {
    ALOGE(
        "HardwareComposer::GetDisplayMetrics: Failed to get display DPI X: %s",
        error.to_string().c_str());
    return error;
  }

  error = GetDisplayAttribute(display, config, HWC2_ATTRIBUTE_DPI_Y,
                              &out_metrics->dpi.y);
  if (error != HWC::Error::None) {
    ALOGE(
        "HardwareComposer::GetDisplayMetrics: Failed to get display DPI Y: %s",
        error.to_string().c_str());
    return error;
  }

  return HWC::Error::None;
}

std::string HardwareComposer::Dump() { return hwc2_hidl_->dumpDebugInfo(); }

void HardwareComposer::PostLayers() {
  ATRACE_NAME("HardwareComposer::PostLayers");

  // Setup the hardware composer layers with current buffers.
  for (size_t i = 0; i < active_layer_count_; i++) {
    layers_[i].Prepare();
  }

  HWC::Error error = Validate(HWC_DISPLAY_PRIMARY);
  if (error != HWC::Error::None) {
    ALOGE("HardwareComposer::PostLayers: Validate failed: %s",
          error.to_string().c_str());
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
      layers_[i].Drop();
    }
    return;
  } else {
    // Make the transition more obvious in systrace when the frame skip happens
    // above.
    ATRACE_INT("frame_skip_count", 0);
  }

#if TRACE
  for (size_t i = 0; i < active_layer_count_; i++)
    ALOGI("HardwareComposer::PostLayers: layer=%zu composition=%s", i,
          layers_[i].GetCompositionType().to_string().c_str());
#endif

  error = Present(HWC_DISPLAY_PRIMARY);
  if (error != HWC::Error::None) {
    ALOGE("HardwareComposer::PostLayers: Present failed: %s",
          error.to_string().c_str());
    return;
  }

  std::vector<Hwc2::Layer> out_layers;
  std::vector<int> out_fences;
  error = hwc2_hidl_->getReleaseFences(HWC_DISPLAY_PRIMARY, &out_layers,
                                       &out_fences);
  ALOGE_IF(error != HWC::Error::None,
           "HardwareComposer::PostLayers: Failed to get release fences: %s",
           error.to_string().c_str());

  // Perform post-frame bookkeeping. Unused layers are a no-op.
  uint32_t num_elements = out_layers.size();
  for (size_t i = 0; i < num_elements; ++i) {
    for (size_t j = 0; j < active_layer_count_; ++j) {
      if (layers_[j].GetLayerHandle() == out_layers[i]) {
        layers_[j].Finish(out_fences[i]);
      }
    }
  }
}

void HardwareComposer::SetDisplaySurfaces(
    std::vector<std::shared_ptr<DirectDisplaySurface>> surfaces) {
  ALOGI("HardwareComposer::SetDisplaySurfaces: surface count=%zd",
        surfaces.size());
  const bool display_idle = surfaces.size() == 0;
  {
    std::unique_lock<std::mutex> lock(post_thread_mutex_);
    pending_surfaces_ = std::move(surfaces);
  }

  // Set idle state based on whether there are any surfaces to handle.
  UpdatePostThreadState(PostThreadState::Idle, display_idle);

  // XXX: TEMPORARY
  // Request control of the display based on whether there are any surfaces to
  // handle. This callback sets the post thread active state once the transition
  // is complete in SurfaceFlinger.
  // TODO(eieio): Unify the control signal used to move SurfaceFlinger into VR
  // mode. Currently this is hooked up to persistent VR mode, but perhaps this
  // makes more sense to control it from VrCore, which could in turn base its
  // decision on persistent VR mode.
  if (request_display_callback_)
    request_display_callback_(!display_idle);
}

int HardwareComposer::PostThreadPollInterruptible(
    const pdx::LocalHandle& event_fd, int requested_events) {
  pollfd pfd[2] = {
      {
          .fd = event_fd.Get(),
          .events = static_cast<short>(requested_events),
          .revents = 0,
      },
      {
          .fd = post_thread_event_fd_.Get(),
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
  // Vsync is signaled by POLLPRI on the fb vsync node.
  return PostThreadPollInterruptible(primary_display_vsync_event_fd_, POLLPRI);
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
    const int64_t threshold_ns = 1000000;  // 1ms

    const int64_t next_vsync_est = last_vsync_timestamp_ + ns_per_frame;
    const int64_t distance_to_vsync_est = next_vsync_est - GetSystemClockNs();

    if (distance_to_vsync_est > threshold_ns) {
      // Wait for vsync event notification.
      error = BlockUntilVSync();
      if (error < 0 || error == kPostThreadInterrupted)
        return error;
    } else {
      // Sleep for a short time (1 millisecond) before retrying.
      error = SleepUntil(GetSystemClockNs() + threshold_ns);
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

  return PostThreadPollInterruptible(vsync_sleep_timer_fd_, POLLIN);
}

void HardwareComposer::PostThread() {
  // NOLINTNEXTLINE(runtime/int)
  prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("VrHwcPost"), 0, 0, 0);

  // Set the scheduler to SCHED_FIFO with high priority. If this fails here
  // there may have been a startup timing issue between this thread and
  // performanced. Try again later when this thread becomes active.
  bool thread_policy_setup =
      SetThreadPolicy("graphics:high", "/system/performance");

#if ENABLE_BACKLIGHT_BRIGHTNESS
  // TODO(hendrikw): This isn't required at the moment. It's possible that there
  //                 is another method to access this when needed.
  // Open the backlight brightness control sysfs node.
  backlight_brightness_fd_ = LocalHandle(kBacklightBrightnessSysFile, O_RDWR);
  ALOGW_IF(!backlight_brightness_fd_,
           "HardwareComposer: Failed to open backlight brightness control: %s",
           strerror(errno));
#endif  // ENABLE_BACKLIGHT_BRIGHTNESS

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

  bool was_running = false;

  while (1) {
    ATRACE_NAME("HardwareComposer::PostThread");

    while (post_thread_quiescent_) {
      std::unique_lock<std::mutex> lock(post_thread_mutex_);
      ALOGI("HardwareComposer::PostThread: Entering quiescent state.");

      // Tear down resources.
      OnPostThreadPaused();

      was_running = false;
      post_thread_resumed_ = false;
      post_thread_ready_.notify_all();

      if (post_thread_state_ & PostThreadState::Quit) {
        ALOGI("HardwareComposer::PostThread: Quitting.");
        return;
      }

      post_thread_wait_.wait(lock, [this] { return !post_thread_quiescent_; });

      post_thread_resumed_ = true;
      post_thread_ready_.notify_all();

      ALOGI("HardwareComposer::PostThread: Exiting quiescent state.");
    }

    if (!was_running) {
      // Setup resources.
      OnPostThreadResumed();
      was_running = true;

      // Try to setup the scheduler policy if it failed during startup. Only
      // attempt to do this on transitions from inactive to active to avoid
      // spamming the system with RPCs and log messages.
      if (!thread_policy_setup) {
        thread_policy_setup =
            SetThreadPolicy("graphics:high", "/system/performance");
      }
    }

    int64_t vsync_timestamp = 0;
    {
      std::array<char, 128> buf;
      snprintf(buf.data(), buf.size(), "wait_vsync|vsync=%d|",
               vsync_count_ + 1);
      ATRACE_NAME(buf.data());

      const int error = WaitForVSync(&vsync_timestamp);
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

    const bool layer_config_changed = UpdateLayerConfig();

    // Signal all of the vsync clients. Because absolute time is used for the
    // wakeup time below, this can take a little time if necessary.
    if (vsync_callback_)
      vsync_callback_(HWC_DISPLAY_PRIMARY, vsync_timestamp,
                      /*frame_time_estimate*/ 0, vsync_count_);

    {
      // Sleep until shortly before vsync.
      ATRACE_NAME("sleep");

      const int64_t display_time_est_ns = vsync_timestamp + ns_per_frame;
      const int64_t now_ns = GetSystemClockNs();
      const int64_t sleep_time_ns =
          display_time_est_ns - now_ns - kFramePostOffsetNs;
      const int64_t wakeup_time_ns = display_time_est_ns - kFramePostOffsetNs;

      ATRACE_INT64("sleep_time_ns", sleep_time_ns);
      if (sleep_time_ns > 0) {
        int error = SleepUntil(wakeup_time_ns);
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

    PostLayers();
  }
}

// Checks for changes in the surface stack and updates the layer config to
// accomodate the new stack.
bool HardwareComposer::UpdateLayerConfig() {
  std::vector<std::shared_ptr<DirectDisplaySurface>> surfaces;
  {
    std::unique_lock<std::mutex> lock(post_thread_mutex_);
    if (pending_surfaces_.empty())
      return false;

    surfaces = std::move(pending_surfaces_);
  }

  ATRACE_NAME("UpdateLayerConfig_HwLayers");

  display_surfaces_.clear();

  Layer* target_layer;
  size_t layer_index;
  for (layer_index = 0;
       layer_index < std::min(surfaces.size(), kMaxHardwareLayers);
       layer_index++) {
    // The bottom layer is opaque, other layers blend.
    HWC::BlendMode blending =
        layer_index == 0 ? HWC::BlendMode::None : HWC::BlendMode::Coverage;
    layers_[layer_index].Setup(surfaces[layer_index], blending,
                               display_transform_, HWC::Composition::Device,
                               layer_index);
    display_surfaces_.push_back(surfaces[layer_index]);
  }

  // Clear unused layers.
  for (size_t i = layer_index; i < kMaxHardwareLayers; i++)
    layers_[i].Reset();

  active_layer_count_ = layer_index;
  ALOGD_IF(TRACE, "HardwareComposer::UpdateLayerConfig: %zd active layers",
           active_layer_count_);

  // Any surfaces left over could not be assigned a hardware layer and will
  // not be displayed.
  ALOGW_IF(surfaces.size() != display_surfaces_.size(),
           "HardwareComposer::UpdateLayerConfig: More surfaces than layers: "
           "pending_surfaces=%zu display_surfaces=%zu",
           surfaces.size(), display_surfaces_.size());

  return true;
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

void Layer::InitializeGlobals(Hwc2::Composer* hwc2_hidl,
                              const HWCDisplayMetrics* metrics) {
  hwc2_hidl_ = hwc2_hidl;
  display_metrics_ = metrics;
}

void Layer::Reset() {
  if (hwc2_hidl_ != nullptr && hardware_composer_layer_) {
    hwc2_hidl_->destroyLayer(HWC_DISPLAY_PRIMARY, hardware_composer_layer_);
    hardware_composer_layer_ = 0;
  }

  z_order_ = 0;
  blending_ = HWC::BlendMode::None;
  transform_ = HWC::Transform::None;
  composition_type_ = HWC::Composition::Invalid;
  target_composition_type_ = composition_type_;
  source_ = EmptyVariant{};
  acquire_fence_.Close();
  surface_rect_functions_applied_ = false;
}

void Layer::Setup(const std::shared_ptr<DirectDisplaySurface>& surface,
                  HWC::BlendMode blending, HWC::Transform transform,
                  HWC::Composition composition_type, size_t z_order) {
  Reset();
  z_order_ = z_order;
  blending_ = blending;
  transform_ = transform;
  composition_type_ = HWC::Composition::Invalid;
  target_composition_type_ = composition_type;
  source_ = SourceSurface{surface};
  CommonLayerSetup();
}

void Layer::Setup(const std::shared_ptr<IonBuffer>& buffer,
                  HWC::BlendMode blending, HWC::Transform transform,
                  HWC::Composition composition_type, size_t z_order) {
  Reset();
  z_order_ = z_order;
  blending_ = blending;
  transform_ = transform;
  composition_type_ = HWC::Composition::Invalid;
  target_composition_type_ = composition_type;
  source_ = SourceBuffer{buffer};
  CommonLayerSetup();
}

void Layer::UpdateBuffer(const std::shared_ptr<IonBuffer>& buffer) {
  if (source_.is<SourceBuffer>())
    std::get<SourceBuffer>(source_) = {buffer};
}

void Layer::SetBlending(HWC::BlendMode blending) { blending_ = blending; }
void Layer::SetZOrder(size_t z_order) { z_order_ = z_order; }

IonBuffer* Layer::GetBuffer() {
  struct Visitor {
    IonBuffer* operator()(SourceSurface& source) { return source.GetBuffer(); }
    IonBuffer* operator()(SourceBuffer& source) { return source.GetBuffer(); }
    IonBuffer* operator()(EmptyVariant) { return nullptr; }
  };
  return source_.Visit(Visitor{});
}

void Layer::UpdateLayerSettings() {
  if (!IsLayerSetup()) {
    ALOGE(
        "HardwareComposer::Layer::UpdateLayerSettings: Attempt to update "
        "unused Layer!");
    return;
  }

  HWC::Error error;
  hwc2_display_t display = HWC_DISPLAY_PRIMARY;

  error = hwc2_hidl_->setLayerCompositionType(
      display, hardware_composer_layer_,
      composition_type_.cast<Hwc2::IComposerClient::Composition>());
  ALOGE_IF(
      error != HWC::Error::None,
      "Layer::UpdateLayerSettings: Error setting layer composition type: %s",
      error.to_string().c_str());

  error = hwc2_hidl_->setLayerBlendMode(
      display, hardware_composer_layer_,
      blending_.cast<Hwc2::IComposerClient::BlendMode>());
  ALOGE_IF(error != HWC::Error::None,
           "Layer::UpdateLayerSettings: Error setting layer blend mode: %s",
           error.to_string().c_str());

  // TODO(eieio): Use surface attributes or some other mechanism to control
  // the layer display frame.
  error = hwc2_hidl_->setLayerDisplayFrame(
      display, hardware_composer_layer_,
      {0, 0, display_metrics_->width, display_metrics_->height});
  ALOGE_IF(error != HWC::Error::None,
           "Layer::UpdateLayerSettings: Error setting layer display frame: %s",
           error.to_string().c_str());

  error = hwc2_hidl_->setLayerVisibleRegion(
      display, hardware_composer_layer_,
      {{0, 0, display_metrics_->width, display_metrics_->height}});
  ALOGE_IF(error != HWC::Error::None,
           "Layer::UpdateLayerSettings: Error setting layer visible region: %s",
           error.to_string().c_str());

  error =
      hwc2_hidl_->setLayerPlaneAlpha(display, hardware_composer_layer_, 1.0f);
  ALOGE_IF(error != HWC::Error::None,
           "Layer::UpdateLayerSettings: Error setting layer plane alpha: %s",
           error.to_string().c_str());

  error =
      hwc2_hidl_->setLayerZOrder(display, hardware_composer_layer_, z_order_);
  ALOGE_IF(error != HWC::Error::None,
           "Layer::UpdateLayerSettings: Error setting z_ order: %s",
           error.to_string().c_str());
}

void Layer::CommonLayerSetup() {
  HWC::Error error =
      hwc2_hidl_->createLayer(HWC_DISPLAY_PRIMARY, &hardware_composer_layer_);
  ALOGE_IF(
      error != HWC::Error::None,
      "Layer::CommonLayerSetup: Failed to create layer on primary display: %s",
      error.to_string().c_str());
  UpdateLayerSettings();
}

void Layer::Prepare() {
  int right, bottom;
  sp<GraphicBuffer> handle;

  // Acquire the next buffer according to the type of source.
  IfAnyOf<SourceSurface, SourceBuffer>::Call(&source_, [&](auto& source) {
    std::tie(right, bottom, handle, acquire_fence_) = source.Acquire();
  });

  // When a layer is first setup there may be some time before the first buffer
  // arrives. Setup the HWC layer as a solid color to stall for time until the
  // first buffer arrives. Once the first buffer arrives there will always be a
  // buffer for the frame even if it is old.
  if (!handle.get()) {
    if (composition_type_ == HWC::Composition::Invalid) {
      composition_type_ = HWC::Composition::SolidColor;
      hwc2_hidl_->setLayerCompositionType(
          HWC_DISPLAY_PRIMARY, hardware_composer_layer_,
          composition_type_.cast<Hwc2::IComposerClient::Composition>());
      Hwc2::IComposerClient::Color layer_color = {0, 0, 0, 0};
      hwc2_hidl_->setLayerColor(HWC_DISPLAY_PRIMARY, hardware_composer_layer_,
                                layer_color);
    } else {
      // The composition type is already set. Nothing else to do until a
      // buffer arrives.
    }
  } else {
    if (composition_type_ != target_composition_type_) {
      composition_type_ = target_composition_type_;
      hwc2_hidl_->setLayerCompositionType(
          HWC_DISPLAY_PRIMARY, hardware_composer_layer_,
          composition_type_.cast<Hwc2::IComposerClient::Composition>());
    }

    HWC::Error error{HWC::Error::None};
    error = hwc2_hidl_->setLayerBuffer(HWC_DISPLAY_PRIMARY,
                                       hardware_composer_layer_, 0, handle,
                                       acquire_fence_.Get());

    ALOGE_IF(error != HWC::Error::None,
             "Layer::Prepare: Error setting layer buffer: %s",
             error.to_string().c_str());

    if (!surface_rect_functions_applied_) {
      const float float_right = right;
      const float float_bottom = bottom;
      error = hwc2_hidl_->setLayerSourceCrop(HWC_DISPLAY_PRIMARY,
                                             hardware_composer_layer_,
                                             {0, 0, float_right, float_bottom});

      ALOGE_IF(error != HWC::Error::None,
               "Layer::Prepare: Error setting layer source crop: %s",
               error.to_string().c_str());

      surface_rect_functions_applied_ = true;
    }
  }
}

void Layer::Finish(int release_fence_fd) {
  IfAnyOf<SourceSurface, SourceBuffer>::Call(
      &source_, [release_fence_fd](auto& source) {
        source.Finish(LocalHandle(release_fence_fd));
      });
}

void Layer::Drop() { acquire_fence_.Close(); }

}  // namespace dvr
}  // namespace android
