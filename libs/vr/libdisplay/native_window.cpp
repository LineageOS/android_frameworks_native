#include <EGL/egl.h>

#include <android/native_window.h>
#include <base/logging.h>
#include <cutils/native_handle.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <string.h>
#include <sys/timerfd.h>
#include <system/window.h>
#include <time.h>
#include <ui/ANativeObjectBase.h>
#include <utils/Errors.h>

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <cutils/log.h>

#include <memory>
#include <mutex>

#include <dvr/graphics.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/display_client.h>
#include <private/dvr/native_buffer.h>
#include <private/dvr/native_buffer_queue.h>

namespace {

constexpr int kDefaultDisplaySurfaceUsage =
    GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;
constexpr int kDefaultDisplaySurfaceFormat = HAL_PIXEL_FORMAT_RGBA_8888;
constexpr int kWarpedDisplaySurfaceFlags = 0;
constexpr int kUnwarpedDisplaySurfaceFlags =
    DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_EDS |
    DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION |
    DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_CAC;
constexpr int kDefaultBufferCount = 4;

}  // anonymous namespace

namespace android {
namespace dvr {

// NativeWindow is an implementation of ANativeWindow. This class interacts with
// displayd through the DisplaySurfaceClient and NativeBufferQueue.
class NativeWindow : public ANativeObjectBase<ANativeWindow, NativeWindow,
                                              LightRefBase<NativeWindow> > {
 public:
  explicit NativeWindow(const std::shared_ptr<DisplaySurfaceClient>& surface);

  void SetVisible(bool visible);
  void SetZOrder(int z_order);
  void PostEarly();

 private:
  friend class LightRefBase<NativeWindow>;

  void Post(sp<NativeBufferProducer> buffer, int fence_fd);

  static int SetSwapInterval(ANativeWindow* window, int interval);
  static int DequeueBuffer(ANativeWindow* window, ANativeWindowBuffer** buffer,
                           int* fence_fd);
  static int QueueBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer,
                         int fence_fd);
  static int CancelBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer,
                          int fence_fd);
  static int Query(const ANativeWindow* window, int what, int* value);
  static int Perform(ANativeWindow* window, int operation, ...);

  static int DequeueBuffer_DEPRECATED(ANativeWindow* window,
                                      ANativeWindowBuffer** buffer);
  static int CancelBuffer_DEPRECATED(ANativeWindow* window,
                                     ANativeWindowBuffer* buffer);
  static int QueueBuffer_DEPRECATED(ANativeWindow* window,
                                    ANativeWindowBuffer* buffer);
  static int LockBuffer_DEPRECATED(ANativeWindow* window,
                                   ANativeWindowBuffer* buffer);

  std::shared_ptr<DisplaySurfaceClient> surface_;

  std::mutex lock_;
  NativeBufferQueue buffer_queue_;
  sp<NativeBufferProducer> next_post_buffer_;
  bool next_buffer_already_posted_;

  NativeWindow(const NativeWindow&) = delete;
  void operator=(NativeWindow&) = delete;
};

NativeWindow::NativeWindow(const std::shared_ptr<DisplaySurfaceClient>& surface)
    : surface_(surface),
      buffer_queue_(surface, kDefaultBufferCount),
      next_post_buffer_(nullptr),
      next_buffer_already_posted_(false) {
  ANativeWindow::setSwapInterval = SetSwapInterval;
  ANativeWindow::dequeueBuffer = DequeueBuffer;
  ANativeWindow::cancelBuffer = CancelBuffer;
  ANativeWindow::queueBuffer = QueueBuffer;
  ANativeWindow::query = Query;
  ANativeWindow::perform = Perform;

  ANativeWindow::dequeueBuffer_DEPRECATED = DequeueBuffer_DEPRECATED;
  ANativeWindow::cancelBuffer_DEPRECATED = CancelBuffer_DEPRECATED;
  ANativeWindow::lockBuffer_DEPRECATED = LockBuffer_DEPRECATED;
  ANativeWindow::queueBuffer_DEPRECATED = QueueBuffer_DEPRECATED;
}

void NativeWindow::SetVisible(bool visible) { surface_->SetVisible(visible); }

void NativeWindow::SetZOrder(int z_order) { surface_->SetZOrder(z_order); }

void NativeWindow::PostEarly() {
  ATRACE_NAME("NativeWindow::PostEarly");
  ALOGI_IF(TRACE, "NativeWindow::PostEarly");

  std::lock_guard<std::mutex> autolock(lock_);

  if (!next_buffer_already_posted_) {
    next_buffer_already_posted_ = true;

    if (!next_post_buffer_.get()) {
      next_post_buffer_ = buffer_queue_.Dequeue();
    }
    ATRACE_ASYNC_BEGIN("BufferPost", next_post_buffer_->buffer()->id());
    Post(next_post_buffer_, -1);
  }
}

void NativeWindow::Post(sp<NativeBufferProducer> buffer, int fence_fd) {
  ATRACE_NAME(__PRETTY_FUNCTION__);
  ALOGI_IF(TRACE, "NativeWindow::Post: buffer_id=%d, fence_fd=%d",
           buffer->buffer()->id(), fence_fd);
  ALOGW_IF(!surface_->visible(),
           "NativeWindow::Post: Posting buffer on invisible surface!!!");
  buffer->Post(fence_fd, 0);
}

int NativeWindow::SetSwapInterval(ANativeWindow* window, int interval) {
  ALOGI_IF(TRACE, "SetSwapInterval: window=%p interval=%d", window, interval);
  return 0;
}

int NativeWindow::DequeueBuffer(ANativeWindow* window,
                                ANativeWindowBuffer** buffer, int* fence_fd) {
  ATRACE_NAME(__PRETTY_FUNCTION__);

  NativeWindow* self = getSelf(window);
  std::lock_guard<std::mutex> autolock(self->lock_);

  if (!self->next_post_buffer_.get()) {
    self->next_post_buffer_ = self->buffer_queue_.Dequeue();
  }
  ATRACE_ASYNC_BEGIN("BufferDraw", self->next_post_buffer_->buffer()->id());
  *fence_fd = self->next_post_buffer_->ClaimReleaseFence().Release();
  *buffer = self->next_post_buffer_.get();

  ALOGI_IF(TRACE, "NativeWindow::DequeueBuffer: fence_fd=%d", *fence_fd);
  return 0;
}

int NativeWindow::QueueBuffer(ANativeWindow* window,
                              ANativeWindowBuffer* buffer, int fence_fd) {
  ATRACE_NAME("NativeWindow::QueueBuffer");
  ALOGI_IF(TRACE, "NativeWindow::QueueBuffer: fence_fd=%d", fence_fd);

  NativeWindow* self = getSelf(window);
  std::lock_guard<std::mutex> autolock(self->lock_);

  NativeBufferProducer* native_buffer =
      static_cast<NativeBufferProducer*>(buffer);
  ATRACE_ASYNC_END("BufferDraw", native_buffer->buffer()->id());
  bool do_post = true;
  if (self->next_buffer_already_posted_) {
    // Check that the buffer is the one we expect, but handle it if this happens
    // in production by allowing this buffer to post on top of the previous one.
    DCHECK(native_buffer == self->next_post_buffer_.get());
    if (native_buffer == self->next_post_buffer_.get()) {
      do_post = false;
      if (fence_fd >= 0)
        close(fence_fd);
    }
  }
  if (do_post) {
    ATRACE_ASYNC_BEGIN("BufferPost", native_buffer->buffer()->id());
    self->Post(native_buffer, fence_fd);
  }
  self->next_buffer_already_posted_ = false;
  self->next_post_buffer_ = nullptr;

  return NO_ERROR;
}

int NativeWindow::CancelBuffer(ANativeWindow* window,
                               ANativeWindowBuffer* buffer, int fence_fd) {
  ATRACE_NAME("NativeWindow::CancelBuffer");
  ALOGI_IF(TRACE, "NativeWindow::CancelBuffer: fence_fd: %d", fence_fd);

  NativeWindow* self = getSelf(window);
  std::lock_guard<std::mutex> autolock(self->lock_);

  NativeBufferProducer* native_buffer =
      static_cast<NativeBufferProducer*>(buffer);
  ATRACE_ASYNC_END("BufferDraw", native_buffer->buffer()->id());
  ATRACE_INT("CancelBuffer", native_buffer->buffer()->id());
  bool do_enqueue = true;
  if (self->next_buffer_already_posted_) {
    // Check that the buffer is the one we expect, but handle it if this happens
    // in production by returning this buffer to the buffer queue.
    DCHECK(native_buffer == self->next_post_buffer_.get());
    if (native_buffer == self->next_post_buffer_.get()) {
      do_enqueue = false;
    }
  }
  if (do_enqueue) {
    self->buffer_queue_.Enqueue(native_buffer);
  }
  if (fence_fd >= 0)
    close(fence_fd);
  self->next_buffer_already_posted_ = false;
  self->next_post_buffer_ = nullptr;

  return NO_ERROR;
}

int NativeWindow::Query(const ANativeWindow* window, int what, int* value) {
  NativeWindow* self = getSelf(const_cast<ANativeWindow*>(window));
  std::lock_guard<std::mutex> autolock(self->lock_);

  switch (what) {
    case NATIVE_WINDOW_WIDTH:
      *value = self->surface_->width();
      return NO_ERROR;
    case NATIVE_WINDOW_HEIGHT:
      *value = self->surface_->height();
      return NO_ERROR;
    case NATIVE_WINDOW_FORMAT:
      *value = self->surface_->format();
      return NO_ERROR;
    case NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS:
      *value = 1;
      return NO_ERROR;
    case NATIVE_WINDOW_CONCRETE_TYPE:
      *value = NATIVE_WINDOW_SURFACE;
      return NO_ERROR;
    case NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER:
      *value = 1;
      return NO_ERROR;
    case NATIVE_WINDOW_DEFAULT_WIDTH:
      *value = self->surface_->width();
      return NO_ERROR;
    case NATIVE_WINDOW_DEFAULT_HEIGHT:
      *value = self->surface_->height();
      return NO_ERROR;
    case NATIVE_WINDOW_TRANSFORM_HINT:
      *value = 0;
      return NO_ERROR;
  }

  *value = 0;
  return BAD_VALUE;
}

int NativeWindow::Perform(ANativeWindow* window, int operation, ...) {
  NativeWindow* self = getSelf(window);
  std::lock_guard<std::mutex> autolock(self->lock_);

  va_list args;
  va_start(args, operation);

  // TODO(eieio): The following operations are not used at this time. They are
  // included here to help document which operations may be useful and what
  // parameters they take.
  switch (operation) {
    case NATIVE_WINDOW_SET_BUFFERS_DIMENSIONS: {
      int w = va_arg(args, int);
      int h = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_DIMENSIONS: w=%d h=%d", w, h);
      return NO_ERROR;
    }

    case NATIVE_WINDOW_SET_BUFFERS_FORMAT: {
      int format = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_FORMAT: format=%d", format);
      return NO_ERROR;
    }

    case NATIVE_WINDOW_SET_BUFFERS_TRANSFORM: {
      int transform = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_TRANSFORM: transform=%d",
               transform);
      return NO_ERROR;
    }

    case NATIVE_WINDOW_SET_USAGE: {
      int usage = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_USAGE: usage=%d", usage);
      return NO_ERROR;
    }

    case NATIVE_WINDOW_CONNECT:
    case NATIVE_WINDOW_DISCONNECT:
    case NATIVE_WINDOW_SET_BUFFERS_GEOMETRY:
    case NATIVE_WINDOW_API_CONNECT:
    case NATIVE_WINDOW_API_DISCONNECT:
      // TODO(eieio): we should implement these
      return NO_ERROR;

    case NATIVE_WINDOW_SET_BUFFER_COUNT: {
      int buffer_count = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFER_COUNT: bufferCount=%d",
               buffer_count);
      return NO_ERROR;
    }
    case NATIVE_WINDOW_SET_BUFFERS_DATASPACE: {
      android_dataspace_t data_space =
          static_cast<android_dataspace_t>(va_arg(args, int));
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_DATASPACE: dataSpace=%d",
               data_space);
      return NO_ERROR;
    }
    case NATIVE_WINDOW_SET_SCALING_MODE: {
      int mode = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_SCALING_MODE: mode=%d", mode);
      return NO_ERROR;
    }

    case NATIVE_WINDOW_LOCK:
    case NATIVE_WINDOW_UNLOCK_AND_POST:
    case NATIVE_WINDOW_SET_CROP:
    case NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP:
      return INVALID_OPERATION;
  }

  return NAME_NOT_FOUND;
}

int NativeWindow::DequeueBuffer_DEPRECATED(ANativeWindow* window,
                                           ANativeWindowBuffer** buffer) {
  int fence_fd = -1;
  int ret = DequeueBuffer(window, buffer, &fence_fd);

  // wait for fence
  if (ret == NO_ERROR && fence_fd != -1)
    close(fence_fd);

  return ret;
}

int NativeWindow::CancelBuffer_DEPRECATED(ANativeWindow* window,
                                          ANativeWindowBuffer* buffer) {
  return CancelBuffer(window, buffer, -1);
}

int NativeWindow::QueueBuffer_DEPRECATED(ANativeWindow* window,
                                         ANativeWindowBuffer* buffer) {
  return QueueBuffer(window, buffer, -1);
}

int NativeWindow::LockBuffer_DEPRECATED(ANativeWindow* /*window*/,
                                        ANativeWindowBuffer* /*buffer*/) {
  return NO_ERROR;
}

}  // namespace dvr
}  // namespace android

static EGLNativeWindowType CreateDisplaySurface(int* display_width,
                                                int* display_height, int format,
                                                int usage, int flags) {
  auto client = android::dvr::DisplayClient::Create();
  if (!client) {
    ALOGE("Failed to create display client!");
    return nullptr;
  }

  // TODO(eieio,jbates): Consider passing flags and other parameters to get
  // metrics based on specific surface requirements.
  android::dvr::SystemDisplayMetrics metrics;
  const int ret = client->GetDisplayMetrics(&metrics);
  if (ret < 0) {
    ALOGE("Failed to get display metrics: %s", strerror(-ret));
    return nullptr;
  }

  int width, height;

  if (flags & DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION) {
    width = metrics.display_native_width;
    height = metrics.display_native_height;
  } else {
    width = metrics.distorted_width;
    height = metrics.distorted_height;
  }

  std::shared_ptr<android::dvr::DisplaySurfaceClient> surface =
      client->CreateDisplaySurface(width, height, format, usage, flags);

  if (display_width)
    *display_width = metrics.display_native_width;
  if (display_height)
    *display_height = metrics.display_native_height;

  // Set the surface visible by default.
  // TODO(eieio,jbates): Remove this from here and set visible somewhere closer
  // to the application to account for situations where the application wants to
  // create surfaces that will be used later or shouldn't be visible yet.
  surface->SetVisible(true);

  return new android::dvr::NativeWindow(surface);
}

std::shared_ptr<android::dvr::DisplaySurfaceClient> CreateDisplaySurfaceClient(
    struct DvrSurfaceParameter* parameters,
    /*out*/ android::dvr::SystemDisplayMetrics* metrics);

extern "C" EGLNativeWindowType dvrCreateDisplaySurfaceExtended(
    struct DvrSurfaceParameter* parameters) {
  android::dvr::SystemDisplayMetrics metrics;
  auto surface = CreateDisplaySurfaceClient(parameters, &metrics);
  if (!surface) {
    ALOGE("Failed to create display surface client");
    return nullptr;
  }
  return new android::dvr::NativeWindow(surface);
}

extern "C" EGLNativeWindowType dvrCreateDisplaySurface() {
  return CreateDisplaySurface(NULL, NULL, kDefaultDisplaySurfaceFormat,
                              kDefaultDisplaySurfaceUsage,
                              kUnwarpedDisplaySurfaceFlags);
}

extern "C" EGLNativeWindowType dvrCreateWarpedDisplaySurface(
    int* display_width, int* display_height) {
  return CreateDisplaySurface(
      display_width, display_height, kDefaultDisplaySurfaceFormat,
      kDefaultDisplaySurfaceUsage, kWarpedDisplaySurfaceFlags);
}

extern "C" void dvrDisplaySurfaceSetVisible(EGLNativeWindowType window,
                                            int visible) {
  auto native_window = reinterpret_cast<android::dvr::NativeWindow*>(window);
  native_window->SetVisible(visible);
}

extern "C" void dvrDisplaySurfaceSetZOrder(EGLNativeWindowType window,
                                           int z_order) {
  auto native_window = reinterpret_cast<android::dvr::NativeWindow*>(window);
  native_window->SetZOrder(z_order);
}

extern "C" void dvrDisplayPostEarly(EGLNativeWindowType window) {
  auto native_window = reinterpret_cast<android::dvr::NativeWindow*>(window);
  native_window->PostEarly();
}
