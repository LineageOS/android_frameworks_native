#include <private/dvr/ion_buffer.h>

#include <cutils/log.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <mutex>

namespace android {
namespace dvr {

gralloc_module_t const* IonBuffer::gralloc_module_ = nullptr;
alloc_device_t* IonBuffer::gralloc_device_ = nullptr;

IonBuffer::IonBuffer() : IonBuffer(nullptr, 0, 0, 0, 0, 0, 0, 0) {}

IonBuffer::IonBuffer(int width, int height, int format, int usage)
    : IonBuffer() {
  Alloc(width, height, format, usage);
}

IonBuffer::IonBuffer(buffer_handle_t handle, int width, int height, int stride,
                     int format, int usage)
    : IonBuffer(handle, width, height, 1, stride, 0, format, usage) {}

IonBuffer::IonBuffer(buffer_handle_t handle, int width, int height,
                     int layer_count, int stride, int layer_stride, int format,
                     int usage)
    : handle_(handle),
      width_(width),
      height_(height),
      layer_count_(layer_count),
      stride_(stride),
      layer_stride_(layer_stride),
      format_(format),
      usage_(usage),
      locked_(false),
      needs_unregister_(false) {
  ALOGD_IF(TRACE,
           "IonBuffer::IonBuffer: handle=%p width=%d height=%d layer_count=%d "
           "stride=%d layer stride=%d format=%d usage=%d",
           handle_, width_, height_, layer_count_, stride_, layer_stride_,
           format_, usage_);
  GrallocInit();
}

IonBuffer::~IonBuffer() {
  ALOGD_IF(TRACE,
           "IonBuffer::~IonBuffer: handle=%p width=%d height=%d stride=%d "
           "format=%d usage=%d",
           handle_, width_, height_, stride_, format_, usage_);

  FreeHandle();
}

IonBuffer::IonBuffer(IonBuffer&& other) : IonBuffer() {
  *this = std::move(other);
}

IonBuffer& IonBuffer::operator=(IonBuffer&& other) {
  ALOGD_IF(TRACE, "IonBuffer::operator=: handle_=%p other.handle_=%p", handle_,
           other.handle_);

  if (this != &other) {
    Replace(other.handle_, other.width_, other.height_, other.layer_count_,
            other.stride_, other.layer_stride_, other.format_, other.usage_,
            other.needs_unregister_);
    locked_ = other.locked_;
    other.handle_ = nullptr;
    other.FreeHandle();
  }

  return *this;
}

void IonBuffer::FreeHandle() {
  if (handle_) {
    // Lock/Unlock don't need to be balanced, but one Unlock is needed to
    // clean/unmap the buffer. Warn if this didn't happen before freeing the
    // native handle.
    ALOGW_IF(locked_,
             "IonBuffer::FreeHandle: freeing a locked handle!!! handle=%p",
             handle_);

    if (needs_unregister_) {
      int ret = gralloc_module_->unregisterBuffer(gralloc_module_, handle_);
      ALOGE_IF(ret < 0,
               "IonBuffer::FreeHandle: Failed to unregister handle: %s",
               strerror(-ret));

      native_handle_close(const_cast<native_handle_t*>(handle_));
      native_handle_delete(const_cast<native_handle_t*>(handle_));
    } else {
      int ret = gralloc_device_->free(gralloc_device_, handle_);
      if (ret < 0) {
        ALOGE("IonBuffer::FreeHandle: failed to free buffer: %s",
              strerror(-ret));

        // Not sure if this is the right thing to do. Attempting to prevent a
        // memory leak of the native handle.
        native_handle_close(const_cast<native_handle_t*>(handle_));
        native_handle_delete(const_cast<native_handle_t*>(handle_));
      }
    }
  }

  // Always re-initialize these members, even if handle_ was nullptr, in case
  // someone was dumb enough to pass a nullptr handle to the constructor or
  // Reset.
  handle_ = nullptr;
  width_ = 0;
  height_ = 0;
  layer_count_ = 0;
  stride_ = 0;
  layer_stride_ = 0;
  format_ = 0;
  usage_ = 0;
  locked_ = false;
  needs_unregister_ = false;
}

int IonBuffer::Alloc(int width, int height, int format, int usage) {
  ATRACE_NAME("IonBuffer::Alloc");
  ALOGD_IF(TRACE, "IonBuffer::Alloc: width=%d height=%d format=%d usage=%d",
           width, height, format, usage);

  int stride;
  buffer_handle_t handle;

  int ret = gralloc_device_->alloc(gralloc_device_, width, height, format,
                                   usage, &handle, &stride);
  if (ret < 0) {
    ALOGE("IonBuffer::Alloc: failed to allocate gralloc buffer: %s",
          strerror(-ret));
    return ret;
  }

  Replace(handle, width, height, 1, stride, 0, format, usage, false);
  return 0;
}

void IonBuffer::Replace(buffer_handle_t handle, int width, int height,
                        int layer_count, int stride, int layer_stride,
                        int format, int usage, bool needs_unregister) {
  FreeHandle();

  handle_ = handle;
  width_ = width;
  height_ = height;
  layer_count_ = layer_count;
  stride_ = stride;
  layer_stride_ = layer_stride;
  format_ = format;
  usage_ = usage;
  needs_unregister_ = needs_unregister;
}

void IonBuffer::Reset(buffer_handle_t handle, int width, int height, int stride,
                      int format, int usage) {
  ALOGD_IF(TRACE,
           "IonBuffer::Reset: handle=%p width=%d height=%d stride=%d format=%d "
           "usage=%d",
           handle, width, height, stride, format, usage);

  Replace(handle, width, height, 1, stride, 0, format, usage, false);
}

int IonBuffer::Import(buffer_handle_t handle, int width, int height, int stride,
                      int format, int usage) {
  ATRACE_NAME("IonBuffer::Import1");
  ALOGD_IF(
      TRACE,
      "IonBuffer::Import: handle=%p width=%d height=%d stride=%d format=%d "
      "usage=%d",
      handle, width, height, stride, format, usage);

  int ret = gralloc_module_->registerBuffer(gralloc_module_, handle);
  if (ret < 0) {
    ALOGE("IonBuffer::Import: failed to import handle: %s", strerror(-ret));
    return ret;
  }

  Replace(handle, width, height, 1, stride, 0, format, usage, true);
  return 0;
}

int IonBuffer::Import(const int* fd_array, int fd_count, const int* int_array,
                      int int_count, int width, int height, int stride,
                      int format, int usage) {
  ATRACE_NAME("IonBuffer::Import2");
  ALOGD_IF(TRACE,
           "IonBuffer::Import: fd_count=%d int_count=%d width=%d height=%d "
           "stride=%d format=%d usage=%d",
           fd_count, int_count, width, height, stride, format, usage);

  if (fd_count < 0 || int_count < 0) {
    ALOGE("IonBuffer::Import: invalid arguments.");
    return -EINVAL;
  }

  native_handle_t* handle = native_handle_create(fd_count, int_count);
  if (!handle) {
    ALOGE("IonBuffer::Import: failed to create new native handle.");
    return -ENOMEM;
  }

  // Copy fd_array into the first part of handle->data and int_array right
  // after it.
  memcpy(handle->data, fd_array, sizeof(int) * fd_count);
  memcpy(handle->data + fd_count, int_array, sizeof(int) * int_count);

  int ret = Import(handle, width, height, stride, format, usage);
  if (ret < 0) {
    ALOGE("IonBuffer::Import: failed to import raw native handle: %s",
          strerror(-ret));
    native_handle_close(handle);
    native_handle_delete(handle);
  }

  return ret;
}

int IonBuffer::Duplicate(const IonBuffer* other) {
  if (!other->handle())
    return -EINVAL;

  const int fd_count = other->handle()->numFds;
  const int int_count = other->handle()->numInts;

  if (fd_count < 0 || int_count < 0)
    return -EINVAL;

  native_handle_t* handle = native_handle_create(fd_count, int_count);
  if (!handle) {
    ALOGE("IonBuffer::Duplicate: Failed to create new native handle.");
    return -ENOMEM;
  }

  // Duplicate the file descriptors from the other native handle.
  for (int i = 0; i < fd_count; i++)
    handle->data[i] = dup(other->handle()->data[i]);

  // Copy the ints after the file descriptors.
  memcpy(handle->data + fd_count, other->handle()->data + fd_count,
         sizeof(int) * int_count);

  const int ret = Import(handle, other->width(), other->height(),
                         other->stride(), other->format(), other->usage());
  if (ret < 0) {
    ALOGE("IonBuffer::Duplicate: Failed to import duplicate native handle: %s",
          strerror(-ret));
    native_handle_close(handle);
    native_handle_delete(handle);
  }

  return ret;
}

int IonBuffer::Lock(int usage, int x, int y, int width, int height,
                    void** address) {
  ATRACE_NAME("IonBuffer::Lock");
  ALOGD_IF(TRACE,
           "IonBuffer::Lock: handle=%p usage=%d x=%d y=%d width=%d height=%d "
           "address=%p",
           handle_, usage, x, y, width, height, address);

  // Lock may be called multiple times; but only one Unlock is required.
  const int err = gralloc_module_->lock(gralloc_module_, handle_, usage, x, y,
                                        width, height, address);
  if (!err)
    locked_ = true;

  return err;
}

int IonBuffer::LockYUV(int usage, int x, int y, int width, int height,
                       struct android_ycbcr* yuv) {
  ATRACE_NAME("IonBuffer::LockYUV");
  ALOGD_IF(TRACE,
           "IonBuffer::Lock: handle=%p usage=%d x=%d y=%d width=%d height=%d",
           handle_, usage, x, y, width, height);
  const int err = gralloc_module_->lock_ycbcr(gralloc_module_, handle_, usage,
                                              x, y, width, height, yuv);
  if (!err)
    locked_ = true;

  return err;
}

int IonBuffer::Unlock() {
  ATRACE_NAME("IonBuffer::Unlock");
  ALOGD_IF(TRACE, "IonBuffer::Unlock: handle=%p", handle_);

  // Lock may be called multiple times; but only one Unlock is required.
  const int err = gralloc_module_->unlock(gralloc_module_, handle_);
  if (!err)
    locked_ = false;

  return err;
}

void IonBuffer::GrallocInit() {
  static std::once_flag gralloc_flag;
  std::call_once(gralloc_flag, []() {
    hw_module_t const* module = nullptr;
    alloc_device_t* device = nullptr;

    int err = hw_get_module(GRALLOC_HARDWARE_MODULE_ID, &module);
    ALOGE_IF(err, "IonBuffer::GrallocInit: failed to find the %s module: %s",
             GRALLOC_HARDWARE_MODULE_ID, strerror(-err));

    err = gralloc_open(module, &device);
    ALOGE_IF(err, "IonBuffer::GrallocInit: failed to open gralloc device: %s",
             strerror(-err));

    gralloc_module_ = reinterpret_cast<gralloc_module_t const*>(module);
    gralloc_device_ = device;
  });
}

}  // namespace dvr
}  // namespace android
