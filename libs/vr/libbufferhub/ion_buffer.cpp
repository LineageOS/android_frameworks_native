#include <private/dvr/ion_buffer.h>
#include <ui/GraphicBufferMapper.h>

#include <log/log.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <mutex>

namespace android {
namespace dvr {

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
    : buffer_(nullptr) {
  ALOGD_IF(TRACE,
         "IonBuffer::IonBuffer: handle=%p width=%d height=%d layer_count=%d "
         "stride=%d layer stride=%d format=%d usage=%d",
         handle, width, height, layer_count, stride, layer_stride,
         format, usage);
  if (handle != 0) {
    Import(handle, width, height, stride, format, usage);
  }
}

IonBuffer::~IonBuffer() {
  ALOGD_IF(TRACE,
           "IonBuffer::~IonBuffer: handle=%p width=%d height=%d stride=%d "
           "format=%d usage=%d",
           handle() , width(), height(), stride(), format(), usage());
  FreeHandle();
}

IonBuffer::IonBuffer(IonBuffer&& other) : IonBuffer() {
  *this = std::move(other);
}

IonBuffer& IonBuffer::operator=(IonBuffer&& other) {
  ALOGD_IF(TRACE, "IonBuffer::operator=: handle_=%p other.handle_=%p", handle(),
           other.handle());

  if (this != &other) {
    buffer_ = other.buffer_;
    other.FreeHandle();
  }
  return *this;
}

void IonBuffer::FreeHandle() {
  if (buffer_.get()) {
    // GraphicBuffer unregisters and cleans up the handle if needed
    buffer_ = nullptr;
  }
}

int IonBuffer::Alloc(int width, int height, int format, int usage) {
  ALOGD_IF(TRACE, "IonBuffer::Alloc: width=%d height=%d format=%d usage=%d",
           width, height, format, usage);

  GraphicBufferMapper& mapper = GraphicBufferMapper::get();
  buffer_ = new GraphicBuffer(width, height, format, usage);
  if (mapper.registerBuffer(buffer_.get()) != OK) {
    ALOGE("IonBuffer::Aloc: Failed to register buffer");
  }
  return 0;
}

void IonBuffer::Reset(buffer_handle_t handle, int width, int height, int stride,
                      int format, int usage) {
  ALOGD_IF(TRACE,
           "IonBuffer::Reset: handle=%p width=%d height=%d stride=%d format=%d "
           "usage=%d",
           handle, width, height, stride, format, usage);
  Import(handle, width, height, stride, format, usage);
}

int IonBuffer::Import(buffer_handle_t handle, int width, int height, int stride,
                      int format, int usage) {
  ATRACE_NAME("IonBuffer::Import1");
  ALOGD_IF(
      TRACE,
      "IonBuffer::Import: handle=%p width=%d height=%d stride=%d format=%d "
      "usage=%d",
      handle, width, height, stride, format, usage);
  FreeHandle();
  GraphicBufferMapper& mapper = GraphicBufferMapper::get();
  buffer_ = new GraphicBuffer(width, height, format, 1, usage,
                              stride, (native_handle_t*)handle, true);
  if (mapper.registerBuffer(buffer_.get()) != OK) {
    ALOGE("IonBuffer::Import: Failed to register cloned buffer");
    return -EINVAL;
  }
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
           handle(), usage, x, y, width, height, address);

  status_t err = buffer_->lock(usage, Rect(x, y, x + width, y + height),
                               address);
  if (err != NO_ERROR)
    return -EINVAL;
  else
    return 0;
}

int IonBuffer::LockYUV(int usage, int x, int y, int width, int height,
                       struct android_ycbcr* yuv) {
  ATRACE_NAME("IonBuffer::LockYUV");
  ALOGD_IF(TRACE,
           "IonBuffer::Lock: handle=%p usage=%d x=%d y=%d width=%d height=%d",
           handle(), usage, x, y, width, height);

  status_t err = buffer_->lockYCbCr(usage, Rect(x, y, x + width, y + height),
                                    yuv);
  if (err != NO_ERROR)
    return -EINVAL;
  else
    return 0;
}

int IonBuffer::Unlock() {
  ATRACE_NAME("IonBuffer::Unlock");
  ALOGD_IF(TRACE, "IonBuffer::Unlock: handle=%p", handle());

  status_t err = buffer_->unlock();
  if (err != NO_ERROR)
    return -EINVAL;
  else
    return 0;
}
} // namespace dvr
} // namespace android
