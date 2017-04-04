#ifndef ANDROID_DVR_ION_BUFFER_H_
#define ANDROID_DVR_ION_BUFFER_H_

#include <hardware/gralloc.h>
#include <log/log.h>
#include <ui/GraphicBuffer.h>

namespace android {
namespace dvr {

// IonBuffer is an abstraction of Ion/Gralloc buffers.
class IonBuffer {
 public:
  IonBuffer();
  IonBuffer(int width, int height, int format, int usage);
  IonBuffer(buffer_handle_t handle, int width, int height, int stride,
            int format, int usage);
  IonBuffer(buffer_handle_t handle, int width, int height, int layer_count,
            int stride, int layer_stride, int format, int usage);
  ~IonBuffer();

  IonBuffer(IonBuffer&& other);
  IonBuffer& operator=(IonBuffer&& other);

  // Frees the underlying native handle and leaves the instance initialized to
  // empty.
  void FreeHandle();

  // Allocates a new native handle with the given parameters, freeing the
  // previous native handle if necessary. Returns 0 on success or a negative
  // errno code otherwise. If allocation fails the previous native handle is
  // left intact.
  int Alloc(int width, int height, int format, int usage);

  // Resets the underlying native handle and parameters, freeing the previous
  // native handle if necessary.
  void Reset(buffer_handle_t handle, int width, int height, int stride,
             int format, int usage);

  // Like Reset but also registers the native handle, which is necessary for
  // native handles received over IPC. Returns 0 on success or a negative errno
  // code otherwise. If import fails the previous native handle is left intact.
  int Import(buffer_handle_t handle, int width, int height, int stride,
             int format, int usage);

  // Like Reset but imports a native handle from raw fd and int arrays. Returns
  // 0 on success or a negative errno code otherwise. If import fails the
  // previous native handle is left intact.
  int Import(const int* fd_array, int fd_count, const int* int_array,
             int int_count, int width, int height, int stride, int format,
             int usage);

  // Duplicates the native handle underlying |other| and then imports it. This
  // is useful for creating multiple, independent views of the same Ion/Gralloc
  // buffer. Returns 0 on success or a negative errno code otherwise. If
  // duplication or import fail the previous native handle is left intact.
  int Duplicate(const IonBuffer* other);

  int Lock(int usage, int x, int y, int width, int height, void** address);
  int LockYUV(int usage, int x, int y, int width, int height,
              struct android_ycbcr* yuv);
  int Unlock();

  const sp<GraphicBuffer>& buffer() const { return buffer_; }
  buffer_handle_t handle() const {
    return buffer_.get() ? buffer_->handle : nullptr;
  }
  int width() const { return buffer_.get() ? buffer_->getWidth() : 0; }
  int height() const { return buffer_.get() ? buffer_->getHeight() : 0; }
  int layer_count() const {
    return buffer_.get() ? buffer_->getLayerCount() : 0;
  }
  int stride() const { return buffer_.get() ? buffer_->getStride() : 0; }
  int layer_stride() const { return 0; }
  int format() const { return buffer_.get() ? buffer_->getPixelFormat() : 0; }
  int usage() const { return buffer_.get() ? buffer_->getUsage() : 0; }

 private:
  sp<GraphicBuffer> buffer_;

  IonBuffer(const IonBuffer&) = delete;
  void operator=(const IonBuffer&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_ION_BUFFER_H_
