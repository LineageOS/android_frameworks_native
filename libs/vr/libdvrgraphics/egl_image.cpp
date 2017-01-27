#include "include/private/dvr/graphics/egl_image.h"

#include <hardware/gralloc.h>

#include <memory>

#include <private/dvr/native_buffer.h>

namespace android {
namespace dvr {

EGLImageKHR CreateEglImage(EGLDisplay dpy, int width, int height, int format,
                           int usage) {
  auto image = std::make_shared<IonBuffer>(width, height, format, usage);

  return eglCreateImageKHR(
      dpy, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
      static_cast<ANativeWindowBuffer*>(new NativeBuffer(image)), nullptr);
}

}  // namespace dvr
}  // namespace android
