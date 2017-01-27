#ifndef ANDROID_DVR_GRAPHICS_EGL_IMAGE_H_
#define ANDROID_DVR_GRAPHICS_EGL_IMAGE_H_

#include <EGL/egl.h>
#include <EGL/eglext.h>

namespace android {
namespace dvr {

// Create an EGLImage with texture storage defined by the given format and
// usage flags.
// For example, to create an RGBA texture for rendering to, specify:
//   format = HAL_PIXEL_FORMAT_RGBA_8888;
//   usage = GRALLOC_USAGE_HW_FB | GRALLOC_USAGE_HW_RENDER;
EGLImageKHR CreateEglImage(EGLDisplay dpy, int width, int height, int format,
                           int usage);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_EGL_IMAGE_H_
