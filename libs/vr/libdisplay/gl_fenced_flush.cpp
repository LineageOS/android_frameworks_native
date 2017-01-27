#include "include/private/dvr/gl_fenced_flush.h"

#include <EGL/eglext.h>
#include <GLES3/gl31.h>

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <base/logging.h>

using android::pdx::LocalHandle;

namespace android {
namespace dvr {

LocalHandle CreateGLSyncAndFlush(EGLDisplay display) {
  ATRACE_NAME("CreateGLSyncAndFlush");

  EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_FD_ANDROID,
                      EGL_NO_NATIVE_FENCE_FD_ANDROID, EGL_NONE};
  EGLSyncKHR sync_point =
      eglCreateSyncKHR(display, EGL_SYNC_NATIVE_FENCE_ANDROID, attribs);
  glFlush();
  if (sync_point == EGL_NO_SYNC_KHR) {
    LOG(ERROR) << "sync_point == EGL_NO_SYNC_KHR";
    return LocalHandle();
  }
  EGLint fence_fd = eglDupNativeFenceFDANDROID(display, sync_point);
  eglDestroySyncKHR(display, sync_point);

  if (fence_fd == EGL_NO_NATIVE_FENCE_FD_ANDROID) {
    LOG(ERROR) << "fence_fd == EGL_NO_NATIVE_FENCE_FD_ANDROID";
    return LocalHandle();
  }
  return LocalHandle(fence_fd);
}

}  // namespace dvr
}  // namespace android
