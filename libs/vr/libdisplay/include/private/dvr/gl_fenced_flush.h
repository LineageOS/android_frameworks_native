#ifndef ANDROID_DVR_GL_FENCED_FLUSH_H_
#define ANDROID_DVR_GL_FENCED_FLUSH_H_

#include <EGL/egl.h>
#include <pdx/file_handle.h>

namespace android {
namespace dvr {

// Creates a EGL_SYNC_NATIVE_FENCE_ANDROID and flushes. Returns the fence as a
// file descriptor.
pdx::LocalHandle CreateGLSyncAndFlush(EGLDisplay display);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GL_FENCED_FLUSH_H_
