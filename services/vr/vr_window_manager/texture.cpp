#include "texture.h"

#include <cutils/log.h>
#include <GLES/glext.h>
#include <system/window.h>

namespace android {
namespace dvr {

Texture::Texture() {}

Texture::~Texture() {
  EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (id_)
    glDeleteTextures(1, &id_);
  if (image_)
    eglDestroyImageKHR(display, image_);
}

bool Texture::Initialize(ANativeWindowBuffer* buffer) {
  width_ = buffer->width;
  height_ = buffer->height;

  EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  image_ = eglCreateImageKHR(display, EGL_NO_CONTEXT,
                             EGL_NATIVE_BUFFER_ANDROID, buffer, nullptr);
  if (!image_) {
    ALOGE("Failed to create eglImage");
    return false;
  }

  glGenTextures(1, &id_);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, id_);
  glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, image_);

  return true;
}

}  // namespace android
}  // namespace dvr
