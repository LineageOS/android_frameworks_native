#ifndef ANDROID_DVR_DEBUG_H_
#define ANDROID_DVR_DEBUG_H_

#include <GLES3/gl3.h>
#include <math.h>

#include <base/logging.h>

#ifndef NDEBUG
#define CHECK_GL()                          \
  do {                                      \
    const GLenum err = glGetError();        \
    if (err != GL_NO_ERROR) {               \
      LOG(ERROR) << "OpenGL error " << err; \
    }                                       \
  } while (0)

#define CHECK_GL_FBO()                                        \
  do {                                                        \
    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER); \
    switch (status) {                                         \
      case GL_FRAMEBUFFER_COMPLETE:                           \
        break;                                                \
      case GL_FRAMEBUFFER_UNSUPPORTED:                        \
        LOG(ERROR) << "GL_FRAMEBUFFER_UNSUPPORTED";           \
        break;                                                \
      default:                                                \
        LOG(ERROR) << "FBO user error: " << status;           \
        break;                                                \
    }                                                         \
  } while (0)
#else
#define CHECK_GL()
#define CHECK_GL_FBO()
#endif

#endif  // ANDROID_DVR_DEBUG_H_
