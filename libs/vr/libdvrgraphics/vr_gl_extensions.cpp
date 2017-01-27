#include "include/private/dvr/graphics/vr_gl_extensions.h"

PFNGLGETQUERYOBJECTI64VEXTPROC glGetQueryObjecti64v = NULL;
PFNGLGETQUERYOBJECTIVEXTPROC glGetQueryObjectiv = NULL;
PFNGLQUERYCOUNTEREXTPROC glQueryCounter = NULL;
PFNGLBUFFERSTORAGEEXTPROC glBufferStorage = NULL;
PFNGLFRAMEBUFFERTEXTUREMULTIVIEWOVR glFramebufferTextureMultiview = NULL;
PFNGLFRAMEBUFFERTEXTUREMULTISAMPLEMULTIVIEWOVR
glFramebufferTextureMultisampleMultiview = NULL;

PFNGLSHAREDBUFFERCREATEQCOM glCreateSharedBufferQCOM = NULL;
PFNGLSHAREDBUFFERDESTROYQCOM glDestroySharedBufferQCOM = NULL;
PFNGLSHAREDBUFFERBINDQCOM glBindSharedBufferQCOM = NULL;
PFNGLGRALLOCBUFFERDATAQCOM glGrallocBufferDataQCOM = NULL;

extern "C" void load_gl_extensions() {
  if (glGetQueryObjecti64v) {
    return;
  }
  glGetQueryObjecti64v = reinterpret_cast<PFNGLGETQUERYOBJECTI64VEXTPROC>(
      eglGetProcAddress("glGetQueryObjecti64vEXT"));
  glGetQueryObjectiv = reinterpret_cast<PFNGLGETQUERYOBJECTIVEXTPROC>(
      eglGetProcAddress("glGetQueryObjectivEXT"));
  glQueryCounter = reinterpret_cast<PFNGLQUERYCOUNTEREXTPROC>(
      eglGetProcAddress("glQueryCounterEXT"));
  glBufferStorage = reinterpret_cast<PFNGLBUFFERSTORAGEEXTPROC>(
      eglGetProcAddress("glBufferStorageEXT"));

  glFramebufferTextureMultiview =
      reinterpret_cast<PFNGLFRAMEBUFFERTEXTUREMULTIVIEWOVR>(
          eglGetProcAddress("glFramebufferTextureMultiviewOVR"));
  glFramebufferTextureMultisampleMultiview =
      reinterpret_cast<PFNGLFRAMEBUFFERTEXTUREMULTISAMPLEMULTIVIEWOVR>(
          eglGetProcAddress("glFramebufferTextureMultisampleMultiviewOVR"));

  glGrallocBufferDataQCOM = reinterpret_cast<PFNGLGRALLOCBUFFERDATAQCOM>(
      eglGetProcAddress("glGrallocBufferDataQCOM"));
  glCreateSharedBufferQCOM = reinterpret_cast<PFNGLSHAREDBUFFERCREATEQCOM>(
      eglGetProcAddress("glCreateSharedBufferQCOM"));
  glBindSharedBufferQCOM = reinterpret_cast<PFNGLSHAREDBUFFERBINDQCOM>(
      eglGetProcAddress("glBindSharedBufferQCOM"));
  glDestroySharedBufferQCOM = reinterpret_cast<PFNGLSHAREDBUFFERDESTROYQCOM>(
      eglGetProcAddress("glDestroySharedBufferQCOM"));
}
