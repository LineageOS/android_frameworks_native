#ifndef ANDROID_DVR_VR_GL_EXTENSIONS_H_
#define ANDROID_DVR_VR_GL_EXTENSIONS_H_

// clang-format off
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl31.h>
#include <GLES3/gl3ext.h>
// clang-format on

// GL_EXT_disjoint_timer_query API function declarations
extern PFNGLGETQUERYOBJECTI64VEXTPROC glGetQueryObjecti64v;
extern PFNGLGETQUERYOBJECTIVEXTPROC glGetQueryObjectiv;
extern PFNGLQUERYCOUNTEREXTPROC glQueryCounter;

// EXT_buffer_storage:
extern PFNGLBUFFERSTORAGEEXTPROC glBufferStorage;

typedef void(GL_APIENTRYP PFNGLFRAMEBUFFERTEXTUREMULTIVIEWOVR)(
    GLenum target, GLenum attachment, GLuint texture, GLint level,
    GLint baseViewIndex, GLsizei numViews);
typedef void(GL_APIENTRYP PFNGLFRAMEBUFFERTEXTUREMULTISAMPLEMULTIVIEWOVR)(
    GLenum target, GLenum attachement, GLuint texture, GLint level,
    GLsizei samples, GLint baseViewIndex, GLsizei numViews);

extern PFNGLFRAMEBUFFERTEXTUREMULTIVIEWOVR glFramebufferTextureMultiview;
extern PFNGLFRAMEBUFFERTEXTUREMULTISAMPLEMULTIVIEWOVR
    glFramebufferTextureMultisampleMultiview;

// QCOM_gralloc_buffer_data and QCOM_shared_buffer
typedef void(GL_APIENTRY* PFNGLGRALLOCBUFFERDATAQCOM)(GLenum target,
                                                      GLsizeiptr sizeInBytes,
                                                      GLvoid* hostPtr,
                                                      GLint fd);
typedef void(GL_APIENTRY* PFNGLSHAREDBUFFERCREATEQCOM)(GLsizeiptr sizeInBytes,
                                                       GLint* outFd);
typedef void(GL_APIENTRY* PFNGLSHAREDBUFFERDESTROYQCOM)(GLint fd);
typedef void(GL_APIENTRY* PFNGLSHAREDBUFFERBINDQCOM)(GLenum target,
                                                     GLsizeiptr sizeInBytes,
                                                     GLint fd);

extern PFNGLGRALLOCBUFFERDATAQCOM glGrallocBufferDataQCOM;
extern PFNGLSHAREDBUFFERCREATEQCOM glCreateSharedBufferQCOM;
extern PFNGLSHAREDBUFFERDESTROYQCOM glDestroySharedBufferQCOM;
extern PFNGLSHAREDBUFFERBINDQCOM glBindSharedBufferQCOM;

extern "C" void load_gl_extensions();

#endif  // ANDROID_DVR_VR_GL_EXTENSIONS_H_
