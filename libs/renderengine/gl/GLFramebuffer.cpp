/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "GLFramebuffer.h"

#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <nativebase/nativebase.h>
#include "GLES20RenderEngine.h"

namespace android {
namespace renderengine {
namespace gl {

GLFramebuffer::GLFramebuffer(const GLES20RenderEngine& engine)
      : mEGLDisplay(engine.getEGLDisplay()), mEGLImage(EGL_NO_IMAGE_KHR) {
    glGenTextures(1, &mTextureName);
    glGenFramebuffers(1, &mFramebufferName);
}

GLFramebuffer::~GLFramebuffer() {
    glDeleteFramebuffers(1, &mFramebufferName);
    glDeleteTextures(1, &mTextureName);
    eglDestroyImageKHR(mEGLDisplay, mEGLImage);
}

bool GLFramebuffer::setNativeWindowBuffer(ANativeWindowBuffer* nativeBuffer) {
    if (mEGLImage != EGL_NO_IMAGE_KHR) {
        eglDestroyImageKHR(mEGLDisplay, mEGLImage);
        mEGLImage = EGL_NO_IMAGE_KHR;
        mBufferWidth = 0;
        mBufferHeight = 0;
    }

    if (nativeBuffer) {
        mEGLImage = eglCreateImageKHR(mEGLDisplay, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
                                      nativeBuffer, nullptr);
        if (mEGLImage == EGL_NO_IMAGE_KHR) {
            return false;
        }
        mBufferWidth = nativeBuffer->width;
        mBufferHeight = nativeBuffer->height;
    }
    return true;
}

} // namespace gl
} // namespace renderengine
} // namespace android
