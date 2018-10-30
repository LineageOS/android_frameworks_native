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

#include "GLSurface.h"

#include <android/native_window.h>
#include <log/log.h>
#include <ui/PixelFormat.h>
#include "GLES20RenderEngine.h"

namespace android {
namespace renderengine {
namespace gl {

GLSurface::GLSurface(const GLES20RenderEngine& engine)
      : mEGLDisplay(engine.getEGLDisplay()), mEGLConfig(engine.getEGLConfig()) {
    // RE does not assume any config when EGL_KHR_no_config_context is supported
    if (mEGLConfig == EGL_NO_CONFIG_KHR) {
        mEGLConfig =
                GLES20RenderEngine::chooseEglConfig(mEGLDisplay, PIXEL_FORMAT_RGBA_8888, false);
    }
}

GLSurface::~GLSurface() {
    setNativeWindow(nullptr);
}

void GLSurface::setNativeWindow(ANativeWindow* window) {
    if (mEGLSurface != EGL_NO_SURFACE) {
        eglDestroySurface(mEGLDisplay, mEGLSurface);
        mEGLSurface = EGL_NO_SURFACE;
        mSurfaceWidth = 0;
        mSurfaceHeight = 0;
    }

    mWindow = window;
    if (mWindow) {
        mEGLSurface = eglCreateWindowSurface(mEGLDisplay, mEGLConfig, mWindow, nullptr);
        mSurfaceWidth = ANativeWindow_getWidth(window);
        mSurfaceHeight = ANativeWindow_getHeight(window);
    }
}

void GLSurface::swapBuffers() const {
    if (!eglSwapBuffers(mEGLDisplay, mEGLSurface)) {
        EGLint error = eglGetError();

        const char format[] = "eglSwapBuffers(%p, %p) failed with 0x%08x";
        if (mCritical || error == EGL_CONTEXT_LOST) {
            LOG_ALWAYS_FATAL(format, mEGLDisplay, mEGLSurface, error);
        } else {
            ALOGE(format, mEGLDisplay, mEGLSurface, error);
        }
    }
}

EGLint GLSurface::queryConfig(EGLint attrib) const {
    EGLint value;
    if (!eglGetConfigAttrib(mEGLDisplay, mEGLConfig, attrib, &value)) {
        value = 0;
    }

    return value;
}

int32_t GLSurface::queryRedSize() const {
    return queryConfig(EGL_RED_SIZE);
}

int32_t GLSurface::queryGreenSize() const {
    return queryConfig(EGL_GREEN_SIZE);
}

int32_t GLSurface::queryBlueSize() const {
    return queryConfig(EGL_BLUE_SIZE);
}

int32_t GLSurface::queryAlphaSize() const {
    return queryConfig(EGL_ALPHA_SIZE);
}

int32_t GLSurface::getWidth() const {
    return mSurfaceWidth;
}

int32_t GLSurface::getHeight() const {
    return mSurfaceHeight;
}

} // namespace gl
} // namespace renderengine
} // namespace android
