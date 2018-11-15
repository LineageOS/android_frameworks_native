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

#pragma once

#include <cstdint>

#include <EGL/egl.h>
#include <android-base/macros.h>
#include <renderengine/Surface.h>

struct ANativeWindow;

namespace android {
namespace renderengine {
namespace gl {

class GLES20RenderEngine;

class GLSurface final : public renderengine::Surface {
public:
    GLSurface(const GLES20RenderEngine& engine);
    ~GLSurface() override;

    // renderengine::Surface implementation
    void setCritical(bool enable) override { mCritical = enable; }
    void setAsync(bool enable) override { mAsync = enable; }

    void setNativeWindow(ANativeWindow* window) override;
    void swapBuffers() const override;

    int32_t queryRedSize() const override;
    int32_t queryGreenSize() const override;
    int32_t queryBlueSize() const override;
    int32_t queryAlphaSize() const override;

    bool getAsync() const { return mAsync; }
    EGLSurface getEGLSurface() const { return mEGLSurface; }

    int32_t getWidth() const override;
    int32_t getHeight() const override;

private:
    EGLint queryConfig(EGLint attrib) const;

    EGLDisplay mEGLDisplay;
    EGLConfig mEGLConfig;

    bool mCritical = false;
    bool mAsync = false;

    int32_t mSurfaceWidth = 0;
    int32_t mSurfaceHeight = 0;

    ANativeWindow* mWindow = nullptr;
    EGLSurface mEGLSurface = EGL_NO_SURFACE;

    DISALLOW_COPY_AND_ASSIGN(GLSurface);
};

} // namespace gl
} // namespace renderengine
} // namespace android
