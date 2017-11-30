/*
 * Copyright 2017 The Android Open Source Project
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

struct ANativeWindow;

namespace android {

class RenderEngine;

namespace RE {

class Surface {
public:
    Surface(const RenderEngine& engine);
    ~Surface();

    Surface(const Surface&) = delete;
    Surface& operator=(const Surface&) = delete;

    void setCritical(bool enable) { mCritical = enable; }
    void setAsync(bool enable) { mAsync = enable; }

    void setNativeWindow(ANativeWindow* window);
    void swapBuffers() const;

    int32_t queryRedSize() const;
    int32_t queryGreenSize() const;
    int32_t queryBlueSize() const;
    int32_t queryAlphaSize() const;

    int32_t queryWidth() const;
    int32_t queryHeight() const;

private:
    EGLint queryConfig(EGLint attrib) const;
    EGLint querySurface(EGLint attrib) const;

    // methods internal to RenderEngine
    friend class android::RenderEngine;
    bool getAsync() const { return mAsync; }
    EGLSurface getEGLSurface() const { return mEGLSurface; }

    EGLDisplay mEGLDisplay;
    EGLConfig mEGLConfig;

    bool mCritical = false;
    bool mAsync = false;

    ANativeWindow* mWindow = nullptr;
    EGLSurface mEGLSurface = EGL_NO_SURFACE;
};

} // namespace RE
} // namespace android
