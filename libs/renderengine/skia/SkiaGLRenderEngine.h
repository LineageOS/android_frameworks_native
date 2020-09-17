/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef SF_SKIAGLRENDERENGINE_H_
#define SF_SKIAGLRENDERENGINE_H_

#include <sys/types.h>
#include <mutex>
#include <unordered_map>

#include <android-base/thread_annotations.h>
#include <renderengine/RenderEngine.h>

#include <GrDirectContext.h>
#include <SkSurface.h>

#include "SkiaRenderEngine.h"

namespace android {
namespace renderengine {
namespace skia {

class SkiaGLRenderEngine : public skia::SkiaRenderEngine {
public:
    static std::unique_ptr<SkiaGLRenderEngine> create(const RenderEngineCreationArgs& args);
    SkiaGLRenderEngine(EGLDisplay display, EGLConfig config, EGLContext ctxt,
                       EGLSurface placeholder, EGLContext protectedContext,
                       EGLSurface protectedPlaceholder);
    ~SkiaGLRenderEngine() override{};

    void unbindExternalTextureBuffer(uint64_t bufferId) override;
    status_t drawLayers(const DisplaySettings& display,
                        const std::vector<const LayerSettings*>& layers,
                        const sp<GraphicBuffer>& buffer, const bool useFramebufferCache,
                        base::unique_fd&& bufferFence, base::unique_fd* drawFence) override;
    void cleanFramebufferCache() override;

protected:
    void dump(std::string& /*result*/) override{};
    size_t getMaxTextureSize() const override;
    size_t getMaxViewportDims() const override;

private:
    static EGLConfig chooseEglConfig(EGLDisplay display, int format, bool logConfig);
    static EGLContext createEglContext(EGLDisplay display, EGLConfig config,
                                       EGLContext shareContext, bool useContextPriority,
                                       Protection protection);
    static EGLSurface createPlaceholderEglPbufferSurface(EGLDisplay display, EGLConfig config,
                                                         int hwcFormat, Protection protection);

    base::unique_fd flush();
    bool waitFence(base::unique_fd fenceFd);

    EGLDisplay mEGLDisplay;
    EGLConfig mEGLConfig;
    EGLContext mEGLContext;
    EGLSurface mPlaceholderSurface;
    EGLContext mProtectedEGLContext;
    EGLSurface mProtectedPlaceholderSurface;

    // Cache of GL images that we'll store per GraphicBuffer ID
    std::unordered_map<uint64_t, sk_sp<SkImage>> mImageCache GUARDED_BY(mRenderingMutex);
    // Mutex guarding rendering operations, so that:
    // 1. GL operations aren't interleaved, and
    // 2. Internal state related to rendering that is potentially modified by
    // multiple threads is guaranteed thread-safe.
    std::mutex mRenderingMutex;

    sp<Fence> mLastDrawFence;

    sk_sp<GrDirectContext> mGrContext;

    std::unordered_map<uint64_t, sk_sp<SkSurface>> mSurfaceCache;
};

} // namespace skia
} // namespace renderengine
} // namespace android

#endif /* SF_GLESRENDERENGINE_H_ */