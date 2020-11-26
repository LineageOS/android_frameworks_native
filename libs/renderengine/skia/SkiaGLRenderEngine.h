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

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GrDirectContext.h>
#include <SkSurface.h>
#include <android-base/thread_annotations.h>
#include <renderengine/RenderEngine.h>
#include <sys/types.h>

#include <mutex>
#include <unordered_map>

#include "AutoBackendTexture.h"
#include "EGL/egl.h"
#include "SkImageInfo.h"
#include "SkiaRenderEngine.h"
#include "android-base/macros.h"
#include "filters/BlurFilter.h"
#include "skia/filters/LinearEffect.h"

namespace android {
namespace renderengine {
namespace skia {

class SkiaGLRenderEngine : public skia::SkiaRenderEngine {
public:
    static std::unique_ptr<SkiaGLRenderEngine> create(const RenderEngineCreationArgs& args);
    SkiaGLRenderEngine(const RenderEngineCreationArgs& args, EGLDisplay display, EGLContext ctxt,
                       EGLSurface placeholder, EGLContext protectedContext,
                       EGLSurface protectedPlaceholder);
    ~SkiaGLRenderEngine() override{};

    void unbindExternalTextureBuffer(uint64_t bufferId) override;
    status_t drawLayers(const DisplaySettings& display,
                        const std::vector<const LayerSettings*>& layers,
                        const sp<GraphicBuffer>& buffer, const bool useFramebufferCache,
                        base::unique_fd&& bufferFence, base::unique_fd* drawFence) override;
    void cleanFramebufferCache() override;
    bool isProtected() const override { return mInProtectedContext; }
    bool supportsProtectedContent() const override;
    bool useProtectedContext(bool useProtectedContext) override;

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
    inline SkRect getSkRect(const FloatRect& layer);
    inline SkRect getSkRect(const Rect& layer);
    inline SkRRect getRoundedRect(const LayerSettings* layer);
    inline BlurRegion getBlurRegion(const LayerSettings* layer);
    inline SkColor getSkColor(const vec4& color);
    inline SkM44 getSkM44(const mat4& matrix);
    inline SkMatrix getDrawTransform(const LayerSettings* layer, const SkMatrix& screenTransform);
    inline SkPoint3 getSkPoint3(const vec3& vector);

    base::unique_fd flush();
    bool waitFence(base::unique_fd fenceFd);
    void drawShadow(SkCanvas* canvas, const SkRect& casterRect, float casterCornerRadius,
                    const ShadowSettings& shadowSettings);
    void drawBlurRegion(SkCanvas* canvas, const BlurRegion& blurRegion,
                        const SkMatrix& drawTransform, sk_sp<SkSurface> blurrendSurface);

    EGLDisplay mEGLDisplay;
    EGLContext mEGLContext;
    EGLSurface mPlaceholderSurface;
    EGLContext mProtectedEGLContext;
    EGLSurface mProtectedPlaceholderSurface;
    BlurFilter* mBlurFilter = nullptr;

    const bool mUseColorManagement;

    // Cache of GL textures that we'll store per GraphicBuffer ID
    std::unordered_map<uint64_t, std::shared_ptr<AutoBackendTexture::LocalRef>> mTextureCache
            GUARDED_BY(mRenderingMutex);
    std::unordered_map<uint64_t, std::shared_ptr<AutoBackendTexture::LocalRef>>
            mProtectedTextureCache GUARDED_BY(mRenderingMutex);
    std::unordered_map<LinearEffect, sk_sp<SkRuntimeEffect>, LinearEffectHasher> mRuntimeEffects;
    // Mutex guarding rendering operations, so that:
    // 1. GL operations aren't interleaved, and
    // 2. Internal state related to rendering that is potentially modified by
    // multiple threads is guaranteed thread-safe.
    std::mutex mRenderingMutex;

    sp<Fence> mLastDrawFence;

    // Graphics context used for creating surfaces and submitting commands
    sk_sp<GrDirectContext> mGrContext;
    // Same as above, but for protected content (eg. DRM)
    sk_sp<GrDirectContext> mProtectedGrContext;

    bool mInProtectedContext = false;
};

} // namespace skia
} // namespace renderengine
} // namespace android

#endif /* SF_GLESRENDERENGINE_H_ */
