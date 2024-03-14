/*
 * Copyright 2024 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "RenderEngine"

#include <include/core/SkSurface.h>
#include <include/gpu/GrDirectContext.h>
#include <include/gpu/gl/GrGLInterface.h>
#include <include/gpu/vk/GrVkBackendContext.h>

#include <log/log.h>

namespace android::renderengine::skia {

/**
 * Abstraction over Ganesh and Graphite's underlying context-like objects.
 */
class SkiaGpuContext {
public:
    static std::unique_ptr<SkiaGpuContext> MakeGL_Ganesh(
            sk_sp<const GrGLInterface> glInterface,
            GrContextOptions::PersistentCache& skSLCacheMonitor);

    // TODO: b/293371537 - Graphite variant.
    static std::unique_ptr<SkiaGpuContext> MakeVulkan_Ganesh(
            const GrVkBackendContext& grVkBackendContext,
            GrContextOptions::PersistentCache& skSLCacheMonitor);

    virtual ~SkiaGpuContext() = default;

    // TODO: b/293371537 - Maybe expose whether this SkiaGpuContext is using Ganesh or Graphite?
    /**
     * Only callable on Ganesh-backed instances of SkiaGpuContext, otherwise fatal.
     */
    virtual sk_sp<GrDirectContext> grDirectContext() {
        LOG_ALWAYS_FATAL("grDirectContext() called on a non-Ganesh instance of SkiaGpuContext!");
    }

    /**
     * Notes:
     * - The surface doesn't count against Skia's caching budgets.
     * - Protected status is set to match the implementation's underlying context.
     * - The origin of the surface in texture space corresponds to the top-left content pixel.
     * - AA is always enabled.
     */
    virtual sk_sp<SkSurface> createRenderTarget(SkImageInfo imageInfo) = 0;

    virtual bool isAbandoned() = 0;
    virtual size_t getMaxRenderTargetSize() const = 0;
    virtual size_t getMaxTextureSize() const = 0;
    virtual void setResourceCacheLimit(size_t maxResourceBytes) = 0;

    virtual void finishRenderingAndAbandonContext() = 0;
    virtual void purgeUnlockedScratchResources() = 0;
    virtual void resetContextIfApplicable() = 0; // No-op outside of GL (&& Ganesh at this point.)

    virtual void dumpMemoryStatistics(SkTraceMemoryDump* traceMemoryDump) const = 0;
};

} // namespace android::renderengine::skia
