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

#include "GaneshGpuContext.h"

#include <include/core/SkImageInfo.h>
#include <include/core/SkSurface.h>
#include <include/core/SkTraceMemoryDump.h>
#include <include/gpu/GrDirectContext.h>
#include <include/gpu/GrTypes.h>
#include <include/gpu/ganesh/SkSurfaceGanesh.h>
#include <include/gpu/ganesh/gl/GrGLDirectContext.h>
#include <include/gpu/ganesh/vk/GrVkDirectContext.h>
#include <include/gpu/gl/GrGLInterface.h>
#include <include/gpu/vk/GrVkBackendContext.h>

#include "../AutoBackendTexture.h"
#include "GaneshBackendTexture.h"
#include "skia/compat/SkiaBackendTexture.h"

#include <android-base/macros.h>
#include <log/log_main.h>
#include <memory>

namespace android::renderengine::skia {

namespace {
// TODO: b/293371537 - Graphite variant.
static GrContextOptions ganeshOptions(GrContextOptions::PersistentCache& skSLCacheMonitor) {
    GrContextOptions options;
    options.fDisableDriverCorrectnessWorkarounds = true;
    options.fDisableDistanceFieldPaths = true;
    options.fReducedShaderVariations = true;
    options.fPersistentCache = &skSLCacheMonitor;
    return options;
}
} // namespace

std::unique_ptr<SkiaGpuContext> SkiaGpuContext::MakeGL_Ganesh(
        sk_sp<const GrGLInterface> glInterface,
        GrContextOptions::PersistentCache& skSLCacheMonitor) {
    return std::make_unique<GaneshGpuContext>(
            GrDirectContexts::MakeGL(glInterface, ganeshOptions(skSLCacheMonitor)));
}

std::unique_ptr<SkiaGpuContext> SkiaGpuContext::MakeVulkan_Ganesh(
        const GrVkBackendContext& grVkBackendContext,
        GrContextOptions::PersistentCache& skSLCacheMonitor) {
    return std::make_unique<GaneshGpuContext>(
            GrDirectContexts::MakeVulkan(grVkBackendContext, ganeshOptions(skSLCacheMonitor)));
}

GaneshGpuContext::GaneshGpuContext(sk_sp<GrDirectContext> grContext) : mGrContext(grContext) {
    LOG_ALWAYS_FATAL_IF(mGrContext.get() == nullptr, "GrDirectContext creation failed");
}

sk_sp<GrDirectContext> GaneshGpuContext::grDirectContext() {
    return mGrContext;
}

std::unique_ptr<SkiaBackendTexture> GaneshGpuContext::makeBackendTexture(AHardwareBuffer* buffer,
                                                                         bool isOutputBuffer) {
    return std::make_unique<GaneshBackendTexture>(mGrContext, buffer, isOutputBuffer);
}

sk_sp<SkSurface> GaneshGpuContext::createRenderTarget(SkImageInfo imageInfo) {
    constexpr int kSampleCount = 1; // enable AA
    constexpr SkSurfaceProps* kProps = nullptr;
    constexpr bool kMipmapped = false;
    return SkSurfaces::RenderTarget(mGrContext.get(), skgpu::Budgeted::kNo, imageInfo, kSampleCount,
                                    kTopLeft_GrSurfaceOrigin, kProps, kMipmapped,
                                    mGrContext->supportsProtectedContent());
}

size_t GaneshGpuContext::getMaxRenderTargetSize() const {
    return mGrContext->maxRenderTargetSize();
};

size_t GaneshGpuContext::getMaxTextureSize() const {
    return mGrContext->maxTextureSize();
};

bool GaneshGpuContext::isAbandonedOrDeviceLost() {
    return mGrContext->abandoned();
}

void GaneshGpuContext::setResourceCacheLimit(size_t maxResourceBytes) {
    mGrContext->setResourceCacheLimit(maxResourceBytes);
}

void GaneshGpuContext::finishRenderingAndAbandonContext() {
    mGrContext->flushAndSubmit(GrSyncCpu::kYes);
    mGrContext->abandonContext();
};

void GaneshGpuContext::purgeUnlockedScratchResources() {
    mGrContext->purgeUnlockedResources(GrPurgeResourceOptions::kScratchResourcesOnly);
}

void GaneshGpuContext::resetContextIfApplicable() {
    mGrContext->resetContext(); // Only applicable to GL
};

void GaneshGpuContext::dumpMemoryStatistics(SkTraceMemoryDump* traceMemoryDump) const {
    mGrContext->dumpMemoryStatistics(traceMemoryDump);
}

} // namespace android::renderengine::skia
