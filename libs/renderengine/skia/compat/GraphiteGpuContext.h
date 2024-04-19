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

#include "SkiaGpuContext.h"
#include "graphite/Recorder.h"

#include <android-base/macros.h>

namespace android::renderengine::skia {

class GraphiteGpuContext : public SkiaGpuContext {
public:
    GraphiteGpuContext(std::unique_ptr<skgpu::graphite::Context> context);
    ~GraphiteGpuContext() override;

    std::shared_ptr<skgpu::graphite::Context> graphiteContext() override;
    std::shared_ptr<skgpu::graphite::Recorder> graphiteRecorder() override;

    std::unique_ptr<SkiaBackendTexture> makeBackendTexture(AHardwareBuffer* buffer,
                                                           bool isOutputBuffer) override;

    sk_sp<SkSurface> createRenderTarget(SkImageInfo imageInfo) override;

    size_t getMaxRenderTargetSize() const override;
    size_t getMaxTextureSize() const override;
    bool isAbandonedOrDeviceLost() override;
    // No-op (large resources like textures, surfaces, images, etc. created by clients don't count
    // towards Graphite's internal caching budgets, so adjusting its limits based on display change
    // events should be unnecessary. Additionally, Graphite doesn't expose many cache tweaking
    // functions yet, as its design may evolve.)
    void setResourceCacheLimit(size_t maxResourceBytes) override{};

    // TODO: b/293371537 - Triple-check and validate that no cleanup is necessary when switching
    // contexts.
    // No-op (unnecessary during context switch for Graphite's client-budgeted memory model).
    void purgeUnlockedScratchResources() override{};
    // No-op (only applicable to GL).
    void resetContextIfApplicable() override{};

    void dumpMemoryStatistics(SkTraceMemoryDump* traceMemoryDump) const override;

private:
    DISALLOW_COPY_AND_ASSIGN(GraphiteGpuContext);

    std::shared_ptr<skgpu::graphite::Context> mContext;
    std::shared_ptr<skgpu::graphite::Recorder> mRecorder;
};

} // namespace android::renderengine::skia
