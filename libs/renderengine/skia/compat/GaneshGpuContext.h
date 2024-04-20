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

#include <android-base/macros.h>

namespace android::renderengine::skia {

class GaneshGpuContext : public SkiaGpuContext {
public:
    GaneshGpuContext(sk_sp<GrDirectContext> grContext);
    ~GaneshGpuContext() override;

    sk_sp<GrDirectContext> grDirectContext() override;

    std::unique_ptr<SkiaBackendTexture> makeBackendTexture(AHardwareBuffer* buffer,
                                                           bool isOutputBuffer) override;

    sk_sp<SkSurface> createRenderTarget(SkImageInfo imageInfo) override;

    size_t getMaxRenderTargetSize() const override;
    size_t getMaxTextureSize() const override;
    bool isAbandonedOrDeviceLost() override;
    void setResourceCacheLimit(size_t maxResourceBytes) override;

    void purgeUnlockedScratchResources() override;
    void resetContextIfApplicable() override;

    void dumpMemoryStatistics(SkTraceMemoryDump* traceMemoryDump) const override;

private:
    DISALLOW_COPY_AND_ASSIGN(GaneshGpuContext);

    const sk_sp<GrDirectContext> mGrContext;
};

} // namespace android::renderengine::skia
