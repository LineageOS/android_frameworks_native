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

#include "SkiaVkRenderEngine.h"

#include <include/gpu/graphite/BackendSemaphore.h>

namespace android::renderengine::skia {

class GraphiteVkRenderEngine : public SkiaVkRenderEngine {
public:
    static std::unique_ptr<GraphiteVkRenderEngine> create(const RenderEngineCreationArgs& args);

protected:
    std::unique_ptr<SkiaGpuContext> createContext(VulkanInterface& vulkanInterface) override;
    void waitFence(SkiaGpuContext* context, base::borrowed_fd fenceFd) override;
    base::unique_fd flushAndSubmit(SkiaGpuContext* context, sk_sp<SkSurface> dstSurface) override;

private:
    GraphiteVkRenderEngine(const RenderEngineCreationArgs& args) : SkiaVkRenderEngine(args) {}

    std::vector<graphite::BackendSemaphore> mStagedWaitSemaphores;
};

} // namespace android::renderengine::skia
