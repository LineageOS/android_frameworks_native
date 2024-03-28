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

#include "skia/SkiaVkRenderEngine.h"

namespace android::renderengine::skia {

class GaneshVkRenderEngine : public SkiaVkRenderEngine {
public:
    static std::unique_ptr<GaneshVkRenderEngine> create(const RenderEngineCreationArgs& args);

protected:
    std::unique_ptr<SkiaGpuContext> createContext(VulkanInterface& vulkanInterface) override;
    void waitFence(SkiaGpuContext* context, base::borrowed_fd fenceFd) override;
    base::unique_fd flushAndSubmit(SkiaGpuContext* context, sk_sp<SkSurface> dstSurface) override;

private:
    GaneshVkRenderEngine(const RenderEngineCreationArgs& args) : SkiaVkRenderEngine(args) {}
};

} // namespace android::renderengine::skia
