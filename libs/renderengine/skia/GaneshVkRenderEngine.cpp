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

#include "GaneshVkRenderEngine.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"

#include <include/gpu/ganesh/vk/GrVkBackendSemaphore.h>

#include <log/log_main.h>
#include <sync/sync.h>
#include <utils/Trace.h>

namespace android::renderengine::skia {

std::unique_ptr<GaneshVkRenderEngine> GaneshVkRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    std::unique_ptr<GaneshVkRenderEngine> engine(new GaneshVkRenderEngine(args));
    engine->ensureContextsCreated();

    if (getVulkanInterface(false).isInitialized()) {
        ALOGD("GaneshVkRenderEngine::%s: successfully initialized GaneshVkRenderEngine", __func__);
        return engine;
    } else {
        ALOGE("GaneshVkRenderEngine::%s: could not create GaneshVkRenderEngine. "
              "Likely insufficient Vulkan support",
              __func__);
        return {};
    }
}

// Ganesh-specific function signature for fFinishedProc callback.
static void unref_semaphore(void* semaphore) {
    SkiaVkRenderEngine::DestroySemaphoreInfo* info =
            reinterpret_cast<SkiaVkRenderEngine::DestroySemaphoreInfo*>(semaphore);
    info->unref();
}

std::unique_ptr<SkiaGpuContext> GaneshVkRenderEngine::createContext(
        VulkanInterface& vulkanInterface) {
    return SkiaGpuContext::MakeVulkan_Ganesh(vulkanInterface.getGaneshBackendContext(),
                                             mSkSLCacheMonitor);
}

void GaneshVkRenderEngine::waitFence(SkiaGpuContext* context, base::borrowed_fd fenceFd) {
    if (fenceFd.get() < 0) return;

    const int dupedFd = dup(fenceFd.get());
    if (dupedFd < 0) {
        ALOGE("failed to create duplicate fence fd: %d", dupedFd);
        sync_wait(fenceFd.get(), -1);
        return;
    }

    base::unique_fd fenceDup(dupedFd);
    VkSemaphore waitSemaphore =
            getVulkanInterface(isProtected()).importSemaphoreFromSyncFd(fenceDup.release());
    GrBackendSemaphore beSemaphore = GrBackendSemaphores::MakeVk(waitSemaphore);
    constexpr bool kDeleteAfterWait = true;
    context->grDirectContext()->wait(1, &beSemaphore, kDeleteAfterWait);
}

base::unique_fd GaneshVkRenderEngine::flushAndSubmit(SkiaGpuContext* context,
                                                     sk_sp<SkSurface> dstSurface) {
    sk_sp<GrDirectContext> grContext = context->grDirectContext();
    {
        ATRACE_NAME("flush surface");
        // TODO: Investigate feasibility of combining this "surface flush" into the "context flush"
        // below.
        context->grDirectContext()->flush(dstSurface.get());
    }

    VulkanInterface& vi = getVulkanInterface(isProtected());
    VkSemaphore semaphore = vi.createExportableSemaphore();
    GrBackendSemaphore backendSemaphore = GrBackendSemaphores::MakeVk(semaphore);

    GrFlushInfo flushInfo;
    DestroySemaphoreInfo* destroySemaphoreInfo = nullptr;
    if (semaphore != VK_NULL_HANDLE) {
        destroySemaphoreInfo = new DestroySemaphoreInfo(vi, semaphore);
        flushInfo.fNumSemaphores = 1;
        flushInfo.fSignalSemaphores = &backendSemaphore;
        flushInfo.fFinishedProc = unref_semaphore;
        flushInfo.fFinishedContext = destroySemaphoreInfo;
    }
    GrSemaphoresSubmitted submitted = grContext->flush(flushInfo);
    grContext->submit(GrSyncCpu::kNo);
    int drawFenceFd = -1;
    if (semaphore != VK_NULL_HANDLE) {
        if (GrSemaphoresSubmitted::kYes == submitted) {
            drawFenceFd = vi.exportSemaphoreSyncFd(semaphore);
        }
        // Now that drawFenceFd has been created, we can delete our reference to this semaphore
        flushInfo.fFinishedProc(destroySemaphoreInfo);
    }
    base::unique_fd res(drawFenceFd);
    return res;
}

} // namespace android::renderengine::skia
