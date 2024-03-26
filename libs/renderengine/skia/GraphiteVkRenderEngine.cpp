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

#include "GraphiteVkRenderEngine.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"

#include <include/gpu/GpuTypes.h>
#include <include/gpu/graphite/BackendSemaphore.h>
#include <include/gpu/graphite/Context.h>
#include <include/gpu/graphite/Recording.h>

#include <log/log_main.h>
#include <sync/sync.h>

#include <memory>
#include <vector>

namespace android::renderengine::skia {

std::unique_ptr<GraphiteVkRenderEngine> GraphiteVkRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    std::unique_ptr<GraphiteVkRenderEngine> engine(new GraphiteVkRenderEngine(args));
    engine->ensureContextsCreated();

    if (getVulkanInterface(false).isInitialized()) {
        ALOGD("GraphiteVkRenderEngine::%s: successfully initialized GraphiteVkRenderEngine",
              __func__);
        return engine;
    } else {
        ALOGE("GraphiteVkRenderEngine::%s: could not create GraphiteVkRenderEngine. "
              "Likely insufficient Vulkan support",
              __func__);
        return {};
    }
}

// Graphite-specific function signature for fFinishedProc callback.
static void unref_semaphore(void* semaphore, skgpu::CallbackResult result) {
    if (result != skgpu::CallbackResult::kSuccess) {
        ALOGE("Graphite submission of work to GPU failed, check for Skia errors");
    }
    SkiaVkRenderEngine::DestroySemaphoreInfo* info =
            reinterpret_cast<SkiaVkRenderEngine::DestroySemaphoreInfo*>(semaphore);
    info->unref();
}

std::unique_ptr<SkiaGpuContext> GraphiteVkRenderEngine::createContext(
        VulkanInterface& vulkanInterface) {
    return SkiaGpuContext::MakeVulkan_Graphite(vulkanInterface.getGraphiteBackendContext());
}

void GraphiteVkRenderEngine::waitFence(SkiaGpuContext*, base::borrowed_fd fenceFd) {
    if (fenceFd.get() < 0) return;

    int dupedFd = dup(fenceFd.get());
    if (dupedFd < 0) {
        ALOGE("failed to create duplicate fence fd: %d", dupedFd);
        sync_wait(fenceFd.get(), -1);
        return;
    }

    base::unique_fd fenceDup(dupedFd);
    VkSemaphore waitSemaphore =
            getVulkanInterface(isProtected()).importSemaphoreFromSyncFd(fenceDup.release());
    graphite::BackendSemaphore beSemaphore(waitSemaphore);
    mStagedWaitSemaphores.push_back(beSemaphore);
}

base::unique_fd GraphiteVkRenderEngine::flushAndSubmit(SkiaGpuContext* context, sk_sp<SkSurface>) {
    // Minimal Recording setup. Required even if there are no incoming semaphores to wait on, and if
    // creating the outgoing signaling semaphore fails.
    std::unique_ptr<graphite::Recording> recording = context->graphiteRecorder()->snap();
    graphite::InsertRecordingInfo insertInfo;
    insertInfo.fRecording = recording.get();

    VulkanInterface& vulkanInterface = getVulkanInterface(isProtected());
    // This "signal" semaphore is called after rendering, but it is cleaned up in the same mechanism
    // as "wait" semaphores from waitFence.
    VkSemaphore vkSignalSemaphore = vulkanInterface.createExportableSemaphore();
    graphite::BackendSemaphore backendSignalSemaphore(vkSignalSemaphore);

    // Collect all Vk semaphores that DestroySemaphoreInfo needs to own and delete after GPU work.
    std::vector<VkSemaphore> vkSemaphoresToCleanUp;
    if (vkSignalSemaphore != VK_NULL_HANDLE) {
        vkSemaphoresToCleanUp.push_back(vkSignalSemaphore);
    }
    for (auto backendWaitSemaphore : mStagedWaitSemaphores) {
        vkSemaphoresToCleanUp.push_back(backendWaitSemaphore.getVkSemaphore());
    }

    DestroySemaphoreInfo* destroySemaphoreInfo = nullptr;
    if (vkSemaphoresToCleanUp.size() > 0) {
        destroySemaphoreInfo =
                new DestroySemaphoreInfo(vulkanInterface, std::move(vkSemaphoresToCleanUp));

        insertInfo.fNumWaitSemaphores = mStagedWaitSemaphores.size();
        insertInfo.fWaitSemaphores = mStagedWaitSemaphores.data();
        insertInfo.fNumSignalSemaphores = 1;
        insertInfo.fSignalSemaphores = &backendSignalSemaphore;
        insertInfo.fFinishedProc = unref_semaphore;
        insertInfo.fFinishedContext = destroySemaphoreInfo;
    }

    const bool inserted = context->graphiteContext()->insertRecording(insertInfo);
    LOG_ALWAYS_FATAL_IF(!inserted,
                        "graphite::Context::insertRecording(...) failed, check for Skia errors");
    const bool submitted = context->graphiteContext()->submit(graphite::SyncToCpu::kNo);
    LOG_ALWAYS_FATAL_IF(!submitted, "graphite::Context::submit(...) failed, check for Skia errors");
    // Skia's "backend" semaphores can be deleted immediately after inserting the recording; only
    // the underlying VK semaphores need to be kept until GPU work is complete.
    mStagedWaitSemaphores.clear();

    base::unique_fd drawFenceFd(-1);
    if (vkSignalSemaphore != VK_NULL_HANDLE) {
        drawFenceFd.reset(vulkanInterface.exportSemaphoreSyncFd(vkSignalSemaphore));
    }
    // Now that drawFenceFd has been created, we can delete RE's reference to this semaphore, as
    // another reference is still held until fFinishedProc is called after completion of GPU work.
    if (destroySemaphoreInfo) {
        destroySemaphoreInfo->unref();
    }
    return drawFenceFd;
}

} // namespace android::renderengine::skia
