/*
 * Copyright 2022 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SkiaVkRenderEngine.h"

#include <GrBackendSemaphore.h>
#include <GrContextOptions.h>
#include <vk/GrVkExtensions.h>
#include <vk/GrVkTypes.h>
#include <include/gpu/ganesh/vk/GrVkBackendSemaphore.h>
#include <include/gpu/ganesh/vk/GrVkDirectContext.h>

#include <android-base/stringprintf.h>
#include <gui/TraceUtils.h>
#include <sync/sync.h>
#include <utils/Trace.h>

#include <memory>
#include <string>

#include <vulkan/vulkan.h>
#include "log/log_main.h"

namespace android {
namespace renderengine {

static skia::VulkanInterface sVulkanInterface;
static skia::VulkanInterface sProtectedContentVulkanInterface;

static void sSetupVulkanInterface() {
    if (!sVulkanInterface.isInitialized()) {
        sVulkanInterface.init(false /* no protected content */);
        // We will have to abort if non-protected VkDevice creation fails (then nothing works).
        LOG_ALWAYS_FATAL_IF(!sVulkanInterface.isInitialized(),
                            "Could not initialize Vulkan RenderEngine!");
    }
    if (!sProtectedContentVulkanInterface.isInitialized()) {
        sProtectedContentVulkanInterface.init(true /* protected content */);
        if (!sProtectedContentVulkanInterface.isInitialized()) {
            ALOGE("Could not initialize protected content Vulkan RenderEngine.");
        }
    }
}

bool RenderEngine::canSupport(GraphicsApi graphicsApi) {
    switch (graphicsApi) {
        case GraphicsApi::GL:
            return true;
        case GraphicsApi::VK: {
            if (!sVulkanInterface.isInitialized()) {
                sVulkanInterface.init(false /* no protected content */);
                ALOGD("%s: initialized == %s.", __func__,
                      sVulkanInterface.isInitialized() ? "true" : "false");
            }
            return sVulkanInterface.isInitialized();
        }
    }
}

namespace skia {

using base::StringAppendF;

std::unique_ptr<SkiaVkRenderEngine> SkiaVkRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    std::unique_ptr<SkiaVkRenderEngine> engine(new SkiaVkRenderEngine(args));
    engine->ensureGrContextsCreated();

    if (sVulkanInterface.isInitialized()) {
        ALOGD("SkiaVkRenderEngine::%s: successfully initialized SkiaVkRenderEngine", __func__);
        return engine;
    } else {
        ALOGD("SkiaVkRenderEngine::%s: could not create SkiaVkRenderEngine. "
              "Likely insufficient Vulkan support",
              __func__);
        return {};
    }
}

SkiaVkRenderEngine::SkiaVkRenderEngine(const RenderEngineCreationArgs& args)
      : SkiaRenderEngine(args.threaded, static_cast<PixelFormat>(args.pixelFormat),
                         args.supportsBackgroundBlur) {}

SkiaVkRenderEngine::~SkiaVkRenderEngine() {
    finishRenderingAndAbandonContext();
}

SkiaRenderEngine::Contexts SkiaVkRenderEngine::createDirectContexts(
        const GrContextOptions& options) {
    sSetupVulkanInterface();

    SkiaRenderEngine::Contexts contexts;
    contexts.first = GrDirectContexts::MakeVulkan(sVulkanInterface.getBackendContext(), options);
    if (supportsProtectedContentImpl()) {
        contexts.second =
                GrDirectContexts::MakeVulkan(sProtectedContentVulkanInterface.getBackendContext(),
                                             options);
    }

    return contexts;
}

bool SkiaVkRenderEngine::supportsProtectedContentImpl() const {
    return sProtectedContentVulkanInterface.isInitialized();
}

bool SkiaVkRenderEngine::useProtectedContextImpl(GrProtected) {
    return true;
}

static void unref_semaphore(void* semaphore) {
    SkiaVkRenderEngine::DestroySemaphoreInfo* info =
            reinterpret_cast<SkiaVkRenderEngine::DestroySemaphoreInfo*>(semaphore);
    info->unref();
}

static VulkanInterface& getVulkanInterface(bool protectedContext) {
    if (protectedContext) {
        return sProtectedContentVulkanInterface;
    }
    return sVulkanInterface;
}

void SkiaVkRenderEngine::waitFence(GrDirectContext* grContext, base::borrowed_fd fenceFd) {
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
    GrBackendSemaphore beSemaphore = GrBackendSemaphores::MakeVk(waitSemaphore);
    grContext->wait(1, &beSemaphore, true /* delete after wait */);
}

base::unique_fd SkiaVkRenderEngine::flushAndSubmit(GrDirectContext* grContext) {
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

int SkiaVkRenderEngine::getContextPriority() {
    // EGL_CONTEXT_PRIORITY_REALTIME_NV
    constexpr int kRealtimePriority = 0x3357;
    if (getVulkanInterface(isProtected()).isRealtimePriority()) {
        return kRealtimePriority;
    } else {
        return 0;
    }
}

void SkiaVkRenderEngine::appendBackendSpecificInfoToDump(std::string& result) {
    StringAppendF(&result, "\n ------------RE Vulkan----------\n");
    StringAppendF(&result, "\n Vulkan device initialized: %d\n", sVulkanInterface.isInitialized());
    StringAppendF(&result, "\n Vulkan protected device initialized: %d\n",
                  sProtectedContentVulkanInterface.isInitialized());

    if (!sVulkanInterface.isInitialized()) {
        return;
    }

    StringAppendF(&result, "\n Instance extensions:\n");
    for (const auto& name : sVulkanInterface.getInstanceExtensionNames()) {
        StringAppendF(&result, "\n %s\n", name.c_str());
    }

    StringAppendF(&result, "\n Device extensions:\n");
    for (const auto& name : sVulkanInterface.getDeviceExtensionNames()) {
        StringAppendF(&result, "\n %s\n", name.c_str());
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android
