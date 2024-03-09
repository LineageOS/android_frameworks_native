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

#ifndef SF_SKIAVKRENDERENGINE_H_
#define SF_SKIAVKRENDERENGINE_H_

#include <vk/GrVkBackendContext.h>

#include "SkiaRenderEngine.h"
#include "VulkanInterface.h"

namespace android {
namespace renderengine {
namespace skia {

class SkiaVkRenderEngine : public SkiaRenderEngine {
public:
    static std::unique_ptr<SkiaVkRenderEngine> create(const RenderEngineCreationArgs& args);
    ~SkiaVkRenderEngine() override;

    int getContextPriority() override;

    class DestroySemaphoreInfo {
    public:
        DestroySemaphoreInfo() = delete;
        DestroySemaphoreInfo(const DestroySemaphoreInfo&) = delete;
        DestroySemaphoreInfo& operator=(const DestroySemaphoreInfo&) = delete;
        DestroySemaphoreInfo& operator=(DestroySemaphoreInfo&&) = delete;

        DestroySemaphoreInfo(VulkanInterface& vulkanInterface, std::vector<VkSemaphore> semaphores)
              : mVulkanInterface(vulkanInterface), mSemaphores(std::move(semaphores)) {}
        DestroySemaphoreInfo(VulkanInterface& vulkanInterface, VkSemaphore semaphore)
              : DestroySemaphoreInfo(vulkanInterface, std::vector<VkSemaphore>(1, semaphore)) {}

        void unref() {
            --mRefs;
            if (!mRefs) {
                for (VkSemaphore semaphore : mSemaphores) {
                    mVulkanInterface.destroySemaphore(semaphore);
                }
                delete this;
            }
        }

    private:
        ~DestroySemaphoreInfo() = default;

        VulkanInterface& mVulkanInterface;
        std::vector<VkSemaphore> mSemaphores;
        // We need to make sure we don't delete the VkSemaphore until it is done being used by both
        // Skia (including by the GPU) and inside SkiaVkRenderEngine. So we always start with two
        // refs, one owned by Skia and one owned by the SkiaVkRenderEngine. The refs are decremented
        // each time unref() is called on this object. Skia will call unref() once it is done with
        // the semaphore and the GPU has finished work on the semaphore. SkiaVkRenderEngine calls
        // unref() after sending the semaphore to Skia and exporting it if need be.
        int mRefs = 2;
    };

protected:
    // Implementations of abstract SkiaRenderEngine functions specific to
    // rendering backend
    virtual SkiaRenderEngine::Contexts createDirectContexts(const GrContextOptions& options);
    bool supportsProtectedContentImpl() const override;
    bool useProtectedContextImpl(GrProtected isProtected) override;
    void waitFence(GrDirectContext* grContext, base::borrowed_fd fenceFd) override;
    base::unique_fd flushAndSubmit(GrDirectContext* context) override;
    void appendBackendSpecificInfoToDump(std::string& result) override;

private:
    SkiaVkRenderEngine(const RenderEngineCreationArgs& args);
    base::unique_fd flush();

    GrVkBackendContext mBackendContext;
};

} // namespace skia
} // namespace renderengine
} // namespace android

#endif
