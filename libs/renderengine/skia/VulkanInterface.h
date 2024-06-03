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

#include <include/gpu/vk/GrVkBackendContext.h>
#include <include/gpu/vk/VulkanExtensions.h>
#include <include/gpu/vk/VulkanTypes.h>

#include <vulkan/vulkan.h>

using namespace skgpu;

namespace skgpu {
struct VulkanBackendContext;
} // namespace skgpu

namespace android {
namespace renderengine {
namespace skia {

class VulkanInterface {
public:
    // Create an uninitialized interface. Initialize with `init`.
    VulkanInterface() = default;
    ~VulkanInterface() = default;
    VulkanInterface(const VulkanInterface&) = delete;
    VulkanInterface& operator=(const VulkanInterface&) = delete;
    VulkanInterface& operator=(VulkanInterface&&) = delete;

    void init(bool protectedContent = false);
    // Returns true and marks this VulkanInterface as "owned" if it is initialized but unused by any
    // RenderEngine instances. Returns false if already owned, indicating that it must not be used
    // by a new RE instance.
    bool takeOwnership();
    void teardown();

    GrVkBackendContext getGaneshBackendContext();
    VulkanBackendContext getGraphiteBackendContext();
    VkSemaphore createExportableSemaphore();
    VkSemaphore importSemaphoreFromSyncFd(int syncFd);
    int exportSemaphoreSyncFd(VkSemaphore semaphore);
    void destroySemaphore(VkSemaphore semaphore);

    bool isInitialized() const { return mInitialized; }
    bool isRealtimePriority() const { return mIsRealtimePriority; }
    const std::vector<std::string>& getInstanceExtensionNames() { return mInstanceExtensionNames; }
    const std::vector<std::string>& getDeviceExtensionNames() { return mDeviceExtensionNames; }

private:
    struct VulkanFuncs {
        PFN_vkCreateSemaphore vkCreateSemaphore = nullptr;
        PFN_vkImportSemaphoreFdKHR vkImportSemaphoreFdKHR = nullptr;
        PFN_vkGetSemaphoreFdKHR vkGetSemaphoreFdKHR = nullptr;
        PFN_vkDestroySemaphore vkDestroySemaphore = nullptr;

        PFN_vkDeviceWaitIdle vkDeviceWaitIdle = nullptr;
        PFN_vkDestroyDevice vkDestroyDevice = nullptr;
        PFN_vkDestroyInstance vkDestroyInstance = nullptr;
    };

    static void onVkDeviceFault(void* callbackContext, const std::string& description,
                                const std::vector<VkDeviceFaultAddressInfoEXT>& addressInfos,
                                const std::vector<VkDeviceFaultVendorInfoEXT>& vendorInfos,
                                const std::vector<std::byte>& vendorBinaryData);

    // Note: keep all field defaults in sync with teardown()
    bool mInitialized = false;
    bool mIsOwned = false;
    VkInstance mInstance = VK_NULL_HANDLE;
    VkPhysicalDevice mPhysicalDevice = VK_NULL_HANDLE;
    VkDevice mDevice = VK_NULL_HANDLE;
    VkQueue mQueue = VK_NULL_HANDLE;
    int mQueueIndex = 0;
    uint32_t mApiVersion = 0;
    skgpu::VulkanExtensions mGrExtensions;
    VkPhysicalDeviceFeatures2* mPhysicalDeviceFeatures2 = nullptr;
    VkPhysicalDeviceSamplerYcbcrConversionFeatures* mSamplerYcbcrConversionFeatures = nullptr;
    VkPhysicalDeviceProtectedMemoryFeatures* mProtectedMemoryFeatures = nullptr;
    VkPhysicalDeviceFaultFeaturesEXT* mDeviceFaultFeatures = nullptr;
    skgpu::VulkanGetProc mGrGetProc = nullptr;
    bool mIsProtected = false;
    bool mIsRealtimePriority = false;

    VulkanFuncs mFuncs;

    std::vector<std::string> mInstanceExtensionNames;
    std::vector<std::string> mDeviceExtensionNames;
};

} // namespace skia
} // namespace renderengine
} // namespace android
