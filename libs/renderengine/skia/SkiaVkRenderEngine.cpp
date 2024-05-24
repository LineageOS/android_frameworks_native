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
#include <include/gpu/ganesh/vk/GrVkDirectContext.h>

#include <android-base/stringprintf.h>
#include <gui/TraceUtils.h>
#include <sync/sync.h>
#include <utils/Trace.h>

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <vulkan/vulkan.h>
#include "log/log_main.h"

namespace android {
namespace renderengine {

struct VulkanFuncs {
    PFN_vkCreateSemaphore vkCreateSemaphore = nullptr;
    PFN_vkImportSemaphoreFdKHR vkImportSemaphoreFdKHR = nullptr;
    PFN_vkGetSemaphoreFdKHR vkGetSemaphoreFdKHR = nullptr;
    PFN_vkDestroySemaphore vkDestroySemaphore = nullptr;

    PFN_vkDeviceWaitIdle vkDeviceWaitIdle = nullptr;
    PFN_vkDestroyDevice vkDestroyDevice = nullptr;
    PFN_vkDestroyInstance vkDestroyInstance = nullptr;
};

// Ref-Count a semaphore
struct DestroySemaphoreInfo {
    VkSemaphore mSemaphore;
    // We need to make sure we don't delete the VkSemaphore until it is done being used by both Skia
    // (including by the GPU) and inside SkiaVkRenderEngine. So we always start with two refs, one
    // owned by Skia and one owned by the SkiaVkRenderEngine. The refs are decremented each time
    // delete_semaphore* is called with this object. Skia will call destroy_semaphore* once it is
    // done with the semaphore and the GPU has finished work on the semaphore. SkiaVkRenderEngine
    // calls delete_semaphore* after sending the semaphore to Skia and exporting it if need be.
    int mRefs = 2;

    DestroySemaphoreInfo(VkSemaphore semaphore) : mSemaphore(semaphore) {}
};

namespace {
void onVkDeviceFault(void* callbackContext, const std::string& description,
                     const std::vector<VkDeviceFaultAddressInfoEXT>& addressInfos,
                     const std::vector<VkDeviceFaultVendorInfoEXT>& vendorInfos,
                     const std::vector<std::byte>& vendorBinaryData);
} // anonymous namespace

struct VulkanInterface {
    bool initialized = false;
    VkInstance instance;
    VkPhysicalDevice physicalDevice;
    VkDevice device;
    VkQueue queue;
    int queueIndex;
    uint32_t apiVersion;
    GrVkExtensions grExtensions;
    VkPhysicalDeviceFeatures2* physicalDeviceFeatures2 = nullptr;
    VkPhysicalDeviceSamplerYcbcrConversionFeatures* samplerYcbcrConversionFeatures = nullptr;
    VkPhysicalDeviceProtectedMemoryFeatures* protectedMemoryFeatures = nullptr;
    VkPhysicalDeviceFaultFeaturesEXT* deviceFaultFeatures = nullptr;
    GrVkGetProc grGetProc;
    bool isProtected;
    bool isRealtimePriority;

    VulkanFuncs funcs;

    std::vector<std::string> instanceExtensionNames;
    std::vector<std::string> deviceExtensionNames;

    GrVkBackendContext getBackendContext() {
        GrVkBackendContext backendContext;
        backendContext.fInstance = instance;
        backendContext.fPhysicalDevice = physicalDevice;
        backendContext.fDevice = device;
        backendContext.fQueue = queue;
        backendContext.fGraphicsQueueIndex = queueIndex;
        backendContext.fMaxAPIVersion = apiVersion;
        backendContext.fVkExtensions = &grExtensions;
        backendContext.fDeviceFeatures2 = physicalDeviceFeatures2;
        backendContext.fGetProc = grGetProc;
        backendContext.fProtectedContext = isProtected ? GrProtected::kYes : GrProtected::kNo;
        backendContext.fDeviceLostContext = this; // VulkanInterface is long-lived
        backendContext.fDeviceLostProc = onVkDeviceFault;
        return backendContext;
    };

    VkSemaphore createExportableSemaphore() {
        VkExportSemaphoreCreateInfo exportInfo;
        exportInfo.sType = VK_STRUCTURE_TYPE_EXPORT_SEMAPHORE_CREATE_INFO;
        exportInfo.pNext = nullptr;
        exportInfo.handleTypes = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;

        VkSemaphoreCreateInfo semaphoreInfo;
        semaphoreInfo.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
        semaphoreInfo.pNext = &exportInfo;
        semaphoreInfo.flags = 0;

        VkSemaphore semaphore;
        VkResult err = funcs.vkCreateSemaphore(device, &semaphoreInfo, nullptr, &semaphore);
        if (VK_SUCCESS != err) {
            ALOGE("%s: failed to create semaphore. err %d\n", __func__, err);
            return VK_NULL_HANDLE;
        }

        return semaphore;
    }

    // syncFd cannot be <= 0
    VkSemaphore importSemaphoreFromSyncFd(int syncFd) {
        VkSemaphoreCreateInfo semaphoreInfo;
        semaphoreInfo.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
        semaphoreInfo.pNext = nullptr;
        semaphoreInfo.flags = 0;

        VkSemaphore semaphore;
        VkResult err = funcs.vkCreateSemaphore(device, &semaphoreInfo, nullptr, &semaphore);
        if (VK_SUCCESS != err) {
            ALOGE("%s: failed to create import semaphore", __func__);
            return VK_NULL_HANDLE;
        }

        VkImportSemaphoreFdInfoKHR importInfo;
        importInfo.sType = VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR;
        importInfo.pNext = nullptr;
        importInfo.semaphore = semaphore;
        importInfo.flags = VK_SEMAPHORE_IMPORT_TEMPORARY_BIT;
        importInfo.handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;
        importInfo.fd = syncFd;

        err = funcs.vkImportSemaphoreFdKHR(device, &importInfo);
        if (VK_SUCCESS != err) {
            funcs.vkDestroySemaphore(device, semaphore, nullptr);
            ALOGE("%s: failed to import semaphore", __func__);
            return VK_NULL_HANDLE;
        }

        return semaphore;
    }

    int exportSemaphoreSyncFd(VkSemaphore semaphore) {
        int res;

        VkSemaphoreGetFdInfoKHR getFdInfo;
        getFdInfo.sType = VK_STRUCTURE_TYPE_SEMAPHORE_GET_FD_INFO_KHR;
        getFdInfo.pNext = nullptr;
        getFdInfo.semaphore = semaphore;
        getFdInfo.handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;

        VkResult err = funcs.vkGetSemaphoreFdKHR(device, &getFdInfo, &res);
        if (VK_SUCCESS != err) {
            ALOGE("%s: failed to export semaphore, err: %d", __func__, err);
            return -1;
        }
        return res;
    }

    void destroySemaphore(VkSemaphore semaphore) {
        funcs.vkDestroySemaphore(device, semaphore, nullptr);
    }
};

namespace {
void onVkDeviceFault(void* callbackContext, const std::string& description,
                     const std::vector<VkDeviceFaultAddressInfoEXT>& addressInfos,
                     const std::vector<VkDeviceFaultVendorInfoEXT>& vendorInfos,
                     const std::vector<std::byte>& vendorBinaryData) {
    VulkanInterface* interface = static_cast<VulkanInterface*>(callbackContext);
    const std::string protectedStr = interface->isProtected ? "protected" : "non-protected";
    // The final crash string should contain as much differentiating info as possible, up to 1024
    // bytes. As this final message is constructed, the same information is also dumped to the logs
    // but in a more verbose format. Building the crash string is unsightly, so the clearer logging
    // statement is always placed first to give context.
    ALOGE("VK_ERROR_DEVICE_LOST (%s context): %s", protectedStr.c_str(), description.c_str());
    std::stringstream crashMsg;
    crashMsg << "VK_ERROR_DEVICE_LOST (" << protectedStr;

    if (!addressInfos.empty()) {
        ALOGE("%zu VkDeviceFaultAddressInfoEXT:", addressInfos.size());
        crashMsg << ", " << addressInfos.size() << " address info (";
        for (VkDeviceFaultAddressInfoEXT addressInfo : addressInfos) {
            ALOGE(" addressType:       %d", (int)addressInfo.addressType);
            ALOGE("  reportedAddress:  %" PRIu64, addressInfo.reportedAddress);
            ALOGE("  addressPrecision: %" PRIu64, addressInfo.addressPrecision);
            crashMsg << addressInfo.addressType << ":"
                     << addressInfo.reportedAddress << ":"
                     << addressInfo.addressPrecision << ", ";
        }
        crashMsg.seekp(-2, crashMsg.cur); // Move back to overwrite trailing ", "
        crashMsg << ")";
    }

    if (!vendorInfos.empty()) {
        ALOGE("%zu VkDeviceFaultVendorInfoEXT:", vendorInfos.size());
        crashMsg << ", " << vendorInfos.size() << " vendor info (";
        for (VkDeviceFaultVendorInfoEXT vendorInfo : vendorInfos) {
            ALOGE(" description:      %s", vendorInfo.description);
            ALOGE("  vendorFaultCode: %" PRIu64, vendorInfo.vendorFaultCode);
            ALOGE("  vendorFaultData: %" PRIu64, vendorInfo.vendorFaultData);
            // Omit descriptions for individual vendor info structs in the crash string, as the
            // fault code and fault data fields should be enough for clustering, and the verbosity
            // isn't worth it. Additionally, vendors may just set the general description field of
            // the overall fault to the description of the first element in this list, and that
            // overall description will be placed at the end of the crash string.
            crashMsg << vendorInfo.vendorFaultCode << ":"
                     << vendorInfo.vendorFaultData << ", ";
        }
        crashMsg.seekp(-2, crashMsg.cur); // Move back to overwrite trailing ", "
        crashMsg << ")";
    }

    if (!vendorBinaryData.empty()) {
        // TODO: b/322830575 - Log in base64, or dump directly to a file that gets put in bugreports
        ALOGE("%zu bytes of vendor-specific binary data (please notify Android's Core Graphics"
              " Stack team if you observe this message).",
              vendorBinaryData.size());
        crashMsg << ", " << vendorBinaryData.size() << " bytes binary";
    }

    crashMsg << "): " << description;
    LOG_ALWAYS_FATAL("%s", crashMsg.str().c_str());
};
} // anonymous namespace

static GrVkGetProc sGetProc = [](const char* proc_name, VkInstance instance, VkDevice device) {
    if (device != VK_NULL_HANDLE) {
        return vkGetDeviceProcAddr(device, proc_name);
    }
    return vkGetInstanceProcAddr(instance, proc_name);
};

#define BAIL(fmt, ...)                                          \
    {                                                           \
        ALOGE("%s: " fmt ", bailing", __func__, ##__VA_ARGS__); \
        return interface;                                       \
    }

#define CHECK_NONNULL(expr)       \
    if ((expr) == nullptr) {      \
        BAIL("[%s] null", #expr); \
    }

#define VK_CHECK(expr)                              \
    if ((expr) != VK_SUCCESS) {                     \
        BAIL("[%s] failed. err = %d", #expr, expr); \
        return interface;                           \
    }

#define VK_GET_PROC(F)                                                           \
    PFN_vk##F vk##F = (PFN_vk##F)vkGetInstanceProcAddr(VK_NULL_HANDLE, "vk" #F); \
    CHECK_NONNULL(vk##F)
#define VK_GET_INST_PROC(instance, F)                                      \
    PFN_vk##F vk##F = (PFN_vk##F)vkGetInstanceProcAddr(instance, "vk" #F); \
    CHECK_NONNULL(vk##F)
#define VK_GET_DEV_PROC(device, F)                                     \
    PFN_vk##F vk##F = (PFN_vk##F)vkGetDeviceProcAddr(device, "vk" #F); \
    CHECK_NONNULL(vk##F)

VulkanInterface initVulkanInterface(bool protectedContent = false) {
    const nsecs_t timeBefore = systemTime();
    VulkanInterface interface;

    VK_GET_PROC(EnumerateInstanceVersion);
    uint32_t instanceVersion;
    VK_CHECK(vkEnumerateInstanceVersion(&instanceVersion));

    if (instanceVersion < VK_MAKE_VERSION(1, 1, 0)) {
        return interface;
    }

    const VkApplicationInfo appInfo = {
            VK_STRUCTURE_TYPE_APPLICATION_INFO, nullptr, "surfaceflinger", 0, "android platform", 0,
            VK_MAKE_VERSION(1, 1, 0),
    };

    VK_GET_PROC(EnumerateInstanceExtensionProperties);

    uint32_t extensionCount = 0;
    VK_CHECK(vkEnumerateInstanceExtensionProperties(nullptr, &extensionCount, nullptr));
    std::vector<VkExtensionProperties> instanceExtensions(extensionCount);
    VK_CHECK(vkEnumerateInstanceExtensionProperties(nullptr, &extensionCount,
                                                    instanceExtensions.data()));
    std::vector<const char*> enabledInstanceExtensionNames;
    enabledInstanceExtensionNames.reserve(instanceExtensions.size());
    interface.instanceExtensionNames.reserve(instanceExtensions.size());
    for (const auto& instExt : instanceExtensions) {
        enabledInstanceExtensionNames.push_back(instExt.extensionName);
        interface.instanceExtensionNames.push_back(instExt.extensionName);
    }

    const VkInstanceCreateInfo instanceCreateInfo = {
            VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
            nullptr,
            0,
            &appInfo,
            0,
            nullptr,
            (uint32_t)enabledInstanceExtensionNames.size(),
            enabledInstanceExtensionNames.data(),
    };

    VK_GET_PROC(CreateInstance);
    VkInstance instance;
    VK_CHECK(vkCreateInstance(&instanceCreateInfo, nullptr, &instance));

    VK_GET_INST_PROC(instance, DestroyInstance);
    interface.funcs.vkDestroyInstance = vkDestroyInstance;
    VK_GET_INST_PROC(instance, EnumeratePhysicalDevices);
    VK_GET_INST_PROC(instance, EnumerateDeviceExtensionProperties);
    VK_GET_INST_PROC(instance, GetPhysicalDeviceProperties2);
    VK_GET_INST_PROC(instance, GetPhysicalDeviceExternalSemaphoreProperties);
    VK_GET_INST_PROC(instance, GetPhysicalDeviceQueueFamilyProperties2);
    VK_GET_INST_PROC(instance, GetPhysicalDeviceFeatures2);
    VK_GET_INST_PROC(instance, CreateDevice);

    uint32_t physdevCount;
    VK_CHECK(vkEnumeratePhysicalDevices(instance, &physdevCount, nullptr));
    if (physdevCount == 0) {
        BAIL("Could not find any physical devices");
    }

    physdevCount = 1;
    VkPhysicalDevice physicalDevice;
    VkResult enumeratePhysDevsErr =
            vkEnumeratePhysicalDevices(instance, &physdevCount, &physicalDevice);
    if (enumeratePhysDevsErr != VK_SUCCESS && VK_INCOMPLETE != enumeratePhysDevsErr) {
        BAIL("vkEnumeratePhysicalDevices failed with non-VK_INCOMPLETE error: %d",
             enumeratePhysDevsErr);
    }

    VkPhysicalDeviceProperties2 physDevProps = {
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
            0,
            {},
    };
    VkPhysicalDeviceProtectedMemoryProperties protMemProps = {
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROTECTED_MEMORY_PROPERTIES,
            0,
            {},
    };

    if (protectedContent) {
        physDevProps.pNext = &protMemProps;
    }

    vkGetPhysicalDeviceProperties2(physicalDevice, &physDevProps);
    if (physDevProps.properties.apiVersion < VK_MAKE_VERSION(1, 1, 0)) {
        BAIL("Could not find a Vulkan 1.1+ physical device");
    }

    if (physDevProps.properties.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU) {
        // TODO: b/326633110 - SkiaVK is not working correctly on swiftshader path.
        BAIL("CPU implementations of Vulkan is not supported");
    }

    // Check for syncfd support. Bail if we cannot both import and export them.
    VkPhysicalDeviceExternalSemaphoreInfo semInfo = {
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_SEMAPHORE_INFO,
            nullptr,
            VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT,
    };
    VkExternalSemaphoreProperties semProps = {
            VK_STRUCTURE_TYPE_EXTERNAL_SEMAPHORE_PROPERTIES, nullptr, 0, 0, 0,
    };
    vkGetPhysicalDeviceExternalSemaphoreProperties(physicalDevice, &semInfo, &semProps);

    bool sufficientSemaphoreSyncFdSupport = (semProps.exportFromImportedHandleTypes &
                                             VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT) &&
            (semProps.compatibleHandleTypes & VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT) &&
            (semProps.externalSemaphoreFeatures & VK_EXTERNAL_SEMAPHORE_FEATURE_EXPORTABLE_BIT) &&
            (semProps.externalSemaphoreFeatures & VK_EXTERNAL_SEMAPHORE_FEATURE_IMPORTABLE_BIT);

    if (!sufficientSemaphoreSyncFdSupport) {
        BAIL("Vulkan device does not support sufficient external semaphore sync fd features. "
             "exportFromImportedHandleTypes 0x%x (needed 0x%x) "
             "compatibleHandleTypes 0x%x (needed 0x%x) "
             "externalSemaphoreFeatures 0x%x (needed 0x%x) ",
             semProps.exportFromImportedHandleTypes, VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT,
             semProps.compatibleHandleTypes, VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT,
             semProps.externalSemaphoreFeatures,
             VK_EXTERNAL_SEMAPHORE_FEATURE_EXPORTABLE_BIT |
                     VK_EXTERNAL_SEMAPHORE_FEATURE_IMPORTABLE_BIT);
    } else {
        ALOGD("Vulkan device supports sufficient external semaphore sync fd features. "
              "exportFromImportedHandleTypes 0x%x (needed 0x%x) "
              "compatibleHandleTypes 0x%x (needed 0x%x) "
              "externalSemaphoreFeatures 0x%x (needed 0x%x) ",
              semProps.exportFromImportedHandleTypes, VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT,
              semProps.compatibleHandleTypes, VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT,
              semProps.externalSemaphoreFeatures,
              VK_EXTERNAL_SEMAPHORE_FEATURE_EXPORTABLE_BIT |
                      VK_EXTERNAL_SEMAPHORE_FEATURE_IMPORTABLE_BIT);
    }

    uint32_t queueCount;
    vkGetPhysicalDeviceQueueFamilyProperties2(physicalDevice, &queueCount, nullptr);
    if (queueCount == 0) {
        BAIL("Could not find queues for physical device");
    }

    std::vector<VkQueueFamilyProperties2> queueProps(queueCount);
    std::vector<VkQueueFamilyGlobalPriorityPropertiesEXT> queuePriorityProps(queueCount);
    VkQueueGlobalPriorityKHR queuePriority = VK_QUEUE_GLOBAL_PRIORITY_MEDIUM_KHR;
    // Even though we don't yet know if the VK_EXT_global_priority extension is available,
    // we can safely add the request to the pNext chain, and if the extension is not
    // available, it will be ignored.
    for (uint32_t i = 0; i < queueCount; ++i) {
        queuePriorityProps[i].sType = VK_STRUCTURE_TYPE_QUEUE_FAMILY_GLOBAL_PRIORITY_PROPERTIES_EXT;
        queuePriorityProps[i].pNext = nullptr;
        queueProps[i].pNext = &queuePriorityProps[i];
    }
    vkGetPhysicalDeviceQueueFamilyProperties2(physicalDevice, &queueCount, queueProps.data());

    int graphicsQueueIndex = -1;
    for (uint32_t i = 0; i < queueCount; ++i) {
        // Look at potential answers to the VK_EXT_global_priority query.  If answers were
        // provided, we may adjust the queuePriority.
        if (queueProps[i].queueFamilyProperties.queueFlags & VK_QUEUE_GRAPHICS_BIT) {
            for (uint32_t j = 0; j < queuePriorityProps[i].priorityCount; j++) {
                if (queuePriorityProps[i].priorities[j] > queuePriority) {
                    queuePriority = queuePriorityProps[i].priorities[j];
                }
            }
            if (queuePriority == VK_QUEUE_GLOBAL_PRIORITY_REALTIME_KHR) {
                interface.isRealtimePriority = true;
            }
            graphicsQueueIndex = i;
            break;
        }
    }

    if (graphicsQueueIndex == -1) {
        BAIL("Could not find a graphics queue family");
    }

    uint32_t deviceExtensionCount;
    VK_CHECK(vkEnumerateDeviceExtensionProperties(physicalDevice, nullptr, &deviceExtensionCount,
                                                  nullptr));
    std::vector<VkExtensionProperties> deviceExtensions(deviceExtensionCount);
    VK_CHECK(vkEnumerateDeviceExtensionProperties(physicalDevice, nullptr, &deviceExtensionCount,
                                                  deviceExtensions.data()));

    std::vector<const char*> enabledDeviceExtensionNames;
    enabledDeviceExtensionNames.reserve(deviceExtensions.size());
    interface.deviceExtensionNames.reserve(deviceExtensions.size());
    for (const auto& devExt : deviceExtensions) {
        enabledDeviceExtensionNames.push_back(devExt.extensionName);
        interface.deviceExtensionNames.push_back(devExt.extensionName);
    }

    interface.grExtensions.init(sGetProc, instance, physicalDevice,
                                enabledInstanceExtensionNames.size(),
                                enabledInstanceExtensionNames.data(),
                                enabledDeviceExtensionNames.size(),
                                enabledDeviceExtensionNames.data());

    if (!interface.grExtensions.hasExtension(VK_KHR_EXTERNAL_SEMAPHORE_FD_EXTENSION_NAME, 1)) {
        BAIL("Vulkan driver doesn't support external semaphore fd");
    }

    interface.physicalDeviceFeatures2 = new VkPhysicalDeviceFeatures2;
    interface.physicalDeviceFeatures2->sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    interface.physicalDeviceFeatures2->pNext = nullptr;

    interface.samplerYcbcrConversionFeatures = new VkPhysicalDeviceSamplerYcbcrConversionFeatures;
    interface.samplerYcbcrConversionFeatures->sType =
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SAMPLER_YCBCR_CONVERSION_FEATURES;
    interface.samplerYcbcrConversionFeatures->pNext = nullptr;

    interface.physicalDeviceFeatures2->pNext = interface.samplerYcbcrConversionFeatures;
    void** tailPnext = &interface.samplerYcbcrConversionFeatures->pNext;

    if (protectedContent) {
        interface.protectedMemoryFeatures = new VkPhysicalDeviceProtectedMemoryFeatures;
        interface.protectedMemoryFeatures->sType =
                VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROTECTED_MEMORY_FEATURES;
        interface.protectedMemoryFeatures->pNext = nullptr;
        *tailPnext = interface.protectedMemoryFeatures;
        tailPnext = &interface.protectedMemoryFeatures->pNext;
    }

    if (interface.grExtensions.hasExtension(VK_EXT_DEVICE_FAULT_EXTENSION_NAME, 1)) {
        interface.deviceFaultFeatures = new VkPhysicalDeviceFaultFeaturesEXT;
        interface.deviceFaultFeatures->sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FAULT_FEATURES_EXT;
        interface.deviceFaultFeatures->pNext = nullptr;
        *tailPnext = interface.deviceFaultFeatures;
        tailPnext = &interface.deviceFaultFeatures->pNext;
    }

    vkGetPhysicalDeviceFeatures2(physicalDevice, interface.physicalDeviceFeatures2);
    // Looks like this would slow things down and we can't depend on it on all platforms
    interface.physicalDeviceFeatures2->features.robustBufferAccess = VK_FALSE;

    if (protectedContent && !interface.protectedMemoryFeatures->protectedMemory) {
        BAIL("Protected memory not supported");
    }

    float queuePriorities[1] = {0.0f};
    void* queueNextPtr = nullptr;

    VkDeviceQueueGlobalPriorityCreateInfoEXT queuePriorityCreateInfo = {
            VK_STRUCTURE_TYPE_DEVICE_QUEUE_GLOBAL_PRIORITY_CREATE_INFO_EXT,
            nullptr,
            // If queue priority is supported, RE should always have realtime priority.
            queuePriority,
    };

    if (interface.grExtensions.hasExtension(VK_EXT_GLOBAL_PRIORITY_EXTENSION_NAME, 2)) {
        queueNextPtr = &queuePriorityCreateInfo;
    }

    VkDeviceQueueCreateFlags deviceQueueCreateFlags =
            (VkDeviceQueueCreateFlags)(protectedContent ? VK_DEVICE_QUEUE_CREATE_PROTECTED_BIT : 0);

    const VkDeviceQueueCreateInfo queueInfo = {
            VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
            queueNextPtr,
            deviceQueueCreateFlags,
            (uint32_t)graphicsQueueIndex,
            1,
            queuePriorities,
    };

    const VkDeviceCreateInfo deviceInfo = {
            VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
            interface.physicalDeviceFeatures2,
            0,
            1,
            &queueInfo,
            0,
            nullptr,
            (uint32_t)enabledDeviceExtensionNames.size(),
            enabledDeviceExtensionNames.data(),
            nullptr,
    };

    ALOGD("Trying to create Vk device with protectedContent=%d", protectedContent);
    VkDevice device;
    VK_CHECK(vkCreateDevice(physicalDevice, &deviceInfo, nullptr, &device));
    ALOGD("Trying to create Vk device with protectedContent=%d (success)", protectedContent);

    VkQueue graphicsQueue;
    VK_GET_DEV_PROC(device, GetDeviceQueue2);
    const VkDeviceQueueInfo2 deviceQueueInfo2 = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2, nullptr,
                                                 deviceQueueCreateFlags,
                                                 (uint32_t)graphicsQueueIndex, 0};
    vkGetDeviceQueue2(device, &deviceQueueInfo2, &graphicsQueue);

    VK_GET_DEV_PROC(device, DeviceWaitIdle);
    VK_GET_DEV_PROC(device, DestroyDevice);
    interface.funcs.vkDeviceWaitIdle = vkDeviceWaitIdle;
    interface.funcs.vkDestroyDevice = vkDestroyDevice;

    VK_GET_DEV_PROC(device, CreateSemaphore);
    VK_GET_DEV_PROC(device, ImportSemaphoreFdKHR);
    VK_GET_DEV_PROC(device, GetSemaphoreFdKHR);
    VK_GET_DEV_PROC(device, DestroySemaphore);
    interface.funcs.vkCreateSemaphore = vkCreateSemaphore;
    interface.funcs.vkImportSemaphoreFdKHR = vkImportSemaphoreFdKHR;
    interface.funcs.vkGetSemaphoreFdKHR = vkGetSemaphoreFdKHR;
    interface.funcs.vkDestroySemaphore = vkDestroySemaphore;

    // At this point, everything's succeeded and we can continue
    interface.initialized = true;
    interface.instance = instance;
    interface.physicalDevice = physicalDevice;
    interface.device = device;
    interface.queue = graphicsQueue;
    interface.queueIndex = graphicsQueueIndex;
    interface.apiVersion = physDevProps.properties.apiVersion;
    // grExtensions already constructed
    // feature pointers already constructed
    interface.grGetProc = sGetProc;
    interface.isProtected = protectedContent;
    // funcs already initialized

    const nsecs_t timeAfter = systemTime();
    const float initTimeMs = static_cast<float>(timeAfter - timeBefore) / 1.0E6;
    ALOGD("%s: Success init Vulkan interface in %f ms", __func__, initTimeMs);
    return interface;
}

void teardownVulkanInterface(VulkanInterface* interface) {
    interface->initialized = false;

    if (interface->device != VK_NULL_HANDLE) {
        interface->funcs.vkDeviceWaitIdle(interface->device);
        interface->funcs.vkDestroyDevice(interface->device, nullptr);
        interface->device = VK_NULL_HANDLE;
    }
    if (interface->instance != VK_NULL_HANDLE) {
        interface->funcs.vkDestroyInstance(interface->instance, nullptr);
        interface->instance = VK_NULL_HANDLE;
    }

    if (interface->protectedMemoryFeatures) {
        delete interface->protectedMemoryFeatures;
    }

    if (interface->samplerYcbcrConversionFeatures) {
        delete interface->samplerYcbcrConversionFeatures;
    }

    if (interface->physicalDeviceFeatures2) {
        delete interface->physicalDeviceFeatures2;
    }

    if (interface->deviceFaultFeatures) {
        delete interface->deviceFaultFeatures;
    }

    interface->samplerYcbcrConversionFeatures = nullptr;
    interface->physicalDeviceFeatures2 = nullptr;
    interface->protectedMemoryFeatures = nullptr;
}

static VulkanInterface sVulkanInterface;
static VulkanInterface sProtectedContentVulkanInterface;

static void sSetupVulkanInterface() {
    if (!sVulkanInterface.initialized) {
        sVulkanInterface = initVulkanInterface(false /* no protected content */);
        // We will have to abort if non-protected VkDevice creation fails (then nothing works).
        LOG_ALWAYS_FATAL_IF(!sVulkanInterface.initialized,
                            "Could not initialize Vulkan RenderEngine!");
    }
    if (!sProtectedContentVulkanInterface.initialized) {
        sProtectedContentVulkanInterface = initVulkanInterface(true /* protected content */);
        if (!sProtectedContentVulkanInterface.initialized) {
            ALOGE("Could not initialize protected content Vulkan RenderEngine.");
        }
    }
}

bool RenderEngine::canSupport(GraphicsApi graphicsApi) {
    switch (graphicsApi) {
        case GraphicsApi::GL:
            return true;
        case GraphicsApi::VK: {
            if (!sVulkanInterface.initialized) {
                sVulkanInterface = initVulkanInterface(false /* no protected content */);
                ALOGD("%s: initialized == %s.", __func__,
                      sVulkanInterface.initialized ? "true" : "false");
            }
            return sVulkanInterface.initialized;
        }
    }
}

namespace skia {

using base::StringAppendF;

std::unique_ptr<SkiaVkRenderEngine> SkiaVkRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    std::unique_ptr<SkiaVkRenderEngine> engine(new SkiaVkRenderEngine(args));
    engine->ensureGrContextsCreated();

    if (sVulkanInterface.initialized) {
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
    return sProtectedContentVulkanInterface.initialized;
}

bool SkiaVkRenderEngine::useProtectedContextImpl(GrProtected) {
    return true;
}

static void delete_semaphore(void* semaphore) {
    DestroySemaphoreInfo* info = reinterpret_cast<DestroySemaphoreInfo*>(semaphore);
    --info->mRefs;
    if (!info->mRefs) {
        sVulkanInterface.destroySemaphore(info->mSemaphore);
        delete info;
    }
}

static void delete_semaphore_protected(void* semaphore) {
    DestroySemaphoreInfo* info = reinterpret_cast<DestroySemaphoreInfo*>(semaphore);
    --info->mRefs;
    if (!info->mRefs) {
        sProtectedContentVulkanInterface.destroySemaphore(info->mSemaphore);
        delete info;
    }
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
    GrBackendSemaphore beSemaphore;
    beSemaphore.initVulkan(waitSemaphore);
    grContext->wait(1, &beSemaphore, true /* delete after wait */);
}

base::unique_fd SkiaVkRenderEngine::flushAndSubmit(GrDirectContext* grContext) {
    VulkanInterface& vi = getVulkanInterface(isProtected());
    VkSemaphore semaphore = vi.createExportableSemaphore();

    GrBackendSemaphore backendSemaphore;
    backendSemaphore.initVulkan(semaphore);

    GrFlushInfo flushInfo;
    DestroySemaphoreInfo* destroySemaphoreInfo = nullptr;
    if (semaphore != VK_NULL_HANDLE) {
        destroySemaphoreInfo = new DestroySemaphoreInfo(semaphore);
        flushInfo.fNumSemaphores = 1;
        flushInfo.fSignalSemaphores = &backendSemaphore;
        flushInfo.fFinishedProc = isProtected() ? delete_semaphore_protected : delete_semaphore;
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
    if (getVulkanInterface(isProtected()).isRealtimePriority) {
        return kRealtimePriority;
    } else {
        return 0;
    }
}

void SkiaVkRenderEngine::appendBackendSpecificInfoToDump(std::string& result) {
    StringAppendF(&result, "\n ------------RE Vulkan----------\n");
    StringAppendF(&result, "\n Vulkan device initialized: %d\n", sVulkanInterface.initialized);
    StringAppendF(&result, "\n Vulkan protected device initialized: %d\n",
                  sProtectedContentVulkanInterface.initialized);

    if (!sVulkanInterface.initialized) {
        return;
    }

    StringAppendF(&result, "\n Instance extensions:\n");
    for (const auto& name : sVulkanInterface.instanceExtensionNames) {
        StringAppendF(&result, "\n %s\n", name.c_str());
    }

    StringAppendF(&result, "\n Device extensions:\n");
    for (const auto& name : sVulkanInterface.deviceExtensionNames) {
        StringAppendF(&result, "\n %s\n", name.c_str());
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android
