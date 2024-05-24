
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
 *
*/

// clang-format off

#ifndef VULKAN_PROFILES_H_
#define VULKAN_PROFILES_H_ 1

#define VPAPI_ATTR

#ifdef __cplusplus
    extern "C" {
#endif

#include <vulkan/vulkan.h>

#if defined(VK_VERSION_1_1) && \
    defined(VK_ANDROID_external_memory_android_hardware_buffer) && \
    defined(VK_EXT_queue_family_foreign) && \
    defined(VK_EXT_swapchain_colorspace) && \
    defined(VK_GOOGLE_display_timing) && \
    defined(VK_KHR_android_surface) && \
    defined(VK_KHR_create_renderpass2) && \
    defined(VK_KHR_dedicated_allocation) && \
    defined(VK_KHR_descriptor_update_template) && \
    defined(VK_KHR_driver_properties) && \
    defined(VK_KHR_external_fence) && \
    defined(VK_KHR_external_fence_capabilities) && \
    defined(VK_KHR_external_fence_fd) && \
    defined(VK_KHR_external_memory) && \
    defined(VK_KHR_external_memory_capabilities) && \
    defined(VK_KHR_external_semaphore) && \
    defined(VK_KHR_external_semaphore_capabilities) && \
    defined(VK_KHR_external_semaphore_fd) && \
    defined(VK_KHR_get_memory_requirements2) && \
    defined(VK_KHR_get_physical_device_properties2) && \
    defined(VK_KHR_get_surface_capabilities2) && \
    defined(VK_KHR_incremental_present) && \
    defined(VK_KHR_maintenance1) && \
    defined(VK_KHR_sampler_mirror_clamp_to_edge) && \
    defined(VK_KHR_storage_buffer_storage_class) && \
    defined(VK_KHR_surface) && \
    defined(VK_KHR_swapchain) && \
    defined(VK_KHR_variable_pointers)
#define VP_ANDROID_baseline_2022 1
#define VP_ANDROID_BASELINE_2022_NAME "VP_ANDROID_baseline_2022"
#define VP_ANDROID_BASELINE_2022_SPEC_VERSION 1
#define VP_ANDROID_BASELINE_2022_MIN_API_VERSION VK_MAKE_VERSION(1, 1, 106)
#endif

#if defined(VK_VERSION_1_3) && \
    defined(VP_ANDROID_baseline_2022) && \
    defined(VK_ANDROID_external_format_resolve) && \
    defined(VK_EXT_4444_formats) && \
    defined(VK_EXT_custom_border_color) && \
    defined(VK_EXT_device_memory_report) && \
    defined(VK_EXT_external_memory_acquire_unmodified) && \
    defined(VK_EXT_index_type_uint8) && \
    defined(VK_EXT_line_rasterization) && \
    defined(VK_EXT_load_store_op_none) && \
    defined(VK_EXT_primitive_topology_list_restart) && \
    defined(VK_EXT_primitives_generated_query) && \
    defined(VK_EXT_provoking_vertex) && \
    defined(VK_EXT_scalar_block_layout) && \
    defined(VK_EXT_surface_maintenance1) && \
    defined(VK_EXT_swapchain_maintenance1) && \
    defined(VK_GOOGLE_surfaceless_query) && \
    defined(VK_IMG_relaxed_line_rasterization) && \
    defined(VK_KHR_16bit_storage) && \
    defined(VK_KHR_maintenance5) && \
    defined(VK_KHR_shader_float16_int8) && \
    defined(VK_KHR_vertex_attribute_divisor)
#define VP_ANDROID_15_minimums 1
#define VP_ANDROID_15_MINIMUMS_NAME "VP_ANDROID_15_minimums"
#define VP_ANDROID_15_MINIMUMS_SPEC_VERSION 1
#define VP_ANDROID_15_MINIMUMS_MIN_API_VERSION VK_MAKE_VERSION(1, 3, 273)
#endif

#if defined(VK_VERSION_1_0) && \
    defined(VK_EXT_swapchain_colorspace) && \
    defined(VK_GOOGLE_display_timing) && \
    defined(VK_KHR_android_surface) && \
    defined(VK_KHR_dedicated_allocation) && \
    defined(VK_KHR_descriptor_update_template) && \
    defined(VK_KHR_external_fence) && \
    defined(VK_KHR_external_fence_capabilities) && \
    defined(VK_KHR_external_fence_fd) && \
    defined(VK_KHR_external_memory) && \
    defined(VK_KHR_external_memory_capabilities) && \
    defined(VK_KHR_external_semaphore) && \
    defined(VK_KHR_external_semaphore_capabilities) && \
    defined(VK_KHR_external_semaphore_fd) && \
    defined(VK_KHR_get_memory_requirements2) && \
    defined(VK_KHR_get_physical_device_properties2) && \
    defined(VK_KHR_get_surface_capabilities2) && \
    defined(VK_KHR_incremental_present) && \
    defined(VK_KHR_maintenance1) && \
    defined(VK_KHR_storage_buffer_storage_class) && \
    defined(VK_KHR_surface) && \
    defined(VK_KHR_swapchain) && \
    defined(VK_KHR_variable_pointers)
#define VP_ANDROID_baseline_2021 1
#define VP_ANDROID_BASELINE_2021_NAME "VP_ANDROID_baseline_2021"
#define VP_ANDROID_BASELINE_2021_SPEC_VERSION 2
#define VP_ANDROID_BASELINE_2021_MIN_API_VERSION VK_MAKE_VERSION(1, 0, 68)
#endif

#if defined(VK_VERSION_1_0) && \
    defined(VK_EXT_swapchain_colorspace) && \
    defined(VK_KHR_android_surface) && \
    defined(VK_KHR_dedicated_allocation) && \
    defined(VK_KHR_descriptor_update_template) && \
    defined(VK_KHR_external_fence) && \
    defined(VK_KHR_external_fence_capabilities) && \
    defined(VK_KHR_external_memory) && \
    defined(VK_KHR_external_memory_capabilities) && \
    defined(VK_KHR_external_semaphore) && \
    defined(VK_KHR_external_semaphore_capabilities) && \
    defined(VK_KHR_external_semaphore_fd) && \
    defined(VK_KHR_get_memory_requirements2) && \
    defined(VK_KHR_get_physical_device_properties2) && \
    defined(VK_KHR_get_surface_capabilities2) && \
    defined(VK_KHR_incremental_present) && \
    defined(VK_KHR_maintenance1) && \
    defined(VK_KHR_storage_buffer_storage_class) && \
    defined(VK_KHR_surface) && \
    defined(VK_KHR_swapchain)
#define VP_ANDROID_baseline_2021_cpu_only 1
#define VP_ANDROID_BASELINE_2021_CPU_ONLY_NAME "VP_ANDROID_baseline_2021_cpu_only"
#define VP_ANDROID_BASELINE_2021_CPU_ONLY_SPEC_VERSION 1
#define VP_ANDROID_BASELINE_2021_CPU_ONLY_MIN_API_VERSION VK_MAKE_VERSION(1, 0, 68)
#endif

#define VP_HEADER_VERSION_COMPLETE VK_MAKE_API_VERSION(0, 2, 0, VK_HEADER_VERSION)

#define VP_MAX_PROFILE_NAME_SIZE 256U

typedef struct VpProfileProperties {
    char        profileName[VP_MAX_PROFILE_NAME_SIZE];
    uint32_t    specVersion;
} VpProfileProperties;

typedef struct VpBlockProperties {
    VpProfileProperties profiles;
    uint32_t apiVersion;
    char blockName[VP_MAX_PROFILE_NAME_SIZE];
} VpBlockProperties;

typedef enum VpInstanceCreateFlagBits {
    VP_INSTANCE_CREATE_FLAG_BITS_MAX_ENUM = 0x7FFFFFFF
} VpInstanceCreateFlagBits;
typedef VkFlags VpInstanceCreateFlags;

typedef struct VpInstanceCreateInfo {
    const VkInstanceCreateInfo* pCreateInfo;
    VpInstanceCreateFlags       flags;
    uint32_t                    enabledFullProfileCount;
    const VpProfileProperties*  pEnabledFullProfiles;
    uint32_t                    enabledProfileBlockCount;
    const VpBlockProperties*    pEnabledProfileBlocks;
} VpInstanceCreateInfo;

typedef enum VpDeviceCreateFlagBits {
    VP_DEVICE_CREATE_DISABLE_ROBUST_BUFFER_ACCESS_BIT = 0x0000001,
    VP_DEVICE_CREATE_DISABLE_ROBUST_IMAGE_ACCESS_BIT = 0x0000002,
    VP_DEVICE_CREATE_DISABLE_ROBUST_ACCESS =
        VP_DEVICE_CREATE_DISABLE_ROBUST_BUFFER_ACCESS_BIT | VP_DEVICE_CREATE_DISABLE_ROBUST_IMAGE_ACCESS_BIT,

    VP_DEVICE_CREATE_FLAG_BITS_MAX_ENUM = 0x7FFFFFFF
} VpDeviceCreateFlagBits;
typedef VkFlags VpDeviceCreateFlags;

typedef struct VpDeviceCreateInfo {
    const VkDeviceCreateInfo*   pCreateInfo;
    VpDeviceCreateFlags         flags;
    uint32_t                    enabledFullProfileCount;
    const VpProfileProperties*  pEnabledFullProfiles;
    uint32_t                    enabledProfileBlockCount;
    const VpBlockProperties*    pEnabledProfileBlocks;
} VpDeviceCreateInfo;

// Query the list of available profiles in the library
VPAPI_ATTR VkResult vpGetProfiles(uint32_t *pPropertyCount, VpProfileProperties *pProperties);

// List the required profiles of a profile
VPAPI_ATTR VkResult vpGetProfileRequiredProfiles(const VpProfileProperties* pProfile, uint32_t* pPropertyCount, VpProfileProperties* pProperties);

// Query the profile required Vulkan API version
VPAPI_ATTR uint32_t vpGetProfileAPIVersion(const VpProfileProperties* pProfile);

// List the recommended fallback profiles of a profile
VPAPI_ATTR VkResult vpGetProfileFallbacks(const VpProfileProperties *pProfile, uint32_t *pPropertyCount, VpProfileProperties *pProperties);

// Query whether the profile has multiple variants. Profiles with multiple variants can only use vpGetInstanceProfileSupport and vpGetPhysicalDeviceProfileSupport capabilities of the library. Other function will return a VK_ERROR_UNKNOWN error
VPAPI_ATTR VkResult vpHasMultipleVariantsProfile(const VpProfileProperties *pProfile, VkBool32 *pHasMultipleVariants);

// Check whether a profile is supported at the instance level
VPAPI_ATTR VkResult vpGetInstanceProfileSupport(const char *pLayerName, const VpProfileProperties *pProfile, VkBool32 *pSupported);

// Check whether a variant of a profile is supported at the instance level and report this list of blocks used to validate the profiles
VPAPI_ATTR VkResult vpGetInstanceProfileVariantsSupport(const char *pLayerName, const VpProfileProperties *pProfile, VkBool32 *pSupported, uint32_t *pPropertyCount, VpBlockProperties* pProperties);

// Create a VkInstance with the profile instance extensions enabled
VPAPI_ATTR VkResult vpCreateInstance(const VpInstanceCreateInfo *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkInstance *pInstance);

// Check whether a profile is supported by the physical device
VPAPI_ATTR VkResult vpGetPhysicalDeviceProfileSupport(VkInstance instance, VkPhysicalDevice physicalDevice, const VpProfileProperties *pProfile, VkBool32 *pSupported);

// Check whether a variant of a profile is supported by the physical device and report this list of blocks used to validate the profiles
VPAPI_ATTR VkResult vpGetPhysicalDeviceProfileVariantsSupport(VkInstance instance, VkPhysicalDevice physicalDevice, const VpProfileProperties *pProfile, VkBool32 *pSupported, uint32_t *pPropertyCount, VpBlockProperties* pProperties);

// Create a VkDevice with the profile features and device extensions enabled
VPAPI_ATTR VkResult vpCreateDevice(VkPhysicalDevice physicalDevice, const VpDeviceCreateInfo *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkDevice *pDevice);

// Query the list of instance extensions of a profile
VPAPI_ATTR VkResult vpGetProfileInstanceExtensionProperties(const VpProfileProperties *pProfile, const char* pBlockName, uint32_t *pPropertyCount, VkExtensionProperties *pProperties);

// Query the list of device extensions of a profile
VPAPI_ATTR VkResult vpGetProfileDeviceExtensionProperties(const VpProfileProperties *pProfile, const char* pBlockName, uint32_t *pPropertyCount, VkExtensionProperties *pProperties);

// Fill the feature structures with the requirements of a profile
VPAPI_ATTR VkResult vpGetProfileFeatures(const VpProfileProperties *pProfile, const char* pBlockName, void *pNext);

// Query the list of feature structure types specified by the profile
VPAPI_ATTR VkResult vpGetProfileFeatureStructureTypes(const VpProfileProperties *pProfile, const char* pBlockName, uint32_t *pStructureTypeCount, VkStructureType *pStructureTypes);

// Fill the property structures with the requirements of a profile
VPAPI_ATTR VkResult vpGetProfileProperties(const VpProfileProperties *pProfile, const char* pBlockName, void *pNext);

// Query the list of property structure types specified by the profile
VPAPI_ATTR VkResult vpGetProfilePropertyStructureTypes(const VpProfileProperties *pProfile, const char* pBlockName, uint32_t *pStructureTypeCount, VkStructureType *pStructureTypes);

// Query the list of formats with specified requirements by a profile
VPAPI_ATTR VkResult vpGetProfileFormats(const VpProfileProperties *pProfile, const char* pBlockName, uint32_t *pFormatCount, VkFormat *pFormats);

// Query the requirements of a format for a profile
VPAPI_ATTR VkResult vpGetProfileFormatProperties(const VpProfileProperties *pProfile, const char* pBlockName, VkFormat format, void *pNext);

// Query the list of format structure types specified by the profile
VPAPI_ATTR VkResult vpGetProfileFormatStructureTypes(const VpProfileProperties *pProfile, const char* pBlockName, uint32_t *pStructureTypeCount, VkStructureType *pStructureTypes);

#ifdef __cplusplus
}
#endif

#endif // VULKAN_PROFILES_H_

// clang-format on
