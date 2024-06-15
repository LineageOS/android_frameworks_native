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

#define LOG_TAG "vkprofiles"

#ifndef VK_USE_PLATFORM_ANDROID_KHR
#define VK_USE_PLATFORM_ANDROID_KHR
#endif

#include <string>
#include <vector>

#include <android/log.h>

#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#include "generated/vulkan_profiles.h"
#include "vkprofiles.h"

namespace android::vkprofiles {

/* Wrap vkProfileGetSupport in an anonymous namespace.
 * vkProfileGetSupport only works for profiles that we explicitly add, we don't
 * want a user of this library to mistakenly call with a profile that we haven't
 * added.
 */
namespace {

std::string vkProfileGetSupport(const VpProfileProperties* pProfile,
                                const uint32_t minApiVersion) {
    VkResult result = VK_SUCCESS;
    VkBool32 supported = VK_FALSE;

    result = vpGetInstanceProfileSupport(nullptr, pProfile, &supported);
    if (result != VK_SUCCESS) {
        std::string error(
            "There was a failure from vpGetInstanceProfileSupport,"
            " check `vkprofiles` in logcat."
            " result = " +
            std::to_string(result));
        return error;
    }
    if (supported != VK_TRUE) {
        std::string error(
            "There was a failure from vpGetInstanceProfileSupport,"
            " check `vkprofiles` in logcat."
            " supported = " +
            std::to_string(supported));
        return error;
    }

    const VkApplicationInfo appInfo = {
        VK_STRUCTURE_TYPE_APPLICATION_INFO,
        nullptr,
        "vkprofiles",
        0,
        "",
        0,
        minApiVersion,
    };
    VkInstanceCreateInfo instanceCreateInfo = {
        VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        nullptr,
        0,
        &appInfo,
        0,
        nullptr,
        0,
        nullptr,
    };

    VpInstanceCreateInfo vpInstanceCreateInfo{};
    vpInstanceCreateInfo.pCreateInfo = &instanceCreateInfo;
    vpInstanceCreateInfo.enabledFullProfileCount = 1;
    vpInstanceCreateInfo.pEnabledFullProfiles = pProfile;

    VkInstance instance = VK_NULL_HANDLE;
    result = vpCreateInstance(&vpInstanceCreateInfo, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::string error(
            "There was a failure from vpCreateInstance,"
            " check `vkprofiles` in logcat."
            " result = " +
            std::to_string(result));
        return error;
    }

    uint32_t count;
    result = vkEnumeratePhysicalDevices(instance, &count, nullptr);
    if (result != VK_SUCCESS) {
        vkDestroyInstance(instance, nullptr);
        std::string error(
            "There was a failure from vkEnumeratePhysicalDevices,"
            " check `vkprofiles` in logcat."
            " result = " +
            std::to_string(result));
        return error;
    }

    std::vector<VkPhysicalDevice> devices(count, VK_NULL_HANDLE);
    result = vkEnumeratePhysicalDevices(instance, &count, devices.data());
    if (result != VK_SUCCESS) {
        vkDestroyInstance(instance, nullptr);
        std::string error(
            "There was a failure from vkEnumeratePhysicalDevices (2),"
            " check `vkprofiles` in logcat."
            " result = " +
            std::to_string(result));
        return error;
    }

    bool onePhysicalDeviceSupports = false;
    for (size_t i = 0; i < count; i++) {
        result = vpGetPhysicalDeviceProfileSupport(instance, devices[i],
                                                   pProfile, &supported);
        if (result != VK_SUCCESS) {
            ALOGD("vpGetPhysicalDeviceProfileSupport fail, result = %d",
                  result);
            continue;
        } else if (supported != VK_TRUE) {
            ALOGD("vpGetPhysicalDeviceProfileSupport fail, supported = %d",
                  supported);
            continue;
        }

        onePhysicalDeviceSupports = true;
    }

    if (!onePhysicalDeviceSupports) {
        std::string error(
            "There was a failure from vpGetPhysicalDeviceProfileSupport,"
            " check `vkprofiles` in logcat."
            " No VkPhysicalDevice supports the profile");
        return error;
    }

    return std::string("SUPPORTED");
}

}  // anonymous namespace

std::string vkAbp2021GetSupport() {
    VpProfileProperties profile{VP_ANDROID_BASELINE_2021_NAME,
                                VP_ANDROID_BASELINE_2021_SPEC_VERSION};
    return vkProfileGetSupport(&profile,
                               VP_ANDROID_BASELINE_2021_MIN_API_VERSION);
}

std::string vkAbp2021CpuOnlyGetSupport() {
    VpProfileProperties profile{VP_ANDROID_BASELINE_2021_CPU_ONLY_NAME,
                                VP_ANDROID_BASELINE_2021_CPU_ONLY_SPEC_VERSION};
    return vkProfileGetSupport(&profile,
                               VP_ANDROID_BASELINE_2021_MIN_API_VERSION);
}

std::string vkAbp2022GetSupport() {
    VpProfileProperties profile{VP_ANDROID_BASELINE_2022_NAME,
                                VP_ANDROID_BASELINE_2022_SPEC_VERSION};
    return vkProfileGetSupport(&profile,
                               VP_ANDROID_BASELINE_2022_MIN_API_VERSION);
}

std::string vkVpa15GetSupport() {
    VpProfileProperties profile{VP_ANDROID_15_MINIMUMS_NAME,
                                VP_ANDROID_15_MINIMUMS_SPEC_VERSION};
    return vkProfileGetSupport(&profile,
                               VP_ANDROID_15_MINIMUMS_MIN_API_VERSION);
}

std::string vkProfiles() {
    return "{"
           "\"" + std::string(VP_ANDROID_BASELINE_2021_NAME) + "\": "
           "\"" + vkAbp2021GetSupport() + "\","
           "\"" + std::string(VP_ANDROID_BASELINE_2021_CPU_ONLY_NAME) + "\": "
           "\"" + vkAbp2021CpuOnlyGetSupport() + "\","
           "\"" + std::string(VP_ANDROID_BASELINE_2022_NAME) + "\": "
           "\"" + vkAbp2022GetSupport() + "\","
           "\"" + std::string(VP_ANDROID_15_MINIMUMS_NAME) + "\": "
           "\"" + vkVpa15GetSupport() + "\""
           "}";
}

}  // namespace android::vkprofiles
