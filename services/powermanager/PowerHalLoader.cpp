/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "PowerHalLoader"

#include <aidl/android/hardware/power/IPower.h>
#include <android/binder_manager.h>
#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/1.2/IPower.h>
#include <android/hardware/power/1.3/IPower.h>
#include <binder/IServiceManager.h>
#include <hardware/power.h>
#include <hardware_legacy/power.h>
#include <powermanager/PowerHalLoader.h>

using namespace android::hardware::power;

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

template <typename T, typename F>
sp<T> loadHal(bool& exists, sp<T>& hal, F& loadFn, const char* halName) {
    if (!exists) {
        return nullptr;
    }
    if (hal) {
        return hal;
    }
    hal = loadFn();
    if (hal) {
        ALOGV("Successfully connected to Power HAL %s service.", halName);
    } else {
        ALOGV("Power HAL %s service not available.", halName);
        exists = false;
    }
    return hal;
}

// -------------------------------------------------------------------------------------------------

std::mutex PowerHalLoader::gHalMutex;
std::shared_ptr<aidl::android::hardware::power::IPower> PowerHalLoader::gHalAidl = nullptr;
sp<V1_0::IPower> PowerHalLoader::gHalHidlV1_0 = nullptr;
sp<V1_1::IPower> PowerHalLoader::gHalHidlV1_1 = nullptr;
sp<V1_2::IPower> PowerHalLoader::gHalHidlV1_2 = nullptr;
sp<V1_3::IPower> PowerHalLoader::gHalHidlV1_3 = nullptr;
int32_t PowerHalLoader::gAidlInterfaceVersion = 0;

void PowerHalLoader::unloadAll() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    gHalAidl = nullptr;
    gHalHidlV1_0 = nullptr;
    gHalHidlV1_1 = nullptr;
    gHalHidlV1_2 = nullptr;
    gHalHidlV1_3 = nullptr;
}

std::shared_ptr<aidl::android::hardware::power::IPower> PowerHalLoader::loadAidl() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    static bool gHalExists = true;
    if (!gHalExists) {
        return nullptr;
    }
    if (gHalAidl) {
        return gHalAidl;
    }
    auto aidlServiceName =
            std::string(aidl::android::hardware::power::IPower::descriptor) + "/default";
    if (!AServiceManager_isDeclared(aidlServiceName.c_str())) {
        gHalExists = false;
        return nullptr;
    }
    gHalAidl = aidl::android::hardware::power::IPower::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(aidlServiceName.c_str())));
    if (gHalAidl) {
        ALOGI("Successfully connected to Power HAL AIDL service.");
        gHalAidl->getInterfaceVersion(&gAidlInterfaceVersion);

    } else {
        ALOGI("Power HAL AIDL service not available.");
        gHalExists = false;
    }
    return gHalAidl;
}

sp<V1_0::IPower> PowerHalLoader::loadHidlV1_0() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    return loadHidlV1_0Locked();
}

sp<V1_1::IPower> PowerHalLoader::loadHidlV1_1() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    static bool gHalExists = true;
    static auto loadFn = []() { return V1_1::IPower::castFrom(loadHidlV1_0Locked()); };
    return loadHal<V1_1::IPower>(gHalExists, gHalHidlV1_1, loadFn, "HIDL v1.1");
}

sp<V1_2::IPower> PowerHalLoader::loadHidlV1_2() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    static bool gHalExists = true;
    static auto loadFn = []() { return V1_2::IPower::castFrom(loadHidlV1_0Locked()); };
    return loadHal<V1_2::IPower>(gHalExists, gHalHidlV1_2, loadFn, "HIDL v1.2");
}

sp<V1_3::IPower> PowerHalLoader::loadHidlV1_3() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    static bool gHalExists = true;
    static auto loadFn = []() { return V1_3::IPower::castFrom(loadHidlV1_0Locked()); };
    return loadHal<V1_3::IPower>(gHalExists, gHalHidlV1_3, loadFn, "HIDL v1.3");
}

sp<V1_0::IPower> PowerHalLoader::loadHidlV1_0Locked() {
    static bool gHalExists = true;
    static auto loadFn = []() { return V1_0::IPower::getService(); };
    return loadHal<V1_0::IPower>(gHalExists, gHalHidlV1_0, loadFn, "HIDL v1.0");
}

int32_t PowerHalLoader::getAidlVersion() {
    return gAidlInterfaceVersion;
}

// -------------------------------------------------------------------------------------------------

} // namespace power

} // namespace android
