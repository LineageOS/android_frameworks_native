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

#ifndef ANDROID_POWERHALLOADER_H
#define ANDROID_POWERHALLOADER_H

#include <aidl/android/hardware/power/IPower.h>
#include <android-base/thread_annotations.h>
#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/1.2/IPower.h>
#include <android/hardware/power/1.3/IPower.h>

namespace android {

namespace power {

// Loads available Power HAL services.
class PowerHalLoader {
public:
    static void unloadAll();
    static std::shared_ptr<aidl::android::hardware::power::IPower> loadAidl();
    static sp<hardware::power::V1_0::IPower> loadHidlV1_0();
    static sp<hardware::power::V1_1::IPower> loadHidlV1_1();
    static sp<hardware::power::V1_2::IPower> loadHidlV1_2();
    static sp<hardware::power::V1_3::IPower> loadHidlV1_3();
    // Returns aidl interface version, or 0 if AIDL is not used
    static int32_t getAidlVersion();

private:
    static std::mutex gHalMutex;
    static std::shared_ptr<aidl::android::hardware::power::IPower> gHalAidl GUARDED_BY(gHalMutex);
    static sp<hardware::power::V1_0::IPower> gHalHidlV1_0 GUARDED_BY(gHalMutex);
    static sp<hardware::power::V1_1::IPower> gHalHidlV1_1 GUARDED_BY(gHalMutex);
    static sp<hardware::power::V1_2::IPower> gHalHidlV1_2 GUARDED_BY(gHalMutex);
    static sp<hardware::power::V1_3::IPower> gHalHidlV1_3 GUARDED_BY(gHalMutex);

    static sp<hardware::power::V1_0::IPower> loadHidlV1_0Locked()
            EXCLUSIVE_LOCKS_REQUIRED(gHalMutex);

    static int32_t gAidlInterfaceVersion;

    PowerHalLoader() = delete;
    ~PowerHalLoader() = delete;
};

}; // namespace power

} // namespace android

#endif // ANDROID_POWERHALLOADER_H
