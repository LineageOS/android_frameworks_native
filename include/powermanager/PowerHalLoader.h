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

#include <android-base/thread_annotations.h>

#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/IPower.h>

using IPowerV1_0 = android::hardware::power::V1_0::IPower;
using IPowerV1_1 = android::hardware::power::V1_1::IPower;
using IPowerAidl = android::hardware::power::IPower;

namespace android {

// Loads available Power HAL services.
class PowerHalLoader {
public:
    static void unloadAll();
    static sp<IPowerAidl> loadAidl();
    static sp<IPowerV1_0> loadHidlV1_0();
    static sp<IPowerV1_1> loadHidlV1_1();

private:
    static std::mutex gHalMutex;
    static sp<IPowerAidl> gHalAidl GUARDED_BY(gHalMutex);
    static sp<IPowerV1_0> gHalHidlV1_0 GUARDED_BY(gHalMutex);
    static sp<IPowerV1_1> gHalHidlV1_1 GUARDED_BY(gHalMutex);

    static sp<IPowerV1_0> loadHidlV1_0Locked() EXCLUSIVE_LOCKS_REQUIRED(gHalMutex);

    PowerHalLoader() = default;
};

} // namespace android

#endif // ANDROID_POWERHALLOADER_H
