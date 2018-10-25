/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_THERMAL_V1_1_THERMALCHANGEDCALLBACK_H
#define ANDROID_HARDWARE_THERMAL_V1_1_THERMALCHANGEDCALLBACK_H

#include <android/hardware/thermal/2.0/IThermalChangedCallback.h>
#include <android/hardware/thermal/2.0/types.h>
#include <android/os/Temperature.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include "services/thermalservice/ThermalService.h"

namespace android {
namespace hardware {
namespace thermal {
namespace V2_0 {
namespace implementation {

using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::os::ThermalService;

class ThermalChangedCallback : public IThermalChangedCallback {
public:
    // Register a binder ThermalService object for sending events
    void registerThermalService(sp<ThermalService> thermalService);

    // Methods from I ThermalChangedCallback::V2_0 follow.
    Return<void> notifyThrottling(
            const android::hardware::thermal::V2_0::Temperature& temperature) override;

private:
    // Our registered binder ThermalService object to use for sending events
    sp<android::os::ThermalService> mThermalService;
};

} // namespace implementation
} // namespace V2_0
} // namespace thermal
} // namespace hardware
} // namespace android

#endif // ANDROID_HARDWARE_THERMAL_V1_1_THERMALCHANGEDCALLBACK_H
