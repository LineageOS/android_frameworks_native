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

#define LOG_TAG "android.hardware.thermal.thermalchangedcallback@2.0-impl"
#include <log/log.h>

#include <android/os/Temperature.h>
#include <hardware/thermal.h>
#include <cmath>
#include "ThermalChangedCallback.h"
#include "services/thermalservice/ThermalService.h"

namespace android {
namespace hardware {
namespace thermal {
namespace V2_0 {
namespace implementation {

using ::android::hardware::thermal::V2_0::TemperatureType;
using ::android::hardware::thermal::V2_0::ThrottlingSeverity;
using ::android::os::ThermalService;

// Register a binder ThermalService object for sending events
void ThermalChangedCallback::registerThermalService(sp<ThermalService> thermalService) {
    mThermalService = thermalService;
}

// Methods from IThermalChangedCallback::V2_0 follow.
Return<void> ThermalChangedCallback::notifyThrottling(
        const android::hardware::thermal::V2_0::Temperature& temperature) {
    // Convert HIDL IThermal Temperature to binder IThermalService Temperature.
    if (mThermalService != nullptr) {
        float value = NAN;
        int type = DEVICE_TEMPERATURE_UNKNOWN;

        switch (temperature.type) {
            case TemperatureType::CPU:
                type = DEVICE_TEMPERATURE_CPU;
                break;
            case TemperatureType::GPU:
                type = DEVICE_TEMPERATURE_GPU;
                break;
            case TemperatureType::BATTERY:
                type = DEVICE_TEMPERATURE_BATTERY;
                break;
            case TemperatureType::SKIN:
                type = DEVICE_TEMPERATURE_SKIN;
                break;
            case TemperatureType::UNKNOWN:
            default:
                type = DEVICE_TEMPERATURE_UNKNOWN;
                break;
        }
        bool isThrottling = (static_cast<size_t>(temperature.throttlingStatus) >=
                             static_cast<size_t>(ThrottlingSeverity::SEVERE))
                ? true
                : false;
        value = temperature.value == UNKNOWN_TEMPERATURE ? NAN :
                temperature.value;
        android::os::Temperature thermal_svc_temp(value, type);
        mThermalService->notifyThrottling(isThrottling, thermal_svc_temp);
    } else {
        SLOGE("IThermalService binder service not created, drop throttling event");
    }
    return Void();
}

} // namespace implementation
} // namespace V2_0
} // namespace thermal
} // namespace hardware
} // namespace android
