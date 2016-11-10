/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef ANDROID_BATTERYSERVICE_H
#define ANDROID_BATTERYSERVICE_H

#include <binder/Parcel.h>
#include <sys/types.h>
#include <utils/Errors.h>
#include <utils/String8.h>

namespace android {

#include "BatteryServiceConstants.h"

// must be kept in sync with definitions in BatteryProperty.java
enum {
    BATTERY_PROP_CHARGE_COUNTER = 1, // equals BatteryProperty.CHARGE_COUNTER constant
    BATTERY_PROP_CURRENT_NOW = 2, // equals BatteryProperty.CURRENT_NOW constant
    BATTERY_PROP_CURRENT_AVG = 3, // equals BatteryProperty.CURRENT_AVG constant
    BATTERY_PROP_CAPACITY = 4, // equals BatteryProperty.CAPACITY constant
    BATTERY_PROP_ENERGY_COUNTER = 5, // equals BatteryProperty.ENERGY_COUNTER constant
};

struct BatteryProperties {
    bool chargerAcOnline;
    bool chargerUsbOnline;
    bool chargerWirelessOnline;
    int maxChargingCurrent;
    int maxChargingVoltage;
    int batteryStatus;
    int batteryHealth;
    bool batteryPresent;
    int batteryLevel;
    int batteryVoltage;
    int batteryTemperature;
    int batteryCurrent;
    int batteryCycleCount;
    int batteryFullCharge;
    int batteryChargeCounter;
    String8 batteryTechnology;

    status_t writeToParcel(Parcel* parcel) const;
    status_t readFromParcel(Parcel* parcel);
};

struct BatteryProperty {
    int64_t valueInt64;

    status_t writeToParcel(Parcel* parcel) const;
    status_t readFromParcel(Parcel* parcel);
};

}; // namespace android

#endif // ANDROID_BATTERYSERVICE_H
