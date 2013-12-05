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

#include <stdint.h>
#include <sys/types.h>
#include <batteryservice/BatteryService.h>
#include <binder/Parcel.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/String16.h>

namespace android {

/*
 * Parcel read/write code must be kept in sync with
 * frameworks/base/core/java/android/os/BatteryProperties.java
 */

status_t BatteryProperties::readFromParcel(Parcel* p) {
    chargerAcOnline = p->readInt32() == 1 ? true : false;
    chargerDockAcOnline = p->readInt32() == 1 ? true : false;
    chargerUsbOnline = p->readInt32() == 1 ? true : false;
    chargerWirelessOnline = p->readInt32() == 1 ? true : false;

    batteryStatus = p->readInt32();
    batteryHealth = p->readInt32();
    batteryPresent = p->readInt32() == 1 ? true : false;
    batteryLevel = p->readInt32();
    batteryVoltage = p->readInt32();
    batteryCurrentNow = p->readInt32();
    batteryChargeCounter = p->readInt32();
    batteryTemperature = p->readInt32();
    batteryTechnology = String8((p->readString16()).string());

    dockBatterySupported = p->readInt32() == 1 ? true : false;
    dockBatteryStatus = p->readInt32();
    dockBatteryHealth = p->readInt32();
    dockBatteryPresent = p->readInt32() == 1 ? true : false;
    dockBatteryLevel = p->readInt32();
    dockBatteryVoltage = p->readInt32();
    dockBatteryCurrentNow = p->readInt32();
    dockBatteryChargeCounter = p->readInt32();
    dockBatteryTemperature = p->readInt32();
    dockBatteryTechnology = String8((p->readString16()).string());

    return OK;
}

status_t BatteryProperties::writeToParcel(Parcel* p) const {
    p->writeInt32(chargerAcOnline ? 1 : 0);
    p->writeInt32(chargerDockAcOnline ? 1 : 0);
    p->writeInt32(chargerUsbOnline ? 1 : 0);
    p->writeInt32(chargerWirelessOnline ? 1 : 0);

    p->writeInt32(batteryStatus);
    p->writeInt32(batteryHealth);
    p->writeInt32(batteryPresent ? 1 : 0);
    p->writeInt32(batteryLevel);
    p->writeInt32(batteryVoltage);
    p->writeInt32(batteryCurrentNow);
    p->writeInt32(batteryChargeCounter);
    p->writeInt32(batteryTemperature);
    p->writeString16(String16(batteryTechnology));

    p->writeInt32(dockBatterySupported ? 1 : 0);
    p->writeInt32(dockBatteryStatus);
    p->writeInt32(dockBatteryHealth);
    p->writeInt32(dockBatteryPresent ? 1 : 0);
    p->writeInt32(dockBatteryLevel);
    p->writeInt32(dockBatteryVoltage);
    p->writeInt32(dockBatteryCurrentNow);
    p->writeInt32(dockBatteryChargeCounter);
    p->writeInt32(dockBatteryTemperature);
    p->writeString16(String16(dockBatteryTechnology));

    return OK;
}

}; // namespace android
