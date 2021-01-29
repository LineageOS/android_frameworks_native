/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "../Macros.h"

#include "BatteryInputMapper.h"

namespace android {

BatteryInputMapper::BatteryInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext) {}

uint32_t BatteryInputMapper::getSources() {
    return 0;
}

void BatteryInputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    InputMapper::populateDeviceInfo(info);

    info->setHasBattery(true);
}

void BatteryInputMapper::process(const RawEvent* rawEvent) {}

std::optional<int32_t> BatteryInputMapper::getBatteryCapacity() {
    return getDeviceContext().getBatteryCapacity();
}

std::optional<int32_t> BatteryInputMapper::getBatteryStatus() {
    return getDeviceContext().getBatteryStatus();
}

void BatteryInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Battery Input Mapper:\n";
    dump += getBatteryCapacity().has_value()
            ? StringPrintf(INDENT3 "Capacity: %d\n", getBatteryCapacity().value())
            : StringPrintf(INDENT3 "Capacity: Unknown");

    std::string status;
    switch (getBatteryStatus().value_or(BATTERY_STATUS_UNKNOWN)) {
        case BATTERY_STATUS_CHARGING:
            status = "Charging";
            break;
        case BATTERY_STATUS_DISCHARGING:
            status = "Discharging";
            break;
        case BATTERY_STATUS_NOT_CHARGING:
            status = "Not charging";
            break;
        case BATTERY_STATUS_FULL:
            status = "Full";
            break;
        default:
            status = "Unknown";
    }
    dump += StringPrintf(INDENT3 "Status: %s\n", status.c_str());
}

} // namespace android
