/*
 * Copyright 2022 The Android Open Source Project
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

#pragma once

#include "DisplayHardware/DisplayMode.h"

namespace android::mock {

inline DisplayModePtr createDisplayMode(
        DisplayModeId modeId, Fps refreshRate, int32_t group = 0,
        ui::Size resolution = ui::Size(1920, 1080),
        PhysicalDisplayId displayId = PhysicalDisplayId::fromPort(0)) {
    return DisplayMode::Builder(hal::HWConfigId(modeId.value()))
            .setId(modeId)
            .setPhysicalDisplayId(displayId)
            .setVsyncPeriod(refreshRate.getPeriodNsecs())
            .setGroup(group)
            .setResolution(resolution)
            .build();
}

inline DisplayModePtr cloneForDisplay(PhysicalDisplayId displayId, const DisplayModePtr& modePtr) {
    return DisplayMode::Builder(modePtr->getHwcId())
            .setId(modePtr->getId())
            .setPhysicalDisplayId(displayId)
            .setVsyncPeriod(modePtr->getVsyncPeriod())
            .setGroup(modePtr->getGroup())
            .setResolution(modePtr->getResolution())
            .build();
}

inline DisplayModes cloneForDisplay(PhysicalDisplayId displayId, const DisplayModes& modes) {
    DisplayModes clones;

    for (const auto& [id, modePtr] : modes) {
        clones.try_emplace(id, cloneForDisplay(displayId, modePtr));
    }

    return clones;
}

} // namespace android::mock
