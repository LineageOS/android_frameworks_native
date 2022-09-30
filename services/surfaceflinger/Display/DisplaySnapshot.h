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

#include <optional>

#include <ui/ColorMode.h>
#include <ui/DisplayId.h>
#include <ui/StaticDisplayInfo.h>

#include "DisplayHardware/DisplayMode.h"
#include "Utils/Dumper.h"

namespace android::display {

// Immutable state of a physical display, captured on hotplug.
class DisplaySnapshot {
public:
    DisplaySnapshot(PhysicalDisplayId, ui::DisplayConnectionType, DisplayModes&&, ui::ColorModes&&,
                    std::optional<DeviceProductInfo>&&);

    DisplaySnapshot(const DisplaySnapshot&) = delete;
    DisplaySnapshot(DisplaySnapshot&&) = default;

    PhysicalDisplayId displayId() const { return mDisplayId; }
    ui::DisplayConnectionType connectionType() const { return mConnectionType; }

    std::optional<DisplayModeId> translateModeId(hal::HWConfigId) const;

    const auto& displayModes() const { return mDisplayModes; }
    const auto& colorModes() const { return mColorModes; }
    const auto& deviceProductInfo() const { return mDeviceProductInfo; }

    ui::ColorModes filterColorModes(bool supportsWideColor) const;

    void dump(utils::Dumper&) const;

private:
    const PhysicalDisplayId mDisplayId;
    const ui::DisplayConnectionType mConnectionType;

    // Effectively const except in move constructor.
    DisplayModes mDisplayModes;
    ui::ColorModes mColorModes;
    std::optional<DeviceProductInfo> mDeviceProductInfo;
};

} // namespace android::display
