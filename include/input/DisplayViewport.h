/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <ftl/enum.h>
#include <ftl/string.h>
#include <input/Input.h>
#include <ui/Rotation.h>

#include <cinttypes>
#include <optional>

using android::base::StringPrintf;

namespace android {

/**
 * Describes the different type of viewports supported by input flinger.
 * Keep in sync with values in InputManagerService.java.
 */
enum class ViewportType : int32_t {
    INTERNAL = 1,
    EXTERNAL = 2,
    VIRTUAL = 3,

    ftl_last = VIRTUAL
};

/*
 * Describes how coordinates are mapped on a physical display.
 * See com.android.server.display.DisplayViewport.
 */
struct DisplayViewport {
    ui::LogicalDisplayId displayId;
    ui::Rotation orientation;
    int32_t logicalLeft;
    int32_t logicalTop;
    int32_t logicalRight;
    int32_t logicalBottom;
    int32_t physicalLeft;
    int32_t physicalTop;
    int32_t physicalRight;
    int32_t physicalBottom;
    int32_t deviceWidth;
    int32_t deviceHeight;
    bool isActive;
    std::string uniqueId;
    // The actual (hardware) port that the associated display is connected to.
    // Not all viewports will have this specified.
    std::optional<uint8_t> physicalPort;
    ViewportType type;

    DisplayViewport()
          : displayId(ui::LogicalDisplayId::INVALID),
            orientation(ui::ROTATION_0),
            logicalLeft(0),
            logicalTop(0),
            logicalRight(0),
            logicalBottom(0),
            physicalLeft(0),
            physicalTop(0),
            physicalRight(0),
            physicalBottom(0),
            deviceWidth(0),
            deviceHeight(0),
            isActive(false),
            uniqueId(),
            physicalPort(std::nullopt),
            type(ViewportType::INTERNAL) {}

    bool operator==(const DisplayViewport& other) const {
        return displayId == other.displayId && orientation == other.orientation &&
                logicalLeft == other.logicalLeft && logicalTop == other.logicalTop &&
                logicalRight == other.logicalRight && logicalBottom == other.logicalBottom &&
                physicalLeft == other.physicalLeft && physicalTop == other.physicalTop &&
                physicalRight == other.physicalRight && physicalBottom == other.physicalBottom &&
                deviceWidth == other.deviceWidth && deviceHeight == other.deviceHeight &&
                isActive == other.isActive && uniqueId == other.uniqueId &&
                physicalPort == other.physicalPort && type == other.type;
    }

    bool operator!=(const DisplayViewport& other) const {
        return !(*this == other);
    }

    inline bool isValid() const { return displayId.isValid(); }

    void setNonDisplayViewport(int32_t width, int32_t height) {
        displayId = ui::LogicalDisplayId::INVALID;
        orientation = ui::ROTATION_0;
        logicalLeft = 0;
        logicalTop = 0;
        logicalRight = width;
        logicalBottom = height;
        physicalLeft = 0;
        physicalTop = 0;
        physicalRight = width;
        physicalBottom = height;
        deviceWidth = width;
        deviceHeight = height;
        isActive = true;
        uniqueId.clear();
        physicalPort = std::nullopt;
        type = ViewportType::INTERNAL;
    }

    std::string toString() const {
        return StringPrintf("Viewport %s: displayId=%s, uniqueId=%s, port=%s, orientation=%d, "
                            "logicalFrame=[%d, %d, %d, %d], "
                            "physicalFrame=[%d, %d, %d, %d], "
                            "deviceSize=[%d, %d], "
                            "isActive=[%d]",
                            ftl::enum_string(type).c_str(), displayId.toString().c_str(),
                            uniqueId.c_str(),
                            physicalPort ? ftl::to_string(*physicalPort).c_str() : "<none>",
                            static_cast<int>(orientation), logicalLeft, logicalTop, logicalRight,
                            logicalBottom, physicalLeft, physicalTop, physicalRight, physicalBottom,
                            deviceWidth, deviceHeight, isActive);
    }
};

} // namespace android
