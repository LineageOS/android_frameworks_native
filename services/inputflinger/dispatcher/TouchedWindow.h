/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gui/WindowInfo.h>
#include <input/Input.h>
#include <utils/BitSet.h>
#include <bitset>
#include <ostream>
#include <set>
#include "InputTarget.h"

namespace android {

namespace inputdispatcher {

// Focus tracking for touch.
struct TouchedWindow {
    sp<gui::WindowInfoHandle> windowHandle;
    InputTarget::DispatchMode dispatchMode = InputTarget::DispatchMode::AS_IS;
    ftl::Flags<InputTarget::Flags> targetFlags;

    // Hovering
    bool hasHoveringPointers() const;
    bool hasHoveringPointers(DeviceId deviceId) const;
    bool hasHoveringPointer(DeviceId deviceId, int32_t pointerId) const;
    void addHoveringPointer(DeviceId deviceId, const PointerProperties& pointer);
    void removeHoveringPointer(DeviceId deviceId, int32_t pointerId);

    // Touching
    bool hasTouchingPointer(DeviceId deviceId, int32_t pointerId) const;
    bool hasTouchingPointers() const;
    bool hasTouchingPointers(DeviceId deviceId) const;
    std::vector<PointerProperties> getTouchingPointers(DeviceId deviceId) const;
    void addTouchingPointers(DeviceId deviceId, const std::vector<PointerProperties>& pointers);
    void removeTouchingPointer(DeviceId deviceId, int32_t pointerId);
    void removeTouchingPointers(DeviceId deviceId, std::bitset<MAX_POINTER_ID + 1> pointers);
    bool hasActiveStylus() const;
    std::set<DeviceId> getTouchingDeviceIds() const;

    // Pilfering pointers
    bool hasPilferingPointers(DeviceId deviceId) const;
    void addPilferingPointers(DeviceId deviceId, std::bitset<MAX_POINTER_ID + 1> pointerIds);
    void addPilferingPointer(DeviceId deviceId, int32_t pointerId);
    std::bitset<MAX_POINTER_ID + 1> getPilferingPointers(DeviceId deviceId) const;
    std::map<DeviceId, std::bitset<MAX_POINTER_ID + 1>> getPilferingPointers() const;

    // Down time
    std::optional<nsecs_t> getDownTimeInTarget(DeviceId deviceId) const;
    void trySetDownTimeInTarget(DeviceId deviceId, nsecs_t downTime);

    void removeAllTouchingPointersForDevice(DeviceId deviceId);
    void removeAllHoveringPointersForDevice(DeviceId deviceId);
    void clearHoveringPointers(DeviceId deviceId);
    std::string dump() const;

private:
    struct DeviceState {
        std::vector<PointerProperties> touchingPointers;
        // The pointer ids of the pointers that this window is currently pilfering, by device
        std::bitset<MAX_POINTER_ID + 1> pilferingPointerIds;
        // Time at which the first action down occurred on this window, for each device
        // NOTE: This is not initialized in case of HOVER entry/exit and DISPATCH_AS_OUTSIDE
        // scenario.
        std::optional<nsecs_t> downTimeInTarget;
        std::vector<PointerProperties> hoveringPointers;

        bool hasPointers() const { return !touchingPointers.empty() || !hoveringPointers.empty(); };
    };

    std::map<DeviceId, DeviceState> mDeviceStates;

    static std::string deviceStateToString(const TouchedWindow::DeviceState& state);
};

std::ostream& operator<<(std::ostream& out, const TouchedWindow& window);

} // namespace inputdispatcher
} // namespace android
