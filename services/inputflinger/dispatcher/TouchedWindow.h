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
#include <set>
#include "InputTarget.h"

namespace android {

namespace inputdispatcher {

// Focus tracking for touch.
struct TouchedWindow {
    sp<gui::WindowInfoHandle> windowHandle;
    ftl::Flags<InputTarget::Flags> targetFlags;

    // Hovering
    bool hasHoveringPointers() const;
    bool hasHoveringPointers(int32_t deviceId) const;
    bool hasHoveringPointer(int32_t deviceId, int32_t pointerId) const;
    void addHoveringPointer(int32_t deviceId, int32_t pointerId);
    void removeHoveringPointer(int32_t deviceId, int32_t pointerId);

    // Touching
    bool hasTouchingPointer(int32_t deviceId, int32_t pointerId) const;
    bool hasTouchingPointers() const;
    bool hasTouchingPointers(int32_t deviceId) const;
    std::bitset<MAX_POINTER_ID + 1> getTouchingPointers(int32_t deviceId) const;
    void addTouchingPointer(int32_t deviceId, int32_t pointerId);
    void addTouchingPointers(int32_t deviceId, std::bitset<MAX_POINTER_ID + 1> pointers);
    void removeTouchingPointer(int32_t deviceId, int32_t pointerId);
    void removeTouchingPointers(int32_t deviceId, std::bitset<MAX_POINTER_ID + 1> pointers);
    /**
     * Get the currently active touching device id. If there isn't exactly 1 touching device, return
     * nullopt.
     */
    std::set<int32_t> getTouchingDeviceIds() const;
    /**
     * The ids of devices that are currently touching or hovering.
     */
    std::set<int32_t> getActiveDeviceIds() const;

    // Pilfering pointers
    bool hasPilferingPointers(int32_t deviceId) const;
    void addPilferingPointers(int32_t deviceId, std::bitset<MAX_POINTER_ID + 1> pointerIds);
    void addPilferingPointer(int32_t deviceId, int32_t pointerId);
    std::bitset<MAX_POINTER_ID + 1> getPilferingPointers(int32_t deviceId) const;
    std::map<int32_t, std::bitset<MAX_POINTER_ID + 1>> getPilferingPointers() const;

    // Down time
    std::optional<nsecs_t> getDownTimeInTarget(int32_t deviceId) const;
    void trySetDownTimeInTarget(int32_t deviceId, nsecs_t downTime);

    void removeAllTouchingPointersForDevice(int32_t deviceId);
    void removeAllHoveringPointersForDevice(int32_t deviceId);
    void clearHoveringPointers();
    std::string dump() const;

private:
    struct DeviceState {
        std::bitset<MAX_POINTER_ID + 1> touchingPointerIds;
        // The pointer ids of the pointers that this window is currently pilfering, by device
        std::bitset<MAX_POINTER_ID + 1> pilferingPointerIds;
        // Time at which the first action down occurred on this window, for each device
        // NOTE: This is not initialized in case of HOVER entry/exit and DISPATCH_AS_OUTSIDE
        // scenario.
        std::optional<nsecs_t> downTimeInTarget;
        std::bitset<MAX_POINTER_ID + 1> hoveringPointerIds;

        bool hasPointers() const { return touchingPointerIds.any() || hoveringPointerIds.any(); };
    };

    std::map<int32_t /*deviceId*/, DeviceState> mDeviceStates;

    static std::string deviceStateToString(const TouchedWindow::DeviceState& state);
};

} // namespace inputdispatcher
} // namespace android
