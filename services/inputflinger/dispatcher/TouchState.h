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

#include <bitset>
#include <ostream>
#include <set>
#include "TouchedWindow.h"

namespace android {

namespace gui {
class WindowInfoHandle;
}

namespace inputdispatcher {

struct TouchState {
    std::vector<TouchedWindow> windows;

    TouchState() = default;
    ~TouchState() = default;
    TouchState& operator=(const TouchState&) = default;

    void reset();
    void clearWindowsWithoutPointers();

    bool hasTouchingPointers(DeviceId deviceId) const;
    void removeTouchingPointer(DeviceId deviceId, int32_t pointerId);
    void removeTouchingPointerFromWindow(DeviceId deviceId, int32_t pointerId,
                                         const sp<android::gui::WindowInfoHandle>& windowHandle);
    void addOrUpdateWindow(const sp<android::gui::WindowInfoHandle>& windowHandle,
                           InputTarget::DispatchMode dispatchMode,
                           ftl::Flags<InputTarget::Flags> targetFlags, DeviceId deviceId,
                           const std::vector<PointerProperties>& touchingPointers,
                           std::optional<nsecs_t> firstDownTimeInTarget = std::nullopt);
    void addHoveringPointerToWindow(const sp<android::gui::WindowInfoHandle>& windowHandle,
                                    DeviceId deviceId, const PointerProperties& pointer);
    void removeHoveringPointer(DeviceId deviceId, int32_t pointerId);
    void clearHoveringPointers(DeviceId deviceId);

    void removeAllPointersForDevice(DeviceId deviceId);
    void removeWindowByToken(const sp<IBinder>& token);

    // Cancel pointers for current set of windows except the window with particular binder token.
    void cancelPointersForWindowsExcept(DeviceId deviceId,
                                        std::bitset<MAX_POINTER_ID + 1> pointerIds,
                                        const sp<IBinder>& token);
    // Cancel pointers for current set of non-pilfering windows i.e. windows with isPilferingWindow
    // set to false.
    void cancelPointersForNonPilferingWindows();

    sp<android::gui::WindowInfoHandle> getFirstForegroundWindowHandle() const;
    bool isSlippery() const;
    sp<android::gui::WindowInfoHandle> getWallpaperWindow() const;
    const TouchedWindow& getTouchedWindow(
            const sp<android::gui::WindowInfoHandle>& windowHandle) const;
    // Whether any of the windows are currently being touched
    bool isDown(DeviceId deviceId) const;
    bool hasHoveringPointers(DeviceId deviceId) const;

    bool hasActiveStylus() const;

    std::set<sp<android::gui::WindowInfoHandle>> getWindowsWithHoveringPointer(
            DeviceId deviceId, int32_t pointerId) const;
    std::string dump() const;
};

std::ostream& operator<<(std::ostream& out, const TouchState& state);

} // namespace inputdispatcher
} // namespace android
