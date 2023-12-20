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

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <gui/WindowInfo.h>

#include "InputTarget.h"
#include "TouchState.h"

using namespace android::ftl::flag_operators;
using android::base::StringPrintf;
using android::gui::WindowInfo;
using android::gui::WindowInfoHandle;

namespace android::inputdispatcher {

void TouchState::reset() {
    *this = TouchState();
}

bool TouchState::hasTouchingPointers(DeviceId deviceId) const {
    return std::any_of(windows.begin(), windows.end(), [&](const TouchedWindow& window) {
        return window.hasTouchingPointers(deviceId);
    });
}

void TouchState::removeTouchingPointer(DeviceId deviceId, int32_t pointerId) {
    for (TouchedWindow& touchedWindow : windows) {
        touchedWindow.removeTouchingPointer(deviceId, pointerId);
    }
    clearWindowsWithoutPointers();
}

void TouchState::removeTouchingPointerFromWindow(
        DeviceId deviceId, int32_t pointerId,
        const sp<android::gui::WindowInfoHandle>& windowHandle) {
    for (TouchedWindow& touchedWindow : windows) {
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.removeTouchingPointer(deviceId, pointerId);
            clearWindowsWithoutPointers();
            return;
        }
    }
}

void TouchState::clearHoveringPointers(DeviceId deviceId) {
    for (TouchedWindow& touchedWindow : windows) {
        touchedWindow.removeAllHoveringPointersForDevice(deviceId);
    }
    clearWindowsWithoutPointers();
}

void TouchState::clearWindowsWithoutPointers() {
    std::erase_if(windows, [](const TouchedWindow& w) {
        return !w.hasTouchingPointers() && !w.hasHoveringPointers();
    });
}

void TouchState::addOrUpdateWindow(const sp<WindowInfoHandle>& windowHandle,
                                   InputTarget::DispatchMode dispatchMode,
                                   ftl::Flags<InputTarget::Flags> targetFlags, DeviceId deviceId,
                                   const std::vector<PointerProperties>& touchingPointers,
                                   std::optional<nsecs_t> firstDownTimeInTarget) {
    if (touchingPointers.empty()) {
        LOG(FATAL) << __func__ << "No pointers specified for " << windowHandle->getName();
        return;
    }
    for (TouchedWindow& touchedWindow : windows) {
        // We do not compare windows by token here because two windows that share the same token
        // may have a different transform. They will be combined later when we create InputTargets.
        // At that point, per-pointer window transform will be considered.
        // An alternative design choice here would have been to compare here by token, but to
        // store per-pointer transform.
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.dispatchMode = dispatchMode;
            touchedWindow.targetFlags |= targetFlags;
            // For cases like hover enter/exit or DISPATCH_AS_OUTSIDE a touch window might not have
            // downTime set initially. Need to update existing window when a pointer is down for the
            // window.
            touchedWindow.addTouchingPointers(deviceId, touchingPointers);
            if (firstDownTimeInTarget) {
                touchedWindow.trySetDownTimeInTarget(deviceId, *firstDownTimeInTarget);
            }
            return;
        }
    }
    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.dispatchMode = dispatchMode;
    touchedWindow.targetFlags = targetFlags;
    touchedWindow.addTouchingPointers(deviceId, touchingPointers);
    if (firstDownTimeInTarget) {
        touchedWindow.trySetDownTimeInTarget(deviceId, *firstDownTimeInTarget);
    }
    windows.push_back(touchedWindow);
}

void TouchState::addHoveringPointerToWindow(const sp<WindowInfoHandle>& windowHandle,
                                            DeviceId deviceId, const PointerProperties& pointer) {
    for (TouchedWindow& touchedWindow : windows) {
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.addHoveringPointer(deviceId, pointer);
            return;
        }
    }

    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.addHoveringPointer(deviceId, pointer);
    windows.push_back(touchedWindow);
}

void TouchState::removeWindowByToken(const sp<IBinder>& token) {
    for (size_t i = 0; i < windows.size(); i++) {
        if (windows[i].windowHandle->getToken() == token) {
            windows.erase(windows.begin() + i);
            return;
        }
    }
}

void TouchState::cancelPointersForWindowsExcept(DeviceId deviceId,
                                                std::bitset<MAX_POINTER_ID + 1> pointerIds,
                                                const sp<IBinder>& token) {
    std::for_each(windows.begin(), windows.end(), [&](TouchedWindow& w) {
        if (w.windowHandle->getToken() != token) {
            w.removeTouchingPointers(deviceId, pointerIds);
        }
    });
    clearWindowsWithoutPointers();
}

/**
 * For any pointer that's being pilfered, remove it from all of the other windows that currently
 * aren't pilfering it. For example, if we determined that pointer 1 is going to both window A and
 * window B, but window A is currently pilfering pointer 1, then pointer 1 should not go to window
 * B.
 */
void TouchState::cancelPointersForNonPilferingWindows() {
    // First, find all pointers that are being pilfered, across all windows
    std::map<DeviceId, std::bitset<MAX_POINTER_ID + 1>> allPilferedPointerIdsByDevice;
    for (const TouchedWindow& w : windows) {
        for (const auto& [deviceId, pilferedPointerIds] : w.getPilferingPointers()) {
            allPilferedPointerIdsByDevice[deviceId] |= pilferedPointerIds;
        }
    };

    // Optimization: most of the time, pilfering does not occur
    if (allPilferedPointerIdsByDevice.empty()) return;

    // Now, remove all pointers from every window that's being pilfered by other windows.
    // For example, if window A is pilfering pointer 1 (only), and window B is pilfering pointer 2
    // (only), the remove pointer 2 from window A and pointer 1 from window B. Usually, the set of
    // pilfered pointers will be disjoint across all windows, but there's no reason to cause that
    // limitation here.
    for (const auto& [deviceId, allPilferedPointerIds] : allPilferedPointerIdsByDevice) {
        std::for_each(windows.begin(), windows.end(), [&](TouchedWindow& w) {
            std::bitset<MAX_POINTER_ID + 1> pilferedByOtherWindows =
                    w.getPilferingPointers(deviceId) ^ allPilferedPointerIds;
            // Remove all pointers pilfered by other windows
            w.removeTouchingPointers(deviceId, pilferedByOtherWindows);
        });
    }
    clearWindowsWithoutPointers();
}

sp<WindowInfoHandle> TouchState::getFirstForegroundWindowHandle() const {
    for (size_t i = 0; i < windows.size(); i++) {
        const TouchedWindow& window = windows[i];
        if (window.targetFlags.test(InputTarget::Flags::FOREGROUND)) {
            return window.windowHandle;
        }
    }
    return nullptr;
}

bool TouchState::isSlippery() const {
    // Must have exactly one foreground window.
    bool haveSlipperyForegroundWindow = false;
    for (const TouchedWindow& window : windows) {
        if (window.targetFlags.test(InputTarget::Flags::FOREGROUND)) {
            if (haveSlipperyForegroundWindow ||
                !window.windowHandle->getInfo()->inputConfig.test(
                        WindowInfo::InputConfig::SLIPPERY)) {
                return false;
            }
            haveSlipperyForegroundWindow = true;
        }
    }
    return haveSlipperyForegroundWindow;
}

sp<WindowInfoHandle> TouchState::getWallpaperWindow() const {
    for (size_t i = 0; i < windows.size(); i++) {
        const TouchedWindow& window = windows[i];
        if (window.windowHandle->getInfo()->inputConfig.test(
                    gui::WindowInfo::InputConfig::IS_WALLPAPER)) {
            return window.windowHandle;
        }
    }
    return nullptr;
}

const TouchedWindow& TouchState::getTouchedWindow(const sp<WindowInfoHandle>& windowHandle) const {
    auto it = std::find_if(windows.begin(), windows.end(),
                           [&](const TouchedWindow& w) { return w.windowHandle == windowHandle; });
    LOG_ALWAYS_FATAL_IF(it == windows.end(), "Could not find %s", windowHandle->getName().c_str());
    return *it;
}

bool TouchState::isDown(DeviceId deviceId) const {
    return std::any_of(windows.begin(), windows.end(), [&deviceId](const TouchedWindow& window) {
        return window.hasTouchingPointers(deviceId);
    });
}

bool TouchState::hasHoveringPointers(DeviceId deviceId) const {
    return std::any_of(windows.begin(), windows.end(), [&deviceId](const TouchedWindow& window) {
        return window.hasHoveringPointers(deviceId);
    });
}

bool TouchState::hasActiveStylus() const {
    return std::any_of(windows.begin(), windows.end(),
                       [](const TouchedWindow& window) { return window.hasActiveStylus(); });
}

std::set<sp<WindowInfoHandle>> TouchState::getWindowsWithHoveringPointer(DeviceId deviceId,
                                                                         int32_t pointerId) const {
    std::set<sp<WindowInfoHandle>> out;
    for (const TouchedWindow& window : windows) {
        if (window.hasHoveringPointer(deviceId, pointerId)) {
            out.insert(window.windowHandle);
        }
    }
    return out;
}

void TouchState::removeHoveringPointer(int32_t hoveringDeviceId, int32_t hoveringPointerId) {
    for (TouchedWindow& window : windows) {
        window.removeHoveringPointer(hoveringDeviceId, hoveringPointerId);
    }
    clearWindowsWithoutPointers();
}

void TouchState::removeAllPointersForDevice(DeviceId deviceId) {
    for (TouchedWindow& window : windows) {
        window.removeAllHoveringPointersForDevice(deviceId);
        window.removeAllTouchingPointersForDevice(deviceId);
    }

    clearWindowsWithoutPointers();
}

std::string TouchState::dump() const {
    std::string out;
    if (!windows.empty()) {
        out += "  Windows:\n";
        for (size_t i = 0; i < windows.size(); i++) {
            const TouchedWindow& touchedWindow = windows[i];
            out += StringPrintf("    %zu : ", i) + touchedWindow.dump();
        }
    } else {
        out += "  Windows: <none>\n";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const TouchState& state) {
    out << state.dump();
    return out;
}

} // namespace android::inputdispatcher
