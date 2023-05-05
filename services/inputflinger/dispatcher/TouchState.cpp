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

std::set<int32_t> TouchState::getActiveDeviceIds() const {
    std::set<int32_t> out;
    for (const TouchedWindow& w : windows) {
        std::set<int32_t> deviceIds = w.getActiveDeviceIds();
        out.insert(deviceIds.begin(), deviceIds.end());
    }
    return out;
}

bool TouchState::hasTouchingPointers(int32_t deviceId) const {
    return std::any_of(windows.begin(), windows.end(), [&](const TouchedWindow& window) {
        return window.hasTouchingPointers(deviceId);
    });
}

void TouchState::removeTouchingPointer(int32_t removedDeviceId, int32_t pointerId) {
    for (TouchedWindow& touchedWindow : windows) {
        touchedWindow.removeTouchingPointer(removedDeviceId, pointerId);
    }
    clearWindowsWithoutPointers();
}

void TouchState::removeTouchingPointerFromWindow(
        int32_t removedDeviceId, int32_t pointerId,
        const sp<android::gui::WindowInfoHandle>& windowHandle) {
    for (TouchedWindow& touchedWindow : windows) {
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.removeTouchingPointer(removedDeviceId, pointerId);
            clearWindowsWithoutPointers();
            return;
        }
    }
}

void TouchState::clearHoveringPointers() {
    for (TouchedWindow& touchedWindow : windows) {
        touchedWindow.clearHoveringPointers();
    }
    clearWindowsWithoutPointers();
}

void TouchState::clearWindowsWithoutPointers() {
    std::erase_if(windows, [](const TouchedWindow& w) {
        return !w.hasTouchingPointers() && !w.hasHoveringPointers();
    });
}

void TouchState::addOrUpdateWindow(const sp<WindowInfoHandle>& windowHandle,
                                   ftl::Flags<InputTarget::Flags> targetFlags,
                                   int32_t addedDeviceId,
                                   std::bitset<MAX_POINTER_ID + 1> touchingPointerIds,
                                   std::optional<nsecs_t> firstDownTimeInTarget) {
    for (TouchedWindow& touchedWindow : windows) {
        // We do not compare windows by token here because two windows that share the same token
        // may have a different transform
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.targetFlags |= targetFlags;
            if (targetFlags.test(InputTarget::Flags::DISPATCH_AS_SLIPPERY_EXIT)) {
                touchedWindow.targetFlags.clear(InputTarget::Flags::DISPATCH_AS_IS);
            }
            // For cases like hover enter/exit or DISPATCH_AS_OUTSIDE a touch window might not have
            // downTime set initially. Need to update existing window when a pointer is down for the
            // window.
            touchedWindow.addTouchingPointers(addedDeviceId, touchingPointerIds);
            if (firstDownTimeInTarget) {
                touchedWindow.trySetDownTimeInTarget(addedDeviceId, *firstDownTimeInTarget);
            }
            return;
        }
    }
    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.targetFlags = targetFlags;
    touchedWindow.addTouchingPointers(addedDeviceId, touchingPointerIds);
    if (firstDownTimeInTarget) {
        touchedWindow.trySetDownTimeInTarget(addedDeviceId, *firstDownTimeInTarget);
    }
    windows.push_back(touchedWindow);
}

void TouchState::addHoveringPointerToWindow(const sp<WindowInfoHandle>& windowHandle,
                                            int32_t hoveringDeviceId, int32_t hoveringPointerId) {
    for (TouchedWindow& touchedWindow : windows) {
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.addHoveringPointer(hoveringDeviceId, hoveringPointerId);
            return;
        }
    }

    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.addHoveringPointer(hoveringDeviceId, hoveringPointerId);
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

void TouchState::filterNonAsIsTouchWindows() {
    for (size_t i = 0; i < windows.size();) {
        TouchedWindow& window = windows[i];
        if (window.targetFlags.any(InputTarget::Flags::DISPATCH_AS_IS |
                                   InputTarget::Flags::DISPATCH_AS_SLIPPERY_ENTER)) {
            window.targetFlags.clear(InputTarget::DISPATCH_MASK);
            window.targetFlags |= InputTarget::Flags::DISPATCH_AS_IS;
            i += 1;
        } else {
            windows.erase(windows.begin() + i);
        }
    }
}

void TouchState::cancelPointersForWindowsExcept(int32_t touchedDeviceId,
                                                std::bitset<MAX_POINTER_ID + 1> pointerIds,
                                                const sp<IBinder>& token) {
    std::for_each(windows.begin(), windows.end(), [&](TouchedWindow& w) {
        if (w.windowHandle->getToken() != token) {
            w.removeTouchingPointers(touchedDeviceId, pointerIds);
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
    std::map<int32_t /*deviceId*/, std::bitset<MAX_POINTER_ID + 1>> allPilferedPointerIdsByDevice;
    for (const TouchedWindow& w : windows) {
        for (const auto& [iterDeviceId, pilferedPointerIds] : w.getPilferingPointers()) {
            allPilferedPointerIdsByDevice[iterDeviceId] |= pilferedPointerIds;
        }
    };

    // Optimization: most of the time, pilfering does not occur
    if (allPilferedPointerIdsByDevice.empty()) return;

    // Now, remove all pointers from every window that's being pilfered by other windows.
    // For example, if window A is pilfering pointer 1 (only), and window B is pilfering pointer 2
    // (only), the remove pointer 2 from window A and pointer 1 from window B. Usually, the set of
    // pilfered pointers will be disjoint across all windows, but there's no reason to cause that
    // limitation here.
    for (const auto& [iterDeviceId, allPilferedPointerIds] : allPilferedPointerIdsByDevice) {
        std::for_each(windows.begin(), windows.end(), [&](TouchedWindow& w) {
            std::bitset<MAX_POINTER_ID + 1> pilferedByOtherWindows =
                    w.getPilferingPointers(iterDeviceId) ^ allPilferedPointerIds;
            // Remove all pointers pilfered by other windows
            w.removeTouchingPointers(iterDeviceId, pilferedByOtherWindows);
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

bool TouchState::isDown() const {
    return std::any_of(windows.begin(), windows.end(),
                       [](const TouchedWindow& window) { return window.hasTouchingPointers(); });
}

bool TouchState::hasHoveringPointers() const {
    return std::any_of(windows.begin(), windows.end(),
                       [](const TouchedWindow& window) { return window.hasHoveringPointers(); });
}

std::set<sp<WindowInfoHandle>> TouchState::getWindowsWithHoveringPointer(int32_t hoveringDeviceId,
                                                                         int32_t pointerId) const {
    std::set<sp<WindowInfoHandle>> out;
    for (const TouchedWindow& window : windows) {
        if (window.hasHoveringPointer(hoveringDeviceId, pointerId)) {
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

void TouchState::removeAllPointersForDevice(int32_t removedDeviceId) {
    for (TouchedWindow& window : windows) {
        window.removeAllHoveringPointersForDevice(removedDeviceId);
        window.removeAllTouchingPointersForDevice(removedDeviceId);
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

} // namespace android::inputdispatcher
