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

void TouchState::addOrUpdateWindow(const sp<WindowInfoHandle>& windowHandle,
                                   ftl::Flags<InputTarget::Flags> targetFlags, BitSet32 pointerIds,
                                   std::optional<nsecs_t> eventTime) {
    for (size_t i = 0; i < windows.size(); i++) {
        TouchedWindow& touchedWindow = windows[i];
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.targetFlags |= targetFlags;
            if (targetFlags.test(InputTarget::Flags::DISPATCH_AS_SLIPPERY_EXIT)) {
                touchedWindow.targetFlags.clear(InputTarget::Flags::DISPATCH_AS_IS);
            }
            // For cases like hover enter/exit or DISPATCH_AS_OUTSIDE a touch window might not have
            // downTime set initially. Need to update existing window when an pointer is down for
            // the window.
            touchedWindow.pointerIds.value |= pointerIds.value;
            if (!touchedWindow.firstDownTimeInTarget.has_value()) {
                touchedWindow.firstDownTimeInTarget = eventTime;
            }
            return;
        }
    }

    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.targetFlags = targetFlags;
    touchedWindow.pointerIds = pointerIds;
    touchedWindow.firstDownTimeInTarget = eventTime;
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

void TouchState::cancelPointersForWindowsExcept(const BitSet32 pointerIds,
                                                const sp<IBinder>& token) {
    if (pointerIds.isEmpty()) return;
    std::for_each(windows.begin(), windows.end(), [&pointerIds, &token](TouchedWindow& w) {
        if (w.windowHandle->getToken() != token) {
            w.pointerIds &= BitSet32(~pointerIds.value);
        }
    });
    std::erase_if(windows, [](const TouchedWindow& w) { return w.pointerIds.isEmpty(); });
}

void TouchState::cancelPointersForNonPilferingWindows(const BitSet32 pointerIds) {
    if (pointerIds.isEmpty()) return;
    std::for_each(windows.begin(), windows.end(), [&pointerIds](TouchedWindow& w) {
        if (!w.isPilferingPointers) {
            w.pointerIds &= BitSet32(~pointerIds.value);
        }
    });
    std::erase_if(windows, [](const TouchedWindow& w) { return w.pointerIds.isEmpty(); });
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

bool TouchState::isDown() const {
    return std::any_of(windows.begin(), windows.end(),
                       [](const TouchedWindow& window) { return !window.pointerIds.isEmpty(); });
}

std::string TouchState::dump() const {
    std::string out;
    out += StringPrintf("deviceId=%d, source=%s\n", deviceId,
                        inputEventSourceToString(source).c_str());
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
