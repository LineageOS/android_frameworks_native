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

#ifndef _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H
#define _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H

#include "Monitor.h"
#include "TouchedWindow.h"

namespace android {

namespace gui {
class WindowInfoHandle;
}

namespace inputdispatcher {

struct TouchState {
    bool down;
    bool split;
    int32_t deviceId;  // id of the device that is currently down, others are rejected
    uint32_t source;   // source of the device that is current down, others are rejected
    int32_t displayId; // id to the display that currently has a touch, others are rejected
    std::vector<TouchedWindow> windows;

    std::vector<Monitor> gestureMonitors;

    TouchState();
    ~TouchState();
    void reset();
    void copyFrom(const TouchState& other);
    void addOrUpdateWindow(const sp<android::gui::WindowInfoHandle>& windowHandle,
                           int32_t targetFlags, BitSet32 pointerIds);
    void addPortalWindow(const sp<android::gui::WindowInfoHandle>& windowHandle);
    void addGestureMonitors(const std::vector<Monitor>& monitors);
    void removeWindowByToken(const sp<IBinder>& token);
    void filterNonAsIsTouchWindows();
    void filterNonMonitors();
    sp<android::gui::WindowInfoHandle> getFirstForegroundWindowHandle() const;
    bool isSlippery() const;
    sp<android::gui::WindowInfoHandle> getWallpaperWindow() const;
};

} // namespace inputdispatcher
} // namespace android

#endif // _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H
