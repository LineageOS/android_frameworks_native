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
#include "InputTarget.h"

namespace android {

namespace inputdispatcher {

// Focus tracking for touch.
struct TouchedWindow {
    sp<gui::WindowInfoHandle> windowHandle;
    ftl::Flags<InputTarget::Flags> targetFlags;
    std::bitset<MAX_POINTER_ID + 1> pointerIds;
    // The pointer ids of the pointers that this window is currently pilfering
    std::bitset<MAX_POINTER_ID + 1> pilferedPointerIds;
    // Time at which the first action down occurred on this window.
    // NOTE: This is not initialized in case of HOVER entry/exit and DISPATCH_AS_OUTSIDE scenario.
    std::optional<nsecs_t> firstDownTimeInTarget;

    bool hasHoveringPointers() const;
    bool hasHoveringPointers(int32_t deviceId) const;

    bool hasHoveringPointer(int32_t deviceId, int32_t pointerId) const;
    void addHoveringPointer(int32_t deviceId, int32_t pointerId);
    void removeHoveringPointer(int32_t deviceId, int32_t pointerId);
    void removeTouchingPointer(int32_t pointerId);
    void clearHoveringPointers();
    std::string dump() const;

private:
    std::map<int32_t /*deviceId*/, std::bitset<MAX_POINTER_ID + 1>> mHoveringPointerIdsByDevice;
};

} // namespace inputdispatcher
} // namespace android
