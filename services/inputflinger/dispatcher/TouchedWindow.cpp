/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "TouchedWindow.h"

#include <android-base/stringprintf.h>
#include <input/PrintTools.h>

using android::base::StringPrintf;

namespace android {

namespace inputdispatcher {

bool TouchedWindow::hasHoveringPointers() const {
    return !mHoveringPointerIdsByDevice.empty();
}

bool TouchedWindow::hasHoveringPointers(int32_t deviceId) const {
    return mHoveringPointerIdsByDevice.find(deviceId) != mHoveringPointerIdsByDevice.end();
}

void TouchedWindow::clearHoveringPointers() {
    mHoveringPointerIdsByDevice.clear();
}

bool TouchedWindow::hasHoveringPointer(int32_t deviceId, int32_t pointerId) const {
    auto it = mHoveringPointerIdsByDevice.find(deviceId);
    if (it == mHoveringPointerIdsByDevice.end()) {
        return false;
    }
    return it->second.test(pointerId);
}

void TouchedWindow::addHoveringPointer(int32_t deviceId, int32_t pointerId) {
    const auto [it, _] = mHoveringPointerIdsByDevice.insert({deviceId, {}});
    it->second.set(pointerId);
}

void TouchedWindow::removeTouchingPointer(int32_t pointerId) {
    pointerIds.reset(pointerId);
    pilferedPointerIds.reset(pointerId);
    if (pointerIds.none()) {
        firstDownTimeInTarget.reset();
    }
}

void TouchedWindow::removeAllTouchingPointers() {
    pointerIds.reset();
}

void TouchedWindow::removeHoveringPointer(int32_t deviceId, int32_t pointerId) {
    const auto it = mHoveringPointerIdsByDevice.find(deviceId);
    if (it == mHoveringPointerIdsByDevice.end()) {
        return;
    }
    it->second.set(pointerId, false);

    if (it->second.none()) {
        mHoveringPointerIdsByDevice.erase(deviceId);
    }
}

void TouchedWindow::removeAllHoveringPointersForDevice(int32_t deviceId) {
    mHoveringPointerIdsByDevice.erase(deviceId);
}

std::string TouchedWindow::dump() const {
    std::string out;
    std::string hoveringPointers =
            dumpMap(mHoveringPointerIdsByDevice, constToString, bitsetToString);
    out += StringPrintf("name='%s', pointerIds=%s, targetFlags=%s, firstDownTimeInTarget=%s, "
                        "mHoveringPointerIdsByDevice=%s, pilferedPointerIds=%s\n",
                        windowHandle->getName().c_str(), bitsetToString(pointerIds).c_str(),
                        targetFlags.string().c_str(), toString(firstDownTimeInTarget).c_str(),
                        hoveringPointers.c_str(), bitsetToString(pilferedPointerIds).c_str());
    return out;
}

} // namespace inputdispatcher
} // namespace android
