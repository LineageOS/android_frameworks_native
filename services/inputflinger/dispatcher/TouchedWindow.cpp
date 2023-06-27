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

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <input/PrintTools.h>

using android::base::StringPrintf;

namespace android {

namespace inputdispatcher {

bool TouchedWindow::hasHoveringPointers() const {
    for (const auto& [_, state] : mDeviceStates) {
        if (state.hoveringPointerIds.any()) {
            return true;
        }
    }
    return false;
}

bool TouchedWindow::hasHoveringPointers(int32_t deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;

    return state.hoveringPointerIds.any();
}

void TouchedWindow::clearHoveringPointers() {
    for (auto& [_, state] : mDeviceStates) {
        state.hoveringPointerIds.reset();
    }

    std::erase_if(mDeviceStates, [](const auto& pair) { return !pair.second.hasPointers(); });
}

bool TouchedWindow::hasHoveringPointer(int32_t deviceId, int32_t pointerId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;

    return state.hoveringPointerIds.test(pointerId);
}

void TouchedWindow::addHoveringPointer(int32_t deviceId, int32_t pointerId) {
    mDeviceStates[deviceId].hoveringPointerIds.set(pointerId);
}

void TouchedWindow::addTouchingPointer(int32_t deviceId, int32_t pointerId) {
    mDeviceStates[deviceId].touchingPointerIds.set(pointerId);
}

void TouchedWindow::addTouchingPointers(int32_t deviceId,
                                        std::bitset<MAX_POINTER_ID + 1> pointers) {
    mDeviceStates[deviceId].touchingPointerIds |= pointers;
}

bool TouchedWindow::hasTouchingPointers() const {
    for (const auto& [_, state] : mDeviceStates) {
        if (state.touchingPointerIds.any()) {
            return true;
        }
    }
    return false;
}

bool TouchedWindow::hasTouchingPointers(int32_t deviceId) const {
    return getTouchingPointers(deviceId).any();
}

bool TouchedWindow::hasTouchingPointer(int32_t deviceId, int32_t pointerId) const {
    return getTouchingPointers(deviceId).test(pointerId);
}

std::bitset<MAX_POINTER_ID + 1> TouchedWindow::getTouchingPointers(int32_t deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return {};
    }
    const DeviceState& state = stateIt->second;

    return state.touchingPointerIds;
}

void TouchedWindow::removeTouchingPointer(int32_t deviceId, int32_t pointerId) {
    std::bitset<MAX_POINTER_ID + 1> pointerIds;
    pointerIds.set(pointerId, true);

    removeTouchingPointers(deviceId, pointerIds);
}

void TouchedWindow::removeTouchingPointers(int32_t deviceId,
                                           std::bitset<MAX_POINTER_ID + 1> pointers) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    state.touchingPointerIds &= ~pointers;
    state.pilferingPointerIds &= ~pointers;

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

std::set<int32_t> TouchedWindow::getTouchingDeviceIds() const {
    std::set<int32_t> deviceIds;
    for (const auto& [deviceId, _] : mDeviceStates) {
        deviceIds.insert(deviceId);
    }
    return deviceIds;
}

bool TouchedWindow::hasPilferingPointers(int32_t deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;

    return state.pilferingPointerIds.any();
}

void TouchedWindow::addPilferingPointers(int32_t deviceId,
                                         std::bitset<MAX_POINTER_ID + 1> pointerIds) {
    mDeviceStates[deviceId].pilferingPointerIds |= pointerIds;
}

void TouchedWindow::addPilferingPointer(int32_t deviceId, int32_t pointerId) {
    mDeviceStates[deviceId].pilferingPointerIds.set(pointerId);
}

std::bitset<MAX_POINTER_ID + 1> TouchedWindow::getPilferingPointers(int32_t deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return {};
    }
    const DeviceState& state = stateIt->second;

    return state.pilferingPointerIds;
}

std::map<int32_t, std::bitset<MAX_POINTER_ID + 1>> TouchedWindow::getPilferingPointers() const {
    std::map<int32_t, std::bitset<MAX_POINTER_ID + 1>> out;
    for (const auto& [deviceId, state] : mDeviceStates) {
        out.emplace(deviceId, state.pilferingPointerIds);
    }
    return out;
}

std::optional<nsecs_t> TouchedWindow::getDownTimeInTarget(int32_t deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return {};
    }
    const DeviceState& state = stateIt->second;
    return state.downTimeInTarget;
}

void TouchedWindow::trySetDownTimeInTarget(int32_t deviceId, nsecs_t downTime) {
    auto [stateIt, _] = mDeviceStates.try_emplace(deviceId);
    DeviceState& state = stateIt->second;

    if (!state.downTimeInTarget) {
        state.downTimeInTarget = downTime;
    }
}

void TouchedWindow::removeAllTouchingPointersForDevice(int32_t deviceId) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    state.touchingPointerIds.reset();
    state.pilferingPointerIds.reset();
    state.downTimeInTarget.reset();

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

void TouchedWindow::removeHoveringPointer(int32_t deviceId, int32_t pointerId) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    state.hoveringPointerIds.set(pointerId, false);

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

void TouchedWindow::removeAllHoveringPointersForDevice(int32_t deviceId) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    state.hoveringPointerIds.reset();

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

std::string TouchedWindow::deviceStateToString(const TouchedWindow::DeviceState& state) {
    return StringPrintf("[touchingPointerIds=%s, "
                        "downTimeInTarget=%s, hoveringPointerIds=%s, pilferingPointerIds=%s]",
                        bitsetToString(state.touchingPointerIds).c_str(),
                        toString(state.downTimeInTarget).c_str(),
                        bitsetToString(state.hoveringPointerIds).c_str(),
                        bitsetToString(state.pilferingPointerIds).c_str());
}

std::string TouchedWindow::dump() const {
    std::string out;
    std::string deviceStates =
            dumpMap(mDeviceStates, constToString, TouchedWindow::deviceStateToString);
    out += StringPrintf("name='%s', targetFlags=%s, mDeviceStates=%s\n",
                        windowHandle->getName().c_str(), targetFlags.string().c_str(),
                        deviceStates.c_str());
    return out;
}

} // namespace inputdispatcher
} // namespace android
