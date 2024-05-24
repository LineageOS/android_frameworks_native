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

namespace {

bool hasPointerId(const std::vector<PointerProperties>& pointers, int32_t pointerId) {
    return std::find_if(pointers.begin(), pointers.end(),
                        [&pointerId](const PointerProperties& properties) {
                            return properties.id == pointerId;
                        }) != pointers.end();
}

} // namespace

bool TouchedWindow::hasHoveringPointers() const {
    for (const auto& [_, state] : mDeviceStates) {
        if (!state.hoveringPointers.empty()) {
            return true;
        }
    }
    return false;
}

bool TouchedWindow::hasHoveringPointers(DeviceId deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;

    return !state.hoveringPointers.empty();
}

void TouchedWindow::clearHoveringPointers(DeviceId deviceId) {
    auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;
    state.hoveringPointers.clear();
    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

bool TouchedWindow::hasHoveringPointer(DeviceId deviceId, int32_t pointerId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;
    return hasPointerId(state.hoveringPointers, pointerId);
}

void TouchedWindow::addHoveringPointer(DeviceId deviceId, const PointerProperties& pointer) {
    std::vector<PointerProperties>& hoveringPointers = mDeviceStates[deviceId].hoveringPointers;
    const size_t initialSize = hoveringPointers.size();
    std::erase_if(hoveringPointers, [&pointer](const PointerProperties& properties) {
        return properties.id == pointer.id;
    });
    if (hoveringPointers.size() != initialSize) {
        LOG(ERROR) << __func__ << ": " << pointer << ", device " << deviceId << " was in " << *this;
    }
    hoveringPointers.push_back(pointer);
}

void TouchedWindow::addTouchingPointers(DeviceId deviceId,
                                        const std::vector<PointerProperties>& pointers) {
    std::vector<PointerProperties>& touchingPointers = mDeviceStates[deviceId].touchingPointers;
    const size_t initialSize = touchingPointers.size();
    for (const PointerProperties& pointer : pointers) {
        std::erase_if(touchingPointers, [&pointer](const PointerProperties& properties) {
            return properties.id == pointer.id;
        });
    }
    if (touchingPointers.size() != initialSize) {
        LOG(ERROR) << __func__ << ": " << dumpVector(pointers, streamableToString) << ", device "
                   << deviceId << " already in " << *this;
    }
    touchingPointers.insert(touchingPointers.end(), pointers.begin(), pointers.end());
}

bool TouchedWindow::hasTouchingPointers() const {
    for (const auto& [_, state] : mDeviceStates) {
        if (!state.touchingPointers.empty()) {
            return true;
        }
    }
    return false;
}

bool TouchedWindow::hasTouchingPointers(DeviceId deviceId) const {
    return !getTouchingPointers(deviceId).empty();
}

bool TouchedWindow::hasTouchingPointer(DeviceId deviceId, int32_t pointerId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;
    return hasPointerId(state.touchingPointers, pointerId);
}

std::vector<PointerProperties> TouchedWindow::getTouchingPointers(DeviceId deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return {};
    }
    const DeviceState& state = stateIt->second;
    return state.touchingPointers;
}

void TouchedWindow::removeTouchingPointer(DeviceId deviceId, int32_t pointerId) {
    std::bitset<MAX_POINTER_ID + 1> pointerIds;
    pointerIds.set(pointerId, true);

    removeTouchingPointers(deviceId, pointerIds);
}

void TouchedWindow::removeTouchingPointers(DeviceId deviceId,
                                           std::bitset<MAX_POINTER_ID + 1> pointers) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    std::erase_if(state.touchingPointers, [&pointers](const PointerProperties& properties) {
        return pointers.test(properties.id);
    });

    state.pilferingPointerIds &= ~pointers;

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

bool TouchedWindow::hasActiveStylus() const {
    for (const auto& [_, state] : mDeviceStates) {
        for (const PointerProperties& properties : state.touchingPointers) {
            if (properties.toolType == ToolType::STYLUS) {
                return true;
            }
        }
        for (const PointerProperties& properties : state.hoveringPointers) {
            if (properties.toolType == ToolType::STYLUS) {
                return true;
            }
        }
    }
    return false;
}

std::set<DeviceId> TouchedWindow::getTouchingDeviceIds() const {
    std::set<DeviceId> deviceIds;
    for (const auto& [deviceId, deviceState] : mDeviceStates) {
        if (!deviceState.touchingPointers.empty()) {
            deviceIds.insert(deviceId);
        }
    }
    return deviceIds;
}

bool TouchedWindow::hasPilferingPointers(DeviceId deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return false;
    }
    const DeviceState& state = stateIt->second;

    return state.pilferingPointerIds.any();
}

void TouchedWindow::addPilferingPointers(DeviceId deviceId,
                                         std::bitset<MAX_POINTER_ID + 1> pointerIds) {
    mDeviceStates[deviceId].pilferingPointerIds |= pointerIds;
}

void TouchedWindow::addPilferingPointer(DeviceId deviceId, int32_t pointerId) {
    mDeviceStates[deviceId].pilferingPointerIds.set(pointerId);
}

std::bitset<MAX_POINTER_ID + 1> TouchedWindow::getPilferingPointers(DeviceId deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return {};
    }
    const DeviceState& state = stateIt->second;

    return state.pilferingPointerIds;
}

std::map<DeviceId, std::bitset<MAX_POINTER_ID + 1>> TouchedWindow::getPilferingPointers() const {
    std::map<DeviceId, std::bitset<MAX_POINTER_ID + 1>> out;
    for (const auto& [deviceId, state] : mDeviceStates) {
        out.emplace(deviceId, state.pilferingPointerIds);
    }
    return out;
}

std::optional<nsecs_t> TouchedWindow::getDownTimeInTarget(DeviceId deviceId) const {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return {};
    }
    const DeviceState& state = stateIt->second;
    return state.downTimeInTarget;
}

void TouchedWindow::trySetDownTimeInTarget(DeviceId deviceId, nsecs_t downTime) {
    auto [stateIt, _] = mDeviceStates.try_emplace(deviceId);
    DeviceState& state = stateIt->second;

    if (!state.downTimeInTarget) {
        state.downTimeInTarget = downTime;
    }
}

void TouchedWindow::removeAllTouchingPointersForDevice(DeviceId deviceId) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    state.touchingPointers.clear();
    state.pilferingPointerIds.reset();
    state.downTimeInTarget.reset();

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

void TouchedWindow::removeHoveringPointer(DeviceId deviceId, int32_t pointerId) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    std::erase_if(state.hoveringPointers, [&pointerId](const PointerProperties& properties) {
        return properties.id == pointerId;
    });

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

void TouchedWindow::removeAllHoveringPointersForDevice(DeviceId deviceId) {
    const auto stateIt = mDeviceStates.find(deviceId);
    if (stateIt == mDeviceStates.end()) {
        return;
    }
    DeviceState& state = stateIt->second;

    state.hoveringPointers.clear();

    if (!state.hasPointers()) {
        mDeviceStates.erase(stateIt);
    }
}

std::string TouchedWindow::deviceStateToString(const TouchedWindow::DeviceState& state) {
    return StringPrintf("[touchingPointers=%s, "
                        "downTimeInTarget=%s, hoveringPointers=%s, pilferingPointerIds=%s]",
                        dumpVector(state.touchingPointers, streamableToString).c_str(),
                        toString(state.downTimeInTarget).c_str(),
                        dumpVector(state.hoveringPointers, streamableToString).c_str(),
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

std::ostream& operator<<(std::ostream& out, const TouchedWindow& window) {
    out << window.dump();
    return out;
}

} // namespace inputdispatcher
} // namespace android
