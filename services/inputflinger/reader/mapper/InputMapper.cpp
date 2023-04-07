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

#include "../Macros.h"

#include "InputMapper.h"

#include <sstream>

#include "InputDevice.h"
#include "input/PrintTools.h"

namespace android {

InputMapper::InputMapper(InputDeviceContext& deviceContext) : mDeviceContext(deviceContext) {}

InputMapper::~InputMapper() {}

void InputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    info.addSource(getSources());
}

void InputMapper::dump(std::string& dump) {}

std::list<NotifyArgs> InputMapper::reconfigure(nsecs_t when, const InputReaderConfiguration* config,
                                               uint32_t changes) {
    return {};
}

std::list<NotifyArgs> InputMapper::reset(nsecs_t when) {
    return {};
}

std::list<NotifyArgs> InputMapper::timeoutExpired(nsecs_t when) {
    return {};
}

int32_t InputMapper::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    return AKEY_STATE_UNKNOWN;
}

int32_t InputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    return AKEY_STATE_UNKNOWN;
}

int32_t InputMapper::getSwitchState(uint32_t sourceMask, int32_t switchCode) {
    return AKEY_STATE_UNKNOWN;
}

int32_t InputMapper::getKeyCodeForKeyLocation(int32_t locationKeyCode) const {
    return AKEYCODE_UNKNOWN;
}

bool InputMapper::markSupportedKeyCodes(uint32_t sourceMask, const std::vector<int32_t>& keyCodes,
                                        uint8_t* outFlags) {
    return false;
}

std::list<NotifyArgs> InputMapper::vibrate(const VibrationSequence& sequence, ssize_t repeat,
                                           int32_t token) {
    return {};
}

std::list<NotifyArgs> InputMapper::cancelVibrate(int32_t token) {
    return {};
}

bool InputMapper::isVibrating() {
    return false;
}

std::vector<int32_t> InputMapper::getVibratorIds() {
    return {};
}

std::list<NotifyArgs> InputMapper::cancelTouch(nsecs_t when, nsecs_t readTime) {
    return {};
}

bool InputMapper::enableSensor(InputDeviceSensorType sensorType,
                               std::chrono::microseconds samplingPeriod,
                               std::chrono::microseconds maxBatchReportLatency) {
    return true;
}

void InputMapper::disableSensor(InputDeviceSensorType sensorType) {}

void InputMapper::flushSensor(InputDeviceSensorType sensorType) {}

int32_t InputMapper::getMetaState() {
    return 0;
}

bool InputMapper::updateMetaState(int32_t keyCode) {
    return false;
}

std::list<NotifyArgs> InputMapper::updateExternalStylusState(const StylusState& state) {
    return {};
}

status_t InputMapper::getAbsoluteAxisInfo(int32_t axis, RawAbsoluteAxisInfo* axisInfo) {
    return getDeviceContext().getAbsoluteAxisInfo(axis, axisInfo);
}

void InputMapper::bumpGeneration() {
    getDeviceContext().bumpGeneration();
}

void InputMapper::dumpRawAbsoluteAxisInfo(std::string& dump, const RawAbsoluteAxisInfo& axis,
                                          const char* name) {
    std::stringstream out;
    out << INDENT4 << name << ": " << axis << "\n";
    dump += out.str();
}

void InputMapper::dumpStylusState(std::string& dump, const StylusState& state) {
    dump += StringPrintf(INDENT4 "When: %" PRId64 "\n", state.when);
    dump += StringPrintf(INDENT4 "Pressure: %s\n", toString(state.pressure).c_str());
    dump += StringPrintf(INDENT4 "Button State: 0x%08x\n", state.buttons);
    dump += StringPrintf(INDENT4 "Tool Type: %" PRId32 "\n", state.toolType);
}

} // namespace android
