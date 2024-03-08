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

#define LOG_TAG "NotifyArgs"

#define ATRACE_TAG ATRACE_TAG_INPUT

#include "NotifyArgs.h"

#include <android-base/stringprintf.h>
#include <android/log.h>
#include <math.h>
#include <utils/Trace.h>

using android::base::StringPrintf;

namespace android {

// --- NotifyInputDevicesChangedArgs ---

NotifyInputDevicesChangedArgs::NotifyInputDevicesChangedArgs(int32_t id,
                                                             std::vector<InputDeviceInfo> infos)
      : id(id), inputDeviceInfos(std::move(infos)) {}

// --- NotifyConfigurationChangedArgs ---

NotifyConfigurationChangedArgs::NotifyConfigurationChangedArgs(int32_t id, nsecs_t eventTime)
      : id(id), eventTime(eventTime) {}

// --- NotifyKeyArgs ---

NotifyKeyArgs::NotifyKeyArgs(int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId,
                             uint32_t source, int32_t displayId, uint32_t policyFlags,
                             int32_t action, int32_t flags, int32_t keyCode, int32_t scanCode,
                             int32_t metaState, nsecs_t downTime)
      : id(id),
        eventTime(eventTime),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        policyFlags(policyFlags),
        action(action),
        flags(flags),
        keyCode(keyCode),
        scanCode(scanCode),
        metaState(metaState),
        downTime(downTime),
        readTime(readTime) {}

// --- NotifyMotionArgs ---

NotifyMotionArgs::NotifyMotionArgs(
        int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId, uint32_t source,
        int32_t displayId, uint32_t policyFlags, int32_t action, int32_t actionButton,
        int32_t flags, int32_t metaState, int32_t buttonState, MotionClassification classification,
        int32_t edgeFlags, uint32_t pointerCount, const PointerProperties* pointerProperties,
        const PointerCoords* pointerCoords, float xPrecision, float yPrecision,
        float xCursorPosition, float yCursorPosition, nsecs_t downTime,
        const std::vector<TouchVideoFrame>& videoFrames)
      : id(id),
        eventTime(eventTime),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        policyFlags(policyFlags),
        action(action),
        actionButton(actionButton),
        flags(flags),
        metaState(metaState),
        buttonState(buttonState),
        classification(classification),
        edgeFlags(edgeFlags),
        xPrecision(xPrecision),
        yPrecision(yPrecision),
        xCursorPosition(xCursorPosition),
        yCursorPosition(yCursorPosition),
        downTime(downTime),
        readTime(readTime),
        videoFrames(videoFrames) {
    for (uint32_t i = 0; i < pointerCount; i++) {
        this->pointerProperties.emplace_back(pointerProperties[i]);
        this->pointerCoords.emplace_back(pointerCoords[i]);
    }
}

static inline bool isCursorPositionEqual(float lhs, float rhs) {
    return (isnan(lhs) && isnan(rhs)) || lhs == rhs;
}

bool NotifyMotionArgs::operator==(const NotifyMotionArgs& rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && readTime == rhs.readTime &&
            deviceId == rhs.deviceId && source == rhs.source && displayId == rhs.displayId &&
            policyFlags == rhs.policyFlags && action == rhs.action &&
            actionButton == rhs.actionButton && flags == rhs.flags && metaState == rhs.metaState &&
            buttonState == rhs.buttonState && classification == rhs.classification &&
            edgeFlags == rhs.edgeFlags && pointerProperties == rhs.pointerProperties &&
            pointerCoords == rhs.pointerCoords && xPrecision == rhs.xPrecision &&
            yPrecision == rhs.yPrecision &&
            isCursorPositionEqual(xCursorPosition, rhs.xCursorPosition) &&
            isCursorPositionEqual(yCursorPosition, rhs.yCursorPosition) &&
            downTime == rhs.downTime && videoFrames == rhs.videoFrames;
}

std::string NotifyMotionArgs::dump() const {
    std::string coords;
    for (uint32_t i = 0; i < getPointerCount(); i++) {
        if (!coords.empty()) {
            coords += ", ";
        }
        coords += StringPrintf("{%" PRIu32 ": ", i);
        coords +=
                StringPrintf("id=%" PRIu32 " x=%.1f y=%.1f pressure=%.1f", pointerProperties[i].id,
                             pointerCoords[i].getX(), pointerCoords[i].getY(),
                             pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
        const ToolType toolType = pointerProperties[i].toolType;
        if (toolType != ToolType::FINGER) {
            coords += StringPrintf(" toolType=%s", ftl::enum_string(toolType).c_str());
        }
        const float major = pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR);
        const float minor = pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR);
        const float orientation = pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION);
        if (major != 0 || minor != 0) {
            coords += StringPrintf(" major=%.1f minor=%.1f orientation=%.1f", major, minor,
                                   orientation);
        }
        coords += "}";
    }
    return StringPrintf("NotifyMotionArgs(id=%" PRId32 ", eventTime=%" PRId64 ", deviceId=%" PRId32
                        ", source=%s, action=%s, pointerCount=%zu pointers=%s, flags=0x%08x)",
                        id, eventTime, deviceId, inputEventSourceToString(source).c_str(),
                        MotionEvent::actionToString(action).c_str(), getPointerCount(),
                        coords.c_str(), flags);
}

// --- NotifySwitchArgs ---

NotifySwitchArgs::NotifySwitchArgs(int32_t id, nsecs_t eventTime, uint32_t policyFlags,
                                   uint32_t switchValues, uint32_t switchMask)
      : id(id),
        eventTime(eventTime),
        policyFlags(policyFlags),
        switchValues(switchValues),
        switchMask(switchMask) {}

// --- NotifySensorArgs ---

NotifySensorArgs::NotifySensorArgs(int32_t id, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                                   InputDeviceSensorType sensorType,
                                   InputDeviceSensorAccuracy accuracy, bool accuracyChanged,
                                   nsecs_t hwTimestamp, std::vector<float> values)
      : id(id),
        eventTime(eventTime),
        deviceId(deviceId),
        source(source),
        sensorType(sensorType),
        accuracy(accuracy),
        accuracyChanged(accuracyChanged),
        hwTimestamp(hwTimestamp),
        values(std::move(values)) {}

// --- NotifyVibratorStateArgs ---

NotifyVibratorStateArgs::NotifyVibratorStateArgs(int32_t id, nsecs_t eventTime, int32_t deviceId,
                                                 bool isOn)
      : id(id), eventTime(eventTime), deviceId(deviceId), isOn(isOn) {}

// --- NotifyDeviceResetArgs ---

NotifyDeviceResetArgs::NotifyDeviceResetArgs(int32_t id, nsecs_t eventTime, int32_t deviceId)
      : id(id), eventTime(eventTime), deviceId(deviceId) {}

// --- NotifyPointerCaptureChangedArgs ---

NotifyPointerCaptureChangedArgs::NotifyPointerCaptureChangedArgs(
        int32_t id, nsecs_t eventTime, const PointerCaptureRequest& request)
      : id(id), eventTime(eventTime), request(request) {}

// Helper to std::visit with lambdas.
template <typename... V>
struct Visitor : V... { using V::operator()...; };
// explicit deduction guide (not needed as of C++20)
template <typename... V>
Visitor(V...) -> Visitor<V...>;

const char* toString(const NotifyArgs& args) {
    Visitor toStringVisitor{
            [&](const NotifyInputDevicesChangedArgs&) { return "NotifyInputDevicesChangedArgs"; },
            [&](const NotifyConfigurationChangedArgs&) { return "NotifyConfigurationChangedArgs"; },
            [&](const NotifyKeyArgs&) { return "NotifyKeyArgs"; },
            [&](const NotifyMotionArgs&) { return "NotifyMotionArgs"; },
            [&](const NotifySensorArgs&) { return "NotifySensorArgs"; },
            [&](const NotifySwitchArgs&) { return "NotifySwitchArgs"; },
            [&](const NotifyDeviceResetArgs&) { return "NotifyDeviceResetArgs"; },
            [&](const NotifyPointerCaptureChangedArgs&) {
                return "NotifyPointerCaptureChangedArgs";
            },
            [&](const NotifyVibratorStateArgs&) { return "NotifyVibratorStateArgs"; },
    };
    return std::visit(toStringVisitor, args);
}

} // namespace android
