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

#pragma once

#include <vector>

#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/TouchVideoFrame.h>

namespace android {

/* Describes a change in any of the connected input devices. */
struct NotifyInputDevicesChangedArgs {
    int32_t id;
    std::vector<InputDeviceInfo> inputDeviceInfos;

    inline NotifyInputDevicesChangedArgs() {}

    NotifyInputDevicesChangedArgs(int32_t id, std::vector<InputDeviceInfo> infos);

    bool operator==(const NotifyInputDevicesChangedArgs& rhs) const = default;

    NotifyInputDevicesChangedArgs(const NotifyInputDevicesChangedArgs& other) = default;
    NotifyInputDevicesChangedArgs& operator=(const NotifyInputDevicesChangedArgs&) = default;
};

/* Describes a configuration change event. */
struct NotifyConfigurationChangedArgs {
    int32_t id;
    nsecs_t eventTime;

    inline NotifyConfigurationChangedArgs() {}

    NotifyConfigurationChangedArgs(int32_t id, nsecs_t eventTime);

    bool operator==(const NotifyConfigurationChangedArgs& rhs) const = default;

    NotifyConfigurationChangedArgs(const NotifyConfigurationChangedArgs& other) = default;
    NotifyConfigurationChangedArgs& operator=(const NotifyConfigurationChangedArgs&) = default;
};

/* Describes a key event. */
struct NotifyKeyArgs {
    int32_t id;
    nsecs_t eventTime;

    int32_t deviceId;
    uint32_t source;
    int32_t displayId;
    uint32_t policyFlags;
    int32_t action;
    int32_t flags;
    int32_t keyCode;
    int32_t scanCode;
    int32_t metaState;
    nsecs_t downTime;
    nsecs_t readTime;

    inline NotifyKeyArgs() {}

    NotifyKeyArgs(int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId,
                  uint32_t source, int32_t displayId, uint32_t policyFlags, int32_t action,
                  int32_t flags, int32_t keyCode, int32_t scanCode, int32_t metaState,
                  nsecs_t downTime);

    bool operator==(const NotifyKeyArgs& rhs) const = default;

    NotifyKeyArgs(const NotifyKeyArgs& other) = default;
    NotifyKeyArgs& operator=(const NotifyKeyArgs&) = default;
};

/* Describes a motion event. */
struct NotifyMotionArgs {
    int32_t id;
    nsecs_t eventTime;

    int32_t deviceId;
    uint32_t source;
    int32_t displayId;
    uint32_t policyFlags;
    int32_t action;
    int32_t actionButton;
    int32_t flags;
    int32_t metaState;
    int32_t buttonState;
    /**
     * Classification of the current touch gesture
     */
    MotionClassification classification;
    int32_t edgeFlags;

    // Vectors 'pointerProperties' and 'pointerCoords' must always have the same number of elements
    std::vector<PointerProperties> pointerProperties;
    std::vector<PointerCoords> pointerCoords;
    float xPrecision;
    float yPrecision;
    /**
     * Mouse cursor position when this event is reported relative to the origin of the specified
     * display. Only valid if this is a mouse event (originates from a mouse or from a trackpad in
     * gestures enabled mode.
     */
    float xCursorPosition;
    float yCursorPosition;
    nsecs_t downTime;
    nsecs_t readTime;
    std::vector<TouchVideoFrame> videoFrames;

    inline NotifyMotionArgs() {}

    NotifyMotionArgs(int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId,
                     uint32_t source, int32_t displayId, uint32_t policyFlags, int32_t action,
                     int32_t actionButton, int32_t flags, int32_t metaState, int32_t buttonState,
                     MotionClassification classification, int32_t edgeFlags, uint32_t pointerCount,
                     const PointerProperties* pointerProperties, const PointerCoords* pointerCoords,
                     float xPrecision, float yPrecision, float xCursorPosition,
                     float yCursorPosition, nsecs_t downTime,
                     const std::vector<TouchVideoFrame>& videoFrames);

    NotifyMotionArgs(const NotifyMotionArgs& other) = default;
    NotifyMotionArgs& operator=(const android::NotifyMotionArgs&) = default;

    bool operator==(const NotifyMotionArgs& rhs) const;

    inline size_t getPointerCount() const { return pointerProperties.size(); }

    std::string dump() const;
};

/* Describes a sensor event. */
struct NotifySensorArgs {
    int32_t id;
    nsecs_t eventTime;

    int32_t deviceId;
    uint32_t source;
    InputDeviceSensorType sensorType;
    InputDeviceSensorAccuracy accuracy;
    bool accuracyChanged;
    nsecs_t hwTimestamp;
    std::vector<float> values;

    inline NotifySensorArgs() {}

    NotifySensorArgs(int32_t id, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                     InputDeviceSensorType sensorType, InputDeviceSensorAccuracy accuracy,
                     bool accuracyChanged, nsecs_t hwTimestamp, std::vector<float> values);

    NotifySensorArgs(const NotifySensorArgs& other) = default;
    NotifySensorArgs& operator=(const NotifySensorArgs&) = default;
};

/* Describes a switch event. */
struct NotifySwitchArgs {
    int32_t id;
    nsecs_t eventTime;

    uint32_t policyFlags;
    uint32_t switchValues;
    uint32_t switchMask;

    inline NotifySwitchArgs() {}

    NotifySwitchArgs(int32_t id, nsecs_t eventTime, uint32_t policyFlags, uint32_t switchValues,
                     uint32_t switchMask);

    NotifySwitchArgs(const NotifySwitchArgs& other) = default;
    NotifySwitchArgs& operator=(const NotifySwitchArgs&) = default;

    bool operator==(const NotifySwitchArgs& rhs) const = default;
};

/* Describes a device reset event, such as when a device is added,
 * reconfigured, or removed. */
struct NotifyDeviceResetArgs {
    int32_t id;
    nsecs_t eventTime;

    int32_t deviceId;

    inline NotifyDeviceResetArgs() {}

    NotifyDeviceResetArgs(int32_t id, nsecs_t eventTime, int32_t deviceId);

    NotifyDeviceResetArgs(const NotifyDeviceResetArgs& other) = default;
    NotifyDeviceResetArgs& operator=(const NotifyDeviceResetArgs&) = default;

    bool operator==(const NotifyDeviceResetArgs& rhs) const = default;
};

/* Describes a change in the state of Pointer Capture. */
struct NotifyPointerCaptureChangedArgs {
    int32_t id;
    nsecs_t eventTime;

    PointerCaptureRequest request;

    inline NotifyPointerCaptureChangedArgs() {}

    NotifyPointerCaptureChangedArgs(int32_t id, nsecs_t eventTime, const PointerCaptureRequest&);

    NotifyPointerCaptureChangedArgs(const NotifyPointerCaptureChangedArgs& other) = default;
    NotifyPointerCaptureChangedArgs& operator=(const NotifyPointerCaptureChangedArgs&) = default;
};

/* Describes a vibrator state event. */
struct NotifyVibratorStateArgs {
    int32_t id;
    nsecs_t eventTime;

    int32_t deviceId;
    bool isOn;

    inline NotifyVibratorStateArgs() {}

    NotifyVibratorStateArgs(int32_t id, nsecs_t eventTIme, int32_t deviceId, bool isOn);

    NotifyVibratorStateArgs(const NotifyVibratorStateArgs& other) = default;
    NotifyVibratorStateArgs& operator=(const NotifyVibratorStateArgs&) = default;
};

using NotifyArgs =
        std::variant<NotifyInputDevicesChangedArgs, NotifyConfigurationChangedArgs, NotifyKeyArgs,
                     NotifyMotionArgs, NotifySensorArgs, NotifySwitchArgs, NotifyDeviceResetArgs,
                     NotifyPointerCaptureChangedArgs, NotifyVibratorStateArgs>;

const char* toString(const NotifyArgs& args);

} // namespace android
