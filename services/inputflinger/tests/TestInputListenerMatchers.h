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

#include <android/input.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/Input.h>

namespace android {

MATCHER_P(WithMotionAction, action, "MotionEvent with specified action") {
    bool matches = action == arg.action;
    if (!matches) {
        *result_listener << "expected action " << MotionEvent::actionToString(action)
                         << ", but got " << MotionEvent::actionToString(arg.action);
    }
    if (action == AMOTION_EVENT_ACTION_CANCEL) {
        if (!matches) {
            *result_listener << "; ";
        }
        *result_listener << "expected FLAG_CANCELED to be set with ACTION_CANCEL, but was not set";
        matches &= (arg.flags & AMOTION_EVENT_FLAG_CANCELED) != 0;
    }
    return matches;
}

MATCHER_P(WithKeyAction, action, "KeyEvent with specified action") {
    *result_listener << "expected action " << KeyEvent::actionToString(action) << ", but got "
                     << KeyEvent::actionToString(arg.action);
    return arg.action == action;
}

MATCHER_P(WithSource, source, "InputEvent with specified source") {
    *result_listener << "expected source " << inputEventSourceToString(source) << ", but got "
                     << inputEventSourceToString(arg.source);
    return arg.source == source;
}

MATCHER_P(WithDisplayId, displayId, "InputEvent with specified displayId") {
    *result_listener << "expected displayId " << displayId << ", but got " << arg.displayId;
    return arg.displayId == displayId;
}

MATCHER_P(WithDeviceId, deviceId, "InputEvent with specified deviceId") {
    *result_listener << "expected deviceId " << deviceId << ", but got " << arg.deviceId;
    return arg.deviceId == deviceId;
}

MATCHER_P(WithKeyCode, keyCode, "KeyEvent with specified key code") {
    *result_listener << "expected key code " << keyCode << ", but got " << arg.keyCode;
    return arg.keyCode == keyCode;
}

MATCHER_P2(WithCoords, x, y, "InputEvent with specified coords") {
    const auto argX = arg.pointerCoords[0].getX();
    const auto argY = arg.pointerCoords[0].getY();
    *result_listener << "expected coords (" << x << ", " << y << "), but got (" << argX << ", "
                     << argY << ")";
    return argX == x && argY == y;
}

MATCHER_P(WithPressure, pressure, "InputEvent with specified pressure") {
    const auto argPressure = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE);
    *result_listener << "expected pressure " << pressure << ", but got " << argPressure;
    return argPressure == pressure;
}

MATCHER_P(WithToolType, toolType, "InputEvent with specified tool type") {
    const auto argToolType = arg.pointerProperties[0].toolType;
    *result_listener << "expected tool type " << motionToolTypeToString(toolType) << ", but got "
                     << motionToolTypeToString(argToolType);
    return argToolType == toolType;
}

MATCHER_P(WithFlags, flags, "InputEvent with specified flags") {
    *result_listener << "expected flags " << flags << ", but got " << arg.flags;
    return arg.flags == flags;
}

MATCHER_P(WithButtonState, buttons, "InputEvent with specified button state") {
    *result_listener << "expected button state " << buttons << ", but got " << arg.buttonState;
    return arg.buttonState == buttons;
}

MATCHER_P(WithEventTime, eventTime, "InputEvent with specified eventTime") {
    *result_listener << "expected event time " << eventTime << ", but got " << arg.eventTime;
    return arg.eventTime == eventTime;
}

} // namespace android
