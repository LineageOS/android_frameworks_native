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

#include <cmath>

#include <android/input.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/Input.h>

#include "NotifyArgs.h"
#include "TestConstants.h"

namespace android {

MATCHER_P(WithSource, source, "InputEvent with specified source") {
    *result_listener << "expected source " << inputEventSourceToString(source) << ", but got "
                     << inputEventSourceToString(arg.source);
    return arg.source == source;
}

/// Key action
class WithKeyActionMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithKeyActionMatcher(int32_t action) : mAction(action) {}

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mAction == args.action;
    }

    bool MatchAndExplain(const KeyEvent& event, std::ostream*) const {
        return mAction == event.getAction();
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with key action " << KeyEvent::actionToString(mAction);
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong action"; }

private:
    const int32_t mAction;
};

WithKeyActionMatcher WithKeyAction(int32_t action);

/// Motion action
class WithMotionActionMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithMotionActionMatcher(int32_t action) : mAction(action) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        bool matches = mAction == args.action;
        if (args.action == AMOTION_EVENT_ACTION_CANCEL) {
            matches &= (args.flags & AMOTION_EVENT_FLAG_CANCELED) != 0;
        }
        return matches;
    }

    bool MatchAndExplain(const MotionEvent& event, std::ostream*) const {
        bool matches = mAction == event.getAction();
        if (event.getAction() == AMOTION_EVENT_ACTION_CANCEL) {
            matches &= (event.getFlags() & AMOTION_EVENT_FLAG_CANCELED) != 0;
        }
        return matches;
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with motion action " << MotionEvent::actionToString(mAction);
        if (mAction == AMOTION_EVENT_ACTION_CANCEL) {
            *os << " and FLAG_CANCELED";
        }
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong action"; }

private:
    const int32_t mAction;
};

WithMotionActionMatcher WithMotionAction(int32_t action);

/// Display Id
class WithDisplayIdMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithDisplayIdMatcher(int32_t displayId) : mDisplayId(displayId) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mDisplayId == args.displayId;
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mDisplayId == args.displayId;
    }

    bool MatchAndExplain(const InputEvent& event, std::ostream*) const {
        return mDisplayId == event.getDisplayId();
    }

    void DescribeTo(std::ostream* os) const { *os << "with display id " << mDisplayId; }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong display id"; }

private:
    const int32_t mDisplayId;
};

WithDisplayIdMatcher WithDisplayId(int32_t displayId);

/// Device Id
class WithDeviceIdMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithDeviceIdMatcher(int32_t deviceId) : mDeviceId(deviceId) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mDeviceId == args.deviceId;
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mDeviceId == args.deviceId;
    }

    bool MatchAndExplain(const NotifyDeviceResetArgs& args, std::ostream*) const {
        return mDeviceId == args.deviceId;
    }

    bool MatchAndExplain(const InputEvent& event, std::ostream*) const {
        return mDeviceId == event.getDeviceId();
    }

    void DescribeTo(std::ostream* os) const { *os << "with device id " << mDeviceId; }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong device id"; }

private:
    const int32_t mDeviceId;
};

WithDeviceIdMatcher WithDeviceId(int32_t deviceId);

MATCHER_P(WithKeyCode, keyCode, "KeyEvent with specified key code") {
    *result_listener << "expected key code " << keyCode << ", but got " << arg.keyCode;
    return arg.keyCode == keyCode;
}

MATCHER_P(WithRepeatCount, repeatCount, "KeyEvent with specified repeat count") {
    return arg.getRepeatCount() == repeatCount;
}

MATCHER_P(WithPointerCount, count, "MotionEvent with specified number of pointers") {
    *result_listener << "expected " << count << " pointer(s), but got " << arg.getPointerCount();
    return arg.getPointerCount() == count;
}

MATCHER_P2(WithPointerId, index, id, "MotionEvent with specified pointer ID for pointer index") {
    const auto argPointerId = arg.pointerProperties[index].id;
    *result_listener << "expected pointer with index " << index << " to have ID " << argPointerId;
    return argPointerId == id;
}

MATCHER_P2(WithCoords, x, y, "InputEvent with specified coords") {
    const auto argX = arg.pointerCoords[0].getX();
    const auto argY = arg.pointerCoords[0].getY();
    *result_listener << "expected coords (" << x << ", " << y << "), but got (" << argX << ", "
                     << argY << ")";
    return argX == x && argY == y;
}

MATCHER_P2(WithCursorPosition, x, y, "InputEvent with specified cursor position") {
    const auto argX = arg.xCursorPosition;
    const auto argY = arg.yCursorPosition;
    *result_listener << "expected cursor position (" << x << ", " << y << "), but got (" << argX
                     << ", " << argY << ")";
    return (isnan(x) ? isnan(argX) : x == argX) && (isnan(y) ? isnan(argY) : y == argY);
}

MATCHER_P3(WithPointerCoords, pointer, x, y, "InputEvent with specified coords for pointer") {
    const auto argX = arg.pointerCoords[pointer].getX();
    const auto argY = arg.pointerCoords[pointer].getY();
    *result_listener << "expected pointer " << pointer << " to have coords (" << x << ", " << y
                     << "), but got (" << argX << ", " << argY << ")";
    return argX == x && argY == y;
}

MATCHER_P2(WithRelativeMotion, x, y, "InputEvent with specified relative motion") {
    const auto argX = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X);
    const auto argY = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y);
    *result_listener << "expected relative motion (" << x << ", " << y << "), but got (" << argX
                     << ", " << argY << ")";
    return argX == x && argY == y;
}

MATCHER_P3(WithGestureOffset, dx, dy, epsilon,
           "InputEvent with specified touchpad gesture offset") {
    const auto argGestureX = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET);
    const auto argGestureY = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET);
    const double xDiff = fabs(argGestureX - dx);
    const double yDiff = fabs(argGestureY - dy);
    *result_listener << "expected gesture offset (" << dx << ", " << dy << ") within " << epsilon
                     << ", but got (" << argGestureX << ", " << argGestureY << ")";
    return xDiff <= epsilon && yDiff <= epsilon;
}

MATCHER_P3(WithGestureScrollDistance, x, y, epsilon,
           "InputEvent with specified touchpad gesture scroll distance") {
    const auto argXDistance =
            arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_SCROLL_X_DISTANCE);
    const auto argYDistance =
            arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_SCROLL_Y_DISTANCE);
    const double xDiff = fabs(argXDistance - x);
    const double yDiff = fabs(argYDistance - y);
    *result_listener << "expected gesture offset (" << x << ", " << y << ") within " << epsilon
                     << ", but got (" << argXDistance << ", " << argYDistance << ")";
    return xDiff <= epsilon && yDiff <= epsilon;
}

MATCHER_P2(WithGesturePinchScaleFactor, factor, epsilon,
           "InputEvent with specified touchpad pinch gesture scale factor") {
    const auto argScaleFactor =
            arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_PINCH_SCALE_FACTOR);
    *result_listener << "expected gesture scale factor " << factor << " within " << epsilon
                     << " but got " << argScaleFactor;
    return fabs(argScaleFactor - factor) <= epsilon;
}

MATCHER_P(WithGestureSwipeFingerCount, count,
          "InputEvent with specified touchpad swipe finger count") {
    const auto argFingerCount =
            arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_SWIPE_FINGER_COUNT);
    *result_listener << "expected gesture swipe finger count " << count << " but got "
                     << argFingerCount;
    return fabs(argFingerCount - count) <= EPSILON;
}

MATCHER_P(WithPressure, pressure, "InputEvent with specified pressure") {
    const auto argPressure = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE);
    *result_listener << "expected pressure " << pressure << ", but got " << argPressure;
    return argPressure == pressure;
}

MATCHER_P2(WithTouchDimensions, maj, min, "InputEvent with specified touch dimensions") {
    const auto argMajor = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR);
    const auto argMinor = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR);
    *result_listener << "expected touch dimensions " << maj << " major x " << min
                     << " minor, but got " << argMajor << " major x " << argMinor << " minor";
    return argMajor == maj && argMinor == min;
}

MATCHER_P2(WithToolDimensions, maj, min, "InputEvent with specified tool dimensions") {
    const auto argMajor = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR);
    const auto argMinor = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR);
    *result_listener << "expected tool dimensions " << maj << " major x " << min
                     << " minor, but got " << argMajor << " major x " << argMinor << " minor";
    return argMajor == maj && argMinor == min;
}

MATCHER_P(WithToolType, toolType, "InputEvent with specified tool type") {
    const auto argToolType = arg.pointerProperties[0].toolType;
    *result_listener << "expected tool type " << ftl::enum_string(toolType) << ", but got "
                     << ftl::enum_string(argToolType);
    return argToolType == toolType;
}

MATCHER_P2(WithPointerToolType, pointer, toolType,
           "InputEvent with specified tool type for pointer") {
    const auto argToolType = arg.pointerProperties[pointer].toolType;
    *result_listener << "expected pointer " << pointer << " to have tool type "
                     << ftl::enum_string(toolType) << ", but got " << ftl::enum_string(argToolType);
    return argToolType == toolType;
}

MATCHER_P(WithFlags, flags, "InputEvent with specified flags") {
    *result_listener << "expected flags " << flags << ", but got " << arg.flags;
    return arg.flags == static_cast<int32_t>(flags);
}

MATCHER_P(WithMotionClassification, classification,
          "InputEvent with specified MotionClassification") {
    *result_listener << "expected classification " << motionClassificationToString(classification)
                     << ", but got " << motionClassificationToString(arg.classification);
    return arg.classification == classification;
}

MATCHER_P(WithButtonState, buttons, "InputEvent with specified button state") {
    *result_listener << "expected button state " << buttons << ", but got " << arg.buttonState;
    return arg.buttonState == buttons;
}

MATCHER_P(WithActionButton, actionButton, "InputEvent with specified action button") {
    *result_listener << "expected action button " << actionButton << ", but got "
                     << arg.actionButton;
    return arg.actionButton == actionButton;
}

MATCHER_P(WithEventTime, eventTime, "InputEvent with specified eventTime") {
    *result_listener << "expected event time " << eventTime << ", but got " << arg.eventTime;
    return arg.eventTime == eventTime;
}

MATCHER_P(WithDownTime, downTime, "InputEvent with specified downTime") {
    *result_listener << "expected down time " << downTime << ", but got " << arg.downTime;
    return arg.downTime == downTime;
}

MATCHER_P2(WithPrecision, xPrecision, yPrecision, "MotionEvent with specified precision") {
    *result_listener << "expected x-precision " << xPrecision << " and y-precision " << yPrecision
                     << ", but got " << arg.xPrecision << " and " << arg.yPrecision;
    return arg.xPrecision == xPrecision && arg.yPrecision == yPrecision;
}

} // namespace android
