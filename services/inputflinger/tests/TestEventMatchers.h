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
#include <compare>
#include <ios>

#include <android-base/stringprintf.h>
#include <android/input.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <input/PrintTools.h>

#include "NotifyArgs.h"
#include "TestConstants.h"

namespace android {

struct PointF {
    float x;
    float y;
    auto operator<=>(const PointF&) const = default;
};

inline std::string pointFToString(const PointF& p) {
    return std::string("(") + std::to_string(p.x) + ", " + std::to_string(p.y) + ")";
}

/// Source
class WithSourceMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithSourceMatcher(uint32_t source) : mSource(source) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mSource == args.source;
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mSource == args.source;
    }

    bool MatchAndExplain(const InputEvent& event, std::ostream*) const {
        return mSource == event.getSource();
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with source " << inputEventSourceToString(mSource);
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong source"; }

private:
    const uint32_t mSource;
};

inline WithSourceMatcher WithSource(uint32_t source) {
    return WithSourceMatcher(source);
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

inline WithKeyActionMatcher WithKeyAction(int32_t action) {
    return WithKeyActionMatcher(action);
}

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

inline WithMotionActionMatcher WithMotionAction(int32_t action) {
    return WithMotionActionMatcher(action);
}

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

inline WithDisplayIdMatcher WithDisplayId(int32_t displayId) {
    return WithDisplayIdMatcher(displayId);
}

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

inline WithDeviceIdMatcher WithDeviceId(int32_t deviceId) {
    return WithDeviceIdMatcher(deviceId);
}

/// Flags
class WithFlagsMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithFlagsMatcher(int32_t flags) : mFlags(flags) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mFlags == args.flags;
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mFlags == args.flags;
    }

    bool MatchAndExplain(const MotionEvent& event, std::ostream*) const {
        return mFlags == event.getFlags();
    }

    bool MatchAndExplain(const KeyEvent& event, std::ostream*) const {
        return mFlags == event.getFlags();
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with flags " << base::StringPrintf("0x%x", mFlags);
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong flags"; }

private:
    const int32_t mFlags;
};

inline WithFlagsMatcher WithFlags(int32_t flags) {
    return WithFlagsMatcher(flags);
}

/// DownTime
class WithDownTimeMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithDownTimeMatcher(nsecs_t downTime) : mDownTime(downTime) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mDownTime == args.downTime;
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mDownTime == args.downTime;
    }

    bool MatchAndExplain(const MotionEvent& event, std::ostream*) const {
        return mDownTime == event.getDownTime();
    }

    bool MatchAndExplain(const KeyEvent& event, std::ostream*) const {
        return mDownTime == event.getDownTime();
    }

    void DescribeTo(std::ostream* os) const { *os << "with down time " << mDownTime; }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong down time"; }

private:
    const nsecs_t mDownTime;
};

inline WithDownTimeMatcher WithDownTime(nsecs_t downTime) {
    return WithDownTimeMatcher(downTime);
}

/// Coordinate matcher
class WithCoordsMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithCoordsMatcher(size_t pointerIndex, float x, float y)
          : mPointerIndex(pointerIndex), mX(x), mY(y) {}

    bool MatchAndExplain(const MotionEvent& event, std::ostream* os) const {
        if (mPointerIndex >= event.getPointerCount()) {
            *os << "Pointer index " << mPointerIndex << " is out of bounds";
            return false;
        }

        bool matches = mX == event.getX(mPointerIndex) && mY == event.getY(mPointerIndex);
        if (!matches) {
            *os << "expected coords (" << mX << ", " << mY << ") at pointer index " << mPointerIndex
                << ", but got (" << event.getX(mPointerIndex) << ", " << event.getY(mPointerIndex)
                << ")";
        }
        return matches;
    }

    bool MatchAndExplain(const NotifyMotionArgs& event, std::ostream* os) const {
        if (mPointerIndex >= event.pointerCoords.size()) {
            *os << "Pointer index " << mPointerIndex << " is out of bounds";
            return false;
        }

        bool matches = mX == event.pointerCoords[mPointerIndex].getX() &&
                mY == event.pointerCoords[mPointerIndex].getY();
        if (!matches) {
            *os << "expected coords (" << mX << ", " << mY << ") at pointer index " << mPointerIndex
                << ", but got (" << event.pointerCoords[mPointerIndex].getX() << ", "
                << event.pointerCoords[mPointerIndex].getY() << ")";
        }
        return matches;
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with coords (" << mX << ", " << mY << ") at pointer index " << mPointerIndex;
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong coords"; }

private:
    const size_t mPointerIndex;
    const float mX;
    const float mY;
};

inline WithCoordsMatcher WithCoords(float x, float y) {
    return WithCoordsMatcher(0, x, y);
}

inline WithCoordsMatcher WithPointerCoords(size_t pointerIndex, float x, float y) {
    return WithCoordsMatcher(pointerIndex, x, y);
}

/// Raw coordinate matcher
class WithRawCoordsMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithRawCoordsMatcher(size_t pointerIndex, float rawX, float rawY)
          : mPointerIndex(pointerIndex), mRawX(rawX), mRawY(rawY) {}

    bool MatchAndExplain(const MotionEvent& event, std::ostream* os) const {
        if (mPointerIndex >= event.getPointerCount()) {
            *os << "Pointer index " << mPointerIndex << " is out of bounds";
            return false;
        }

        bool matches =
                mRawX == event.getRawX(mPointerIndex) && mRawY == event.getRawY(mPointerIndex);
        if (!matches) {
            *os << "expected raw coords (" << mRawX << ", " << mRawY << ") at pointer index "
                << mPointerIndex << ", but got (" << event.getRawX(mPointerIndex) << ", "
                << event.getRawY(mPointerIndex) << ")";
        }
        return matches;
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with raw coords (" << mRawX << ", " << mRawY << ") at pointer index "
            << mPointerIndex;
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong raw coords"; }

private:
    const size_t mPointerIndex;
    const float mRawX;
    const float mRawY;
};

inline WithRawCoordsMatcher WithRawCoords(float rawX, float rawY) {
    return WithRawCoordsMatcher(0, rawX, rawY);
}

inline WithRawCoordsMatcher WithPointerRawCoords(size_t pointerIndex, float rawX, float rawY) {
    return WithRawCoordsMatcher(pointerIndex, rawX, rawY);
}

/// Pointer count
class WithPointerCountMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithPointerCountMatcher(size_t pointerCount) : mPointerCount(pointerCount) {}

    bool MatchAndExplain(const MotionEvent& event, std::ostream* os) const {
        if (event.getPointerCount() != mPointerCount) {
            *os << "expected pointer count " << mPointerCount << ", but got "
                << event.getPointerCount();
            return false;
        }
        return true;
    }

    bool MatchAndExplain(const NotifyMotionArgs& event, std::ostream* os) const {
        if (event.pointerCoords.size() != mPointerCount) {
            *os << "expected pointer count " << mPointerCount << ", but got "
                << event.pointerCoords.size();
            return false;
        }
        return true;
    }

    void DescribeTo(std::ostream* os) const { *os << "with pointer count " << mPointerCount; }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong pointer count"; }

private:
    const size_t mPointerCount;
};

inline WithPointerCountMatcher WithPointerCount(size_t pointerCount) {
    return WithPointerCountMatcher(pointerCount);
}

/// Pointers matcher
class WithPointersMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithPointersMatcher(std::map<int32_t, PointF> pointers) : mPointers(pointers) {}

    bool MatchAndExplain(const MotionEvent& event, std::ostream* os) const {
        std::map<int32_t, PointF> actualPointers;
        for (size_t pointerIndex = 0; pointerIndex < event.getPointerCount(); pointerIndex++) {
            const int32_t pointerId = event.getPointerId(pointerIndex);
            actualPointers[pointerId] = {event.getX(pointerIndex), event.getY(pointerIndex)};
        }

        if (mPointers != actualPointers) {
            *os << "expected pointers " << dumpMap(mPointers, constToString, pointFToString)
                << ", but got " << dumpMap(actualPointers, constToString, pointFToString);
            return false;
        }
        return true;
    }

    bool MatchAndExplain(const NotifyMotionArgs& event, std::ostream* os) const {
        std::map<int32_t, PointF> actualPointers;
        for (size_t pointerIndex = 0; pointerIndex < event.pointerCoords.size(); pointerIndex++) {
            const int32_t pointerId = event.pointerProperties[pointerIndex].id;
            actualPointers[pointerId] = {event.pointerCoords[pointerIndex].getX(),
                                         event.pointerCoords[pointerIndex].getY()};
        }

        if (mPointers != actualPointers) {
            *os << "expected pointers " << dumpMap(mPointers, constToString, pointFToString)
                << ", but got " << dumpMap(actualPointers, constToString, pointFToString);
            return false;
        }
        return true;
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with pointers " << dumpMap(mPointers, constToString, pointFToString);
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong pointers"; }

private:
    const std::map<int32_t, PointF> mPointers;
};

inline WithPointersMatcher WithPointers(
        const std::map<int32_t /*id*/, PointF /*coords*/>& pointers) {
    return WithPointersMatcher(pointers);
}

/// Pointer ids matcher
class WithPointerIdsMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithPointerIdsMatcher(std::set<int32_t> pointerIds) : mPointerIds(pointerIds) {}

    bool MatchAndExplain(const MotionEvent& event, std::ostream* os) const {
        std::set<int32_t> actualPointerIds;
        for (size_t pointerIndex = 0; pointerIndex < event.getPointerCount(); pointerIndex++) {
            const PointerProperties* properties = event.getPointerProperties(pointerIndex);
            actualPointerIds.insert(properties->id);
        }

        if (mPointerIds != actualPointerIds) {
            *os << "expected pointer ids " << dumpSet(mPointerIds) << ", but got "
                << dumpSet(actualPointerIds);
            return false;
        }
        return true;
    }

    bool MatchAndExplain(const NotifyMotionArgs& event, std::ostream* os) const {
        std::set<int32_t> actualPointerIds;
        for (const PointerProperties& properties : event.pointerProperties) {
            actualPointerIds.insert(properties.id);
        }

        if (mPointerIds != actualPointerIds) {
            *os << "expected pointer ids " << dumpSet(mPointerIds) << ", but got "
                << dumpSet(actualPointerIds);
            return false;
        }
        return true;
    }

    void DescribeTo(std::ostream* os) const { *os << "with pointer ids " << dumpSet(mPointerIds); }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong pointer ids"; }

private:
    const std::set<int32_t> mPointerIds;
};

inline WithPointerIdsMatcher WithPointerIds(const std::set<int32_t /*id*/>& pointerIds) {
    return WithPointerIdsMatcher(pointerIds);
}

/// Key code
class WithKeyCodeMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithKeyCodeMatcher(int32_t keyCode) : mKeyCode(keyCode) {}

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mKeyCode == args.keyCode;
    }

    bool MatchAndExplain(const KeyEvent& event, std::ostream*) const {
        return mKeyCode == event.getKeyCode();
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with key code " << KeyEvent::getLabel(mKeyCode);
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong key code"; }

private:
    const int32_t mKeyCode;
};

inline WithKeyCodeMatcher WithKeyCode(int32_t keyCode) {
    return WithKeyCodeMatcher(keyCode);
}

/// EventId
class WithEventIdMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithEventIdMatcher(int32_t eventId) : mEventId(eventId) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mEventId == args.id;
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mEventId == args.id;
    }

    bool MatchAndExplain(const InputEvent& event, std::ostream*) const {
        return mEventId == event.getId();
    }

    void DescribeTo(std::ostream* os) const { *os << "with eventId 0x" << std::hex << mEventId; }

    void DescribeNegationTo(std::ostream* os) const {
        *os << "with eventId not equal to 0x" << std::hex << mEventId;
    }

private:
    const int32_t mEventId;
};

inline WithEventIdMatcher WithEventId(int32_t eventId) {
    return WithEventIdMatcher(eventId);
}

/// EventIdSource
class WithEventIdSourceMatcher {
public:
    using is_gtest_matcher = void;
    explicit WithEventIdSourceMatcher(IdGenerator::Source eventIdSource)
          : mEventIdSource(eventIdSource) {}

    bool MatchAndExplain(const NotifyMotionArgs& args, std::ostream*) const {
        return mEventIdSource == IdGenerator::getSource(args.id);
    }

    bool MatchAndExplain(const NotifyKeyArgs& args, std::ostream*) const {
        return mEventIdSource == IdGenerator::getSource(args.id);
    }

    bool MatchAndExplain(const InputEvent& event, std::ostream*) const {
        return mEventIdSource == IdGenerator::getSource(event.getId());
    }

    void DescribeTo(std::ostream* os) const {
        *os << "with eventId from source 0x" << std::hex << ftl::to_underlying(mEventIdSource);
    }

    void DescribeNegationTo(std::ostream* os) const { *os << "wrong event from source"; }

private:
    const IdGenerator::Source mEventIdSource;
};

inline WithEventIdSourceMatcher WithEventIdSource(IdGenerator::Source eventIdSource) {
    return WithEventIdSourceMatcher(eventIdSource);
}

MATCHER_P(WithRepeatCount, repeatCount, "KeyEvent with specified repeat count") {
    return arg.getRepeatCount() == repeatCount;
}

MATCHER_P2(WithPointerId, index, id, "MotionEvent with specified pointer ID for pointer index") {
    const auto argPointerId = arg.pointerProperties[index].id;
    *result_listener << "expected pointer with index " << index << " to have ID " << argPointerId;
    return argPointerId == id;
}

MATCHER_P2(WithCursorPosition, x, y, "InputEvent with specified cursor position") {
    const auto argX = arg.xCursorPosition;
    const auto argY = arg.yCursorPosition;
    *result_listener << "expected cursor position (" << x << ", " << y << "), but got (" << argX
                     << ", " << argY << ")";
    return (isnan(x) ? isnan(argX) : x == argX) && (isnan(y) ? isnan(argY) : y == argY);
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

MATCHER_P(WithSize, size, "MotionEvent with specified size") {
    const auto argSize = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_SIZE);
    *result_listener << "expected size " << size << ", but got " << argSize;
    return argSize == size;
}

MATCHER_P(WithOrientation, orientation, "MotionEvent with specified orientation") {
    const auto argOrientation = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION);
    *result_listener << "expected orientation " << orientation << ", but got " << argOrientation;
    return argOrientation == orientation;
}

MATCHER_P(WithDistance, distance, "MotionEvent with specified distance") {
    const auto argDistance = arg.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_DISTANCE);
    *result_listener << "expected distance " << distance << ", but got " << argDistance;
    return argDistance == distance;
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

MATCHER_P(WithMetaState, metaState, "InputEvent with specified meta state") {
    *result_listener << "expected meta state 0x" << std::hex << metaState << ", but got 0x"
                     << arg.metaState;
    return arg.metaState == metaState;
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

MATCHER_P(WithPolicyFlags, policyFlags, "InputEvent with specified policy flags") {
    *result_listener << "expected policy flags 0x" << std::hex << policyFlags << ", but got 0x"
                     << arg.policyFlags;
    return arg.policyFlags == static_cast<uint32_t>(policyFlags);
}

MATCHER_P(WithEdgeFlags, edgeFlags, "InputEvent with specified edge flags") {
    *result_listener << "expected edge flags 0x" << std::hex << edgeFlags << ", but got 0x"
                     << arg.edgeFlags;
    return arg.edgeFlags == edgeFlags;
}

} // namespace android
