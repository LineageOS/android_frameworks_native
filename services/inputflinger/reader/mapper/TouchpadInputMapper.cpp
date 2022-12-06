/*
 * Copyright 2022 The Android Open Source Project
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

#include <log/log_main.h>
#include <chrono>
#include "TouchpadInputMapper.h"

namespace android {

namespace {

short getMaxTouchCount(const InputDeviceContext& context) {
    if (context.hasKeyCode(BTN_TOOL_QUINTTAP)) return 5;
    if (context.hasKeyCode(BTN_TOOL_QUADTAP)) return 4;
    if (context.hasKeyCode(BTN_TOOL_TRIPLETAP)) return 3;
    if (context.hasKeyCode(BTN_TOOL_DOUBLETAP)) return 2;
    if (context.hasKeyCode(BTN_TOOL_FINGER)) return 1;
    return 0;
}

HardwareProperties createHardwareProperties(const InputDeviceContext& context) {
    HardwareProperties props;
    RawAbsoluteAxisInfo absMtPositionX;
    context.getAbsoluteAxisInfo(ABS_MT_POSITION_X, &absMtPositionX);
    props.left = absMtPositionX.minValue;
    props.right = absMtPositionX.maxValue;
    props.res_x = absMtPositionX.resolution;

    RawAbsoluteAxisInfo absMtPositionY;
    context.getAbsoluteAxisInfo(ABS_MT_POSITION_Y, &absMtPositionY);
    props.top = absMtPositionY.minValue;
    props.bottom = absMtPositionY.maxValue;
    props.res_y = absMtPositionY.resolution;

    RawAbsoluteAxisInfo absMtOrientation;
    context.getAbsoluteAxisInfo(ABS_MT_ORIENTATION, &absMtOrientation);
    props.orientation_minimum = absMtOrientation.minValue;
    props.orientation_maximum = absMtOrientation.maxValue;

    RawAbsoluteAxisInfo absMtSlot;
    context.getAbsoluteAxisInfo(ABS_MT_SLOT, &absMtSlot);
    props.max_finger_cnt = absMtSlot.maxValue - absMtSlot.minValue + 1;
    props.max_touch_cnt = getMaxTouchCount(context);

    // T5R2 ("Track 5, Report 2") is a feature of some old Synaptics touchpads that could track 5
    // fingers but only report the coordinates of 2 of them. We don't know of any external touchpads
    // that did this, so assume false.
    props.supports_t5r2 = false;

    props.support_semi_mt = context.hasInputProperty(INPUT_PROP_SEMI_MT);
    props.is_button_pad = context.hasInputProperty(INPUT_PROP_BUTTONPAD);

    // Mouse-only properties, which will always be false.
    props.has_wheel = false;
    props.wheel_is_hi_res = false;

    // Linux Kernel haptic touchpad support isn't merged yet, so for now assume that no touchpads
    // are haptic.
    props.is_haptic_pad = false;
    return props;
}

void gestureInterpreterCallback(void* clientData, const struct Gesture* gesture) {
    // TODO(b/251196347): turn the gesture into a NotifyArgs and dispatch it.
    ALOGD("Gesture ready: %s", gesture->String().c_str());
}

} // namespace

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext),
        mGestureInterpreter(NewGestureInterpreter(), DeleteGestureInterpreter),
        mTouchButtonAccumulator(deviceContext) {
    mGestureInterpreter->Initialize(GESTURES_DEVCLASS_TOUCHPAD);
    mGestureInterpreter->SetHardwareProperties(createHardwareProperties(deviceContext));
    mGestureInterpreter->SetCallback(gestureInterpreterCallback, nullptr);
    // TODO(b/251196347): set a property provider, so we can change gesture properties.
    // TODO(b/251196347): set a timer provider, so the library can use timers.

    RawAbsoluteAxisInfo slotAxisInfo;
    getAbsoluteAxisInfo(ABS_MT_SLOT, &slotAxisInfo);
    if (!slotAxisInfo.valid || slotAxisInfo.maxValue <= 0) {
        ALOGW("Touchpad \"%s\" doesn't have a valid ABS_MT_SLOT axis, and probably won't work "
              "properly.",
              getDeviceName().c_str());
    }
    mMotionAccumulator.configure(getDeviceContext(), slotAxisInfo.maxValue + 1, true);
    mTouchButtonAccumulator.configure();
}

uint32_t TouchpadInputMapper::getSources() const {
    return AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD;
}

std::list<NotifyArgs> TouchpadInputMapper::reset(nsecs_t when) {
    mCursorButtonAccumulator.reset(getDeviceContext());
    mTouchButtonAccumulator.reset();
    mMscTimestamp = 0;
    return InputMapper::reset(when);
}

std::list<NotifyArgs> TouchpadInputMapper::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        sync(rawEvent->when);
    }
    if (rawEvent->type == EV_MSC && rawEvent->code == MSC_TIMESTAMP) {
        mMscTimestamp = rawEvent->value;
    }
    mCursorButtonAccumulator.process(rawEvent);
    mMotionAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);
    return {};
}

void TouchpadInputMapper::sync(nsecs_t when) {
    HardwareState hwState;
    // The gestures library uses doubles to represent timestamps in seconds.
    hwState.timestamp = std::chrono::duration<stime_t>(std::chrono::nanoseconds(when)).count();
    hwState.msc_timestamp =
            std::chrono::duration<stime_t>(std::chrono::microseconds(mMscTimestamp)).count();

    hwState.buttons_down = 0;
    if (mCursorButtonAccumulator.isLeftPressed()) {
        hwState.buttons_down |= GESTURES_BUTTON_LEFT;
    }
    if (mCursorButtonAccumulator.isMiddlePressed()) {
        hwState.buttons_down |= GESTURES_BUTTON_MIDDLE;
    }
    if (mCursorButtonAccumulator.isRightPressed()) {
        hwState.buttons_down |= GESTURES_BUTTON_RIGHT;
    }
    if (mCursorButtonAccumulator.isBackPressed() || mCursorButtonAccumulator.isSidePressed()) {
        hwState.buttons_down |= GESTURES_BUTTON_BACK;
    }
    if (mCursorButtonAccumulator.isForwardPressed() || mCursorButtonAccumulator.isExtraPressed()) {
        hwState.buttons_down |= GESTURES_BUTTON_FORWARD;
    }

    std::vector<FingerState> fingers;
    for (size_t i = 0; i < mMotionAccumulator.getSlotCount(); i++) {
        MultiTouchMotionAccumulator::Slot slot = mMotionAccumulator.getSlot(i);
        if (slot.isInUse()) {
            FingerState& fingerState = fingers.emplace_back();
            fingerState = {};
            fingerState.touch_major = slot.getTouchMajor();
            fingerState.touch_minor = slot.getTouchMinor();
            fingerState.width_major = slot.getToolMajor();
            fingerState.width_minor = slot.getToolMinor();
            fingerState.pressure = slot.getPressure();
            fingerState.orientation = slot.getOrientation();
            fingerState.position_x = slot.getX();
            fingerState.position_y = slot.getY();
            fingerState.tracking_id = slot.getTrackingId();
        }
    }
    hwState.fingers = fingers.data();
    hwState.finger_cnt = fingers.size();
    hwState.touch_cnt = mTouchButtonAccumulator.getTouchCount();

    mGestureInterpreter->PushHardwareState(&hwState);
    mMotionAccumulator.finishSync();
    mMscTimestamp = 0;
}

} // namespace android
