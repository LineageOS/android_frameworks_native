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

#include <android/input.h>
#include <linux/input-event-codes.h>
#include <log/log_main.h>
#include "TouchCursorInputMapperCommon.h"
#include "TouchpadInputMapper.h"

namespace android {

namespace {

short getMaxTouchCount(const InputDeviceContext& context) {
    if (context.hasScanCode(BTN_TOOL_QUINTTAP)) return 5;
    if (context.hasScanCode(BTN_TOOL_QUADTAP)) return 4;
    if (context.hasScanCode(BTN_TOOL_TRIPLETAP)) return 3;
    if (context.hasScanCode(BTN_TOOL_DOUBLETAP)) return 2;
    if (context.hasScanCode(BTN_TOOL_FINGER)) return 1;
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

void gestureInterpreterCallback(void* clientData, const Gesture* gesture) {
    TouchpadInputMapper* mapper = static_cast<TouchpadInputMapper*>(clientData);
    mapper->consumeGesture(gesture);
}

} // namespace

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext),
        mGestureInterpreter(NewGestureInterpreter(), DeleteGestureInterpreter),
        mPointerController(getContext()->getPointerController(getDeviceId())),
        mStateConverter(deviceContext),
        mGestureConverter(*getContext(), getDeviceId()) {
    mGestureInterpreter->Initialize(GESTURES_DEVCLASS_TOUCHPAD);
    mGestureInterpreter->SetHardwareProperties(createHardwareProperties(deviceContext));
    // Even though we don't explicitly delete copy/move semantics, it's safe to
    // give away a pointer to TouchpadInputMapper here because
    // 1) mGestureInterpreter's lifecycle is determined by TouchpadInputMapper, and
    // 2) TouchpadInputMapper is stored as a unique_ptr and not moved.
    mGestureInterpreter->SetCallback(gestureInterpreterCallback, this);
    // TODO(b/251196347): set a property provider, so we can change gesture properties.
    // TODO(b/251196347): set a timer provider, so the library can use timers.
}

TouchpadInputMapper::~TouchpadInputMapper() {
    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
    }
}

uint32_t TouchpadInputMapper::getSources() const {
    return AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD;
}

std::list<NotifyArgs> TouchpadInputMapper::reset(nsecs_t when) {
    mStateConverter.reset();
    mGestureConverter.reset();
    return InputMapper::reset(when);
}

std::list<NotifyArgs> TouchpadInputMapper::process(const RawEvent* rawEvent) {
    std::optional<SelfContainedHardwareState> state = mStateConverter.processRawEvent(rawEvent);
    if (state) {
        return sendHardwareState(rawEvent->when, rawEvent->readTime, *state);
    } else {
        return {};
    }
}

std::list<NotifyArgs> TouchpadInputMapper::sendHardwareState(nsecs_t when, nsecs_t readTime,
                                                             SelfContainedHardwareState schs) {
    mProcessing = true;
    mGestureInterpreter->PushHardwareState(&schs.state);
    mProcessing = false;

    return processGestures(when, readTime);
}

void TouchpadInputMapper::consumeGesture(const Gesture* gesture) {
    ALOGD("Gesture ready: %s", gesture->String().c_str());
    if (!mProcessing) {
        ALOGE("Received gesture outside of the normal processing flow; ignoring it.");
        return;
    }
    mGesturesToProcess.push_back(*gesture);
}

std::list<NotifyArgs> TouchpadInputMapper::processGestures(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out = {};
    for (Gesture& gesture : mGesturesToProcess) {
        out += mGestureConverter.handleGesture(when, readTime, gesture);
    }
    mGesturesToProcess.clear();
    return out;
}

} // namespace android
