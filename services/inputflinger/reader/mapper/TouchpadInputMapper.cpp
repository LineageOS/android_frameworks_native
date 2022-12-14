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

#include <chrono>

#include <android/input.h>
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

uint32_t gesturesButtonToMotionEventButton(uint32_t gesturesButton) {
    switch (gesturesButton) {
        case GESTURES_BUTTON_LEFT:
            return AMOTION_EVENT_BUTTON_PRIMARY;
        case GESTURES_BUTTON_MIDDLE:
            return AMOTION_EVENT_BUTTON_TERTIARY;
        case GESTURES_BUTTON_RIGHT:
            return AMOTION_EVENT_BUTTON_SECONDARY;
        case GESTURES_BUTTON_BACK:
            return AMOTION_EVENT_BUTTON_BACK;
        case GESTURES_BUTTON_FORWARD:
            return AMOTION_EVENT_BUTTON_FORWARD;
        default:
            return 0;
    }
}

} // namespace

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext),
        mGestureInterpreter(NewGestureInterpreter(), DeleteGestureInterpreter),
        mPointerController(getContext()->getPointerController(getDeviceId())),
        mTouchButtonAccumulator(deviceContext) {
    mGestureInterpreter->Initialize(GESTURES_DEVCLASS_TOUCHPAD);
    mGestureInterpreter->SetHardwareProperties(createHardwareProperties(deviceContext));
    // Even though we don't explicitly delete copy/move semantics, it's safe to
    // give away a pointer to TouchpadInputMapper here because
    // 1) mGestureInterpreter's lifecycle is determined by TouchpadInputMapper, and
    // 2) TouchpadInputMapper is stored as a unique_ptr and not moved.
    mGestureInterpreter->SetCallback(gestureInterpreterCallback, this);
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

TouchpadInputMapper::~TouchpadInputMapper() {
    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
    }
}

uint32_t TouchpadInputMapper::getSources() const {
    return AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD;
}

std::list<NotifyArgs> TouchpadInputMapper::reset(nsecs_t when) {
    mCursorButtonAccumulator.reset(getDeviceContext());
    mTouchButtonAccumulator.reset();
    mMscTimestamp = 0;

    mButtonState = 0;
    return InputMapper::reset(when);
}

std::list<NotifyArgs> TouchpadInputMapper::process(const RawEvent* rawEvent) {
    std::list<NotifyArgs> out = {};
    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        out = sync(rawEvent->when, rawEvent->readTime);
    }
    if (rawEvent->type == EV_MSC && rawEvent->code == MSC_TIMESTAMP) {
        mMscTimestamp = rawEvent->value;
    }
    mCursorButtonAccumulator.process(rawEvent);
    mMotionAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);
    return out;
}

std::list<NotifyArgs> TouchpadInputMapper::sync(nsecs_t when, nsecs_t readTime) {
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

    mProcessing = true;
    mGestureInterpreter->PushHardwareState(&hwState);
    mProcessing = false;

    std::list<NotifyArgs> out = processGestures(when, readTime);

    mMotionAccumulator.finishSync();
    mMscTimestamp = 0;
    return out;
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
        switch (gesture.type) {
            case kGestureTypeMove:
                out.push_back(handleMove(when, readTime, gesture));
                break;
            case kGestureTypeButtonsChange:
                out += handleButtonsChange(when, readTime, gesture);
                break;
            default:
                // TODO(b/251196347): handle more gesture types.
                break;
        }
    }
    mGesturesToProcess.clear();
    return out;
}

NotifyArgs TouchpadInputMapper::handleMove(nsecs_t when, nsecs_t readTime, const Gesture& gesture) {
    PointerProperties props;
    props.clear();
    props.id = 0;
    props.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
    mPointerController->move(gesture.details.move.dx, gesture.details.move.dy);
    mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
    float xCursorPosition, yCursorPosition;
    mPointerController->getPosition(&xCursorPosition, &yCursorPosition);

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, gesture.details.move.dx);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, gesture.details.move.dy);
    const bool down = isPointerDown(mButtonState);
    coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, down ? 1.0f : 0.0f);

    const int32_t action = down ? AMOTION_EVENT_ACTION_MOVE : AMOTION_EVENT_ACTION_HOVER_MOVE;
    return makeMotionArgs(when, readTime, action, /* actionButton= */ 0, mButtonState,
                          /* pointerCount= */ 1, &props, &coords, xCursorPosition, yCursorPosition);
}

std::list<NotifyArgs> TouchpadInputMapper::handleButtonsChange(nsecs_t when, nsecs_t readTime,
                                                               const Gesture& gesture) {
    std::list<NotifyArgs> out = {};

    mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
    mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);

    PointerProperties props;
    props.clear();
    props.id = 0;
    props.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    float xCursorPosition, yCursorPosition;
    mPointerController->getPosition(&xCursorPosition, &yCursorPosition);

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0);
    const uint32_t buttonsPressed = gesture.details.buttons.down;
    bool pointerDown = isPointerDown(mButtonState) ||
            buttonsPressed &
                    (GESTURES_BUTTON_LEFT | GESTURES_BUTTON_MIDDLE | GESTURES_BUTTON_RIGHT);
    coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, pointerDown ? 1.0f : 0.0f);

    uint32_t newButtonState = mButtonState;
    std::list<NotifyArgs> pressEvents = {};
    for (uint32_t button = 1; button <= GESTURES_BUTTON_FORWARD; button <<= 1) {
        if (buttonsPressed & button) {
            uint32_t actionButton = gesturesButtonToMotionEventButton(button);
            newButtonState |= actionButton;
            pressEvents.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_BUTTON_PRESS,
                                                 actionButton, newButtonState,
                                                 /* pointerCount= */ 1, &props, &coords,
                                                 xCursorPosition, yCursorPosition));
        }
    }
    if (!isPointerDown(mButtonState) && isPointerDown(newButtonState)) {
        mDownTime = when;
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_DOWN,
                                     /* actionButton= */ 0, newButtonState, /* pointerCount= */ 1,
                                     &props, &coords, xCursorPosition, yCursorPosition));
    }
    out.splice(out.end(), pressEvents);

    // The same button may be in both down and up in the same gesture, in which case we should treat
    // it as having gone down and then up. So, we treat a single button change gesture as two state
    // changes: a set of buttons going down, followed by a set of buttons going up.
    mButtonState = newButtonState;

    const uint32_t buttonsReleased = gesture.details.buttons.up;
    for (uint32_t button = 1; button <= GESTURES_BUTTON_FORWARD; button <<= 1) {
        if (buttonsReleased & button) {
            uint32_t actionButton = gesturesButtonToMotionEventButton(button);
            newButtonState &= ~actionButton;
            out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                                         actionButton, newButtonState, /* pointerCount= */ 1,
                                         &props, &coords, xCursorPosition, yCursorPosition));
        }
    }
    if (isPointerDown(mButtonState) && !isPointerDown(newButtonState)) {
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 0.0f);
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_UP, /* actionButton= */ 0,
                                     newButtonState, /* pointerCount= */ 1, &props, &coords,
                                     xCursorPosition, yCursorPosition));
    }
    mButtonState = newButtonState;
    return out;
}

NotifyMotionArgs TouchpadInputMapper::makeMotionArgs(nsecs_t when, nsecs_t readTime, int32_t action,
                                                     int32_t actionButton, int32_t buttonState,
                                                     uint32_t pointerCount,
                                                     const PointerProperties* pointerProperties,
                                                     const PointerCoords* pointerCoords,
                                                     float xCursorPosition, float yCursorPosition) {
    // TODO(b/260226362): consider what the appropriate source for these events is.
    const uint32_t source = AINPUT_SOURCE_MOUSE;

    return NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(), source,
                            mPointerController->getDisplayId(), /* policyFlags= */ 0, action,
                            /* actionButton= */ actionButton, /* flags= */ 0,
                            getContext()->getGlobalMetaState(), buttonState,
                            MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount,
                            pointerProperties, pointerCoords,
                            /* xPrecision= */ 1.0f, /* yPrecision= */ 1.0f, xCursorPosition,
                            yCursorPosition, /* downTime= */ mDownTime, /* videoFrames= */ {});
}

} // namespace android
