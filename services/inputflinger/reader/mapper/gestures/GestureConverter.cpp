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

#include "gestures/GestureConverter.h"

#include <android/input.h>

#include "TouchCursorInputMapperCommon.h"
#include "input/Input.h"

namespace android {

namespace {

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

GestureConverter::GestureConverter(InputReaderContext& readerContext, int32_t deviceId)
      : mDeviceId(deviceId),
        mReaderContext(readerContext),
        mPointerController(readerContext.getPointerController(deviceId)) {}

void GestureConverter::reset() {
    mButtonState = 0;
}

std::list<NotifyArgs> GestureConverter::handleGesture(nsecs_t when, nsecs_t readTime,
                                                      const Gesture& gesture) {
    switch (gesture.type) {
        case kGestureTypeMove:
            return {handleMove(when, readTime, gesture)};
        case kGestureTypeButtonsChange:
            return handleButtonsChange(when, readTime, gesture);
        default:
            // TODO(b/251196347): handle more gesture types.
            return {};
    }
}

NotifyArgs GestureConverter::handleMove(nsecs_t when, nsecs_t readTime, const Gesture& gesture) {
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

std::list<NotifyArgs> GestureConverter::handleButtonsChange(nsecs_t when, nsecs_t readTime,
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

NotifyMotionArgs GestureConverter::makeMotionArgs(nsecs_t when, nsecs_t readTime, int32_t action,
                                                  int32_t actionButton, int32_t buttonState,
                                                  uint32_t pointerCount,
                                                  const PointerProperties* pointerProperties,
                                                  const PointerCoords* pointerCoords,
                                                  float xCursorPosition, float yCursorPosition) {
    // TODO(b/260226362): consider what the appropriate source for these events is.
    const uint32_t source = AINPUT_SOURCE_MOUSE;

    return NotifyMotionArgs(mReaderContext.getNextId(), when, readTime, mDeviceId, source,
                            mPointerController->getDisplayId(), /* policyFlags= */ 0, action,
                            /* actionButton= */ actionButton, /* flags= */ 0,
                            mReaderContext.getGlobalMetaState(), buttonState,
                            MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount,
                            pointerProperties, pointerCoords,
                            /* xPrecision= */ 1.0f, /* yPrecision= */ 1.0f, xCursorPosition,
                            yCursorPosition, /* downTime= */ mDownTime, /* videoFrames= */ {});
}

} // namespace android
