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

#include <optional>
#include <sstream>

#include <android-base/stringprintf.h>
#include <com_android_input_flags.h>
#include <ftl/enum.h>
#include <linux/input-event-codes.h>
#include <log/log_main.h>
#include <ui/FloatRect.h>

#include "TouchCursorInputMapperCommon.h"
#include "input/Input.h"

namespace input_flags = com::android::input::flags;

namespace android {

namespace {

// This will disable the tap to click while the user is typing on a physical keyboard
const bool ENABLE_TOUCHPAD_PALM_REJECTION = input_flags::enable_touchpad_typing_palm_rejection();

// In addition to v1, v2 will also cancel ongoing move gestures while typing and add delay in
// re-enabling the tap to click.
const bool ENABLE_TOUCHPAD_PALM_REJECTION_V2 =
        input_flags::enable_v2_touchpad_typing_palm_rejection();

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

GestureConverter::GestureConverter(InputReaderContext& readerContext,
                                   const InputDeviceContext& deviceContext, int32_t deviceId)
      : mDeviceId(deviceId),
        mReaderContext(readerContext),
        mPointerController(readerContext.getPointerController(deviceId)),
        mEnableFlingStop(input_flags::enable_touchpad_fling_stop()) {
    deviceContext.getAbsoluteAxisInfo(ABS_MT_POSITION_X, &mXAxisInfo);
    deviceContext.getAbsoluteAxisInfo(ABS_MT_POSITION_Y, &mYAxisInfo);
}

std::string GestureConverter::dump() const {
    std::stringstream out;
    out << "Orientation: " << ftl::enum_string(mOrientation) << "\n";
    out << "Axis info:\n";
    out << "  X: " << mXAxisInfo << "\n";
    out << "  Y: " << mYAxisInfo << "\n";
    out << StringPrintf("Button state: 0x%08x\n", mButtonState);
    out << "Down time: " << mDownTime << "\n";
    out << "Current classification: " << ftl::enum_string(mCurrentClassification) << "\n";
    out << "Is hovering: " << mIsHovering << "\n";
    out << "Enable Tap Timestamp: " << mWhenToEnableTapToClick << "\n";
    return out.str();
}

std::list<NotifyArgs> GestureConverter::reset(nsecs_t when) {
    std::list<NotifyArgs> out;
    switch (mCurrentClassification) {
        case MotionClassification::TWO_FINGER_SWIPE:
            out += endScroll(when, when);
            break;
        case MotionClassification::MULTI_FINGER_SWIPE:
            out += handleMultiFingerSwipeLift(when, when);
            break;
        case MotionClassification::PINCH:
            out += endPinch(when, when);
            break;
        case MotionClassification::NONE:
            // When a button is pressed, the Gestures library always ends the current gesture,
            // so we don't have to worry about the case where buttons need to be lifted during a
            // pinch or swipe.
            if (mButtonState) {
                out += releaseAllButtons(when, when);
            }
            break;
        default:
            break;
    }
    mCurrentClassification = MotionClassification::NONE;
    mDownTime = 0;
    return out;
}

void GestureConverter::populateMotionRanges(InputDeviceInfo& info) const {
    info.addMotionRange(AMOTION_EVENT_AXIS_PRESSURE, SOURCE, 0.0f, 1.0f, 0, 0, 0);

    if (!mBoundsInLogicalDisplay.isEmpty()) {
        info.addMotionRange(AMOTION_EVENT_AXIS_X, SOURCE, mBoundsInLogicalDisplay.left,
                            mBoundsInLogicalDisplay.right, 0, 0, 0);
        info.addMotionRange(AMOTION_EVENT_AXIS_Y, SOURCE, mBoundsInLogicalDisplay.top,
                            mBoundsInLogicalDisplay.bottom, 0, 0, 0);
    }

    info.addMotionRange(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET, SOURCE, -1.0f, 1.0f, 0, 0, 0);
    info.addMotionRange(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET, SOURCE, -1.0f, 1.0f, 0, 0, 0);

    // The other axes that can be reported don't have ranges that are easy to define. RELATIVE_X/Y
    // and GESTURE_SCROLL_X/Y_DISTANCE are the result of acceleration functions being applied to
    // finger movements, so their maximum values can't simply be derived from the size of the
    // touchpad. GESTURE_PINCH_SCALE_FACTOR's maximum value depends on the minimum finger separation
    // that the pad can report, which cannot be determined from its raw axis information. (Assuming
    // a minimum finger separation of 1 unit would let us calculate a theoretical maximum, but it
    // would be orders of magnitude too high, so probably not very useful.)
}

std::list<NotifyArgs> GestureConverter::handleGesture(nsecs_t when, nsecs_t readTime,
                                                      nsecs_t gestureStartTime,
                                                      const Gesture& gesture) {
    if (!mDisplayId) {
        // Ignore gestures when there is no target display configured.
        return {};
    }

    switch (gesture.type) {
        case kGestureTypeMove:
            return handleMove(when, readTime, gestureStartTime, gesture);
        case kGestureTypeButtonsChange:
            return handleButtonsChange(when, readTime, gesture);
        case kGestureTypeScroll:
            return handleScroll(when, readTime, gesture);
        case kGestureTypeFling:
            return handleFling(when, readTime, gestureStartTime, gesture);
        case kGestureTypeSwipe:
            return handleMultiFingerSwipe(when, readTime, 3, gesture.details.swipe.dx,
                                          gesture.details.swipe.dy);
        case kGestureTypeFourFingerSwipe:
            return handleMultiFingerSwipe(when, readTime, 4, gesture.details.four_finger_swipe.dx,
                                          gesture.details.four_finger_swipe.dy);
        case kGestureTypeSwipeLift:
        case kGestureTypeFourFingerSwipeLift:
            return handleMultiFingerSwipeLift(when, readTime);
        case kGestureTypePinch:
            return handlePinch(when, readTime, gesture);
        default:
            return {};
    }
}

std::list<NotifyArgs> GestureConverter::handleMove(nsecs_t when, nsecs_t readTime,
                                                   nsecs_t gestureStartTime,
                                                   const Gesture& gesture) {
    float deltaX = gesture.details.move.dx;
    float deltaY = gesture.details.move.dy;
    const auto [oldXCursorPosition, oldYCursorPosition] = mPointerController->getPosition();
    if (ENABLE_TOUCHPAD_PALM_REJECTION_V2) {
        bool wasHoverCancelled = mIsHoverCancelled;
        // Gesture will be cancelled if it started before the user started typing and
        // there is a active IME connection.
        mIsHoverCancelled = gestureStartTime <= mReaderContext.getLastKeyDownTimestamp() &&
                mReaderContext.getPolicy()->isInputMethodConnectionActive();

        if (!wasHoverCancelled && mIsHoverCancelled) {
            // This is the first event of the cancelled gesture, we won't return because we need to
            // generate a HOVER_EXIT event
            mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
            return exitHover(when, readTime, oldXCursorPosition, oldYCursorPosition);
        } else if (mIsHoverCancelled) {
            return {};
        }
    }

    rotateDelta(mOrientation, &deltaX, &deltaY);

    // Update the cursor, and enable tap to click if the gesture is not cancelled
    if (!mIsHoverCancelled) {
        // handleFling calls hoverMove with zero delta on FLING_TAP_DOWN. Don't enable tap to click
        // for this case as subsequent handleButtonsChange may choose to ignore this tap.
        if ((ENABLE_TOUCHPAD_PALM_REJECTION || ENABLE_TOUCHPAD_PALM_REJECTION_V2) &&
            (std::abs(deltaX) > 0 || std::abs(deltaY) > 0)) {
            enableTapToClick(when);
        }
        mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
        mPointerController->move(deltaX, deltaY);
        mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
    }

    std::list<NotifyArgs> out;
    const bool down = isPointerDown(mButtonState);
    if (!down) {
        out += enterHover(when, readTime, oldXCursorPosition, oldYCursorPosition);
    }
    const auto [newXCursorPosition, newYCursorPosition] = mPointerController->getPosition();

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, newXCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, newYCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, deltaX);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, deltaY);
    coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, down ? 1.0f : 0.0f);

    const int32_t action = down ? AMOTION_EVENT_ACTION_MOVE : AMOTION_EVENT_ACTION_HOVER_MOVE;
    out.push_back(makeMotionArgs(when, readTime, action, /*actionButton=*/0, mButtonState,
                                 /*pointerCount=*/1, &coords, newXCursorPosition,
                                 newYCursorPosition));
    return out;
}

std::list<NotifyArgs> GestureConverter::handleButtonsChange(nsecs_t when, nsecs_t readTime,
                                                            const Gesture& gesture) {
    std::list<NotifyArgs> out = {};

    mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
    mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);

    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0);

    // V2 palm rejection should override V1
    if (ENABLE_TOUCHPAD_PALM_REJECTION_V2) {
        enableTapToClick(when);
        if (gesture.details.buttons.is_tap && when <= mWhenToEnableTapToClick) {
            // return early to prevent this tap
            return out;
        }
    } else if (ENABLE_TOUCHPAD_PALM_REJECTION && mReaderContext.isPreventingTouchpadTaps()) {
        enableTapToClick(when);
        if (gesture.details.buttons.is_tap) {
            // return early to prevent this tap
            return out;
        }
    }

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
                                                 /*pointerCount=*/1, &coords, xCursorPosition,
                                                 yCursorPosition));
        }
    }
    if (!isPointerDown(mButtonState) && isPointerDown(newButtonState)) {
        mDownTime = when;
        out += exitHover(when, readTime, xCursorPosition, yCursorPosition);
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_DOWN,
                                     /* actionButton= */ 0, newButtonState, /* pointerCount= */ 1,
                                     &coords, xCursorPosition, yCursorPosition));
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
                                         &coords, xCursorPosition, yCursorPosition));
        }
    }
    if (isPointerDown(mButtonState) && !isPointerDown(newButtonState)) {
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 0.0f);
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_UP, /* actionButton= */ 0,
                                     newButtonState, /* pointerCount= */ 1, &coords,
                                     xCursorPosition, yCursorPosition));
        mButtonState = newButtonState;
        out += enterHover(when, readTime, xCursorPosition, yCursorPosition);
    }
    mButtonState = newButtonState;
    return out;
}

std::list<NotifyArgs> GestureConverter::releaseAllButtons(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0);
    const bool pointerDown = isPointerDown(mButtonState);
    coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, pointerDown ? 1.0f : 0.0f);
    uint32_t newButtonState = mButtonState;
    for (uint32_t button = AMOTION_EVENT_BUTTON_PRIMARY; button <= AMOTION_EVENT_BUTTON_FORWARD;
         button <<= 1) {
        if (mButtonState & button) {
            newButtonState &= ~button;
            out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                                         button, newButtonState, /*pointerCount=*/1, &coords,
                                         xCursorPosition, yCursorPosition));
        }
    }
    mButtonState = 0;
    if (pointerDown) {
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 0.0f);
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_UP, /*actionButton=*/0,
                                     mButtonState, /*pointerCount=*/1, &coords, xCursorPosition,
                                     yCursorPosition));
        out += enterHover(when, readTime, xCursorPosition, yCursorPosition);
    }
    return out;
}

std::list<NotifyArgs> GestureConverter::handleScroll(nsecs_t when, nsecs_t readTime,
                                                     const Gesture& gesture) {
    std::list<NotifyArgs> out;
    PointerCoords& coords = mFakeFingerCoords[0];
    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();
    if (mCurrentClassification != MotionClassification::TWO_FINGER_SWIPE) {
        out += exitHover(when, readTime, xCursorPosition, yCursorPosition);

        mCurrentClassification = MotionClassification::TWO_FINGER_SWIPE;
        coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
        mDownTime = when;
        NotifyMotionArgs args =
                makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_DOWN, /* actionButton= */ 0,
                               mButtonState, /* pointerCount= */ 1, mFakeFingerCoords.data(),
                               xCursorPosition, yCursorPosition);
        args.flags |= AMOTION_EVENT_FLAG_IS_GENERATED_GESTURE;
        out.push_back(args);
    }
    float deltaX = gesture.details.scroll.dx;
    float deltaY = gesture.details.scroll.dy;
    rotateDelta(mOrientation, &deltaX, &deltaY);

    coords.setAxisValue(AMOTION_EVENT_AXIS_X, coords.getAxisValue(AMOTION_EVENT_AXIS_X) + deltaX);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, coords.getAxisValue(AMOTION_EVENT_AXIS_Y) + deltaY);
    // TODO(b/262876643): set AXIS_GESTURE_{X,Y}_OFFSET.
    coords.setAxisValue(AMOTION_EVENT_AXIS_GESTURE_SCROLL_X_DISTANCE, -gesture.details.scroll.dx);
    coords.setAxisValue(AMOTION_EVENT_AXIS_GESTURE_SCROLL_Y_DISTANCE, -gesture.details.scroll.dy);
    NotifyMotionArgs args =
            makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_MOVE, /* actionButton= */ 0,
                           mButtonState, /* pointerCount= */ 1, mFakeFingerCoords.data(),
                           xCursorPosition, yCursorPosition);
    args.flags |= AMOTION_EVENT_FLAG_IS_GENERATED_GESTURE;
    out.push_back(args);
    return out;
}

std::list<NotifyArgs> GestureConverter::handleFling(nsecs_t when, nsecs_t readTime,
                                                    nsecs_t gestureStartTime,
                                                    const Gesture& gesture) {
    switch (gesture.details.fling.fling_state) {
        case GESTURES_FLING_START:
            if (mCurrentClassification == MotionClassification::TWO_FINGER_SWIPE) {
                // We don't actually want to use the gestures library's fling velocity values (to
                // ensure consistency between touchscreen and touchpad flings), so we're just using
                // the "start fling" gestures as a marker for the end of a two-finger scroll
                // gesture.
                mFlingMayBeInProgress = true;
                return endScroll(when, readTime);
            }
            break;
        case GESTURES_FLING_TAP_DOWN:
            if (mCurrentClassification == MotionClassification::NONE) {
                if (mEnableFlingStop && mFlingMayBeInProgress) {
                    // The user has just touched the pad again after ending a two-finger scroll
                    // motion, which might have started a fling. We want to stop the fling, but
                    // unfortunately there's currently no API for doing so. Instead, send and
                    // immediately cancel a fake finger to cause the scrolling to stop and hopefully
                    // avoid side effects (e.g. activation of UI elements).
                    // TODO(b/326056750): add an API for fling stops.
                    mFlingMayBeInProgress = false;
                    const auto [xCursorPosition, yCursorPosition] =
                            mPointerController->getPosition();
                    PointerCoords coords;
                    coords.clear();
                    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
                    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
                    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0);
                    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0);

                    std::list<NotifyArgs> out;
                    mDownTime = when;
                    out += exitHover(when, readTime, xCursorPosition, yCursorPosition);
                    // TODO(b/281106755): add a MotionClassification value for fling stops.
                    out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_DOWN,
                                                 /*actionButton=*/0, /*buttonState=*/0,
                                                 /*pointerCount=*/1, &coords, xCursorPosition,
                                                 yCursorPosition));
                    out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_CANCEL,
                                                 /*actionButton=*/0, /*buttonState=*/0,
                                                 /*pointerCount=*/1, &coords, xCursorPosition,
                                                 yCursorPosition));
                    out += enterHover(when, readTime, xCursorPosition, yCursorPosition);
                    return out;
                } else {
                    // Use the tap down state of a fling gesture as an indicator that a contact
                    // has been initiated with the touchpad. We treat this as a move event with zero
                    // magnitude, which will also result in the pointer icon being updated.
                    // TODO(b/282023644): Add a signal in libgestures for when a stable contact has
                    //  been initiated with a touchpad.
                    return handleMove(when, readTime, gestureStartTime,
                                      Gesture(kGestureMove, gesture.start_time, gesture.end_time,
                                              /*dx=*/0.f,
                                              /*dy=*/0.f));
                }
            }
            break;
        default:
            break;
    }

    return {};
}

std::list<NotifyArgs> GestureConverter::endScroll(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_SCROLL_X_DISTANCE, 0);
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_SCROLL_Y_DISTANCE, 0);
    NotifyMotionArgs args =
            makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_UP, /* actionButton= */ 0,
                           mButtonState, /* pointerCount= */ 1, mFakeFingerCoords.data(),
                           xCursorPosition, yCursorPosition);
    args.flags |= AMOTION_EVENT_FLAG_IS_GENERATED_GESTURE;
    out.push_back(args);
    mCurrentClassification = MotionClassification::NONE;
    out += enterHover(when, readTime, xCursorPosition, yCursorPosition);
    return out;
}

[[nodiscard]] std::list<NotifyArgs> GestureConverter::handleMultiFingerSwipe(nsecs_t when,
                                                                             nsecs_t readTime,
                                                                             uint32_t fingerCount,
                                                                             float dx, float dy) {
    std::list<NotifyArgs> out = {};

    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();
    if (mCurrentClassification != MotionClassification::MULTI_FINGER_SWIPE) {
        // If the user changes the number of fingers mid-way through a swipe (e.g. they start with
        // three and then put a fourth finger down), the gesture library will treat it as two
        // separate swipes with an appropriate lift event between them, so we don't have to worry
        // about the finger count changing mid-swipe.

        out += exitHover(when, readTime, xCursorPosition, yCursorPosition);

        mCurrentClassification = MotionClassification::MULTI_FINGER_SWIPE;

        mSwipeFingerCount = fingerCount;

        constexpr float FAKE_FINGER_SPACING = 100;
        float xCoord = xCursorPosition - FAKE_FINGER_SPACING * (mSwipeFingerCount - 1) / 2;
        for (size_t i = 0; i < mSwipeFingerCount; i++) {
            PointerCoords& coords = mFakeFingerCoords[i];
            coords.clear();
            coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCoord);
            coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
            coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
            xCoord += FAKE_FINGER_SPACING;
        }

        mDownTime = when;
        mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_SWIPE_FINGER_COUNT,
                                          fingerCount);
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_DOWN,
                                     /* actionButton= */ 0, mButtonState, /* pointerCount= */ 1,
                                     mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
        for (size_t i = 1; i < mSwipeFingerCount; i++) {
            out.push_back(makeMotionArgs(when, readTime,
                                         AMOTION_EVENT_ACTION_POINTER_DOWN |
                                                 (i << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                                         /* actionButton= */ 0, mButtonState,
                                         /* pointerCount= */ i + 1, mFakeFingerCoords.data(),
                                         xCursorPosition, yCursorPosition));
        }
    }
    float rotatedDeltaX = dx, rotatedDeltaY = -dy;
    rotateDelta(mOrientation, &rotatedDeltaX, &rotatedDeltaY);
    for (size_t i = 0; i < mSwipeFingerCount; i++) {
        PointerCoords& coords = mFakeFingerCoords[i];
        coords.setAxisValue(AMOTION_EVENT_AXIS_X,
                            coords.getAxisValue(AMOTION_EVENT_AXIS_X) + rotatedDeltaX);
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y,
                            coords.getAxisValue(AMOTION_EVENT_AXIS_Y) + rotatedDeltaY);
    }
    float xOffset = dx / (mXAxisInfo.maxValue - mXAxisInfo.minValue);
    float yOffset = -dy / (mYAxisInfo.maxValue - mYAxisInfo.minValue);
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET, xOffset);
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET, yOffset);
    out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_MOVE, /* actionButton= */ 0,
                                 mButtonState, /* pointerCount= */ mSwipeFingerCount,
                                 mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
    return out;
}

[[nodiscard]] std::list<NotifyArgs> GestureConverter::handleMultiFingerSwipeLift(nsecs_t when,
                                                                                 nsecs_t readTime) {
    std::list<NotifyArgs> out = {};
    if (mCurrentClassification != MotionClassification::MULTI_FINGER_SWIPE) {
        return out;
    }
    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET, 0);
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET, 0);

    for (size_t i = mSwipeFingerCount; i > 1; i--) {
        out.push_back(makeMotionArgs(when, readTime,
                                     AMOTION_EVENT_ACTION_POINTER_UP |
                                             ((i - 1) << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                                     /* actionButton= */ 0, mButtonState, /* pointerCount= */ i,
                                     mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
    }
    out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_UP,
                                 /* actionButton= */ 0, mButtonState, /* pointerCount= */ 1,
                                 mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_SWIPE_FINGER_COUNT, 0);
    mCurrentClassification = MotionClassification::NONE;
    out += enterHover(when, readTime, xCursorPosition, yCursorPosition);
    mSwipeFingerCount = 0;
    return out;
}

[[nodiscard]] std::list<NotifyArgs> GestureConverter::handlePinch(nsecs_t when, nsecs_t readTime,
                                                                  const Gesture& gesture) {
    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();

    // Pinch gesture phases are reported a little differently from others, in that the same details
    // struct is used for all phases of the gesture, just with different zoom_state values. When
    // zoom_state is START or END, dz will always be 1, so we don't need to move the pointers in
    // those cases.

    if (mCurrentClassification != MotionClassification::PINCH) {
        LOG_ALWAYS_FATAL_IF(gesture.details.pinch.zoom_state != GESTURES_ZOOM_START,
                            "First pinch gesture does not have the START zoom state (%d instead).",
                            gesture.details.pinch.zoom_state);
        std::list<NotifyArgs> out;

        out += exitHover(when, readTime, xCursorPosition, yCursorPosition);

        mCurrentClassification = MotionClassification::PINCH;
        mPinchFingerSeparation = INITIAL_PINCH_SEPARATION_PX;
        mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_PINCH_SCALE_FACTOR, 1.0);
        mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                          xCursorPosition - mPinchFingerSeparation / 2);
        mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
        mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
        mFakeFingerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_X,
                                          xCursorPosition + mPinchFingerSeparation / 2);
        mFakeFingerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
        mFakeFingerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
        mDownTime = when;
        out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_DOWN,
                                     /* actionButton= */ 0, mButtonState, /* pointerCount= */ 1,
                                     mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
        out.push_back(makeMotionArgs(when, readTime,
                                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                                             1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT,
                                     /* actionButton= */ 0, mButtonState, /* pointerCount= */ 2,
                                     mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
        return out;
    }

    if (gesture.details.pinch.zoom_state == GESTURES_ZOOM_END) {
        return endPinch(when, readTime);
    }

    mPinchFingerSeparation *= gesture.details.pinch.dz;
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_PINCH_SCALE_FACTOR,
                                      gesture.details.pinch.dz);
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                      xCursorPosition - mPinchFingerSeparation / 2);
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    mFakeFingerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_X,
                                      xCursorPosition + mPinchFingerSeparation / 2);
    mFakeFingerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    return {makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_MOVE, /*actionButton=*/0,
                           mButtonState, /*pointerCount=*/2, mFakeFingerCoords.data(),
                           xCursorPosition, yCursorPosition)};
}

std::list<NotifyArgs> GestureConverter::endPinch(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    const auto [xCursorPosition, yCursorPosition] = mPointerController->getPosition();

    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_PINCH_SCALE_FACTOR, 1.0);
    out.push_back(makeMotionArgs(when, readTime,
                                 AMOTION_EVENT_ACTION_POINTER_UP |
                                         1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT,
                                 /*actionButton=*/0, mButtonState, /*pointerCount=*/2,
                                 mFakeFingerCoords.data(), xCursorPosition, yCursorPosition));
    out.push_back(makeMotionArgs(when, readTime, AMOTION_EVENT_ACTION_UP, /*actionButton=*/0,
                                 mButtonState, /*pointerCount=*/1, mFakeFingerCoords.data(),
                                 xCursorPosition, yCursorPosition));
    mFakeFingerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_GESTURE_PINCH_SCALE_FACTOR, 0);
    mCurrentClassification = MotionClassification::NONE;
    out += enterHover(when, readTime, xCursorPosition, yCursorPosition);
    return out;
}

std::list<NotifyArgs> GestureConverter::enterHover(nsecs_t when, nsecs_t readTime,
                                                   float xCursorPosition, float yCursorPosition) {
    if (!mIsHovering) {
        mIsHovering = true;
        return {makeHoverEvent(when, readTime, AMOTION_EVENT_ACTION_HOVER_ENTER, xCursorPosition,
                               yCursorPosition)};
    } else {
        return {};
    }
}

std::list<NotifyArgs> GestureConverter::exitHover(nsecs_t when, nsecs_t readTime,
                                                  float xCursorPosition, float yCursorPosition) {
    if (mIsHovering) {
        mIsHovering = false;
        return {makeHoverEvent(when, readTime, AMOTION_EVENT_ACTION_HOVER_EXIT, xCursorPosition,
                               yCursorPosition)};
    } else {
        return {};
    }
}

NotifyMotionArgs GestureConverter::makeHoverEvent(nsecs_t when, nsecs_t readTime, int32_t action,
                                                  float xCursorPosition, float yCursorPosition) {
    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0);
    return makeMotionArgs(when, readTime, action, /*actionButton=*/0, mButtonState,
                          /*pointerCount=*/1, &coords, xCursorPosition, yCursorPosition);
}

NotifyMotionArgs GestureConverter::makeMotionArgs(nsecs_t when, nsecs_t readTime, int32_t action,
                                                  int32_t actionButton, int32_t buttonState,
                                                  uint32_t pointerCount,
                                                  const PointerCoords* pointerCoords,
                                                  float xCursorPosition, float yCursorPosition) {
    return {mReaderContext.getNextId(),
            when,
            readTime,
            mDeviceId,
            SOURCE,
            *mDisplayId,
            /* policyFlags= */ POLICY_FLAG_WAKE,
            action,
            /* actionButton= */ actionButton,
            /* flags= */ action == AMOTION_EVENT_ACTION_CANCEL ? AMOTION_EVENT_FLAG_CANCELED : 0,
            mReaderContext.getGlobalMetaState(),
            buttonState,
            mCurrentClassification,
            AMOTION_EVENT_EDGE_FLAG_NONE,
            pointerCount,
            mFingerProps.data(),
            pointerCoords,
            /* xPrecision= */ 1.0f,
            /* yPrecision= */ 1.0f,
            xCursorPosition,
            yCursorPosition,
            /* downTime= */ mDownTime,
            /* videoFrames= */ {}};
}

void GestureConverter::enableTapToClick(nsecs_t when) {
    if (mReaderContext.isPreventingTouchpadTaps()) {
        mWhenToEnableTapToClick = when + TAP_ENABLE_DELAY_NANOS.count();
        mReaderContext.setPreventingTouchpadTaps(false);
    }
}

} // namespace android
