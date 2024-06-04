/*
 * Copyright (C) 2019 The Android Open Source Project
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

// clang-format off
#include "../Macros.h"
// clang-format on

#include "CursorInputMapper.h"

#include <optional>

#include <com_android_input_flags.h>
#include <ftl/enum.h>
#include <input/AccelerationCurve.h>

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "PointerControllerInterface.h"
#include "TouchCursorInputMapperCommon.h"

#include "input/PrintTools.h"

namespace input_flags = com::android::input::flags;

namespace android {

// The default velocity control parameters that has no effect.
static const VelocityControlParameters FLAT_VELOCITY_CONTROL_PARAMS{};

// --- CursorMotionAccumulator ---

CursorMotionAccumulator::CursorMotionAccumulator() {
    clearRelativeAxes();
}

void CursorMotionAccumulator::reset(InputDeviceContext& deviceContext) {
    clearRelativeAxes();
}

void CursorMotionAccumulator::clearRelativeAxes() {
    mRelX = 0;
    mRelY = 0;
}

void CursorMotionAccumulator::process(const RawEvent& rawEvent) {
    if (rawEvent.type == EV_REL) {
        switch (rawEvent.code) {
            case REL_X:
                mRelX = rawEvent.value;
                break;
            case REL_Y:
                mRelY = rawEvent.value;
                break;
        }
    }
}

void CursorMotionAccumulator::finishSync() {
    clearRelativeAxes();
}

// --- CursorInputMapper ---

CursorInputMapper::CursorInputMapper(InputDeviceContext& deviceContext,
                                     const InputReaderConfiguration& readerConfig)
      : InputMapper(deviceContext, readerConfig),
        mLastEventTime(std::numeric_limits<nsecs_t>::min()),
        mEnableNewMousePointerBallistics(input_flags::enable_new_mouse_pointer_ballistics()) {}

uint32_t CursorInputMapper::getSources() const {
    return mSource;
}

void CursorInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);

    if (mParameters.mode == Parameters::Mode::POINTER) {
        if (!mBoundsInLogicalDisplay.isEmpty()) {
            info.addMotionRange(AMOTION_EVENT_AXIS_X, mSource, mBoundsInLogicalDisplay.left,
                                mBoundsInLogicalDisplay.right, 0.0f, 0.0f, 0.0f);
            info.addMotionRange(AMOTION_EVENT_AXIS_Y, mSource, mBoundsInLogicalDisplay.top,
                                mBoundsInLogicalDisplay.bottom, 0.0f, 0.0f, 0.0f);
        }
    } else {
        info.addMotionRange(AMOTION_EVENT_AXIS_X, mSource, -1.0f, 1.0f, 0.0f, mXScale, 0.0f);
        info.addMotionRange(AMOTION_EVENT_AXIS_Y, mSource, -1.0f, 1.0f, 0.0f, mYScale, 0.0f);
        info.addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_X, mSource, -1.0f, 1.0f, 0.0f, mXScale,
                            0.0f);
        info.addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_Y, mSource, -1.0f, 1.0f, 0.0f, mYScale,
                            0.0f);
    }
    info.addMotionRange(AMOTION_EVENT_AXIS_PRESSURE, mSource, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f);

    if (mCursorScrollAccumulator.haveRelativeVWheel()) {
        info.addMotionRange(AMOTION_EVENT_AXIS_VSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }
    if (mCursorScrollAccumulator.haveRelativeHWheel()) {
        info.addMotionRange(AMOTION_EVENT_AXIS_HSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }
}

void CursorInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Cursor Input Mapper:\n";
    dumpParameters(dump);
    dump += StringPrintf(INDENT3 "XScale: %0.3f\n", mXScale);
    dump += StringPrintf(INDENT3 "YScale: %0.3f\n", mYScale);
    dump += StringPrintf(INDENT3 "XPrecision: %0.3f\n", mXPrecision);
    dump += StringPrintf(INDENT3 "YPrecision: %0.3f\n", mYPrecision);
    dump += StringPrintf(INDENT3 "HaveVWheel: %s\n",
                         toString(mCursorScrollAccumulator.haveRelativeVWheel()));
    dump += StringPrintf(INDENT3 "HaveHWheel: %s\n",
                         toString(mCursorScrollAccumulator.haveRelativeHWheel()));
    dump += StringPrintf(INDENT3 "WheelYVelocityControlParameters: %s",
                         mWheelYVelocityControl.getParameters().dump().c_str());
    dump += StringPrintf(INDENT3 "WheelXVelocityControlParameters: %s",
                         mWheelXVelocityControl.getParameters().dump().c_str());
    dump += StringPrintf(INDENT3 "VWheelScale: %0.3f\n", mVWheelScale);
    dump += StringPrintf(INDENT3 "HWheelScale: %0.3f\n", mHWheelScale);
    dump += StringPrintf(INDENT3 "DisplayId: %s\n",
                         toString(mDisplayId, streamableToString).c_str());
    dump += StringPrintf(INDENT3 "Orientation: %s\n", ftl::enum_string(mOrientation).c_str());
    dump += StringPrintf(INDENT3 "ButtonState: 0x%08x\n", mButtonState);
    dump += StringPrintf(INDENT3 "Down: %s\n", toString(isPointerDown(mButtonState)));
    dump += StringPrintf(INDENT3 "DownTime: %" PRId64 "\n", mDownTime);
}

std::list<NotifyArgs> CursorInputMapper::reconfigure(nsecs_t when,
                                                     const InputReaderConfiguration& readerConfig,
                                                     ConfigurationChanges changes) {
    std::list<NotifyArgs> out = InputMapper::reconfigure(when, readerConfig, changes);

    if (!changes.any()) { // first time only
        configureBasicParams();
    }

    const bool configurePointerCapture = !changes.any() ||
            (mParameters.mode != Parameters::Mode::NAVIGATION &&
             changes.test(InputReaderConfiguration::Change::POINTER_CAPTURE));
    if (configurePointerCapture) {
        configureOnPointerCapture(readerConfig);
        out.push_back(NotifyDeviceResetArgs(getContext()->getNextId(), when, getDeviceId()));
    }

    if (!changes.any() || changes.test(InputReaderConfiguration::Change::DISPLAY_INFO) ||
        configurePointerCapture) {
        configureOnChangeDisplayInfo(readerConfig);
    }

    // Pointer speed settings depend on display settings.
    if (!changes.any() || changes.test(InputReaderConfiguration::Change::POINTER_SPEED) ||
        changes.test(InputReaderConfiguration::Change::DISPLAY_INFO) || configurePointerCapture) {
        configureOnChangePointerSpeed(readerConfig);
    }
    return out;
}

CursorInputMapper::Parameters CursorInputMapper::computeParameters(
        const InputDeviceContext& deviceContext) {
    Parameters parameters;
    parameters.mode = Parameters::Mode::POINTER;
    const PropertyMap& config = deviceContext.getConfiguration();
    std::optional<std::string> cursorModeString = config.getString("cursor.mode");
    if (cursorModeString.has_value()) {
        if (*cursorModeString == "navigation") {
            parameters.mode = Parameters::Mode::NAVIGATION;
        } else if (*cursorModeString != "pointer" && *cursorModeString != "default") {
            ALOGW("Invalid value for cursor.mode: '%s'", cursorModeString->c_str());
        }
    }

    parameters.orientationAware = config.getBool("cursor.orientationAware").value_or(false);

    parameters.hasAssociatedDisplay = false;
    if (parameters.mode == Parameters::Mode::POINTER || parameters.orientationAware) {
        parameters.hasAssociatedDisplay = true;
    }
    return parameters;
}

void CursorInputMapper::dumpParameters(std::string& dump) {
    dump += INDENT3 "Parameters:\n";
    dump += StringPrintf(INDENT4 "HasAssociatedDisplay: %s\n",
                         toString(mParameters.hasAssociatedDisplay));
    dump += StringPrintf(INDENT4 "Mode: %s\n", ftl::enum_string(mParameters.mode).c_str());
    dump += StringPrintf(INDENT4 "OrientationAware: %s\n", toString(mParameters.orientationAware));
}

std::list<NotifyArgs> CursorInputMapper::reset(nsecs_t when) {
    mButtonState = 0;
    mDownTime = 0;
    mLastEventTime = std::numeric_limits<nsecs_t>::min();

    mOldPointerVelocityControl.reset();
    mNewPointerVelocityControl.reset();
    mWheelXVelocityControl.reset();
    mWheelYVelocityControl.reset();

    mCursorButtonAccumulator.reset(getDeviceContext());
    mCursorMotionAccumulator.reset(getDeviceContext());
    mCursorScrollAccumulator.reset(getDeviceContext());

    return InputMapper::reset(when);
}

std::list<NotifyArgs> CursorInputMapper::process(const RawEvent& rawEvent) {
    std::list<NotifyArgs> out;
    mCursorButtonAccumulator.process(rawEvent);
    mCursorMotionAccumulator.process(rawEvent);
    mCursorScrollAccumulator.process(rawEvent);

    if (rawEvent.type == EV_SYN && rawEvent.code == SYN_REPORT) {
        const auto [eventTime, readTime] =
                applyBluetoothTimestampSmoothening(getDeviceContext().getDeviceIdentifier(),
                                                   rawEvent.when, rawEvent.readTime,
                                                   mLastEventTime);
        out += sync(eventTime, readTime);
        mLastEventTime = eventTime;
    }
    return out;
}

std::list<NotifyArgs> CursorInputMapper::sync(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    if (!mDisplayId) {
        // Ignore events when there is no target display configured.
        return out;
    }

    int32_t lastButtonState = mButtonState;
    int32_t currentButtonState = mCursorButtonAccumulator.getButtonState();
    mButtonState = currentButtonState;

    bool wasDown = isPointerDown(lastButtonState);
    bool down = isPointerDown(currentButtonState);
    bool downChanged;
    if (!wasDown && down) {
        mDownTime = when;
        downChanged = true;
    } else if (wasDown && !down) {
        downChanged = true;
    } else {
        downChanged = false;
    }
    nsecs_t downTime = mDownTime;
    bool buttonsChanged = currentButtonState != lastButtonState;
    int32_t buttonsPressed = currentButtonState & ~lastButtonState;
    int32_t buttonsReleased = lastButtonState & ~currentButtonState;

    float deltaX = mCursorMotionAccumulator.getRelativeX() * mXScale;
    float deltaY = mCursorMotionAccumulator.getRelativeY() * mYScale;
    bool moved = deltaX != 0 || deltaY != 0;

    // Rotate delta according to orientation.
    rotateDelta(mOrientation, &deltaX, &deltaY);

    // Move the pointer.
    PointerProperties pointerProperties;
    pointerProperties.clear();
    pointerProperties.id = 0;
    pointerProperties.toolType = ToolType::MOUSE;

    PointerCoords pointerCoords;
    pointerCoords.clear();

    float vscroll = mCursorScrollAccumulator.getRelativeVWheel();
    float hscroll = mCursorScrollAccumulator.getRelativeHWheel();
    bool scrolled = vscroll != 0 || hscroll != 0;

    mWheelYVelocityControl.move(when, nullptr, &vscroll);
    mWheelXVelocityControl.move(when, &hscroll, nullptr);

    if (mEnableNewMousePointerBallistics) {
        mNewPointerVelocityControl.move(when, &deltaX, &deltaY);
    } else {
        mOldPointerVelocityControl.move(when, &deltaX, &deltaY);
    }

    float xCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    float yCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    if (mSource == AINPUT_SOURCE_MOUSE) {
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, deltaX);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, deltaY);
    } else {
        // Pointer capture and navigation modes
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_X, deltaX);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, deltaY);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, deltaX);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, deltaY);
    }

    pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, down ? 1.0f : 0.0f);

    // Moving an external trackball or mouse should wake the device.
    // We don't do this for internal cursor devices to prevent them from waking up
    // the device in your pocket.
    // TODO: Use the input device configuration to control this behavior more finely.
    uint32_t policyFlags = 0;
    if ((buttonsPressed || moved || scrolled) && getDeviceContext().isExternal()) {
        policyFlags |= POLICY_FLAG_WAKE;
    }

    // Synthesize key down from buttons if needed.
    out += synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_DOWN, when, readTime, getDeviceId(),
                                mSource, *mDisplayId, policyFlags, lastButtonState,
                                currentButtonState);

    // Send motion event.
    if (downChanged || moved || scrolled || buttonsChanged) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = lastButtonState;
        int32_t motionEventAction;
        if (downChanged) {
            motionEventAction = down ? AMOTION_EVENT_ACTION_DOWN : AMOTION_EVENT_ACTION_UP;
        } else if (down || (mSource != AINPUT_SOURCE_MOUSE)) {
            motionEventAction = AMOTION_EVENT_ACTION_MOVE;
        } else {
            motionEventAction = AMOTION_EVENT_ACTION_HOVER_MOVE;
        }

        if (buttonsReleased) {
            BitSet32 released(buttonsReleased);
            while (!released.isEmpty()) {
                int32_t actionButton = BitSet32::valueForBit(released.clearFirstMarkedBit());
                buttonState &= ~actionButton;
                out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime,
                                               getDeviceId(), mSource, *mDisplayId, policyFlags,
                                               AMOTION_EVENT_ACTION_BUTTON_RELEASE, actionButton, 0,
                                               metaState, buttonState, MotionClassification::NONE,
                                               AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                               &pointerCoords, mXPrecision, mYPrecision,
                                               xCursorPosition, yCursorPosition, downTime,
                                               /*videoFrames=*/{}));
            }
        }

        out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                       mSource, *mDisplayId, policyFlags, motionEventAction, 0, 0,
                                       metaState, currentButtonState, MotionClassification::NONE,
                                       AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                       &pointerCoords, mXPrecision, mYPrecision, xCursorPosition,
                                       yCursorPosition, downTime,
                                       /*videoFrames=*/{}));

        if (buttonsPressed) {
            BitSet32 pressed(buttonsPressed);
            while (!pressed.isEmpty()) {
                int32_t actionButton = BitSet32::valueForBit(pressed.clearFirstMarkedBit());
                buttonState |= actionButton;
                out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime,
                                               getDeviceId(), mSource, *mDisplayId, policyFlags,
                                               AMOTION_EVENT_ACTION_BUTTON_PRESS, actionButton, 0,
                                               metaState, buttonState, MotionClassification::NONE,
                                               AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                               &pointerCoords, mXPrecision, mYPrecision,
                                               xCursorPosition, yCursorPosition, downTime,
                                               /*videoFrames=*/{}));
            }
        }

        ALOG_ASSERT(buttonState == currentButtonState);

        // Send hover move after UP to tell the application that the mouse is hovering now.
        if (motionEventAction == AMOTION_EVENT_ACTION_UP && (mSource == AINPUT_SOURCE_MOUSE)) {
            out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                           mSource, *mDisplayId, policyFlags,
                                           AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                                           currentButtonState, MotionClassification::NONE,
                                           AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                           &pointerCoords, mXPrecision, mYPrecision,
                                           xCursorPosition, yCursorPosition, downTime,
                                           /*videoFrames=*/{}));
        }

        // Send scroll events.
        if (scrolled) {
            pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_VSCROLL, vscroll);
            pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_HSCROLL, hscroll);

            out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                           mSource, *mDisplayId, policyFlags,
                                           AMOTION_EVENT_ACTION_SCROLL, 0, 0, metaState,
                                           currentButtonState, MotionClassification::NONE,
                                           AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                           &pointerCoords, mXPrecision, mYPrecision,
                                           xCursorPosition, yCursorPosition, downTime,
                                           /*videoFrames=*/{}));
        }
    }

    // Synthesize key up from buttons if needed.
    out += synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_UP, when, readTime, getDeviceId(),
                                mSource, *mDisplayId, policyFlags, lastButtonState,
                                currentButtonState);

    mCursorMotionAccumulator.finishSync();
    mCursorScrollAccumulator.finishSync();
    return out;
}

int32_t CursorInputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    if (scanCode >= BTN_MOUSE && scanCode < BTN_JOYSTICK) {
        return getDeviceContext().getScanCodeState(scanCode);
    } else {
        return AKEY_STATE_UNKNOWN;
    }
}

std::optional<ui::LogicalDisplayId> CursorInputMapper::getAssociatedDisplayId() {
    return mDisplayId;
}

void CursorInputMapper::configureBasicParams() {
    mCursorScrollAccumulator.configure(getDeviceContext());

    // Configure basic parameters.
    mParameters = computeParameters(getDeviceContext());

    // Configure device mode.
    switch (mParameters.mode) {
        case Parameters::Mode::POINTER_RELATIVE:
            // Should not happen during first time configuration.
            ALOGE("Cannot start a device in MODE_POINTER_RELATIVE, starting in MODE_POINTER");
            mParameters.mode = Parameters::Mode::POINTER;
            [[fallthrough]];
        case Parameters::Mode::POINTER:
            mSource = AINPUT_SOURCE_MOUSE;
            mXPrecision = 1.0f;
            mYPrecision = 1.0f;
            mXScale = 1.0f;
            mYScale = 1.0f;
            break;
        case Parameters::Mode::NAVIGATION:
            mSource = AINPUT_SOURCE_TRACKBALL;
            mXPrecision = TRACKBALL_MOVEMENT_THRESHOLD;
            mYPrecision = TRACKBALL_MOVEMENT_THRESHOLD;
            mXScale = 1.0f / TRACKBALL_MOVEMENT_THRESHOLD;
            mYScale = 1.0f / TRACKBALL_MOVEMENT_THRESHOLD;
            break;
    }

    mVWheelScale = 1.0f;
    mHWheelScale = 1.0f;
}

void CursorInputMapper::configureOnPointerCapture(const InputReaderConfiguration& config) {
    if (config.pointerCaptureRequest.isEnable()) {
        if (mParameters.mode == Parameters::Mode::POINTER) {
            mParameters.mode = Parameters::Mode::POINTER_RELATIVE;
            mSource = AINPUT_SOURCE_MOUSE_RELATIVE;
        } else {
            ALOGE("Cannot request pointer capture, device is not in MODE_POINTER");
        }
    } else {
        if (mParameters.mode == Parameters::Mode::POINTER_RELATIVE) {
            mParameters.mode = Parameters::Mode::POINTER;
            mSource = AINPUT_SOURCE_MOUSE;
        } else {
            ALOGE("Cannot release pointer capture, device is not in MODE_POINTER_RELATIVE");
        }
    }
    bumpGeneration();
}

void CursorInputMapper::configureOnChangePointerSpeed(const InputReaderConfiguration& config) {
    if (mParameters.mode == Parameters::Mode::POINTER_RELATIVE) {
        // Disable any acceleration or scaling for the pointer when Pointer Capture is enabled.
        if (mEnableNewMousePointerBallistics) {
            mNewPointerVelocityControl.setAccelerationEnabled(false);
        } else {
            mOldPointerVelocityControl.setParameters(FLAT_VELOCITY_CONTROL_PARAMS);
        }
        mWheelXVelocityControl.setParameters(FLAT_VELOCITY_CONTROL_PARAMS);
        mWheelYVelocityControl.setParameters(FLAT_VELOCITY_CONTROL_PARAMS);
    } else {
        if (mEnableNewMousePointerBallistics) {
            mNewPointerVelocityControl.setAccelerationEnabled(
                    config.displaysWithMousePointerAccelerationDisabled.count(
                            mDisplayId.value_or(ui::LogicalDisplayId::INVALID)) == 0);
            mNewPointerVelocityControl.setCurve(
                    createAccelerationCurveForPointerSensitivity(config.mousePointerSpeed));
        } else {
            mOldPointerVelocityControl.setParameters(
                    (config.displaysWithMousePointerAccelerationDisabled.count(
                             mDisplayId.value_or(ui::LogicalDisplayId::INVALID)) == 0)
                            ? config.pointerVelocityControlParameters
                            : FLAT_VELOCITY_CONTROL_PARAMS);
        }
        mWheelXVelocityControl.setParameters(config.wheelVelocityControlParameters);
        mWheelYVelocityControl.setParameters(config.wheelVelocityControlParameters);
    }
}

void CursorInputMapper::configureOnChangeDisplayInfo(const InputReaderConfiguration& config) {
    const bool isPointer = mParameters.mode == Parameters::Mode::POINTER;

    mDisplayId = ui::LogicalDisplayId::INVALID;
    std::optional<DisplayViewport> resolvedViewport;
    if (auto assocViewport = mDeviceContext.getAssociatedViewport(); assocViewport) {
        // This InputDevice is associated with a viewport.
        // Only generate events for the associated display.
        mDisplayId = assocViewport->displayId;
        resolvedViewport = *assocViewport;
    } else if (isPointer) {
        // The InputDevice is not associated with a viewport, but it controls the mouse pointer.
        // Always use DISPLAY_ID_NONE for mouse events.
        // PointerChoreographer will make it target the correct the displayId later.
        resolvedViewport = getContext()->getPolicy()->getPointerViewportForAssociatedDisplay();
        mDisplayId =
                resolvedViewport ? std::make_optional(ui::LogicalDisplayId::INVALID) : std::nullopt;
    }

    mOrientation = (mParameters.orientationAware && mParameters.hasAssociatedDisplay) ||
                    mParameters.mode == Parameters::Mode::POINTER_RELATIVE || !resolvedViewport
            ? ui::ROTATION_0
            : getInverseRotation(resolvedViewport->orientation);

    mBoundsInLogicalDisplay = resolvedViewport
            ? FloatRect{static_cast<float>(resolvedViewport->logicalLeft),
                        static_cast<float>(resolvedViewport->logicalTop),
                        static_cast<float>(resolvedViewport->logicalRight - 1),
                        static_cast<float>(resolvedViewport->logicalBottom - 1)}
            : FloatRect{0, 0, 0, 0};

    bumpGeneration();
}

} // namespace android
