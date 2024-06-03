/*
 * Copyright 2023 The Android Open Source Project
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

#include <NotifyArgs.h>
#include <android/input.h>
#include <attestation/HmacKeyManager.h>
#include <input/Input.h>
#include <input/InputEventBuilders.h>
#include <input/Keyboard.h>
#include <utils/Timers.h> // for nsecs_t, systemTime

#include <vector>

namespace android {

class MotionArgsBuilder {
public:
    MotionArgsBuilder(int32_t action, int32_t source) : mEventId(InputEvent::nextId()) {
        mAction = action;
        if (mAction == AMOTION_EVENT_ACTION_CANCEL) {
            addFlag(AMOTION_EVENT_FLAG_CANCELED);
        }
        mSource = source;
        mEventTime = systemTime(SYSTEM_TIME_MONOTONIC);
        mDownTime = mEventTime;
    }

    MotionArgsBuilder& deviceId(int32_t deviceId) {
        mDeviceId = deviceId;
        return *this;
    }

    MotionArgsBuilder& downTime(nsecs_t downTime) {
        mDownTime = downTime;
        return *this;
    }

    MotionArgsBuilder& eventTime(nsecs_t eventTime) {
        mEventTime = eventTime;
        return *this;
    }

    MotionArgsBuilder& displayId(ui::LogicalDisplayId displayId) {
        mDisplayId = displayId;
        return *this;
    }

    MotionArgsBuilder& policyFlags(int32_t policyFlags) {
        mPolicyFlags = policyFlags;
        return *this;
    }

    MotionArgsBuilder& actionButton(int32_t actionButton) {
        mActionButton = actionButton;
        return *this;
    }

    MotionArgsBuilder& buttonState(int32_t buttonState) {
        mButtonState = buttonState;
        return *this;
    }

    MotionArgsBuilder& rawXCursorPosition(float rawXCursorPosition) {
        mRawXCursorPosition = rawXCursorPosition;
        return *this;
    }

    MotionArgsBuilder& rawYCursorPosition(float rawYCursorPosition) {
        mRawYCursorPosition = rawYCursorPosition;
        return *this;
    }

    MotionArgsBuilder& pointer(PointerBuilder pointer) {
        mPointers.push_back(pointer);
        return *this;
    }

    MotionArgsBuilder& addFlag(uint32_t flags) {
        mFlags |= flags;
        return *this;
    }

    MotionArgsBuilder& classification(MotionClassification classification) {
        mClassification = classification;
        return *this;
    }

    NotifyMotionArgs build() const {
        std::vector<PointerProperties> pointerProperties;
        std::vector<PointerCoords> pointerCoords;
        for (const PointerBuilder& pointer : mPointers) {
            pointerProperties.push_back(pointer.buildProperties());
            pointerCoords.push_back(pointer.buildCoords());
        }

        // Set mouse cursor position for the most common cases to avoid boilerplate.
        float resolvedCursorX = mRawXCursorPosition;
        float resolvedCursorY = mRawYCursorPosition;
        if (mSource == AINPUT_SOURCE_MOUSE &&
            !MotionEvent::isValidCursorPosition(mRawXCursorPosition, mRawYCursorPosition) &&
            BitSet64::hasBit(pointerCoords[0].bits, AMOTION_EVENT_AXIS_X) &&
            BitSet64::hasBit(pointerCoords[0].bits, AMOTION_EVENT_AXIS_Y)) {
            resolvedCursorX = pointerCoords[0].getX();
            resolvedCursorY = pointerCoords[0].getY();
        }

        return {mEventId,
                mEventTime,
                /*readTime=*/mEventTime,
                mDeviceId,
                mSource,
                mDisplayId,
                mPolicyFlags,
                mAction,
                mActionButton,
                mFlags,
                AMETA_NONE,
                mButtonState,
                mClassification,
                /*edgeFlags=*/0,
                static_cast<uint32_t>(mPointers.size()),
                pointerProperties.data(),
                pointerCoords.data(),
                /*xPrecision=*/0,
                /*yPrecision=*/0,
                resolvedCursorX,
                resolvedCursorY,
                mDownTime,
                /*videoFrames=*/{}};
    }

private:
    const int32_t mEventId;
    int32_t mAction;
    int32_t mDeviceId{DEFAULT_DEVICE_ID};
    uint32_t mSource;
    nsecs_t mDownTime;
    nsecs_t mEventTime;
    ui::LogicalDisplayId mDisplayId{ui::LogicalDisplayId::DEFAULT};
    uint32_t mPolicyFlags = DEFAULT_POLICY_FLAGS;
    int32_t mActionButton{0};
    int32_t mButtonState{0};
    int32_t mFlags{0};
    MotionClassification mClassification{MotionClassification::NONE};
    float mRawXCursorPosition{AMOTION_EVENT_INVALID_CURSOR_POSITION};
    float mRawYCursorPosition{AMOTION_EVENT_INVALID_CURSOR_POSITION};

    std::vector<PointerBuilder> mPointers;
};

class KeyArgsBuilder {
public:
    KeyArgsBuilder(int32_t action, int32_t source) : mEventId(InputEvent::nextId()) {
        mAction = action;
        mSource = source;
        mEventTime = systemTime(SYSTEM_TIME_MONOTONIC);
        mDownTime = mEventTime;
    }

    KeyArgsBuilder& deviceId(int32_t deviceId) {
        mDeviceId = deviceId;
        return *this;
    }

    KeyArgsBuilder& downTime(nsecs_t downTime) {
        mDownTime = downTime;
        return *this;
    }

    KeyArgsBuilder& eventTime(nsecs_t eventTime) {
        mEventTime = eventTime;
        return *this;
    }

    KeyArgsBuilder& displayId(ui::LogicalDisplayId displayId) {
        mDisplayId = displayId;
        return *this;
    }

    KeyArgsBuilder& policyFlags(int32_t policyFlags) {
        mPolicyFlags = policyFlags;
        return *this;
    }

    KeyArgsBuilder& addFlag(uint32_t flags) {
        mFlags |= flags;
        return *this;
    }

    KeyArgsBuilder& keyCode(int32_t keyCode) {
        mKeyCode = keyCode;
        return *this;
    }

    KeyArgsBuilder& metaState(int32_t metaState) {
        mMetaState |= metaState;
        mMetaState = normalizeMetaState(/*oldMetaState=*/mMetaState);
        return *this;
    }

    NotifyKeyArgs build() const {
        return {mEventId,
                mEventTime,
                /*readTime=*/mEventTime,
                mDeviceId,
                mSource,
                mDisplayId,
                mPolicyFlags,
                mAction,
                mFlags,
                mKeyCode,
                mScanCode,
                mMetaState,
                mDownTime};
    }

private:
    const int32_t mEventId;
    int32_t mAction;
    int32_t mDeviceId = DEFAULT_DEVICE_ID;
    uint32_t mSource;
    nsecs_t mDownTime;
    nsecs_t mEventTime;
    ui::LogicalDisplayId mDisplayId{ui::LogicalDisplayId::DEFAULT};
    uint32_t mPolicyFlags = DEFAULT_POLICY_FLAGS;
    int32_t mFlags{0};
    int32_t mKeyCode{AKEYCODE_UNKNOWN};
    int32_t mScanCode{0};
    int32_t mMetaState{AMETA_NONE};
};

} // namespace android
