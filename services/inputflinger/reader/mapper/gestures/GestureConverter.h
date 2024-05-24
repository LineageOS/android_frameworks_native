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

#pragma once

#include <array>
#include <list>
#include <memory>

#include <PointerControllerInterface.h>
#include <android/input.h>
#include <utils/Timers.h>

#include "EventHub.h"
#include "InputDevice.h"
#include "InputReaderContext.h"
#include "NotifyArgs.h"
#include "ui/Rotation.h"

#include "include/gestures.h"

namespace android {

using std::chrono_literals::operator""ms;
/**
 * This duration is decided based on internal team testing, it may be updated after testing with
 * larger groups
 */
constexpr std::chrono::nanoseconds TAP_ENABLE_DELAY_NANOS = 400ms;

// Converts Gesture structs from the gestures library into NotifyArgs and the appropriate
// PointerController calls.
class GestureConverter {
public:
    GestureConverter(InputReaderContext& readerContext, const InputDeviceContext& deviceContext,
                     int32_t deviceId);

    std::string dump() const;

    void setOrientation(ui::Rotation orientation) { mOrientation = orientation; }
    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when);

    void setDisplayId(std::optional<int32_t> displayId) { mDisplayId = displayId; }

    void setBoundsInLogicalDisplay(FloatRect bounds) { mBoundsInLogicalDisplay = bounds; }

    void populateMotionRanges(InputDeviceInfo& info) const;

    [[nodiscard]] std::list<NotifyArgs> handleGesture(nsecs_t when, nsecs_t readTime,
                                                      nsecs_t gestureStartTime,
                                                      const Gesture& gesture);

private:
    [[nodiscard]] std::list<NotifyArgs> handleMove(nsecs_t when, nsecs_t readTime,
                                                   nsecs_t gestureStartTime,
                                                   const Gesture& gesture);
    [[nodiscard]] std::list<NotifyArgs> handleButtonsChange(nsecs_t when, nsecs_t readTime,
                                                            const Gesture& gesture);
    [[nodiscard]] std::list<NotifyArgs> releaseAllButtons(nsecs_t when, nsecs_t readTime);
    [[nodiscard]] std::list<NotifyArgs> handleScroll(nsecs_t when, nsecs_t readTime,
                                                     const Gesture& gesture);
    [[nodiscard]] std::list<NotifyArgs> handleFling(nsecs_t when, nsecs_t readTime,
                                                    nsecs_t gestureStartTime,
                                                    const Gesture& gesture);
    [[nodiscard]] std::list<NotifyArgs> endScroll(nsecs_t when, nsecs_t readTime);

    [[nodiscard]] std::list<NotifyArgs> handleMultiFingerSwipe(nsecs_t when, nsecs_t readTime,
                                                               uint32_t fingerCount, float dx,
                                                               float dy);
    [[nodiscard]] std::list<NotifyArgs> handleMultiFingerSwipeLift(nsecs_t when, nsecs_t readTime);
    [[nodiscard]] std::list<NotifyArgs> handlePinch(nsecs_t when, nsecs_t readTime,
                                                    const Gesture& gesture);
    [[nodiscard]] std::list<NotifyArgs> endPinch(nsecs_t when, nsecs_t readTime);

    [[nodiscard]] std::list<NotifyArgs> enterHover(nsecs_t when, nsecs_t readTime,
                                                   float xCursorPosition, float yCursorPosition);
    [[nodiscard]] std::list<NotifyArgs> exitHover(nsecs_t when, nsecs_t readTime,
                                                  float xCursorPosition, float yCursorPosition);

    NotifyMotionArgs makeHoverEvent(nsecs_t when, nsecs_t readTime, int32_t action,
                                    float xCursorPosition, float yCursorPosition);

    NotifyMotionArgs makeMotionArgs(nsecs_t when, nsecs_t readTime, int32_t action,
                                    int32_t actionButton, int32_t buttonState,
                                    uint32_t pointerCount, const PointerCoords* pointerCoords,
                                    float xCursorPosition, float yCursorPosition);

    void enableTapToClick(nsecs_t when);
    bool mIsHoverCancelled{false};
    nsecs_t mWhenToEnableTapToClick{0};

    const int32_t mDeviceId;
    InputReaderContext& mReaderContext;
    std::shared_ptr<PointerControllerInterface> mPointerController;
    const bool mEnableFlingStop;

    std::optional<int32_t> mDisplayId;
    FloatRect mBoundsInLogicalDisplay{};
    ui::Rotation mOrientation = ui::ROTATION_0;
    RawAbsoluteAxisInfo mXAxisInfo;
    RawAbsoluteAxisInfo mYAxisInfo;

    // The current button state according to the gestures library, but converted into MotionEvent
    // button values (AMOTION_EVENT_BUTTON_...).
    uint32_t mButtonState = 0;
    nsecs_t mDownTime = 0;
    // Whether we are currently in a hover state (i.e. a HOVER_ENTER event has been sent without a
    // matching HOVER_EXIT).
    bool mIsHovering = false;
    // Whether we've received a "fling start" gesture (i.e. the end of a scroll) but no "fling tap
    // down" gesture to match it yet.
    bool mFlingMayBeInProgress = false;

    MotionClassification mCurrentClassification = MotionClassification::NONE;
    // Only used when mCurrentClassification is MULTI_FINGER_SWIPE.
    uint32_t mSwipeFingerCount = 0;
    static constexpr float INITIAL_PINCH_SEPARATION_PX = 200.0;
    // Only used when mCurrentClassification is PINCH.
    float mPinchFingerSeparation;
    static constexpr size_t MAX_FAKE_FINGERS = 4;
    // We never need any PointerProperties other than the finger tool type, so we can just keep a
    // const array of them.
    const std::array<PointerProperties, MAX_FAKE_FINGERS> mFingerProps = {{
            {.id = 0, .toolType = ToolType::FINGER},
            {.id = 1, .toolType = ToolType::FINGER},
            {.id = 2, .toolType = ToolType::FINGER},
            {.id = 3, .toolType = ToolType::FINGER},
    }};
    std::array<PointerCoords, MAX_FAKE_FINGERS> mFakeFingerCoords = {};

    // TODO(b/260226362): consider what the appropriate source for these events is.
    static constexpr uint32_t SOURCE = AINPUT_SOURCE_MOUSE;
};

} // namespace android
