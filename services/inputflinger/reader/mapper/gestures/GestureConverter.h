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

#include <list>
#include <memory>

#include <PointerControllerInterface.h>
#include <utils/Timers.h>

#include "InputReaderContext.h"
#include "NotifyArgs.h"
#include "ui/Rotation.h"

#include "include/gestures.h"

namespace android {

// Converts Gesture structs from the gestures library into NotifyArgs and the appropriate
// PointerController calls.
class GestureConverter {
public:
    GestureConverter(InputReaderContext& readerContext, int32_t deviceId);

    void setOrientation(ui::Rotation orientation) { mOrientation = orientation; }
    void reset();

    [[nodiscard]] std::list<NotifyArgs> handleGesture(nsecs_t when, nsecs_t readTime,
                                                      const Gesture& gesture);

private:
    NotifyArgs handleMove(nsecs_t when, nsecs_t readTime, const Gesture& gesture);
    [[nodiscard]] std::list<NotifyArgs> handleButtonsChange(nsecs_t when, nsecs_t readTime,
                                                            const Gesture& gesture);

    NotifyMotionArgs makeMotionArgs(nsecs_t when, nsecs_t readTime, int32_t action,
                                    int32_t actionButton, int32_t buttonState,
                                    uint32_t pointerCount,
                                    const PointerProperties* pointerProperties,
                                    const PointerCoords* pointerCoords, float xCursorPosition,
                                    float yCursorPosition);

    const int32_t mDeviceId;
    InputReaderContext& mReaderContext;
    std::shared_ptr<PointerControllerInterface> mPointerController;

    ui::Rotation mOrientation = ui::ROTATION_0;
    // The current button state according to the gestures library, but converted into MotionEvent
    // button values (AMOTION_EVENT_BUTTON_...).
    uint32_t mButtonState = 0;
    nsecs_t mDownTime = 0;
};

} // namespace android
