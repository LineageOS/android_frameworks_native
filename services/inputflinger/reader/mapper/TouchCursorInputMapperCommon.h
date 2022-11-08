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

#pragma once

#include <input/DisplayViewport.h>
#include <stdint.h>

#include "EventHub.h"
#include "InputListener.h"
#include "InputReaderContext.h"

namespace android {

// --- Static Definitions ---

static int32_t getInverseRotation(int32_t orientation) {
    switch (orientation) {
        case DISPLAY_ORIENTATION_90:
            return DISPLAY_ORIENTATION_270;
        case DISPLAY_ORIENTATION_270:
            return DISPLAY_ORIENTATION_90;
        default:
            return orientation;
    }
}

static void rotateDelta(int32_t orientation, float* deltaX, float* deltaY) {
    float temp;
    switch (orientation) {
        case DISPLAY_ORIENTATION_90:
            temp = *deltaX;
            *deltaX = *deltaY;
            *deltaY = -temp;
            break;

        case DISPLAY_ORIENTATION_180:
            *deltaX = -*deltaX;
            *deltaY = -*deltaY;
            break;

        case DISPLAY_ORIENTATION_270:
            temp = *deltaX;
            *deltaX = -*deltaY;
            *deltaY = temp;
            break;

        default:
            break;
    }
}

// Returns true if the pointer should be reported as being down given the specified
// button states.  This determines whether the event is reported as a touch event.
static bool isPointerDown(int32_t buttonState) {
    return buttonState &
            (AMOTION_EVENT_BUTTON_PRIMARY | AMOTION_EVENT_BUTTON_SECONDARY |
             AMOTION_EVENT_BUTTON_TERTIARY);
}

[[nodiscard]] static std::list<NotifyArgs> synthesizeButtonKey(
        InputReaderContext* context, int32_t action, nsecs_t when, nsecs_t readTime,
        int32_t deviceId, uint32_t source, int32_t displayId, uint32_t policyFlags,
        int32_t lastButtonState, int32_t currentButtonState, int32_t buttonState, int32_t keyCode) {
    std::list<NotifyArgs> out;
    if ((action == AKEY_EVENT_ACTION_DOWN && !(lastButtonState & buttonState) &&
         (currentButtonState & buttonState)) ||
        (action == AKEY_EVENT_ACTION_UP && (lastButtonState & buttonState) &&
         !(currentButtonState & buttonState))) {
        out.push_back(NotifyKeyArgs(context->getNextId(), when, readTime, deviceId, source,
                                    displayId, policyFlags, action, 0, keyCode, 0,
                                    context->getGlobalMetaState(), when));
    }
    return out;
}

[[nodiscard]] static std::list<NotifyArgs> synthesizeButtonKeys(
        InputReaderContext* context, int32_t action, nsecs_t when, nsecs_t readTime,
        int32_t deviceId, uint32_t source, int32_t displayId, uint32_t policyFlags,
        int32_t lastButtonState, int32_t currentButtonState) {
    std::list<NotifyArgs> out;
    out += synthesizeButtonKey(context, action, when, readTime, deviceId, source, displayId,
                               policyFlags, lastButtonState, currentButtonState,
                               AMOTION_EVENT_BUTTON_BACK, AKEYCODE_BACK);
    out += synthesizeButtonKey(context, action, when, readTime, deviceId, source, displayId,
                               policyFlags, lastButtonState, currentButtonState,
                               AMOTION_EVENT_BUTTON_FORWARD, AKEYCODE_FORWARD);
    return out;
}

// For devices connected over Bluetooth, although they may produce events at a consistent rate,
// the events might end up reaching Android in a "batched" manner through the Bluetooth
// stack, where a few events may be clumped together and processed around the same time.
// In this case, if the input device or its driver does not send or process the actual event
// generation timestamps, the event time will set to whenever the kernel received the event.
// When the timestamp deltas are minuscule for these batched events, any changes in x or y
// coordinates result in extremely large instantaneous velocities, which can negatively impact
// user experience. To avoid this, we augment the timestamps so that subsequent event timestamps
// differ by at least a minimum delta value.
static nsecs_t applyBluetoothTimestampSmoothening(const InputDeviceIdentifier& identifier,
                                                  nsecs_t currentEventTime, nsecs_t lastEventTime) {
    if (identifier.bus != BUS_BLUETOOTH) {
        return currentEventTime;
    }

    // Assume the fastest rate at which a Bluetooth touch device can report input events is one
    // every 4 milliseconds, or 250 Hz. Timestamps for successive events from a Bluetooth device
    // will be separated by at least this amount.
    constexpr static nsecs_t MIN_BLUETOOTH_TIMESTAMP_DELTA = ms2ns(4);
    // We define a maximum smoothing time delta so that we don't generate events too far into the
    // future.
    constexpr static nsecs_t MAX_BLUETOOTH_SMOOTHING_DELTA = ms2ns(32);
    return std::min(std::max(currentEventTime, lastEventTime + MIN_BLUETOOTH_TIMESTAMP_DELTA),
                    currentEventTime + MAX_BLUETOOTH_SMOOTHING_DELTA);
}

} // namespace android
