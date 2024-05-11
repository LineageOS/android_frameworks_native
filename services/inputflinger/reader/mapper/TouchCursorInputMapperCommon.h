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
#include <ui/Rotation.h>

#include "EventHub.h"
#include "InputListener.h"
#include "InputReaderContext.h"

namespace android {

ui::Rotation getInverseRotation(ui::Rotation orientation);

void rotateDelta(ui::Rotation orientation, float* deltaX, float* deltaY);

// Returns true if the pointer should be reported as being down given the specified
// button states.  This determines whether the event is reported as a touch event.
bool isPointerDown(int32_t buttonState);

[[nodiscard]] std::list<NotifyArgs> synthesizeButtonKeys(
        InputReaderContext* context, int32_t action, nsecs_t when, nsecs_t readTime,
        int32_t deviceId, uint32_t source, ui::LogicalDisplayId displayId, uint32_t policyFlags,
        int32_t lastButtonState, int32_t currentButtonState);

// For devices connected over Bluetooth, although they may produce events at a consistent rate,
// the events might end up reaching Android in a "batched" manner through the Bluetooth
// stack, where a few events may be clumped together and processed around the same time.
// In this case, if the input device or its driver does not send or process the actual event
// generation timestamps, the event time will set to whenever the kernel received the event.
// When the timestamp deltas are minuscule for these batched events, any changes in x or y
// coordinates result in extremely large instantaneous velocities, which can negatively impact
// user experience. To avoid this, we augment the timestamps so that subsequent event timestamps
// differ by at least a minimum delta value.
std::tuple<nsecs_t /*eventTime*/, nsecs_t /*readTime*/> applyBluetoothTimestampSmoothening(
        const InputDeviceIdentifier& identifier, nsecs_t currentEventTime, nsecs_t readTime,
        nsecs_t lastEventTime);

} // namespace android
