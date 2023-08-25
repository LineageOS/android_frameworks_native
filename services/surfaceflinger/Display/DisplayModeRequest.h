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

#include <ftl/non_null.h>

#include <scheduler/FrameRateMode.h>

namespace android::display {

struct DisplayModeRequest {
    scheduler::FrameRateMode mode;

    // Whether to emit DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE.
    bool emitEvent = false;
};

inline bool operator==(const DisplayModeRequest& lhs, const DisplayModeRequest& rhs) {
    return lhs.mode == rhs.mode && lhs.emitEvent == rhs.emitEvent;
}

} // namespace android::display
