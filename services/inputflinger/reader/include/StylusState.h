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

#include <input/Input.h>

#include <limits.h>

namespace android {

struct StylusState {
    /* Time the stylus event was received. */
    nsecs_t when{};
    /*
     * Pressure as reported by the stylus if supported, normalized to the range [0, 1.0].
     * The presence of a pressure value indicates that the stylus is able to tell whether it is
     * touching the display.
     */
    std::optional<float> pressure{};
    /* The state of the stylus buttons as a bitfield (e.g. AMOTION_EVENT_BUTTON_SECONDARY). */
    uint32_t buttons{};
    /* Which tool type the stylus is currently using (e.g. ToolType::ERASER). */
    ToolType toolType{ToolType::UNKNOWN};

    void clear() { *this = StylusState{}; }
};

} // namespace android
