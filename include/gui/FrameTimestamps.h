/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_GUI_FRAMETIMESTAMPS_H
#define ANDROID_GUI_FRAMETIMESTAMPS_H

#include <utils/Timers.h>
#include <utils/Flattenable.h>

namespace android {

enum class SupportableFrameTimestamps {
    REQUESTED_PRESENT,
    ACQUIRE,
    REFRESH_START,
    GL_COMPOSITION_DONE_TIME,
    DISPLAY_PRESENT_TIME,
    DISPLAY_RETIRE_TIME,
    RELEASE_TIME,
};

struct FrameTimestamps : public LightFlattenablePod<FrameTimestamps> {
    uint64_t frameNumber{0};
    nsecs_t requestedPresentTime{0};
    nsecs_t acquireTime{0};
    nsecs_t refreshStartTime{0};
    nsecs_t glCompositionDoneTime{0};
    nsecs_t displayPresentTime{0};
    nsecs_t displayRetireTime{0};
    nsecs_t releaseTime{0};
};

} // namespace android
#endif
