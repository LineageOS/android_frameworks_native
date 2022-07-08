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

#include <utils/Timers.h>

namespace android::gui {

// Expected timing of the next composited frame, based on the timing of the latest frames.
struct CompositorTiming {
    static constexpr nsecs_t kDefaultVsyncPeriod = 16'666'667;

    CompositorTiming() = default;
    CompositorTiming(nsecs_t vsyncDeadline, nsecs_t vsyncPeriod, nsecs_t vsyncPhase,
                     nsecs_t presentLatency);

    // Time point when compositing is expected to start.
    nsecs_t deadline = 0;

    // Duration between consecutive frames. In other words, the VSYNC period.
    nsecs_t interval = kDefaultVsyncPeriod;

    // Duration between composite start and present. For missed frames, the extra latency is rounded
    // to a multiple of the VSYNC period, such that the remainder (presentLatency % interval) always
    // evaluates to the VSYNC phase offset.
    nsecs_t presentLatency = kDefaultVsyncPeriod;
};

} // namespace android::gui
