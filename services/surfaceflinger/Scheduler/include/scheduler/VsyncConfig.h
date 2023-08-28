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

#include <chrono>

#include <utils/Timers.h>

namespace android::scheduler {

using namespace std::chrono_literals;

// Phase offsets and work durations for SF and app deadlines from VSYNC.
struct VsyncConfig {
    nsecs_t sfOffset;
    nsecs_t appOffset;
    std::chrono::nanoseconds sfWorkDuration;
    std::chrono::nanoseconds appWorkDuration;

    bool operator==(const VsyncConfig& other) const {
        return sfOffset == other.sfOffset && appOffset == other.appOffset &&
                sfWorkDuration == other.sfWorkDuration && appWorkDuration == other.appWorkDuration;
    }

    bool operator!=(const VsyncConfig& other) const { return !(*this == other); }

    // The duration for which SF can delay a frame if it is considered early based on the
    // VsyncConfig::appWorkDuration.
    static constexpr std::chrono::nanoseconds kEarlyLatchMaxThreshold = 100ms;
};

struct VsyncConfigSet {
    VsyncConfig early;    // Used for early transactions, and during refresh rate change.
    VsyncConfig earlyGpu; // Used during GPU composition.
    VsyncConfig late;     // Default.
    std::chrono::nanoseconds hwcMinWorkDuration; // Used for calculating the earliest present time.

    bool operator==(const VsyncConfigSet& other) const {
        return early == other.early && earlyGpu == other.earlyGpu && late == other.late &&
                hwcMinWorkDuration == other.hwcMinWorkDuration;
    }

    bool operator!=(const VsyncConfigSet& other) const { return !(*this == other); }
};

} // namespace android::scheduler
