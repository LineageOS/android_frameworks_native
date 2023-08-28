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

#include <memory>
#include <queue>
#include <utility>

#include <scheduler/Time.h>

namespace android {

class FenceTime;

namespace scheduler {

// Computes composite-to-present latency by tracking recently composited frames pending to present.
class PresentLatencyTracker {
public:
    // For tests.
    static constexpr size_t kMaxPendingFrames = 4;

    // Returns the present latency of the latest frame.
    Duration trackPendingFrame(TimePoint compositeTime,
                               std::shared_ptr<FenceTime> presentFenceTime);

private:
    struct PendingFrame {
        PendingFrame(TimePoint compositeTime, std::shared_ptr<FenceTime> presentFenceTime)
              : compositeTime(compositeTime), presentFenceTime(std::move(presentFenceTime)) {}

        const TimePoint compositeTime;
        const std::shared_ptr<FenceTime> presentFenceTime;
    };

    std::queue<PendingFrame> mPendingFrames;
};

} // namespace scheduler
} // namespace android
