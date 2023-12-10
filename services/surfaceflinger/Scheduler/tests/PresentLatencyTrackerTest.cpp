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

#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include <scheduler/PresentLatencyTracker.h>
#include <ui/FenceTime.h>

namespace android::scheduler {

TEST(PresentLatencyTrackerTest, skipsInvalidFences) {
    PresentLatencyTracker tracker;

    const TimePoint kCompositeTime = TimePoint::fromNs(999);
    EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, FenceTime::NO_FENCE), Duration::zero());
    EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, FenceTime::NO_FENCE), Duration::zero());
    EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, FenceTime::NO_FENCE), Duration::zero());

    FenceToFenceTimeMap fenceMap;
    const auto [fence, fenceTime] = fenceMap.makePendingFenceForTest();
    EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, fenceTime), Duration::zero());

    fenceTime->signalForTest(9999);

    EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, FenceTime::NO_FENCE),
              Duration::fromNs(9000));
}

TEST(PresentLatencyTrackerTest, tracksPendingFrames) {
    PresentLatencyTracker tracker;

    FenceToFenceTimeMap fenceMap;
    std::array<FenceToFenceTimeMap::FencePair, PresentLatencyTracker::kMaxPendingFrames> fences;
    std::generate(fences.begin(), fences.end(),
                  [&fenceMap] { return fenceMap.makePendingFenceForTest(); });

    // The present latency is 0 if all fences are pending.
    const TimePoint kCompositeTime = TimePoint::fromNs(1234);
    for (const auto& [fence, fenceTime] : fences) {
        EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, fenceTime), Duration::zero());
    }

    // If multiple frames have been presented...
    constexpr size_t kPresentCount = fences.size() / 2;
    for (size_t i = 0; i < kPresentCount; i++) {
        fences[i].second->signalForTest(kCompositeTime.ns() + static_cast<nsecs_t>(i));
    }

    const auto fence = fenceMap.makePendingFenceForTest();

    // ...then the present latency is measured using the latest frame.
    constexpr Duration kPresentLatency = Duration::fromNs(static_cast<nsecs_t>(kPresentCount) - 1);
    EXPECT_EQ(tracker.trackPendingFrame(kCompositeTime, fence.second), kPresentLatency);
}

} // namespace android::scheduler
