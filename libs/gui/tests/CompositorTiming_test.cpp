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
#include <gui/CompositorTiming.h>

namespace android::test {
namespace {

constexpr nsecs_t kMillisecond = 1'000'000;
constexpr nsecs_t kVsyncPeriod = 8'333'333;
constexpr nsecs_t kVsyncPhase = -2'166'667;
constexpr nsecs_t kIdealLatency = -kVsyncPhase;

} // namespace

TEST(CompositorTimingTest, InvalidVsyncPeriod) {
    const nsecs_t vsyncDeadline = systemTime();
    constexpr nsecs_t kInvalidVsyncPeriod = -1;

    const gui::CompositorTiming timing(vsyncDeadline, kInvalidVsyncPeriod, kVsyncPhase,
                                       kIdealLatency);

    EXPECT_EQ(timing.deadline, 0);
    EXPECT_EQ(timing.interval, gui::CompositorTiming::kDefaultVsyncPeriod);
    EXPECT_EQ(timing.presentLatency, gui::CompositorTiming::kDefaultVsyncPeriod);
}

TEST(CompositorTimingTest, PresentLatencySnapping) {
    for (nsecs_t presentDelay = 0, compositeTime = systemTime(); presentDelay < 10 * kVsyncPeriod;
         presentDelay += kMillisecond, compositeTime += kVsyncPeriod) {
        const nsecs_t presentLatency = kIdealLatency + presentDelay;
        const nsecs_t vsyncDeadline = compositeTime + presentLatency + kVsyncPeriod;

        const gui::CompositorTiming timing(vsyncDeadline, kVsyncPeriod, kVsyncPhase,
                                           presentLatency);

        EXPECT_EQ(timing.deadline, compositeTime + presentDelay + kVsyncPeriod);
        EXPECT_EQ(timing.interval, kVsyncPeriod);

        // The presentDelay should be rounded to a multiple of the VSYNC period, such that the
        // remainder (presentLatency % interval) always evaluates to the VSYNC phase offset.
        EXPECT_GE(timing.presentLatency, kIdealLatency);
        EXPECT_EQ(timing.presentLatency % timing.interval, kIdealLatency);
    }
}

} // namespace android::test
