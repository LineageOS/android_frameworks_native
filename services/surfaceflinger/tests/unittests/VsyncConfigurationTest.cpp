/*
 * Copyright 2019 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <log/log.h>
#include <chrono>
#include <thread>

#include "Scheduler/VsyncConfiguration.h"

using namespace testing;

namespace android::scheduler {

using namespace std::chrono_literals;

class TestableWorkDuration : public impl::WorkDuration {
public:
    TestableWorkDuration(Fps currentFps, nsecs_t sfDuration, nsecs_t appDuration,
                         nsecs_t sfEarlyDuration, nsecs_t appEarlyDuration,
                         nsecs_t sfEarlyGlDuration, nsecs_t appEarlyGlDuration)
          : impl::WorkDuration(currentFps, sfDuration, appDuration, sfEarlyDuration,
                               appEarlyDuration, sfEarlyGlDuration, appEarlyGlDuration) {}
};

class WorkDurationTest : public testing::Test {
protected:
    WorkDurationTest()
          : mWorkDuration(Fps(60.0f), 10'500'000, 20'500'000, 16'000'000, 16'500'000, 13'500'000,
                          21'000'000) {}

    ~WorkDurationTest() = default;

    TestableWorkDuration mWorkDuration;
};

/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(WorkDurationTest, getConfigsForRefreshRate_60Hz) {
    mWorkDuration.setRefreshRateFps(Fps(60.0f));
    auto currentOffsets = mWorkDuration.getCurrentConfigs();
    auto offsets = mWorkDuration.getConfigsForRefreshRate(Fps(60.0f));

    EXPECT_EQ(currentOffsets, offsets);
    EXPECT_EQ(offsets.late.sfOffset, 6'166'667);
    EXPECT_EQ(offsets.late.appOffset, 2'333'334);

    EXPECT_EQ(offsets.late.sfWorkDuration, 10'500'000ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 20'500'000ns);

    EXPECT_EQ(offsets.early.sfOffset, 666'667);
    EXPECT_EQ(offsets.early.appOffset, 833'334);

    EXPECT_EQ(offsets.early.sfWorkDuration, 16'000'000ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 16'500'000ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 3'166'667);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 15'500'001);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 13'500'000ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 21'000'000ns);
}

TEST_F(WorkDurationTest, getConfigsForRefreshRate_90Hz) {
    mWorkDuration.setRefreshRateFps(Fps(90.0f));
    auto currentOffsets = mWorkDuration.getCurrentConfigs();
    auto offsets = mWorkDuration.getConfigsForRefreshRate(Fps(90.0f));

    EXPECT_EQ(currentOffsets, offsets);
    EXPECT_EQ(offsets.late.sfOffset, 611'111);
    EXPECT_EQ(offsets.late.appOffset, 2'333'333);

    EXPECT_EQ(offsets.late.sfWorkDuration, 10'500'000ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 20'500'000ns);

    EXPECT_EQ(offsets.early.sfOffset, -4'888'889);
    EXPECT_EQ(offsets.early.appOffset, 833'333);

    EXPECT_EQ(offsets.early.sfWorkDuration, 16'000'000ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 16'500'000ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, -2'388'889);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 9'944'444);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 13'500'000ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 21'000'000ns);
}

TEST_F(WorkDurationTest, getConfigsForRefreshRate_DefaultOffsets) {
    TestableWorkDuration phaseOffsetsWithDefaultValues(Fps(60.0f), -1, -1, -1, -1, -1, -1);

    auto validateOffsets = [](const auto& offsets, std::chrono::nanoseconds vsyncPeriod) {
        EXPECT_EQ(offsets.late.sfOffset, 1'000'000);
        EXPECT_EQ(offsets.late.appOffset, 1'000'000);

        EXPECT_EQ(offsets.late.sfWorkDuration, vsyncPeriod - 1'000'000ns);
        EXPECT_EQ(offsets.late.appWorkDuration, vsyncPeriod);

        EXPECT_EQ(offsets.early.sfOffset, 1'000'000);
        EXPECT_EQ(offsets.early.appOffset, 1'000'000);

        EXPECT_EQ(offsets.early.sfWorkDuration, vsyncPeriod - 1'000'000ns);
        EXPECT_EQ(offsets.early.appWorkDuration, vsyncPeriod);

        EXPECT_EQ(offsets.earlyGpu.sfOffset, 1'000'000);
        EXPECT_EQ(offsets.earlyGpu.appOffset, 1'000'000);

        EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, vsyncPeriod - 1'000'000ns);
        EXPECT_EQ(offsets.earlyGpu.appWorkDuration, vsyncPeriod);
    };

    const auto testForRefreshRate = [&](Fps refreshRate) {
        phaseOffsetsWithDefaultValues.setRefreshRateFps(refreshRate);
        auto currentOffsets = phaseOffsetsWithDefaultValues.getCurrentConfigs();
        auto offsets = phaseOffsetsWithDefaultValues.getConfigsForRefreshRate(refreshRate);
        EXPECT_EQ(currentOffsets, offsets);
        validateOffsets(offsets, std::chrono::nanoseconds(refreshRate.getPeriodNsecs()));
    };

    testForRefreshRate(Fps(90.0f));
    testForRefreshRate(Fps(60.0f));
}

TEST_F(WorkDurationTest, getConfigsForRefreshRate_unknownRefreshRate) {
    auto offsets = mWorkDuration.getConfigsForRefreshRate(Fps(14.7f));

    EXPECT_EQ(offsets.late.sfOffset, 57'527'208);
    EXPECT_EQ(offsets.late.appOffset, 37'027'208);

    EXPECT_EQ(offsets.late.sfWorkDuration, 10'500'000ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 20'500'000ns);

    EXPECT_EQ(offsets.early.sfOffset, 52'027'208);
    EXPECT_EQ(offsets.early.appOffset, 35'527'208);

    EXPECT_EQ(offsets.early.sfWorkDuration, 16'000'000ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 16'500'000ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 54'527'208);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 33'527'208);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 13'500'000ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 21'000'000ns);
}

class TestablePhaseOffsets : public impl::PhaseOffsets {
public:
    TestablePhaseOffsets(nsecs_t vsyncPhaseOffsetNs, nsecs_t sfVSyncPhaseOffsetNs,
                         std::optional<nsecs_t> earlySfOffsetNs,
                         std::optional<nsecs_t> earlyGpuSfOffsetNs,
                         std::optional<nsecs_t> earlyAppOffsetNs,
                         std::optional<nsecs_t> earlyGpuAppOffsetNs,
                         nsecs_t highFpsVsyncPhaseOffsetNs, nsecs_t highFpsSfVSyncPhaseOffsetNs,
                         std::optional<nsecs_t> highFpsEarlySfOffsetNs,
                         std::optional<nsecs_t> highFpsEarlyGpuSfOffsetNs,
                         std::optional<nsecs_t> highFpsEarlyAppOffsetNs,
                         std::optional<nsecs_t> highFpsEarlyGpuAppOffsetNs,
                         nsecs_t thresholdForNextVsync)
          : impl::PhaseOffsets(Fps(60.0f), vsyncPhaseOffsetNs, sfVSyncPhaseOffsetNs,
                               earlySfOffsetNs, earlyGpuSfOffsetNs, earlyAppOffsetNs,
                               earlyGpuAppOffsetNs, highFpsVsyncPhaseOffsetNs,
                               highFpsSfVSyncPhaseOffsetNs, highFpsEarlySfOffsetNs,
                               highFpsEarlyGpuSfOffsetNs, highFpsEarlyAppOffsetNs,
                               highFpsEarlyGpuAppOffsetNs, thresholdForNextVsync) {}
};

class PhaseOffsetsTest : public testing::Test {
protected:
    PhaseOffsetsTest() = default;
    ~PhaseOffsetsTest() = default;

    TestablePhaseOffsets mPhaseOffsets{2'000'000, 6'000'000, 7'000'000, 8'000'000, 3'000'000,
                                       4'000'000, 2'000'000, 1'000'000, 2'000'000, 3'000'000,
                                       3'000'000, 4'000'000, 10'000'000};
};

TEST_F(PhaseOffsetsTest, getConfigsForRefreshRate_unknownRefreshRate) {
    auto offsets = mPhaseOffsets.getConfigsForRefreshRate(Fps(14.7f));

    EXPECT_EQ(offsets.late.sfOffset, 6'000'000);
    EXPECT_EQ(offsets.late.appOffset, 2'000'000);

    EXPECT_EQ(offsets.late.sfWorkDuration, 62'027'208ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 72'027'208ns);

    EXPECT_EQ(offsets.early.sfOffset, 7'000'000);
    EXPECT_EQ(offsets.early.appOffset, 3'000'000);

    EXPECT_EQ(offsets.early.sfWorkDuration, 61'027'208ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 72'027'208ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 8'000'000);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 4'000'000);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 60'027'208ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 72'027'208ns);
}

TEST_F(PhaseOffsetsTest, getConfigsForRefreshRate_60Hz) {
    auto offsets = mPhaseOffsets.getConfigsForRefreshRate(Fps(60.0f));

    EXPECT_EQ(offsets.late.sfOffset, 6'000'000);
    EXPECT_EQ(offsets.late.appOffset, 2'000'000);

    EXPECT_EQ(offsets.late.sfWorkDuration, 10'666'667ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 20'666'667ns);

    EXPECT_EQ(offsets.early.sfOffset, 7'000'000);
    EXPECT_EQ(offsets.early.appOffset, 3'000'000);

    EXPECT_EQ(offsets.early.sfWorkDuration, 9'666'667ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 20'666'667ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 8'000'000);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 4'000'000);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 8'666'667ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 20'666'667ns);
}

TEST_F(PhaseOffsetsTest, getConfigsForRefreshRate_90Hz) {
    auto offsets = mPhaseOffsets.getConfigsForRefreshRate(Fps(90.0f));

    EXPECT_EQ(offsets.late.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.late.appOffset, 2'000'000);

    EXPECT_EQ(offsets.late.sfWorkDuration, 10'111'111ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 21'222'222ns);

    EXPECT_EQ(offsets.early.sfOffset, 2'000'000);
    EXPECT_EQ(offsets.early.appOffset, 3'000'000);

    EXPECT_EQ(offsets.early.sfWorkDuration, 9'111'111ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 21'222'222ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 3'000'000);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 4'000'000);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 8'111'111ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 21'222'222ns);
}

TEST_F(PhaseOffsetsTest, getConfigsForRefreshRate_DefaultValues_60Hz) {
    TestablePhaseOffsets phaseOffsets{1'000'000, 1'000'000, {}, {}, {}, {},        2'000'000,
                                      1'000'000, {},        {}, {}, {}, 10'000'000};
    auto offsets = phaseOffsets.getConfigsForRefreshRate(Fps(60.0f));

    EXPECT_EQ(offsets.late.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.late.appOffset, 1'000'000);

    EXPECT_EQ(offsets.late.sfWorkDuration, 15'666'667ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 16'666'667ns);

    EXPECT_EQ(offsets.early.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.early.appOffset, 1'000'000);

    EXPECT_EQ(offsets.early.sfWorkDuration, 15'666'667ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 16'666'667ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 1'000'000);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 15'666'667ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 16'666'667ns);
}

TEST_F(PhaseOffsetsTest, getConfigsForRefreshRate_DefaultValues_90Hz) {
    TestablePhaseOffsets phaseOffsets{1'000'000, 1'000'000, {}, {}, {}, {},        2'000'000,
                                      1'000'000, {},        {}, {}, {}, 10'000'000};
    auto offsets = phaseOffsets.getConfigsForRefreshRate(Fps(90.0f));

    EXPECT_EQ(offsets.late.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.late.appOffset, 2'000'000);

    EXPECT_EQ(offsets.late.sfWorkDuration, 10'111'111ns);
    EXPECT_EQ(offsets.late.appWorkDuration, 21'222'222ns);

    EXPECT_EQ(offsets.early.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.early.appOffset, 2'000'000);

    EXPECT_EQ(offsets.early.sfWorkDuration, 10'111'111ns);
    EXPECT_EQ(offsets.early.appWorkDuration, 21'222'222ns);

    EXPECT_EQ(offsets.earlyGpu.sfOffset, 1'000'000);
    EXPECT_EQ(offsets.earlyGpu.appOffset, 2'000'000);

    EXPECT_EQ(offsets.earlyGpu.sfWorkDuration, 10'111'111ns);
    EXPECT_EQ(offsets.earlyGpu.appWorkDuration, 21'222'222ns);
}

} // namespace android::scheduler
