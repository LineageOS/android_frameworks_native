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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <log/log.h>
#include <thread>

#include "Scheduler/PhaseOffsets.h"

using namespace testing;

namespace android {
namespace scheduler {

class TestablePhaseOffsetsAsDurations : public impl::PhaseDurations {
public:
    TestablePhaseOffsetsAsDurations(float currentFps, nsecs_t sfDuration, nsecs_t appDuration,
                                    nsecs_t sfEarlyDuration, nsecs_t appEarlyDuration,
                                    nsecs_t sfEarlyGlDuration, nsecs_t appEarlyGlDuration)
          : impl::PhaseDurations({60.0f, 90.0f}, currentFps, sfDuration, appDuration,
                                 sfEarlyDuration, appEarlyDuration, sfEarlyGlDuration,
                                 appEarlyGlDuration) {}
};

class PhaseOffsetsTest : public testing::Test {
protected:
    PhaseOffsetsTest()
          : mPhaseOffsets(60.0f, 10'500'000, 20'500'000, 16'000'000, 33'500'000, 13'500'000,
                          38'000'000) {}

    ~PhaseOffsetsTest() = default;

    TestablePhaseOffsetsAsDurations mPhaseOffsets;
};

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(PhaseOffsetsTest, getOffsetsForRefreshRate_60Hz) {
    mPhaseOffsets.setRefreshRateFps(60.0f);
    auto currentOffsets = mPhaseOffsets.getCurrentOffsets();
    auto offsets = mPhaseOffsets.getOffsetsForRefreshRate(60.0f);

    EXPECT_EQ(currentOffsets, offsets);
    EXPECT_EQ(offsets.late.sf, 6'166'667);

    EXPECT_EQ(offsets.late.app, 2'333'334);

    EXPECT_EQ(offsets.early.sf, 666'667);

    EXPECT_EQ(offsets.early.app, 500'001);

    EXPECT_EQ(offsets.earlyGl.sf, 3'166'667);

    EXPECT_EQ(offsets.earlyGl.app, 15'166'668);
}

TEST_F(PhaseOffsetsTest, getOffsetsForRefreshRate_90Hz) {
    mPhaseOffsets.setRefreshRateFps(90.0f);
    auto currentOffsets = mPhaseOffsets.getCurrentOffsets();
    auto offsets = mPhaseOffsets.getOffsetsForRefreshRate(90.0f);

    EXPECT_EQ(currentOffsets, offsets);
    EXPECT_EQ(offsets.late.sf, 611'111);

    EXPECT_EQ(offsets.late.app, 2'333'333);

    EXPECT_EQ(offsets.early.sf, -4'888'889);

    EXPECT_EQ(offsets.early.app, 6'055'555);

    EXPECT_EQ(offsets.earlyGl.sf, -2'388'889);

    EXPECT_EQ(offsets.earlyGl.app, 4'055'555);
}

TEST_F(PhaseOffsetsTest, getOffsetsForRefreshRate_DefaultOffsets) {
    TestablePhaseOffsetsAsDurations phaseOffsetsWithDefaultValues(60.0f, -1, -1, -1, -1, -1, -1);

    auto validateOffsets = [](auto& offsets) {
        EXPECT_EQ(offsets.late.sf, 1'000'000);

        EXPECT_EQ(offsets.late.app, 1'000'000);

        EXPECT_EQ(offsets.early.sf, 1'000'000);

        EXPECT_EQ(offsets.early.app, 1'000'000);

        EXPECT_EQ(offsets.earlyGl.sf, 1'000'000);

        EXPECT_EQ(offsets.earlyGl.app, 1'000'000);
    };

    phaseOffsetsWithDefaultValues.setRefreshRateFps(90.0f);
    auto currentOffsets = phaseOffsetsWithDefaultValues.getCurrentOffsets();
    auto offsets = phaseOffsetsWithDefaultValues.getOffsetsForRefreshRate(90.0f);
    EXPECT_EQ(currentOffsets, offsets);
    validateOffsets(offsets);

    phaseOffsetsWithDefaultValues.setRefreshRateFps(60.0f);
    currentOffsets = phaseOffsetsWithDefaultValues.getCurrentOffsets();
    offsets = phaseOffsetsWithDefaultValues.getOffsetsForRefreshRate(90.0f);
    EXPECT_EQ(currentOffsets, offsets);
    validateOffsets(offsets);
}

} // namespace
} // namespace scheduler
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"