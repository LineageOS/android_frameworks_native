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

class PhaseDurationTest : public testing::Test {
protected:
    PhaseDurationTest()
          : mPhaseDurations(60.0f, 10'500'000, 20'500'000, 16'000'000, 16'500'000, 13'500'000,
                            21'000'000) {}

    ~PhaseDurationTest() = default;

    TestablePhaseOffsetsAsDurations mPhaseDurations;
};

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(PhaseDurationTest, getOffsetsForRefreshRate_60Hz) {
    mPhaseDurations.setRefreshRateFps(60.0f);
    auto currentOffsets = mPhaseDurations.getCurrentOffsets();
    auto offsets = mPhaseDurations.getOffsetsForRefreshRate(60.0f);

    EXPECT_EQ(currentOffsets, offsets);
    EXPECT_EQ(offsets.late.sf, 6'166'667);

    EXPECT_EQ(offsets.late.app, 2'333'334);

    EXPECT_EQ(offsets.early.sf, 666'667);

    EXPECT_EQ(offsets.early.app, 833'334);

    EXPECT_EQ(offsets.earlyGl.sf, 3'166'667);

    EXPECT_EQ(offsets.earlyGl.app, 15'500'001);
}

TEST_F(PhaseDurationTest, getOffsetsForRefreshRate_90Hz) {
    mPhaseDurations.setRefreshRateFps(90.0f);
    auto currentOffsets = mPhaseDurations.getCurrentOffsets();
    auto offsets = mPhaseDurations.getOffsetsForRefreshRate(90.0f);

    EXPECT_EQ(currentOffsets, offsets);
    EXPECT_EQ(offsets.late.sf, 611'111);

    EXPECT_EQ(offsets.late.app, 2'333'333);

    EXPECT_EQ(offsets.early.sf, -4'888'889);

    EXPECT_EQ(offsets.early.app, 833'333);

    EXPECT_EQ(offsets.earlyGl.sf, -2'388'889);

    EXPECT_EQ(offsets.earlyGl.app, 9'944'444);
}

TEST_F(PhaseDurationTest, getOffsetsForRefreshRate_DefaultOffsets) {
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

TEST_F(PhaseDurationTest, getOffsetsForRefreshRate_unknownRefreshRate) {
    auto offsets = mPhaseDurations.getOffsetsForRefreshRate(14.7f);

    EXPECT_EQ(offsets.late.sf, 57'527'208);

    EXPECT_EQ(offsets.late.app, 37'027'208);

    EXPECT_EQ(offsets.early.sf, 52'027'208);

    EXPECT_EQ(offsets.early.app, 35'527'208);

    EXPECT_EQ(offsets.earlyGl.sf, 54'527'208);

    EXPECT_EQ(offsets.earlyGl.app, 33'527'208);
}

} // namespace

class TestablePhaseOffsets : public impl::PhaseOffsets {
public:
    TestablePhaseOffsets()
          : impl::PhaseOffsets({60.0f, 90.0f}, 60.0f, 1'000'000, 1'000'000, {}, {}, {}, {},
                               10'000'000) {}
};

class PhaseOffsetsTest : public testing::Test {
protected:
    PhaseOffsetsTest() = default;
    ~PhaseOffsetsTest() = default;

    TestablePhaseOffsets mPhaseOffsets;
};

namespace {
TEST_F(PhaseOffsetsTest, getOffsetsForRefreshRate_unknownRefreshRate) {
    auto offsets = mPhaseOffsets.getOffsetsForRefreshRate(14.7f);

    EXPECT_EQ(offsets.late.sf, 1'000'000);

    EXPECT_EQ(offsets.late.app, 1'000'000);

    EXPECT_EQ(offsets.early.sf, 1'000'000);

    EXPECT_EQ(offsets.early.app, 1'000'000);

    EXPECT_EQ(offsets.earlyGl.sf, 1'000'000);

    EXPECT_EQ(offsets.earlyGl.app, 1'000'000);
}

} // namespace
} // namespace scheduler
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"