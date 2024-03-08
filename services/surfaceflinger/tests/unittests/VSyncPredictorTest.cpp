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
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"
#define LOG_NDEBUG 0

#include <common/test/FlagUtils.h>
#include "Scheduler/VSyncPredictor.h"
#include "mock/DisplayHardware/MockDisplayMode.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <optional>
#include <utility>

#include <com_android_graphics_surfaceflinger_flags.h>

using namespace testing;
using namespace std::literals;
using namespace com::android::graphics::surfaceflinger;

using NotifyExpectedPresentConfig =
        ::aidl::android::hardware::graphics::composer3::VrrConfig::NotifyExpectedPresentConfig;

using android::mock::createDisplayMode;
using android::mock::createDisplayModeBuilder;
using android::mock::createVrrDisplayMode;

namespace android::scheduler {

namespace {
MATCHER_P2(IsCloseTo, value, tolerance, "is within tolerance") {
    return arg <= value + tolerance && arg >= value - tolerance;
}

MATCHER_P(FpsMatcher, value, "equals") {
    using fps_approx_ops::operator==;
    return arg == value;
}

std::vector<nsecs_t> generateVsyncTimestamps(size_t count, nsecs_t period, nsecs_t bias) {
    std::vector<nsecs_t> vsyncs(count);
    std::generate(vsyncs.begin(), vsyncs.end(),
                  [&, n = 0]() mutable { return n++ * period + bias; });
    return vsyncs;
}

constexpr PhysicalDisplayId DEFAULT_DISPLAY_ID = PhysicalDisplayId::fromPort(42u);

ftl::NonNull<DisplayModePtr> displayMode(nsecs_t period) {
    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto refreshRate = Fps::fromPeriodNsecs(period);
    return ftl::as_non_null(createDisplayMode(DisplayModeId(0), refreshRate, kGroup, kResolution,
                                              DEFAULT_DISPLAY_ID));
}

class TestClock : public Clock {
public:
    TestClock() = default;

    nsecs_t now() const override { return mNow; }
    void setNow(nsecs_t now) { mNow = now; }

private:
    nsecs_t mNow = 0;
};

class ClockWrapper : public Clock {
public:
    ClockWrapper(std::shared_ptr<Clock> const& clock) : mClock(clock) {}

    nsecs_t now() const { return mClock->now(); }

private:
    std::shared_ptr<Clock> const mClock;
};

} // namespace

struct VSyncPredictorTest : testing::Test {
    nsecs_t mNow = 0;
    nsecs_t mPeriod = 1000;
    ftl::NonNull<DisplayModePtr> mMode = displayMode(mPeriod);
    static constexpr size_t kHistorySize = 10;
    static constexpr size_t kMinimumSamplesForPrediction = 6;
    static constexpr size_t kOutlierTolerancePercent = 25;
    static constexpr nsecs_t mMaxRoundingError = 100;

    std::shared_ptr<TestClock> mClock{std::make_shared<TestClock>()};

    VSyncPredictor tracker{std::make_unique<ClockWrapper>(mClock), mMode, kHistorySize,
                           kMinimumSamplesForPrediction, kOutlierTolerancePercent};
};

TEST_F(VSyncPredictorTest, reportsAnticipatedPeriod) {
    auto model = tracker.getVSyncPredictionModel();

    EXPECT_THAT(model.slope, Eq(mPeriod));
    EXPECT_THAT(model.intercept, Eq(0));

    auto const changedPeriod = 2000;
    tracker.setDisplayModePtr(displayMode(changedPeriod));
    model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, Eq(changedPeriod));
    EXPECT_THAT(model.intercept, Eq(0));
}

TEST_F(VSyncPredictorTest, reportsSamplesNeededWhenHasNoDataPoints) {
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.needsMoreSamples());
        tracker.addVsyncTimestamp(mNow += mPeriod);
    }
    EXPECT_FALSE(tracker.needsMoreSamples());
}

TEST_F(VSyncPredictorTest, reportsSamplesNeededAfterExplicitRateChange) {
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        tracker.addVsyncTimestamp(mNow += mPeriod);
    }
    EXPECT_FALSE(tracker.needsMoreSamples());

    auto const changedPeriod = mPeriod * 2;
    tracker.setDisplayModePtr(displayMode(changedPeriod));
    EXPECT_TRUE(tracker.needsMoreSamples());

    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.needsMoreSamples());
        tracker.addVsyncTimestamp(mNow += changedPeriod);
    }
    EXPECT_FALSE(tracker.needsMoreSamples());
}

TEST_F(VSyncPredictorTest, transitionsToModelledPointsAfterSynthetic) {
    auto last = mNow;
    auto const bias = 10;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(last + mPeriod));
        mNow += mPeriod - bias;
        last = mNow;
        tracker.addVsyncTimestamp(mNow);
        mNow += bias;
    }

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod - bias));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 100), Eq(mNow + mPeriod - bias));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 990), Eq(mNow + 2 * mPeriod - bias));
}

TEST_F(VSyncPredictorTest, uponNotifiedOfInaccuracyUsesSynthetic) {
    auto const slightlyLessPeriod = mPeriod - 10;
    auto const changedPeriod = mPeriod - 1;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        tracker.addVsyncTimestamp(mNow += slightlyLessPeriod);
    }

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + slightlyLessPeriod));
    tracker.setDisplayModePtr(displayMode(changedPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + changedPeriod));
}

// b/159882858
TEST_F(VSyncPredictorTest, updatesTimebaseForSyntheticAfterIdleTime) {
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.addVsyncTimestamp(mNow += mPeriod));
    }

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod));

    auto const halfPeriod = mPeriod >> 2;
    nsecs_t relativelyLongGapWithDrift = mPeriod * 100 + halfPeriod;

    EXPECT_FALSE(tracker.addVsyncTimestamp(mNow += relativelyLongGapWithDrift));

    tracker.resetModel();
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod));
}

TEST_F(VSyncPredictorTest, uponBadVsyncWillSwitchToSyntheticWhileRecalibrating) {
    auto const slightlyMorePeriod = mPeriod + 10;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.addVsyncTimestamp(mNow += slightlyMorePeriod));
    }

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + slightlyMorePeriod));

    auto const halfPeriod = mPeriod >> 2;
    EXPECT_FALSE(tracker.addVsyncTimestamp(mNow += halfPeriod));

    tracker.resetModel();
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod));
}

TEST_F(VSyncPredictorTest, adaptsToFenceTimelines_60hzHighVariance) {
    // these are precomputed simulated 16.6s vsyncs with uniform distribution +/- 1.6ms error
    std::vector<nsecs_t> const simulatedVsyncs{
            15492949,  32325658,  49534984,  67496129,  84652891,
            100332564, 117737004, 132125931, 149291099, 165199602,
    };
    auto constexpr idealPeriod = 16600000;
    auto constexpr expectedPeriod = 16639242;
    auto constexpr expectedIntercept = 1049341;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }
    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, adaptsToFenceTimelines_90hzLowVariance) {
    // these are precomputed simulated 11.1 vsyncs with uniform distribution +/- 1ms error
    std::vector<nsecs_t> const simulatedVsyncs{
            11167047, 22603464, 32538479, 44938134, 56321268,
            66730346, 78062637, 88171429, 99707843, 111397621,
    };
    auto idealPeriod = 11110000;
    auto expectedPeriod = 11089413;
    auto expectedIntercept = 94421;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }
    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, adaptsToFenceTimelinesDiscontinuous_22hzLowVariance) {
    // these are 11.1s vsyncs with low variance, randomly computed, between -1 and 1ms
    std::vector<nsecs_t> const simulatedVsyncs{
            45259463,   // 0
            91511026,   // 1
            136307650,  // 2
            1864501714, // 40
            1908641034, // 41
            1955278544, // 42
            4590180096, // 100
            4681594994, // 102
            5499224734, // 120
            5591378272, // 122
    };
    auto idealPeriod = 45454545;
    auto expectedPeriod = 45450152;
    auto expectedIntercept = 469647;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }
    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, againstOutliersDiscontinuous_500hzLowVariance) {
    std::vector<nsecs_t> const simulatedVsyncs{
            1992548,    // 0
            4078038,    // 1
            6165794,    // 2
            7958171,    // 3
            10193537,   // 4
            2401840200, // 1200
            2403000000, // an outlier that should be excluded (1201 and a half)
            2405803629, // 1202
            2408028599, // 1203
            2410121051, // 1204
    };
    auto idealPeriod = 2000000;
    auto expectedPeriod = 1999892;
    auto expectedIntercept = 86342;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }

    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, handlesVsyncChange) {
    auto const fastPeriod = 100;
    auto const fastTimeBase = 100;
    auto const slowPeriod = 400;
    auto const slowTimeBase = 800;
    auto const simulatedVsyncsFast =
            generateVsyncTimestamps(kMinimumSamplesForPrediction, fastPeriod, fastTimeBase);
    auto const simulatedVsyncsSlow =
            generateVsyncTimestamps(kMinimumSamplesForPrediction, slowPeriod, slowTimeBase);

    tracker.setDisplayModePtr(displayMode(fastPeriod));
    for (auto const& timestamp : simulatedVsyncsFast) {
        tracker.addVsyncTimestamp(timestamp);
    }

    auto const mMaxRoundingError = 100;
    auto model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, IsCloseTo(fastPeriod, mMaxRoundingError));
    EXPECT_THAT(model.intercept, IsCloseTo(0, mMaxRoundingError));

    tracker.setDisplayModePtr(displayMode(slowPeriod));
    for (auto const& timestamp : simulatedVsyncsSlow) {
        tracker.addVsyncTimestamp(timestamp);
    }
    model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, IsCloseTo(slowPeriod, mMaxRoundingError));
    EXPECT_THAT(model.intercept, IsCloseTo(0, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, willBeAccurateUsingPriorResultsForRate) {
    auto const fastPeriod = 101000;
    auto const fastTimeBase = fastPeriod - 500;
    auto const fastPeriod2 = 99000;

    auto const slowPeriod = 400000;
    auto const slowTimeBase = 800000 - 201;
    auto const simulatedVsyncsFast =
            generateVsyncTimestamps(kMinimumSamplesForPrediction, fastPeriod, fastTimeBase);
    auto const simulatedVsyncsSlow =
            generateVsyncTimestamps(kMinimumSamplesForPrediction, slowPeriod, slowTimeBase);
    auto const simulatedVsyncsFast2 =
            generateVsyncTimestamps(kMinimumSamplesForPrediction, fastPeriod2, fastTimeBase);

    auto idealPeriod = 100000;
    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncsFast) {
        tracker.addVsyncTimestamp(timestamp);
    }
    auto model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, Eq(fastPeriod));
    EXPECT_THAT(model.intercept, Eq(0));

    tracker.setDisplayModePtr(displayMode(slowPeriod));
    for (auto const& timestamp : simulatedVsyncsSlow) {
        tracker.addVsyncTimestamp(timestamp);
    }

    // we had a model for 100ns mPeriod before, use that until the new samples are
    // sufficiently built up
    tracker.setDisplayModePtr(displayMode(idealPeriod));
    model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, Eq(fastPeriod));
    EXPECT_THAT(model.intercept, Eq(0));

    for (auto const& timestamp : simulatedVsyncsFast2) {
        tracker.addVsyncTimestamp(timestamp);
    }
    model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, Eq(fastPeriod2));
    EXPECT_THAT(model.intercept, Eq(0));
}

TEST_F(VSyncPredictorTest, idealModelPredictionsBeforeRegressionModelIsBuilt) {
    auto const simulatedVsyncs =
            generateVsyncTimestamps(kMinimumSamplesForPrediction + 1, mPeriod, 0);
    nsecs_t const mNow = 0;
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mPeriod));

    nsecs_t const aBitOfTime = 422;

    for (auto i = 0; i < kMinimumSamplesForPrediction; i++) {
        tracker.addVsyncTimestamp(simulatedVsyncs[i]);
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(simulatedVsyncs[i] + aBitOfTime),
                    Eq(mPeriod + simulatedVsyncs[i]));
    }

    for (auto i = kMinimumSamplesForPrediction; i < simulatedVsyncs.size(); i++) {
        tracker.addVsyncTimestamp(simulatedVsyncs[i]);
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(simulatedVsyncs[i] + aBitOfTime),
                    Eq(mPeriod + simulatedVsyncs[i]));
    }
}

// See b/145667109, and comment in prod code under test.
TEST_F(VSyncPredictorTest, doesNotPredictBeforeTimePointWithHigherIntercept) {
    std::vector<nsecs_t> const simulatedVsyncs{
            158929578733000,
            158929306806205, // oldest TS in ringbuffer
            158929650879052,
            158929661969209,
            158929684198847,
            158929695268171,
            158929706370359,
    };
    auto const idealPeriod = 11111111;
    auto const expectedPeriod = 11113919;
    auto const expectedIntercept = -1195945;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }

    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));

    // (timePoint - oldestTS) % expectedPeriod works out to be: 395334
    // (timePoint - oldestTS) / expectedPeriod works out to be: 38.96
    // so failure to account for the offset will floor the ordinal to 38, which was in the past.
    auto const timePoint = 158929728723871;
    auto const prediction = tracker.nextAnticipatedVSyncTimeFrom(timePoint);
    EXPECT_THAT(prediction, Ge(timePoint));
}

// See b/151146131
TEST_F(VSyncPredictorTest, hasEnoughPrecision) {
    const auto mode = displayMode(mPeriod);
    VSyncPredictor tracker{std::make_unique<ClockWrapper>(mClock), mode, 20,
                           kMinimumSamplesForPrediction, kOutlierTolerancePercent};
    std::vector<nsecs_t> const simulatedVsyncs{840873348817, 840890049444, 840906762675,
                                               840923581635, 840940161584, 840956868096,
                                               840973702473, 840990256277, 841007116851,
                                               841023722530, 841040452167, 841057073002,
                                               841073800920, 841090474360, 841107278632,
                                               841123898634, 841140750875, 841157287127,
                                               841591357014, 840856664232

    };
    auto const idealPeriod = 16666666;
    auto const expectedPeriod = 16698426;
    auto const expectedIntercept = 58055;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }

    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, resetsWhenInstructed) {
    auto const idealPeriod = 10000;
    auto const realPeriod = 10500;
    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto i = 0; i < kMinimumSamplesForPrediction; i++) {
        tracker.addVsyncTimestamp(i * realPeriod);
    }

    EXPECT_THAT(tracker.getVSyncPredictionModel().slope, IsCloseTo(realPeriod, mMaxRoundingError));
    tracker.resetModel();
    EXPECT_THAT(tracker.getVSyncPredictionModel().slope, IsCloseTo(idealPeriod, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, slopeAlwaysValid) {
    constexpr auto kNumVsyncs = 100;
    auto invalidPeriod = mPeriod;
    auto now = 0;
    for (int i = 0; i < kNumVsyncs; i++) {
        tracker.addVsyncTimestamp(now);
        now += invalidPeriod;
        invalidPeriod *= 0.9f;

        auto [slope, intercept] = tracker.getVSyncPredictionModel();
        EXPECT_THAT(slope, IsCloseTo(mPeriod, mPeriod * kOutlierTolerancePercent / 100.f));

        // When VsyncPredictor returns the period it means that it doesn't know how to predict and
        // it needs to get more samples
        if (slope == mPeriod && intercept == 0) {
            EXPECT_TRUE(tracker.needsMoreSamples());
        }
    }
}

constexpr nsecs_t operator""_years(unsigned long long years) noexcept {
    using namespace std::chrono_literals;
    return years * 365 * 24 * 3600 *
            std::chrono::duration_cast<std::chrono::nanoseconds>(1s).count();
}
TEST_F(VSyncPredictorTest, aPhoneThatHasBeenAroundAWhileCanStillComputePeriod) {
    constexpr nsecs_t timeBase = 100_years;

    for (auto i = 0; i < kHistorySize; i++) {
        tracker.addVsyncTimestamp(timeBase + i * mPeriod);
    }
    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(mPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, Eq(0));
}

TEST_F(VSyncPredictorTest, isVSyncInPhase) {
    auto last = mNow;
    auto const bias = 10;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(last + mPeriod));
        mNow += mPeriod - bias;
        last = mNow;
        tracker.addVsyncTimestamp(mNow);
        mNow += bias;
    }

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod - bias));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 100), Eq(mNow + mPeriod - bias));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 990), Eq(mNow + 2 * mPeriod - bias));

    const auto maxDivisor = 5;
    const auto maxPeriods = 15;
    for (int divisor = 1; divisor < maxDivisor; divisor++) {
        for (int i = 0; i < maxPeriods; i++) {
            const bool expectedInPhase = ((kMinimumSamplesForPrediction - 1 + i) % divisor) == 0;
            EXPECT_THAT(expectedInPhase,
                        tracker.isVSyncInPhase(mNow + i * mPeriod - bias,
                                               Fps::fromPeriodNsecs(divisor * mPeriod)))
                    << "vsync at " << mNow + (i + 1) * mPeriod - bias << " is "
                    << (expectedInPhase ? "not " : "") << "in phase for divisor " << divisor;
        }
    }
}

TEST_F(VSyncPredictorTest, isVSyncInPhaseForDivisors) {
    auto last = mNow;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(last + mPeriod));
        mNow += mPeriod;
        last = mNow;
        tracker.addVsyncTimestamp(mNow);
    }

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod));

    EXPECT_TRUE(tracker.isVSyncInPhase(mNow + 1 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 2)));
    EXPECT_FALSE(tracker.isVSyncInPhase(mNow + 2 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 2)));
    EXPECT_TRUE(tracker.isVSyncInPhase(mNow + 3 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 2)));

    EXPECT_FALSE(tracker.isVSyncInPhase(mNow + 5 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 4)));
    EXPECT_TRUE(tracker.isVSyncInPhase(mNow + 3 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 4)));
    EXPECT_FALSE(tracker.isVSyncInPhase(mNow + 4 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 4)));
    EXPECT_FALSE(tracker.isVSyncInPhase(mNow + 6 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 4)));
    EXPECT_TRUE(tracker.isVSyncInPhase(mNow + 7 * mPeriod, Fps::fromPeriodNsecs(mPeriod * 4)));
}

TEST_F(VSyncPredictorTest, inconsistentVsyncValueIsFlushedEventually) {
    EXPECT_TRUE(tracker.addVsyncTimestamp(600));
    EXPECT_TRUE(tracker.needsMoreSamples());

    EXPECT_FALSE(tracker.addVsyncTimestamp(mNow += mPeriod));

    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.needsMoreSamples());
        EXPECT_TRUE(tracker.addVsyncTimestamp(mNow += mPeriod));
    }

    EXPECT_FALSE(tracker.needsMoreSamples());
}

TEST_F(VSyncPredictorTest, knownVsyncIsUpdated) {
    EXPECT_TRUE(tracker.addVsyncTimestamp(600));
    EXPECT_TRUE(tracker.needsMoreSamples());
    EXPECT_EQ(600, tracker.nextAnticipatedVSyncTimeFrom(mNow));

    EXPECT_FALSE(tracker.addVsyncTimestamp(mNow += mPeriod));
    EXPECT_EQ(mNow + 1000, tracker.nextAnticipatedVSyncTimeFrom(mNow));

    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.needsMoreSamples());
        EXPECT_TRUE(tracker.addVsyncTimestamp(mNow += mPeriod));
        EXPECT_EQ(mNow + 1000, tracker.nextAnticipatedVSyncTimeFrom(mNow));
    }

    EXPECT_FALSE(tracker.needsMoreSamples());
    EXPECT_EQ(mNow + 1000, tracker.nextAnticipatedVSyncTimeFrom(mNow));
}

TEST_F(VSyncPredictorTest, robustToDuplicateTimestamps_60hzRealTraceData) {
    // these are real vsync timestamps from b/190331974 which caused vsync predictor
    // period to spike to 18ms due to very close timestamps
    std::vector<nsecs_t> const simulatedVsyncs{
            198353408177, 198370074844, 198371400000, 198374274000, 198390941000, 198407565000,
            198540887994, 198607538588, 198624218276, 198657655939, 198674224176, 198690880955,
            198724204319, 198740988133, 198758166681, 198790869196, 198824205052, 198840871678,
            198857715631, 198890885797, 198924199640, 198940873834, 198974204401,
    };
    auto constexpr idealPeriod = 16'666'666;
    auto constexpr expectedPeriod = 16'644'742;
    auto constexpr expectedIntercept = 125'626;

    tracker.setDisplayModePtr(displayMode(idealPeriod));
    for (auto const& timestamp : simulatedVsyncs) {
        tracker.addVsyncTimestamp(timestamp);
    }
    auto [slope, intercept] = tracker.getVSyncPredictionModel();
    EXPECT_THAT(slope, IsCloseTo(expectedPeriod, mMaxRoundingError));
    EXPECT_THAT(intercept, IsCloseTo(expectedIntercept, mMaxRoundingError));
}

TEST_F(VSyncPredictorTest, setRenderRateIsRespected) {
    auto last = mNow;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(last + mPeriod));
        mNow += mPeriod;
        last = mNow;
        tracker.addVsyncTimestamp(mNow);
    }

    tracker.setRenderRate(Fps::fromPeriodNsecs(3 * mPeriod), /*applyImmediately*/ false);

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + 3 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 100), Eq(mNow + 3 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 1100), Eq(mNow + 3 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 2100), Eq(mNow + 3 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 3100), Eq(mNow + 6 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 4100), Eq(mNow + 6 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 5100), Eq(mNow + 6 * mPeriod));
}

TEST_F(VSyncPredictorTest, setRenderRateIsIgnoredIfNotDivisor) {
    auto last = mNow;
    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(last + mPeriod));
        mNow += mPeriod;
        last = mNow;
        tracker.addVsyncTimestamp(mNow);
    }

    tracker.setRenderRate(Fps::fromPeriodNsecs(3.5f * mPeriod), /*applyImmediately*/ false);

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow), Eq(mNow + mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 100), Eq(mNow + mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 1100), Eq(mNow + 2 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 2100), Eq(mNow + 3 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 3100), Eq(mNow + 4 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 4100), Eq(mNow + 5 * mPeriod));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(mNow + 5100), Eq(mNow + 6 * mPeriod));
}

TEST_F(VSyncPredictorTest, setRenderRateHighIsAppliedImmediately) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto vsyncRate = Fps::fromPeriodNsecs(500);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), vsyncRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(1000), /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);
    EXPECT_EQ(1000, vrrTracker.nextAnticipatedVSyncTimeFrom(700));
    EXPECT_EQ(2000, vrrTracker.nextAnticipatedVSyncTimeFrom(1000, 1000));

    // commit to a vsync in the future
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(2000), /*applyImmediately*/ false);
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4000, 4000));
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));
    EXPECT_EQ(8000, vrrTracker.nextAnticipatedVSyncTimeFrom(6000, 6000));

    EXPECT_EQ(12000, vrrTracker.nextAnticipatedVSyncTimeFrom(10000, 10000));

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(3500), /*applyImmediately*/ false);
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4000, 4000));
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));
    EXPECT_EQ(8000, vrrTracker.nextAnticipatedVSyncTimeFrom(6000, 6000));
    EXPECT_EQ(10000, vrrTracker.nextAnticipatedVSyncTimeFrom(8000, 8000));
    EXPECT_EQ(12000, vrrTracker.nextAnticipatedVSyncTimeFrom(10000, 10000));
    EXPECT_EQ(15500, vrrTracker.nextAnticipatedVSyncTimeFrom(12000, 12000));
    EXPECT_EQ(19000, vrrTracker.nextAnticipatedVSyncTimeFrom(15500, 15500));

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(2500), /*applyImmediately*/ false);
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4000, 4000));
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));
    EXPECT_EQ(8000, vrrTracker.nextAnticipatedVSyncTimeFrom(6000, 6000));
    EXPECT_EQ(10000, vrrTracker.nextAnticipatedVSyncTimeFrom(8000, 8000));
    EXPECT_EQ(12000, vrrTracker.nextAnticipatedVSyncTimeFrom(10000, 10000));
    EXPECT_EQ(15500, vrrTracker.nextAnticipatedVSyncTimeFrom(12000, 12000));
    EXPECT_EQ(19000, vrrTracker.nextAnticipatedVSyncTimeFrom(15500, 15500));
    EXPECT_EQ(21500, vrrTracker.nextAnticipatedVSyncTimeFrom(19000, 19000));

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(1000), /*applyImmediately*/ false);
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4000, 4000));
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));
    EXPECT_EQ(7000, vrrTracker.nextAnticipatedVSyncTimeFrom(6000, 6000));
    EXPECT_EQ(9000, vrrTracker.nextAnticipatedVSyncTimeFrom(8000, 8000));
    EXPECT_EQ(11000, vrrTracker.nextAnticipatedVSyncTimeFrom(10000, 10000));
    EXPECT_EQ(13000, vrrTracker.nextAnticipatedVSyncTimeFrom(12000, 12000));
    EXPECT_EQ(17000, vrrTracker.nextAnticipatedVSyncTimeFrom(15500, 15500));
    EXPECT_EQ(20000, vrrTracker.nextAnticipatedVSyncTimeFrom(19000, 19000));
}

TEST_F(VSyncPredictorTest, minFramePeriodDoesntApplyWhenSameWithRefreshRate) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto vsyncRate = Fps::fromPeriodNsecs(1000);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), vsyncRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(1000), /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);
    EXPECT_EQ(1000, vrrTracker.nextAnticipatedVSyncTimeFrom(700));
    EXPECT_EQ(2000, vrrTracker.nextAnticipatedVSyncTimeFrom(1000, 1000));

    // Assume that the last vsync is wrong due to a vsync drift. It shouldn't matter.
    EXPECT_EQ(2000, vrrTracker.nextAnticipatedVSyncTimeFrom(1000, 1700));
}

TEST_F(VSyncPredictorTest, setRenderRateExplicitAppliedImmediately) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto vsyncRate = Fps::fromPeriodNsecs(500);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), vsyncRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(1000), /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);
    EXPECT_EQ(1000, vrrTracker.nextAnticipatedVSyncTimeFrom(700));
    EXPECT_EQ(2000, vrrTracker.nextAnticipatedVSyncTimeFrom(1000, 1000));

    // commit to a vsync in the future
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 2000));

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(2000), /*applyImmediately*/ true);
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4000));
    EXPECT_EQ(7000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));
    EXPECT_EQ(9000, vrrTracker.nextAnticipatedVSyncTimeFrom(7000, 7000));
}

TEST_F(VSyncPredictorTest, selectsClosestVsyncAfterInactivity) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto vsyncRate = Fps::fromPeriodNsecs(500);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), vsyncRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(5000), /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4700));
    EXPECT_EQ(10000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));

    mClock->setNow(50000);
    EXPECT_EQ(50500, vrrTracker.nextAnticipatedVSyncTimeFrom(50000, 10000));
}

TEST_F(VSyncPredictorTest, returnsCorrectVsyncWhenLastIsNot) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto vsyncRate = Fps::fromPeriodNsecs(500);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), vsyncRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(Fps::fromPeriodNsecs(1000), /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);
    EXPECT_EQ(2000, vrrTracker.nextAnticipatedVSyncTimeFrom(1234, 1234));
}

TEST_F(VSyncPredictorTest, adjustsVrrTimeline) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto refreshRate = Fps::fromPeriodNsecs(500);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), refreshRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(minFrameRate, /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);
    EXPECT_EQ(1000, vrrTracker.nextAnticipatedVSyncTimeFrom(700));
    EXPECT_EQ(2000, vrrTracker.nextAnticipatedVSyncTimeFrom(1000));

    vrrTracker.onFrameBegin(TimePoint::fromNs(2000), TimePoint::fromNs(1500));
    EXPECT_EQ(3500, vrrTracker.nextAnticipatedVSyncTimeFrom(2000, 2000));
    EXPECT_EQ(4500, vrrTracker.nextAnticipatedVSyncTimeFrom(3500, 3500));

    // Miss when starting 4500 and expect the next vsync will be at 5000 (next one)
    vrrTracker.onFrameBegin(TimePoint::fromNs(3500), TimePoint::fromNs(2500));
    vrrTracker.onFrameMissed(TimePoint::fromNs(4500));
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4500, 4500));
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));

    vrrTracker.onFrameBegin(TimePoint::fromNs(7000), TimePoint::fromNs(6500));
    EXPECT_EQ(10500, vrrTracker.nextAnticipatedVSyncTimeFrom(9000, 7000));
}

TEST_F(VSyncPredictorTest, adjustsVrrTimelineTwoClients) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto refreshRate = Fps::fromPeriodNsecs(500);
    const auto minFrameRate = Fps::fromPeriodNsecs(1000);
    hal::VrrConfig vrrConfig;
    vrrConfig.minFrameIntervalNs = minFrameRate.getPeriodNsecs();
    const ftl::NonNull<DisplayModePtr> kMode =
            ftl::as_non_null(createDisplayModeBuilder(DisplayModeId(0), refreshRate, kGroup,
                                                      kResolution, DEFAULT_DISPLAY_ID)
                                     .setVrrConfig(std::move(vrrConfig))
                                     .build());

    VSyncPredictor vrrTracker{std::make_unique<ClockWrapper>(mClock), kMode, kHistorySize,
                              kMinimumSamplesForPrediction, kOutlierTolerancePercent};

    vrrTracker.setRenderRate(minFrameRate, /*applyImmediately*/ false);
    vrrTracker.addVsyncTimestamp(0);

    // App runs ahead
    EXPECT_EQ(3000, vrrTracker.nextAnticipatedVSyncTimeFrom(2700));
    EXPECT_EQ(4000, vrrTracker.nextAnticipatedVSyncTimeFrom(3000, 3000));
    EXPECT_EQ(5000, vrrTracker.nextAnticipatedVSyncTimeFrom(4000, 4000));

    // SF starts to catch up
    EXPECT_EQ(3000, vrrTracker.nextAnticipatedVSyncTimeFrom(2700));
    vrrTracker.onFrameBegin(TimePoint::fromNs(3000), TimePoint::fromNs(0));

    // SF misses last frame (3000) and observes that when committing (4000)
    EXPECT_EQ(6000, vrrTracker.nextAnticipatedVSyncTimeFrom(5000, 5000));
    EXPECT_EQ(4000, vrrTracker.nextAnticipatedVSyncTimeFrom(3700));
    vrrTracker.onFrameMissed(TimePoint::fromNs(4000));

    // SF wakes up again instead of the (4000) missed frame
    EXPECT_EQ(4500, vrrTracker.nextAnticipatedVSyncTimeFrom(4000, 4000));
    vrrTracker.onFrameBegin(TimePoint::fromNs(4500), TimePoint::fromNs(4500));

    // Timeline shifted. The app needs to get the next frame at (7500) as its last frame (6500) will
    // be presented at (7500)
    EXPECT_EQ(7500, vrrTracker.nextAnticipatedVSyncTimeFrom(6000, 6000));
    EXPECT_EQ(5500, vrrTracker.nextAnticipatedVSyncTimeFrom(4500, 4500));
    vrrTracker.onFrameBegin(TimePoint::fromNs(5500), TimePoint::fromNs(4500));

    EXPECT_EQ(8500, vrrTracker.nextAnticipatedVSyncTimeFrom(7500, 7500));
    EXPECT_EQ(6500, vrrTracker.nextAnticipatedVSyncTimeFrom(5500, 5500));
    vrrTracker.onFrameBegin(TimePoint::fromNs(6500), TimePoint::fromNs(5500));
}

TEST_F(VSyncPredictorTest, renderRateIsPreservedForCommittedVsyncs) {
    tracker.addVsyncTimestamp(1000);

    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(1), Eq(1000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(5001), Eq(6000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(6001), Eq(7000));

    tracker.setRenderRate(Fps::fromPeriodNsecs(2000), /*applyImmediately*/ false);
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(1), Eq(1000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(5001), Eq(6000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(6001), Eq(7000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(7001), Eq(9000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(8001), Eq(9000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(9001), Eq(11000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(10001), Eq(11000));

    tracker.setRenderRate(Fps::fromPeriodNsecs(3000), /*applyImmediately*/ false);
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(1), Eq(1000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(5001), Eq(6000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(6001), Eq(7000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(7001), Eq(9000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(8001), Eq(9000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(9001), Eq(11000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(10001), Eq(11000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(11001), Eq(14000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(12001), Eq(14000));

    // Check the purge logic works
    mClock->setNow(20000);
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(1), Eq(2000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(5001), Eq(8000));
    EXPECT_THAT(tracker.nextAnticipatedVSyncTimeFrom(6001), Eq(8000));
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
