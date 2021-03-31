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

#include "Scheduler/VSyncPredictor.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <utility>

using namespace testing;
using namespace std::literals;

namespace android::scheduler {

MATCHER_P2(IsCloseTo, value, tolerance, "is within tolerance") {
    return arg <= value + tolerance && arg >= value - tolerance;
}

std::vector<nsecs_t> generateVsyncTimestamps(size_t count, nsecs_t period, nsecs_t bias) {
    std::vector<nsecs_t> vsyncs(count);
    std::generate(vsyncs.begin(), vsyncs.end(),
                  [&, n = 0]() mutable { return n++ * period + bias; });
    return vsyncs;
}

struct VSyncPredictorTest : testing::Test {
    nsecs_t mNow = 0;
    nsecs_t mPeriod = 1000;
    static constexpr size_t kHistorySize = 10;
    static constexpr size_t kMinimumSamplesForPrediction = 6;
    static constexpr size_t kOutlierTolerancePercent = 25;
    static constexpr nsecs_t mMaxRoundingError = 100;

    VSyncPredictor tracker{mPeriod, kHistorySize, kMinimumSamplesForPrediction,
                           kOutlierTolerancePercent};
};

TEST_F(VSyncPredictorTest, reportsAnticipatedPeriod) {
    auto model = tracker.getVSyncPredictionModel();

    EXPECT_THAT(model.slope, Eq(mPeriod));
    EXPECT_THAT(model.intercept, Eq(0));

    auto const changedPeriod = 2000;
    tracker.setPeriod(changedPeriod);
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
    tracker.setPeriod(changedPeriod);
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
    tracker.setPeriod(changedPeriod);
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

    tracker.setPeriod(idealPeriod);
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

    tracker.setPeriod(idealPeriod);
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

    tracker.setPeriod(idealPeriod);
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

    tracker.setPeriod(idealPeriod);
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

    tracker.setPeriod(fastPeriod);
    for (auto const& timestamp : simulatedVsyncsFast) {
        tracker.addVsyncTimestamp(timestamp);
    }

    auto const mMaxRoundingError = 100;
    auto model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, IsCloseTo(fastPeriod, mMaxRoundingError));
    EXPECT_THAT(model.intercept, IsCloseTo(0, mMaxRoundingError));

    tracker.setPeriod(slowPeriod);
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
    tracker.setPeriod(idealPeriod);
    for (auto const& timestamp : simulatedVsyncsFast) {
        tracker.addVsyncTimestamp(timestamp);
    }
    auto model = tracker.getVSyncPredictionModel();
    EXPECT_THAT(model.slope, Eq(fastPeriod));
    EXPECT_THAT(model.intercept, Eq(0));

    tracker.setPeriod(slowPeriod);
    for (auto const& timestamp : simulatedVsyncsSlow) {
        tracker.addVsyncTimestamp(timestamp);
    }

    // we had a model for 100ns mPeriod before, use that until the new samples are
    // sufficiently built up
    tracker.setPeriod(idealPeriod);
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

    tracker.setPeriod(idealPeriod);
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
    VSyncPredictor tracker{mPeriod, 20, kMinimumSamplesForPrediction, kOutlierTolerancePercent};
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

    tracker.setPeriod(idealPeriod);
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
    tracker.setPeriod(idealPeriod);
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

    const auto maxDivider = 5;
    const auto maxPeriods = 15;
    for (int divider = 1; divider < maxDivider; divider++) {
        for (int i = 0; i < maxPeriods; i++) {
            const bool expectedInPhase = (i % divider) == 0;
            EXPECT_THAT(expectedInPhase,
                        tracker.isVSyncInPhase(mNow + i * mPeriod - bias,
                                               Fps::fromPeriodNsecs(divider * mPeriod)))
                    << "vsync at " << mNow + (i + 1) * mPeriod - bias << " is "
                    << (expectedInPhase ? "not " : "") << "in phase for divider " << divider;
        }
    }
}

TEST_F(VSyncPredictorTest, InconsistentVsyncValueIsFlushedEventually) {
    EXPECT_TRUE(tracker.addVsyncTimestamp(600));
    EXPECT_TRUE(tracker.needsMoreSamples());

    EXPECT_FALSE(tracker.addVsyncTimestamp(mNow += mPeriod));

    for (auto i = 0u; i < kMinimumSamplesForPrediction; i++) {
        EXPECT_TRUE(tracker.needsMoreSamples());
        EXPECT_TRUE(tracker.addVsyncTimestamp(mNow += mPeriod));
    }

    EXPECT_FALSE(tracker.needsMoreSamples());
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
