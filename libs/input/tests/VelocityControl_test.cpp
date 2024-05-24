/*
 * Copyright 2024 The Android Open Source Project
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

#include <input/VelocityControl.h>

#include <limits>

#include <gtest/gtest.h>
#include <input/AccelerationCurve.h>
#include <utils/Timers.h>

namespace android {

namespace {

constexpr float EPSILON = 0.001;
constexpr float COUNTS_PER_MM = 800 / 25.4;

} // namespace

class CurvedVelocityControlTest : public testing::Test {
protected:
    CurvedVelocityControl mCtrl;

    void moveWithoutCheckingResult(nsecs_t eventTime, float deltaX, float deltaY) {
        mCtrl.move(eventTime, &deltaX, &deltaY);
    }

    void moveAndCheckRatio(nsecs_t eventTime, const float deltaX, const float deltaY,
                           float expectedRatio) {
        float newDeltaX = deltaX, newDeltaY = deltaY;
        mCtrl.move(eventTime, &newDeltaX, &newDeltaY);
        ASSERT_NEAR(expectedRatio * deltaX, newDeltaX, EPSILON)
                << "Expected ratio of " << expectedRatio << " in X, but actual ratio was "
                << newDeltaX / deltaX;
        ASSERT_NEAR(expectedRatio * deltaY, newDeltaY, EPSILON)
                << "Expected ratio of " << expectedRatio << " in Y, but actual ratio was "
                << newDeltaY / deltaY;
    }
};

TEST_F(CurvedVelocityControlTest, SegmentSelection) {
    // To make the maths simple, use a "curve" that's actually just a sequence of steps.
    mCtrl.setCurve({
            {10, 2, 0},
            {20, 3, 0},
            {30, 4, 0},
            {std::numeric_limits<double>::infinity(), 5, 0},
    });

    // Establish a velocity of 16 mm/s.
    moveWithoutCheckingResult(0, 0, 0);
    moveWithoutCheckingResult(10'000'000, 0.16 * COUNTS_PER_MM, 0);
    moveWithoutCheckingResult(20'000'000, 0.16 * COUNTS_PER_MM, 0);
    moveWithoutCheckingResult(30'000'000, 0.16 * COUNTS_PER_MM, 0);
    ASSERT_NO_FATAL_FAILURE(
            moveAndCheckRatio(40'000'000, 0.16 * COUNTS_PER_MM, 0, /*expectedRatio=*/3));

    // Establish a velocity of 50 mm/s.
    mCtrl.reset();
    moveWithoutCheckingResult(100'000'000, 0, 0);
    moveWithoutCheckingResult(110'000'000, 0.50 * COUNTS_PER_MM, 0);
    moveWithoutCheckingResult(120'000'000, 0.50 * COUNTS_PER_MM, 0);
    moveWithoutCheckingResult(130'000'000, 0.50 * COUNTS_PER_MM, 0);
    ASSERT_NO_FATAL_FAILURE(
            moveAndCheckRatio(140'000'000, 0.50 * COUNTS_PER_MM, 0, /*expectedRatio=*/5));
}

TEST_F(CurvedVelocityControlTest, RatioDefaultsToFirstSegmentWhenVelocityIsUnknown) {
    mCtrl.setCurve({
            {10, 3, 0},
            {20, 2, 0},
            {std::numeric_limits<double>::infinity(), 4, 0},
    });

    // Only send two moves, which won't be enough for VelocityTracker to calculate a velocity from.
    moveWithoutCheckingResult(0, 0, 0);
    ASSERT_NO_FATAL_FAILURE(
            moveAndCheckRatio(10'000'000, 0.25 * COUNTS_PER_MM, 0, /*expectedRatio=*/3));
}

TEST_F(CurvedVelocityControlTest, VelocityCalculatedUsingBothAxes) {
    mCtrl.setCurve({
            {8.0, 3, 0},
            {8.1, 2, 0},
            {std::numeric_limits<double>::infinity(), 4, 0},
    });

    // Establish a velocity of 8.06 (= √65 = √(7²+4²)) mm/s between the two axes.
    moveWithoutCheckingResult(0, 0, 0);
    moveWithoutCheckingResult(10'000'000, 0.07 * COUNTS_PER_MM, 0.04 * COUNTS_PER_MM);
    moveWithoutCheckingResult(20'000'000, 0.07 * COUNTS_PER_MM, 0.04 * COUNTS_PER_MM);
    moveWithoutCheckingResult(30'000'000, 0.07 * COUNTS_PER_MM, 0.04 * COUNTS_PER_MM);
    ASSERT_NO_FATAL_FAILURE(moveAndCheckRatio(40'000'000, 0.07 * COUNTS_PER_MM,
                                              0.04 * COUNTS_PER_MM,
                                              /*expectedRatio=*/2));
}

TEST_F(CurvedVelocityControlTest, ReciprocalTerm) {
    mCtrl.setCurve({
            {10, 2, 0},
            {20, 3, -10},
            {std::numeric_limits<double>::infinity(), 3, 0},
    });

    // Establish a velocity of 15 mm/s.
    moveWithoutCheckingResult(0, 0, 0);
    moveWithoutCheckingResult(10'000'000, 0, 0.15 * COUNTS_PER_MM);
    moveWithoutCheckingResult(20'000'000, 0, 0.15 * COUNTS_PER_MM);
    moveWithoutCheckingResult(30'000'000, 0, 0.15 * COUNTS_PER_MM);
    // Expected ratio is 3 - 10 / 15 = 2.33333...
    ASSERT_NO_FATAL_FAILURE(
            moveAndCheckRatio(40'000'000, 0, 0.15 * COUNTS_PER_MM, /*expectedRatio=*/2.33333));
}

} // namespace android