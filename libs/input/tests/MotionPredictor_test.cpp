/*
 * Copyright (C) 2022 The Android Open Source Project
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

// TODO(b/331815574): Decouple this test from assumed config values.
#include <chrono>
#include <cmath>

#include <com_android_input_flags.h>
#include <flag_macros.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <input/MotionPredictor.h>

using namespace std::literals::chrono_literals;

namespace android {

using ::testing::IsEmpty;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

constexpr int32_t DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr int32_t MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr int32_t UP = AMOTION_EVENT_ACTION_UP;
constexpr nsecs_t NSEC_PER_MSEC = 1'000'000;

static MotionEvent getMotionEvent(int32_t action, float x, float y,
                                  std::chrono::nanoseconds eventTime, int32_t deviceId = 0) {
    MotionEvent event;
    constexpr size_t pointerCount = 1;
    std::vector<PointerProperties> pointerProperties;
    std::vector<PointerCoords> pointerCoords;
    for (size_t i = 0; i < pointerCount; i++) {
        PointerProperties properties;
        properties.clear();
        properties.id = i;
        properties.toolType = ToolType::STYLUS;
        pointerProperties.push_back(properties);
        PointerCoords coords;
        coords.clear();
        coords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        pointerCoords.push_back(coords);
    }

    ui::Transform identityTransform;
    event.initialize(InputEvent::nextId(), deviceId, AINPUT_SOURCE_STYLUS,
                     ui::LogicalDisplayId::DEFAULT, {0}, action, /*actionButton=*/0, /*flags=*/0,
                     AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE, /*buttonState=*/0,
                     MotionClassification::NONE, identityTransform,
                     /*xPrecision=*/0.1,
                     /*yPrecision=*/0.2, /*xCursorPosition=*/280, /*yCursorPosition=*/540,
                     identityTransform, /*downTime=*/100, eventTime.count(), pointerCount,
                     pointerProperties.data(), pointerCoords.data());
    return event;
}

TEST(JerkTrackerTest, JerkReadiness) {
    JerkTracker jerkTracker(true);
    EXPECT_FALSE(jerkTracker.jerkMagnitude());
    jerkTracker.pushSample(/*timestamp=*/0, 20, 50);
    EXPECT_FALSE(jerkTracker.jerkMagnitude());
    jerkTracker.pushSample(/*timestamp=*/1, 25, 53);
    EXPECT_FALSE(jerkTracker.jerkMagnitude());
    jerkTracker.pushSample(/*timestamp=*/2, 30, 60);
    EXPECT_FALSE(jerkTracker.jerkMagnitude());
    jerkTracker.pushSample(/*timestamp=*/3, 35, 70);
    EXPECT_TRUE(jerkTracker.jerkMagnitude());
    jerkTracker.reset();
    EXPECT_FALSE(jerkTracker.jerkMagnitude());
    jerkTracker.pushSample(/*timestamp=*/4, 30, 60);
    EXPECT_FALSE(jerkTracker.jerkMagnitude());
}

TEST(JerkTrackerTest, JerkCalculationNormalizedDtTrue) {
    JerkTracker jerkTracker(true);
    jerkTracker.pushSample(/*timestamp=*/0, 20, 50);
    jerkTracker.pushSample(/*timestamp=*/1, 25, 53);
    jerkTracker.pushSample(/*timestamp=*/2, 30, 60);
    jerkTracker.pushSample(/*timestamp=*/3, 45, 70);
    /**
     * Jerk derivative table
     * x:    20   25   30   45
     * x':    5    5   15
     * x'':   0   10
     * x''': 10
     *
     * y:    50   53   60   70
     * y':    3    7   10
     * y'':   4    3
     * y''': -1
     */
    EXPECT_FLOAT_EQ(jerkTracker.jerkMagnitude().value(), std::hypot(10, -1));
    jerkTracker.pushSample(/*timestamp=*/4, 20, 65);
    /**
     * (continuing from above table)
     * x:    45 -> 20
     * x':   15 -> -25
     * x'':  10 -> -40
     * x''': -50
     *
     * y:    70 -> 65
     * y':   10 -> -5
     * y'':  3 -> -15
     * y''': -18
     */
    EXPECT_FLOAT_EQ(jerkTracker.jerkMagnitude().value(), std::hypot(-50, -18));
}

TEST(JerkTrackerTest, JerkCalculationNormalizedDtFalse) {
    JerkTracker jerkTracker(false);
    jerkTracker.pushSample(/*timestamp=*/0, 20, 50);
    jerkTracker.pushSample(/*timestamp=*/10, 25, 53);
    jerkTracker.pushSample(/*timestamp=*/20, 30, 60);
    jerkTracker.pushSample(/*timestamp=*/30, 45, 70);
    /**
     * Jerk derivative table
     * x:     20   25   30   45
     * x':    .5   .5  1.5
     * x'':    0   .1
     * x''': .01
     *
     * y:       50   53   60   70
     * y':      .3   .7    1
     * y'':    .04  .03
     * y''': -.001
     */
    EXPECT_FLOAT_EQ(jerkTracker.jerkMagnitude().value(), std::hypot(.01, -.001));
    jerkTracker.pushSample(/*timestamp=*/50, 20, 65);
    /**
     * (continuing from above table)
     * x:    45 -> 20
     * x':   1.5 -> -1.25 (delta above, divide by 20)
     * x'':  .1 -> -.275 (delta above, divide by 10)
     * x''': -.0375 (delta above, divide by 10)
     *
     * y:    70 -> 65
     * y':   1 -> -.25 (delta above, divide by 20)
     * y'':  .03 -> -.125 (delta above, divide by 10)
     * y''': -.0155 (delta above, divide by 10)
     */
    EXPECT_FLOAT_EQ(jerkTracker.jerkMagnitude().value(), std::hypot(-.0375, -.0155));
}

TEST(JerkTrackerTest, JerkCalculationAfterReset) {
    JerkTracker jerkTracker(true);
    jerkTracker.pushSample(/*timestamp=*/0, 20, 50);
    jerkTracker.pushSample(/*timestamp=*/1, 25, 53);
    jerkTracker.pushSample(/*timestamp=*/2, 30, 60);
    jerkTracker.pushSample(/*timestamp=*/3, 45, 70);
    jerkTracker.pushSample(/*timestamp=*/4, 20, 65);
    jerkTracker.reset();
    jerkTracker.pushSample(/*timestamp=*/5, 20, 50);
    jerkTracker.pushSample(/*timestamp=*/6, 25, 53);
    jerkTracker.pushSample(/*timestamp=*/7, 30, 60);
    jerkTracker.pushSample(/*timestamp=*/8, 45, 70);
    EXPECT_FLOAT_EQ(jerkTracker.jerkMagnitude().value(), std::hypot(10, -1));
}

TEST(MotionPredictorTest, IsPredictionAvailable) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });
    ASSERT_TRUE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_STYLUS));
    ASSERT_FALSE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_TOUCHSCREEN));
}

TEST(MotionPredictorTest, StationaryNoiseFloor) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/1,
                              []() { return true /*enable prediction*/; });
    predictor.record(getMotionEvent(DOWN, 0, 1, 30ms));
    predictor.record(getMotionEvent(MOVE, 0, 1, 35ms)); // No movement.
    std::unique_ptr<MotionEvent> predicted = predictor.predict(40 * NSEC_PER_MSEC);
    ASSERT_EQ(nullptr, predicted);
}

TEST(MotionPredictorTest, Offset) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/1,
                              []() { return true /*enable prediction*/; });
    predictor.record(getMotionEvent(DOWN, 0, 1, 30ms));
    predictor.record(getMotionEvent(MOVE, 0, 5, 35ms)); // Move enough to overcome the noise floor.
    std::unique_ptr<MotionEvent> predicted = predictor.predict(40 * NSEC_PER_MSEC);
    ASSERT_NE(nullptr, predicted);
    ASSERT_GE(predicted->getEventTime(), 41);
}

TEST(MotionPredictorTest, FollowsGesture) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });
    predictor.record(getMotionEvent(DOWN, 3.75, 3, 20ms));
    predictor.record(getMotionEvent(MOVE, 4.8, 3, 30ms));
    predictor.record(getMotionEvent(MOVE, 6.2, 3, 40ms));
    predictor.record(getMotionEvent(MOVE, 8, 3, 50ms));
    EXPECT_NE(nullptr, predictor.predict(90 * NSEC_PER_MSEC));

    predictor.record(getMotionEvent(UP, 10.25, 3, 60ms));
    EXPECT_EQ(nullptr, predictor.predict(100 * NSEC_PER_MSEC));
}

TEST(MotionPredictorTest, MultipleDevicesNotSupported) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    ASSERT_TRUE(predictor.record(getMotionEvent(DOWN, 1, 3, 0ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 1, 3, 10ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 2, 5, 20ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 3, 7, 30ms, /*deviceId=*/0)).ok());

    ASSERT_FALSE(predictor.record(getMotionEvent(DOWN, 100, 300, 40ms, /*deviceId=*/1)).ok());
    ASSERT_FALSE(predictor.record(getMotionEvent(MOVE, 100, 300, 50ms, /*deviceId=*/1)).ok());
}

TEST(MotionPredictorTest, IndividualGesturesFromDifferentDevicesAreSupported) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    ASSERT_TRUE(predictor.record(getMotionEvent(DOWN, 1, 3, 0ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 1, 3, 10ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 2, 5, 20ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(UP, 2, 5, 30ms, /*deviceId=*/0)).ok());

    // Now, send a gesture from a different device. Since we have no active gesture, the new gesture
    // should be processed correctly.
    ASSERT_TRUE(predictor.record(getMotionEvent(DOWN, 100, 300, 40ms, /*deviceId=*/1)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 100, 300, 50ms, /*deviceId=*/1)).ok());
}

TEST(MotionPredictorTest, FlagDisablesPrediction) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return false /*disable prediction*/; });
    predictor.record(getMotionEvent(DOWN, 0, 1, 30ms));
    predictor.record(getMotionEvent(MOVE, 0, 1, 35ms));
    std::unique_ptr<MotionEvent> predicted = predictor.predict(40 * NSEC_PER_MSEC);
    ASSERT_EQ(nullptr, predicted);
    ASSERT_FALSE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_STYLUS));
    ASSERT_FALSE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_TOUCHSCREEN));
}

TEST_WITH_FLAGS(
        MotionPredictorTest, LowJerkNoPruning,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::input::flags,
                                            enable_prediction_pruning_via_jerk_thresholding))) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    // Jerk is low (0.05 normalized).
    predictor.record(getMotionEvent(DOWN, 2, 7, 20ms));
    predictor.record(getMotionEvent(MOVE, 2.75, 7, 30ms));
    predictor.record(getMotionEvent(MOVE, 3.8, 7, 40ms));
    predictor.record(getMotionEvent(MOVE, 5.2, 7, 50ms));
    predictor.record(getMotionEvent(MOVE, 7, 7, 60ms));
    std::unique_ptr<MotionEvent> predicted = predictor.predict(90 * NSEC_PER_MSEC);
    EXPECT_NE(nullptr, predicted);
    EXPECT_EQ(static_cast<size_t>(5), predicted->getHistorySize() + 1);
}

TEST_WITH_FLAGS(
        MotionPredictorTest, HighJerkPredictionsPruned,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::input::flags,
                                            enable_prediction_pruning_via_jerk_thresholding))) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    // Jerk is incredibly high.
    predictor.record(getMotionEvent(DOWN, 0, 5, 20ms));
    predictor.record(getMotionEvent(MOVE, 0, 70, 30ms));
    predictor.record(getMotionEvent(MOVE, 0, 139, 40ms));
    predictor.record(getMotionEvent(MOVE, 0, 1421, 50ms));
    predictor.record(getMotionEvent(MOVE, 0, 41233, 60ms));
    std::unique_ptr<MotionEvent> predicted = predictor.predict(90 * NSEC_PER_MSEC);
    EXPECT_EQ(nullptr, predicted);
}

TEST_WITH_FLAGS(
        MotionPredictorTest, MediumJerkPredictionsSomePruned,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::input::flags,
                                            enable_prediction_pruning_via_jerk_thresholding))) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    // Jerk is medium (1.05 normalized, which is halfway between LOW_JANK and HIGH_JANK)
    predictor.record(getMotionEvent(DOWN, 0, 5.2, 20ms));
    predictor.record(getMotionEvent(MOVE, 0, 11.5, 30ms));
    predictor.record(getMotionEvent(MOVE, 0, 22, 40ms));
    predictor.record(getMotionEvent(MOVE, 0, 37.75, 50ms));
    predictor.record(getMotionEvent(MOVE, 0, 59.8, 60ms));
    std::unique_ptr<MotionEvent> predicted = predictor.predict(82 * NSEC_PER_MSEC);
    EXPECT_NE(nullptr, predicted);
    // Halfway between LOW_JANK and HIGH_JANK means that half of the predictions
    // will be pruned. If model prediction window is close enough to predict()
    // call time window, then half of the model predictions (5/2 -> 2) will be
    // ouputted.
    EXPECT_EQ(static_cast<size_t>(3), predicted->getHistorySize() + 1);
}

using AtomFields = MotionPredictorMetricsManager::AtomFields;
using ReportAtomFunction = MotionPredictorMetricsManager::ReportAtomFunction;

// Creates a mock atom reporting function that appends the reported atom to the given vector.
// The passed-in pointer must not be nullptr.
ReportAtomFunction createMockReportAtomFunction(std::vector<AtomFields>* reportedAtomFields) {
    return [reportedAtomFields](const AtomFields& atomFields) -> void {
        reportedAtomFields->push_back(atomFields);
    };
}

TEST(MotionPredictorMetricsManagerIntegrationTest, ReportsMetrics) {
    std::vector<AtomFields> reportedAtomFields;
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; },
                              createMockReportAtomFunction(&reportedAtomFields));

    ASSERT_TRUE(predictor.record(getMotionEvent(DOWN, 1, 1, 0ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 2, 2, 4ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 3, 3, 8ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 4, 4, 12ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 5, 5, 16ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(MOVE, 6, 6, 20ms, /*deviceId=*/0)).ok());
    ASSERT_TRUE(predictor.record(getMotionEvent(UP, 7, 7, 24ms, /*deviceId=*/0)).ok());

    // The number of atoms reported should equal the number of prediction time buckets, which is
    // given by the prediction model's output length. For now, this value is always 5, and we
    // hardcode it because it's not publicly accessible from the MotionPredictor.
    EXPECT_EQ(5u, reportedAtomFields.size());
}

} // namespace android
