/*
 * Copyright 2023 The Android Open Source Project
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

#include <input/MotionPredictor.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/InputEventBuilders.h>
#include <utils/Timers.h> // for nsecs_t

#include "Eigen/Core"
#include "Eigen/Geometry"

namespace android {
namespace {

using ::testing::FloatNear;
using ::testing::Matches;

using GroundTruthPoint = MotionPredictorMetricsManager::GroundTruthPoint;
using PredictionPoint = MotionPredictorMetricsManager::PredictionPoint;
using AtomFields = MotionPredictorMetricsManager::AtomFields;
using ReportAtomFunction = MotionPredictorMetricsManager::ReportAtomFunction;

inline constexpr int NANOS_PER_MILLIS = 1'000'000;

inline constexpr nsecs_t TEST_INITIAL_TIMESTAMP = 1'000'000'000;
inline constexpr size_t TEST_MAX_NUM_PREDICTIONS = 5;
inline constexpr nsecs_t TEST_PREDICTION_INTERVAL_NANOS = 12'500'000 / 3; // 1 / (240 hz)
inline constexpr int NO_DATA_SENTINEL = MotionPredictorMetricsManager::NO_DATA_SENTINEL;

// Parameters:
//  • arg: Eigen::Vector2f
//  • target: Eigen::Vector2f
//  • epsilon: float
MATCHER_P2(Vector2fNear, target, epsilon, "") {
    return Matches(FloatNear(target[0], epsilon))(arg[0]) &&
            Matches(FloatNear(target[1], epsilon))(arg[1]);
}

// Parameters:
//  • arg: PredictionPoint
//  • target: PredictionPoint
//  • epsilon: float
MATCHER_P2(PredictionPointNear, target, epsilon, "") {
    if (!Matches(Vector2fNear(target.position, epsilon))(arg.position)) {
        *result_listener << "Position mismatch. Actual: (" << arg.position[0] << ", "
                         << arg.position[1] << "), expected: (" << target.position[0] << ", "
                         << target.position[1] << ")";
        return false;
    }
    if (!Matches(FloatNear(target.pressure, epsilon))(arg.pressure)) {
        *result_listener << "Pressure mismatch. Actual: " << arg.pressure
                         << ", expected: " << target.pressure;
        return false;
    }
    if (arg.originTimestamp != target.originTimestamp) {
        *result_listener << "Origin timestamp mismatch. Actual: " << arg.originTimestamp
                         << ", expected: " << target.originTimestamp;
        return false;
    }
    if (arg.targetTimestamp != target.targetTimestamp) {
        *result_listener << "Target timestamp mismatch. Actual: " << arg.targetTimestamp
                         << ", expected: " << target.targetTimestamp;
        return false;
    }
    return true;
}

// --- Mathematical helper functions. ---

template <typename T>
T average(std::vector<T> values) {
    return std::accumulate(values.begin(), values.end(), T{}) / static_cast<T>(values.size());
}

template <typename T>
T standardDeviation(std::vector<T> values) {
    T mean = average(values);
    T accumulator = {};
    for (const T value : values) {
        accumulator += value * value - mean * mean;
    }
    // Take the max with 0 to avoid negative values caused by numerical instability.
    return std::sqrt(std::max(T{}, accumulator) / static_cast<T>(values.size()));
}

template <typename T>
T rmse(std::vector<T> errors) {
    T sse = {};
    for (const T error : errors) {
        sse += error * error;
    }
    return std::sqrt(sse / static_cast<T>(errors.size()));
}

TEST(MathematicalHelperFunctionTest, Average) {
    std::vector<float> values{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    EXPECT_EQ(5.5f, average(values));
}

TEST(MathematicalHelperFunctionTest, StandardDeviation) {
    // https://www.calculator.net/standard-deviation-calculator.html?numberinputs=10%2C+12%2C+23%2C+23%2C+16%2C+23%2C+21%2C+16
    std::vector<float> values{10, 12, 23, 23, 16, 23, 21, 16};
    EXPECT_FLOAT_EQ(4.8989794855664f, standardDeviation(values));
}

TEST(MathematicalHelperFunctionTest, Rmse) {
    std::vector<float> errors{1, 5, 7, 7, 8, 20};
    EXPECT_FLOAT_EQ(9.899494937f, rmse(errors));
}

// --- MotionEvent-related helper functions. ---

// Creates a MotionEvent corresponding to the given GroundTruthPoint.
MotionEvent makeMotionEvent(const GroundTruthPoint& groundTruthPoint) {
    // Build single pointer of type STYLUS, with coordinates from groundTruthPoint.
    PointerBuilder pointerBuilder =
            PointerBuilder(/*id=*/0, ToolType::STYLUS)
                    .x(groundTruthPoint.position[1])
                    .y(groundTruthPoint.position[0])
                    .axis(AMOTION_EVENT_AXIS_PRESSURE, groundTruthPoint.pressure);
    return MotionEventBuilder(/*action=*/AMOTION_EVENT_ACTION_MOVE,
                              /*source=*/AINPUT_SOURCE_CLASS_POINTER)
            .eventTime(groundTruthPoint.timestamp)
            .pointer(pointerBuilder)
            .build();
}

// Creates a MotionEvent corresponding to the given sequence of PredictionPoints.
MotionEvent makeMotionEvent(const std::vector<PredictionPoint>& predictionPoints) {
    // Build single pointer of type STYLUS, with coordinates from first prediction point.
    PointerBuilder pointerBuilder =
            PointerBuilder(/*id=*/0, ToolType::STYLUS)
                    .x(predictionPoints[0].position[1])
                    .y(predictionPoints[0].position[0])
                    .axis(AMOTION_EVENT_AXIS_PRESSURE, predictionPoints[0].pressure);
    MotionEvent predictionEvent =
            MotionEventBuilder(
                    /*action=*/AMOTION_EVENT_ACTION_MOVE, /*source=*/AINPUT_SOURCE_CLASS_POINTER)
                    .eventTime(predictionPoints[0].targetTimestamp)
                    .pointer(pointerBuilder)
                    .build();
    for (size_t i = 1; i < predictionPoints.size(); ++i) {
        PointerCoords coords =
                PointerBuilder(/*id=*/0, ToolType::STYLUS)
                        .x(predictionPoints[i].position[1])
                        .y(predictionPoints[i].position[0])
                        .axis(AMOTION_EVENT_AXIS_PRESSURE, predictionPoints[i].pressure)
                        .buildCoords();
        predictionEvent.addSample(predictionPoints[i].targetTimestamp, &coords);
    }
    return predictionEvent;
}

// Creates a MotionEvent corresponding to a stylus lift (UP) ground truth event.
MotionEvent makeLiftMotionEvent() {
    return MotionEventBuilder(/*action=*/AMOTION_EVENT_ACTION_UP,
                              /*source=*/AINPUT_SOURCE_CLASS_POINTER)
            .pointer(PointerBuilder(/*id=*/0, ToolType::STYLUS))
            .build();
}

TEST(MakeMotionEventTest, MakeGroundTruthMotionEvent) {
    const GroundTruthPoint groundTruthPoint{{.position = Eigen::Vector2f(10.0f, 20.0f),
                                             .pressure = 0.6f},
                                            .timestamp = TEST_INITIAL_TIMESTAMP};
    const MotionEvent groundTruthMotionEvent = makeMotionEvent(groundTruthPoint);

    ASSERT_EQ(1u, groundTruthMotionEvent.getPointerCount());
    // Note: a MotionEvent's "history size" is one less than its number of samples.
    ASSERT_EQ(0u, groundTruthMotionEvent.getHistorySize());
    EXPECT_EQ(groundTruthPoint.position[0], groundTruthMotionEvent.getRawPointerCoords(0)->getY());
    EXPECT_EQ(groundTruthPoint.position[1], groundTruthMotionEvent.getRawPointerCoords(0)->getX());
    EXPECT_EQ(groundTruthPoint.pressure,
              groundTruthMotionEvent.getRawPointerCoords(0)->getAxisValue(
                      AMOTION_EVENT_AXIS_PRESSURE));
    EXPECT_EQ(AMOTION_EVENT_ACTION_MOVE, groundTruthMotionEvent.getAction());
}

TEST(MakeMotionEventTest, MakePredictionMotionEvent) {
    const nsecs_t originTimestamp = TEST_INITIAL_TIMESTAMP;
    const std::vector<PredictionPoint>
            predictionPoints{{{.position = Eigen::Vector2f(10.0f, 20.0f), .pressure = 0.6f},
                              .originTimestamp = originTimestamp,
                              .targetTimestamp = originTimestamp + 5 * NANOS_PER_MILLIS},
                             {{.position = Eigen::Vector2f(11.0f, 22.0f), .pressure = 0.5f},
                              .originTimestamp = originTimestamp,
                              .targetTimestamp = originTimestamp + 10 * NANOS_PER_MILLIS},
                             {{.position = Eigen::Vector2f(12.0f, 24.0f), .pressure = 0.4f},
                              .originTimestamp = originTimestamp,
                              .targetTimestamp = originTimestamp + 15 * NANOS_PER_MILLIS}};
    const MotionEvent predictionMotionEvent = makeMotionEvent(predictionPoints);

    ASSERT_EQ(1u, predictionMotionEvent.getPointerCount());
    // Note: a MotionEvent's "history size" is one less than its number of samples.
    ASSERT_EQ(predictionPoints.size(), predictionMotionEvent.getHistorySize() + 1);
    for (size_t i = 0; i < predictionPoints.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        const PointerCoords coords = *predictionMotionEvent.getHistoricalRawPointerCoords(
                /*pointerIndex=*/0, /*historicalIndex=*/i);
        EXPECT_EQ(predictionPoints[i].position[0], coords.getY());
        EXPECT_EQ(predictionPoints[i].position[1], coords.getX());
        EXPECT_EQ(predictionPoints[i].pressure, coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
        // Note: originTimestamp is discarded when converting PredictionPoint to MotionEvent.
        EXPECT_EQ(predictionPoints[i].targetTimestamp,
                  predictionMotionEvent.getHistoricalEventTime(i));
        EXPECT_EQ(AMOTION_EVENT_ACTION_MOVE, predictionMotionEvent.getAction());
    }
}

TEST(MakeMotionEventTest, MakeLiftMotionEvent) {
    const MotionEvent liftMotionEvent = makeLiftMotionEvent();
    ASSERT_EQ(1u, liftMotionEvent.getPointerCount());
    // Note: a MotionEvent's "history size" is one less than its number of samples.
    ASSERT_EQ(0u, liftMotionEvent.getHistorySize());
    EXPECT_EQ(AMOTION_EVENT_ACTION_UP, liftMotionEvent.getAction());
}

// --- Ground-truth-generation helper functions. ---

std::vector<GroundTruthPoint> generateConstantGroundTruthPoints(
        const GroundTruthPoint& groundTruthPoint, size_t numPoints) {
    std::vector<GroundTruthPoint> groundTruthPoints;
    nsecs_t timestamp = groundTruthPoint.timestamp;
    for (size_t i = 0; i < numPoints; ++i) {
        groundTruthPoints.emplace_back(groundTruthPoint);
        groundTruthPoints.back().timestamp = timestamp;
        timestamp += TEST_PREDICTION_INTERVAL_NANOS;
    }
    return groundTruthPoints;
}

// This function uses the coordinate system (y, x), with +y pointing downwards and +x pointing
// rightwards. Angles are measured counterclockwise from down (+y).
std::vector<GroundTruthPoint> generateCircularArcGroundTruthPoints(Eigen::Vector2f initialPosition,
                                                                   float initialAngle,
                                                                   float velocity,
                                                                   float turningAngle,
                                                                   size_t numPoints) {
    std::vector<GroundTruthPoint> groundTruthPoints;
    // Create first point.
    if (numPoints > 0) {
        groundTruthPoints.push_back({{.position = initialPosition, .pressure = 0.0f},
                                     .timestamp = TEST_INITIAL_TIMESTAMP});
    }
    float trajectoryAngle = initialAngle; // measured counterclockwise from +y axis.
    for (size_t i = 1; i < numPoints; ++i) {
        const Eigen::Vector2f trajectory =
                Eigen::Rotation2D(trajectoryAngle) * Eigen::Vector2f(1, 0);
        groundTruthPoints.push_back(
                {{.position = groundTruthPoints.back().position + velocity * trajectory,
                  .pressure = 0.0f},
                 .timestamp = groundTruthPoints.back().timestamp + TEST_PREDICTION_INTERVAL_NANOS});
        trajectoryAngle += turningAngle;
    }
    return groundTruthPoints;
}

TEST(GenerateConstantGroundTruthPointsTest, BasicTest) {
    const GroundTruthPoint groundTruthPoint{{.position = Eigen::Vector2f(10, 20), .pressure = 0.3f},
                                            .timestamp = TEST_INITIAL_TIMESTAMP};
    const std::vector<GroundTruthPoint> groundTruthPoints =
            generateConstantGroundTruthPoints(groundTruthPoint, /*numPoints=*/3);

    ASSERT_EQ(3u, groundTruthPoints.size());
    // First point.
    EXPECT_EQ(groundTruthPoints[0].position, groundTruthPoint.position);
    EXPECT_EQ(groundTruthPoints[0].pressure, groundTruthPoint.pressure);
    EXPECT_EQ(groundTruthPoints[0].timestamp, groundTruthPoint.timestamp);
    // Second point.
    EXPECT_EQ(groundTruthPoints[1].position, groundTruthPoint.position);
    EXPECT_EQ(groundTruthPoints[1].pressure, groundTruthPoint.pressure);
    EXPECT_GT(groundTruthPoints[1].timestamp, groundTruthPoints[0].timestamp);
    // Third point.
    EXPECT_EQ(groundTruthPoints[2].position, groundTruthPoint.position);
    EXPECT_EQ(groundTruthPoints[2].pressure, groundTruthPoint.pressure);
    EXPECT_GT(groundTruthPoints[2].timestamp, groundTruthPoints[1].timestamp);
}

TEST(GenerateCircularArcGroundTruthTest, StraightLineUpwards) {
    const std::vector<GroundTruthPoint> groundTruthPoints = generateCircularArcGroundTruthPoints(
            /*initialPosition=*/Eigen::Vector2f(0, 0),
            /*initialAngle=*/M_PI,
            /*velocity=*/1.0f,
            /*turningAngle=*/0.0f,
            /*numPoints=*/3);

    ASSERT_EQ(3u, groundTruthPoints.size());
    EXPECT_THAT(groundTruthPoints[0].position, Vector2fNear(Eigen::Vector2f(0, 0), 1e-6));
    EXPECT_THAT(groundTruthPoints[1].position, Vector2fNear(Eigen::Vector2f(-1, 0), 1e-6));
    EXPECT_THAT(groundTruthPoints[2].position, Vector2fNear(Eigen::Vector2f(-2, 0), 1e-6));
    // Check that timestamps are increasing between consecutive ground truth points.
    EXPECT_GT(groundTruthPoints[1].timestamp, groundTruthPoints[0].timestamp);
    EXPECT_GT(groundTruthPoints[2].timestamp, groundTruthPoints[1].timestamp);
}

TEST(GenerateCircularArcGroundTruthTest, CounterclockwiseSquare) {
    // Generate points in a counterclockwise unit square starting pointing right.
    const std::vector<GroundTruthPoint> groundTruthPoints = generateCircularArcGroundTruthPoints(
            /*initialPosition=*/Eigen::Vector2f(10, 100),
            /*initialAngle=*/M_PI_2,
            /*velocity=*/1.0f,
            /*turningAngle=*/M_PI_2,
            /*numPoints=*/5);

    ASSERT_EQ(5u, groundTruthPoints.size());
    EXPECT_THAT(groundTruthPoints[0].position, Vector2fNear(Eigen::Vector2f(10, 100), 1e-6));
    EXPECT_THAT(groundTruthPoints[1].position, Vector2fNear(Eigen::Vector2f(10, 101), 1e-6));
    EXPECT_THAT(groundTruthPoints[2].position, Vector2fNear(Eigen::Vector2f(9, 101), 1e-6));
    EXPECT_THAT(groundTruthPoints[3].position, Vector2fNear(Eigen::Vector2f(9, 100), 1e-6));
    EXPECT_THAT(groundTruthPoints[4].position, Vector2fNear(Eigen::Vector2f(10, 100), 1e-6));
}

// --- Prediction-generation helper functions. ---

// Creates a sequence of predictions with values equal to those of the given GroundTruthPoint.
std::vector<PredictionPoint> generateConstantPredictions(const GroundTruthPoint& groundTruthPoint) {
    std::vector<PredictionPoint> predictions;
    nsecs_t predictionTimestamp = groundTruthPoint.timestamp + TEST_PREDICTION_INTERVAL_NANOS;
    for (size_t j = 0; j < TEST_MAX_NUM_PREDICTIONS; ++j) {
        predictions.push_back(PredictionPoint{{.position = groundTruthPoint.position,
                                               .pressure = groundTruthPoint.pressure},
                                              .originTimestamp = groundTruthPoint.timestamp,
                                              .targetTimestamp = predictionTimestamp});
        predictionTimestamp += TEST_PREDICTION_INTERVAL_NANOS;
    }
    return predictions;
}

// Generates TEST_MAX_NUM_PREDICTIONS predictions from the given most recent two ground truth points
// by linear extrapolation of position and pressure. The interval between consecutive predictions'
// timestamps is TEST_PREDICTION_INTERVAL_NANOS.
std::vector<PredictionPoint> generatePredictionsByLinearExtrapolation(
        const GroundTruthPoint& firstGroundTruth, const GroundTruthPoint& secondGroundTruth) {
    // Precompute deltas.
    const Eigen::Vector2f trajectory = secondGroundTruth.position - firstGroundTruth.position;
    const float deltaPressure = secondGroundTruth.pressure - firstGroundTruth.pressure;
    // Compute predictions.
    std::vector<PredictionPoint> predictions;
    Eigen::Vector2f predictionPosition = secondGroundTruth.position;
    float predictionPressure = secondGroundTruth.pressure;
    nsecs_t predictionTargetTimestamp = secondGroundTruth.timestamp;
    for (size_t i = 0; i < TEST_MAX_NUM_PREDICTIONS; ++i) {
        predictionPosition += trajectory;
        predictionPressure += deltaPressure;
        predictionTargetTimestamp += TEST_PREDICTION_INTERVAL_NANOS;
        predictions.push_back(
                PredictionPoint{{.position = predictionPosition, .pressure = predictionPressure},
                                .originTimestamp = secondGroundTruth.timestamp,
                                .targetTimestamp = predictionTargetTimestamp});
    }
    return predictions;
}

TEST(GeneratePredictionsTest, GenerateConstantPredictions) {
    const GroundTruthPoint groundTruthPoint{{.position = Eigen::Vector2f(10, 20), .pressure = 0.3f},
                                            .timestamp = TEST_INITIAL_TIMESTAMP};
    const std::vector<PredictionPoint> predictionPoints =
            generateConstantPredictions(groundTruthPoint);

    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, predictionPoints.size());
    for (size_t i = 0; i < predictionPoints.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        EXPECT_THAT(predictionPoints[i].position, Vector2fNear(groundTruthPoint.position, 1e-6));
        EXPECT_THAT(predictionPoints[i].pressure, FloatNear(groundTruthPoint.pressure, 1e-6));
        EXPECT_EQ(predictionPoints[i].originTimestamp, groundTruthPoint.timestamp);
        EXPECT_EQ(predictionPoints[i].targetTimestamp,
                  groundTruthPoint.timestamp +
                          static_cast<nsecs_t>(i + 1) * TEST_PREDICTION_INTERVAL_NANOS);
    }
}

TEST(GeneratePredictionsTest, LinearExtrapolationFromTwoPoints) {
    const nsecs_t initialTimestamp = TEST_INITIAL_TIMESTAMP;
    const std::vector<PredictionPoint> predictionPoints = generatePredictionsByLinearExtrapolation(
            GroundTruthPoint{{.position = Eigen::Vector2f(100, 200), .pressure = 0.9f},
                             .timestamp = initialTimestamp},
            GroundTruthPoint{{.position = Eigen::Vector2f(105, 190), .pressure = 0.8f},
                             .timestamp = initialTimestamp + TEST_PREDICTION_INTERVAL_NANOS});

    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, predictionPoints.size());
    const nsecs_t originTimestamp = initialTimestamp + TEST_PREDICTION_INTERVAL_NANOS;
    EXPECT_THAT(predictionPoints[0],
                PredictionPointNear(PredictionPoint{{.position = Eigen::Vector2f(110, 180),
                                                     .pressure = 0.7f},
                                                    .originTimestamp = originTimestamp,
                                                    .targetTimestamp = originTimestamp +
                                                            TEST_PREDICTION_INTERVAL_NANOS},
                                    0.001));
    EXPECT_THAT(predictionPoints[1],
                PredictionPointNear(PredictionPoint{{.position = Eigen::Vector2f(115, 170),
                                                     .pressure = 0.6f},
                                                    .originTimestamp = originTimestamp,
                                                    .targetTimestamp = originTimestamp +
                                                            2 * TEST_PREDICTION_INTERVAL_NANOS},
                                    0.001));
    EXPECT_THAT(predictionPoints[2],
                PredictionPointNear(PredictionPoint{{.position = Eigen::Vector2f(120, 160),
                                                     .pressure = 0.5f},
                                                    .originTimestamp = originTimestamp,
                                                    .targetTimestamp = originTimestamp +
                                                            3 * TEST_PREDICTION_INTERVAL_NANOS},
                                    0.001));
    EXPECT_THAT(predictionPoints[3],
                PredictionPointNear(PredictionPoint{{.position = Eigen::Vector2f(125, 150),
                                                     .pressure = 0.4f},
                                                    .originTimestamp = originTimestamp,
                                                    .targetTimestamp = originTimestamp +
                                                            4 * TEST_PREDICTION_INTERVAL_NANOS},
                                    0.001));
    EXPECT_THAT(predictionPoints[4],
                PredictionPointNear(PredictionPoint{{.position = Eigen::Vector2f(130, 140),
                                                     .pressure = 0.3f},
                                                    .originTimestamp = originTimestamp,
                                                    .targetTimestamp = originTimestamp +
                                                            5 * TEST_PREDICTION_INTERVAL_NANOS},
                                    0.001));
}

// Generates predictions by linear extrapolation for each consecutive pair of ground truth points
// (see the comment for the above function for further explanation). Returns a vector of vectors of
// prediction points, where the first index is the source ground truth index, and the second is the
// prediction target index.
//
// The returned vector has size equal to the input vector, and the first element of the returned
// vector is always empty.
std::vector<std::vector<PredictionPoint>> generateAllPredictionsByLinearExtrapolation(
        const std::vector<GroundTruthPoint>& groundTruthPoints) {
    std::vector<std::vector<PredictionPoint>> allPredictions;
    allPredictions.emplace_back();
    for (size_t i = 1; i < groundTruthPoints.size(); ++i) {
        allPredictions.push_back(generatePredictionsByLinearExtrapolation(groundTruthPoints[i - 1],
                                                                          groundTruthPoints[i]));
    }
    return allPredictions;
}

TEST(GeneratePredictionsTest, GenerateAllPredictions) {
    const nsecs_t initialTimestamp = TEST_INITIAL_TIMESTAMP;
    std::vector<GroundTruthPoint>
            groundTruthPoints{GroundTruthPoint{{.position = Eigen::Vector2f(0, 0),
                                                .pressure = 0.5f},
                                               .timestamp = initialTimestamp},
                              GroundTruthPoint{{.position = Eigen::Vector2f(1, -1),
                                                .pressure = 0.51f},
                                               .timestamp = initialTimestamp +
                                                       2 * TEST_PREDICTION_INTERVAL_NANOS},
                              GroundTruthPoint{{.position = Eigen::Vector2f(2, -2),
                                                .pressure = 0.52f},
                                               .timestamp = initialTimestamp +
                                                       3 * TEST_PREDICTION_INTERVAL_NANOS}};

    const std::vector<std::vector<PredictionPoint>> allPredictions =
            generateAllPredictionsByLinearExtrapolation(groundTruthPoints);

    // Check format of allPredictions data.
    ASSERT_EQ(groundTruthPoints.size(), allPredictions.size());
    EXPECT_TRUE(allPredictions[0].empty());
    EXPECT_EQ(TEST_MAX_NUM_PREDICTIONS, allPredictions[1].size());
    EXPECT_EQ(TEST_MAX_NUM_PREDICTIONS, allPredictions[2].size());

    // Check positions of predictions generated from first pair of ground truth points.
    EXPECT_THAT(allPredictions[1][0].position, Vector2fNear(Eigen::Vector2f(2, -2), 1e-9));
    EXPECT_THAT(allPredictions[1][1].position, Vector2fNear(Eigen::Vector2f(3, -3), 1e-9));
    EXPECT_THAT(allPredictions[1][2].position, Vector2fNear(Eigen::Vector2f(4, -4), 1e-9));
    EXPECT_THAT(allPredictions[1][3].position, Vector2fNear(Eigen::Vector2f(5, -5), 1e-9));
    EXPECT_THAT(allPredictions[1][4].position, Vector2fNear(Eigen::Vector2f(6, -6), 1e-9));

    // Check pressures of predictions generated from first pair of ground truth points.
    EXPECT_FLOAT_EQ(0.52f, allPredictions[1][0].pressure);
    EXPECT_FLOAT_EQ(0.53f, allPredictions[1][1].pressure);
    EXPECT_FLOAT_EQ(0.54f, allPredictions[1][2].pressure);
    EXPECT_FLOAT_EQ(0.55f, allPredictions[1][3].pressure);
    EXPECT_FLOAT_EQ(0.56f, allPredictions[1][4].pressure);
}

// --- Prediction error helper functions. ---

struct GeneralPositionErrors {
    float alongTrajectoryErrorMean;
    float alongTrajectoryErrorStd;
    float offTrajectoryRmse;
};

// Inputs:
//  • Vector of ground truth points
//  • Vector of vectors of prediction points, where the first index is the source ground truth
//    index, and the second is the prediction target index.
//
// Returns a vector of GeneralPositionErrors, indexed by prediction time delta bucket.
std::vector<GeneralPositionErrors> computeGeneralPositionErrors(
        const std::vector<GroundTruthPoint>& groundTruthPoints,
        const std::vector<std::vector<PredictionPoint>>& predictionPoints) {
    // Aggregate errors by time bucket (prediction target index).
    std::vector<GeneralPositionErrors> generalPostitionErrors;
    for (size_t predictionTargetIndex = 0; predictionTargetIndex < TEST_MAX_NUM_PREDICTIONS;
         ++predictionTargetIndex) {
        std::vector<float> alongTrajectoryErrors;
        std::vector<float> alongTrajectorySquaredErrors;
        std::vector<float> offTrajectoryErrors;
        for (size_t sourceGroundTruthIndex = 1; sourceGroundTruthIndex < groundTruthPoints.size();
             ++sourceGroundTruthIndex) {
            const size_t targetGroundTruthIndex =
                    sourceGroundTruthIndex + predictionTargetIndex + 1;
            // Only include errors for points with a ground truth value.
            if (targetGroundTruthIndex < groundTruthPoints.size()) {
                const Eigen::Vector2f trajectory =
                        (groundTruthPoints[targetGroundTruthIndex].position -
                         groundTruthPoints[targetGroundTruthIndex - 1].position)
                                .normalized();
                const Eigen::Vector2f orthogonalTrajectory =
                        Eigen::Rotation2Df(M_PI_2) * trajectory;
                const Eigen::Vector2f positionError =
                        predictionPoints[sourceGroundTruthIndex][predictionTargetIndex].position -
                        groundTruthPoints[targetGroundTruthIndex].position;
                alongTrajectoryErrors.push_back(positionError.dot(trajectory));
                alongTrajectorySquaredErrors.push_back(alongTrajectoryErrors.back() *
                                                       alongTrajectoryErrors.back());
                offTrajectoryErrors.push_back(positionError.dot(orthogonalTrajectory));
            }
        }
        generalPostitionErrors.push_back(
                {.alongTrajectoryErrorMean = average(alongTrajectoryErrors),
                 .alongTrajectoryErrorStd = standardDeviation(alongTrajectoryErrors),
                 .offTrajectoryRmse = rmse(offTrajectoryErrors)});
    }
    return generalPostitionErrors;
}

// Inputs:
//  • Vector of ground truth points
//  • Vector of vectors of prediction points, where the first index is the source ground truth
//    index, and the second is the prediction target index.
//
// Returns a vector of pressure RMSEs, indexed by prediction time delta bucket.
std::vector<float> computePressureRmses(
        const std::vector<GroundTruthPoint>& groundTruthPoints,
        const std::vector<std::vector<PredictionPoint>>& predictionPoints) {
    // Aggregate errors by time bucket (prediction target index).
    std::vector<float> pressureRmses;
    for (size_t predictionTargetIndex = 0; predictionTargetIndex < TEST_MAX_NUM_PREDICTIONS;
         ++predictionTargetIndex) {
        std::vector<float> pressureErrors;
        for (size_t sourceGroundTruthIndex = 1; sourceGroundTruthIndex < groundTruthPoints.size();
             ++sourceGroundTruthIndex) {
            const size_t targetGroundTruthIndex =
                    sourceGroundTruthIndex + predictionTargetIndex + 1;
            // Only include errors for points with a ground truth value.
            if (targetGroundTruthIndex < groundTruthPoints.size()) {
                pressureErrors.push_back(
                        predictionPoints[sourceGroundTruthIndex][predictionTargetIndex].pressure -
                        groundTruthPoints[targetGroundTruthIndex].pressure);
            }
        }
        pressureRmses.push_back(rmse(pressureErrors));
    }
    return pressureRmses;
}

TEST(ErrorComputationHelperTest, ComputeGeneralPositionErrorsSimpleTest) {
    std::vector<GroundTruthPoint> groundTruthPoints =
            generateConstantGroundTruthPoints(GroundTruthPoint{{.position = Eigen::Vector2f(0, 0),
                                                                .pressure = 0.0f},
                                                               .timestamp = TEST_INITIAL_TIMESTAMP},
                                              /*numPoints=*/TEST_MAX_NUM_PREDICTIONS + 2);
    groundTruthPoints[3].position = Eigen::Vector2f(1, 0);
    groundTruthPoints[4].position = Eigen::Vector2f(1, 1);
    groundTruthPoints[5].position = Eigen::Vector2f(1, 3);
    groundTruthPoints[6].position = Eigen::Vector2f(2, 3);

    std::vector<std::vector<PredictionPoint>> predictionPoints =
            generateAllPredictionsByLinearExtrapolation(groundTruthPoints);

    // The generated predictions look like:
    //
    // |    Source  |         Target Ground Truth Index          |
    // |     Index  |   2    |   3    |   4    |   5    |   6    |
    // |------------|--------|--------|--------|--------|--------|
    // |          1 | (0, 0) | (0, 0) | (0, 0) | (0, 0) | (0, 0) |
    // |          2 |        | (0, 0) | (0, 0) | (0, 0) | (0, 0) |
    // |          3 |        |        | (2, 0) | (3, 0) | (4, 0) |
    // |          4 |        |        |        | (1, 2) | (1, 3) |
    // |          5 |        |        |        |        | (1, 5) |
    // |---------------------------------------------------------|
    // |               Actual Ground Truth Values                |
    // |  Position  | (0, 0) | (1, 0) | (1, 1) | (1, 3) | (2, 3) |
    // |  Previous  | (0, 0) | (0, 0) | (1, 0) | (1, 1) | (1, 3) |
    //
    // Note: this table organizes prediction targets by target ground truth index. Metrics are
    // aggregated across points with the same prediction time bucket index, which is different.
    // Each down-right diagonal from this table gives us points from a unique time bucket.

    // Initialize expected prediction errors from the table above. The first time bucket corresponds
    // to the long diagonal of the table, and subsequent time buckets step up-right from there.
    const std::vector<std::vector<float>> expectedAlongTrajectoryErrors{{0, -1, -1, -1, -1},
                                                                        {-1, -1, -3, -1},
                                                                        {-1, -3, 2},
                                                                        {-3, -2},
                                                                        {-2}};
    const std::vector<std::vector<float>> expectedOffTrajectoryErrors{{0, 0, 1, 0, 2},
                                                                      {0, 1, 2, 0},
                                                                      {1, 1, 3},
                                                                      {1, 3},
                                                                      {3}};

    std::vector<GeneralPositionErrors> generalPositionErrors =
            computeGeneralPositionErrors(groundTruthPoints, predictionPoints);

    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, generalPositionErrors.size());
    for (size_t i = 0; i < generalPositionErrors.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        EXPECT_FLOAT_EQ(average(expectedAlongTrajectoryErrors[i]),
                        generalPositionErrors[i].alongTrajectoryErrorMean);
        EXPECT_FLOAT_EQ(standardDeviation(expectedAlongTrajectoryErrors[i]),
                        generalPositionErrors[i].alongTrajectoryErrorStd);
        EXPECT_FLOAT_EQ(rmse(expectedOffTrajectoryErrors[i]),
                        generalPositionErrors[i].offTrajectoryRmse);
    }
}

TEST(ErrorComputationHelperTest, ComputePressureRmsesSimpleTest) {
    // Generate ground truth points with pressures {0.0, 0.0, 0.0, 0.0, 0.5, 0.5, 0.5}.
    // (We need TEST_MAX_NUM_PREDICTIONS + 2 to test all prediction time buckets.)
    std::vector<GroundTruthPoint> groundTruthPoints =
            generateConstantGroundTruthPoints(GroundTruthPoint{{.position = Eigen::Vector2f(0, 0),
                                                                .pressure = 0.0f},
                                                               .timestamp = TEST_INITIAL_TIMESTAMP},
                                              /*numPoints=*/TEST_MAX_NUM_PREDICTIONS + 2);
    for (size_t i = 4; i < groundTruthPoints.size(); ++i) {
        groundTruthPoints[i].pressure = 0.5f;
    }

    std::vector<std::vector<PredictionPoint>> predictionPoints =
            generateAllPredictionsByLinearExtrapolation(groundTruthPoints);

    std::vector<float> pressureRmses = computePressureRmses(groundTruthPoints, predictionPoints);

    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, pressureRmses.size());
    EXPECT_FLOAT_EQ(rmse(std::vector<float>{0.0f, 0.0f, -0.5f, 0.5f, 0.0f}), pressureRmses[0]);
    EXPECT_FLOAT_EQ(rmse(std::vector<float>{0.0f, -0.5f, -0.5f, 1.0f}), pressureRmses[1]);
    EXPECT_FLOAT_EQ(rmse(std::vector<float>{-0.5f, -0.5f, -0.5f}), pressureRmses[2]);
    EXPECT_FLOAT_EQ(rmse(std::vector<float>{-0.5f, -0.5f}), pressureRmses[3]);
    EXPECT_FLOAT_EQ(rmse(std::vector<float>{-0.5f}), pressureRmses[4]);
}

// --- MotionPredictorMetricsManager tests. ---

// Creates a mock atom reporting function that appends the reported atom to the given vector.
ReportAtomFunction createMockReportAtomFunction(std::vector<AtomFields>& reportedAtomFields) {
    return [&reportedAtomFields](const AtomFields& atomFields) -> void {
        reportedAtomFields.push_back(atomFields);
    };
}

// Helper function that instantiates a MetricsManager that reports metrics to outReportedAtomFields.
// Takes vectors of ground truth and prediction points of the same length, and passes these points
// to the MetricsManager. The format of these vectors is expected to be:
//  • groundTruthPoints: chronologically-ordered ground truth points, with at least 2 elements.
//  • predictionPoints: the first index points to a vector of predictions corresponding to the
//    source ground truth point with the same index.
//     - The first element should be empty, because there are not expected to be predictions until
//       we have received 2 ground truth points.
//     - The last element may be empty, because there will be no future ground truth points to
//       associate with those predictions (if not empty, it will be ignored).
//     - To test all prediction buckets, there should be at least TEST_MAX_NUM_PREDICTIONS non-empty
//       prediction sets (that is, excluding the first and last). Thus, groundTruthPoints and
//       predictionPoints should have size at least TEST_MAX_NUM_PREDICTIONS + 2.
//
// When the function returns, outReportedAtomFields will contain the reported AtomFields.
//
// This function returns void so that it can use test assertions.
void runMetricsManager(const std::vector<GroundTruthPoint>& groundTruthPoints,
                       const std::vector<std::vector<PredictionPoint>>& predictionPoints,
                       std::vector<AtomFields>& outReportedAtomFields) {
    MotionPredictorMetricsManager metricsManager(TEST_PREDICTION_INTERVAL_NANOS,
                                                 TEST_MAX_NUM_PREDICTIONS,
                                                 createMockReportAtomFunction(
                                                         outReportedAtomFields));

    // Validate structure of groundTruthPoints and predictionPoints.
    ASSERT_EQ(predictionPoints.size(), groundTruthPoints.size());
    ASSERT_GE(groundTruthPoints.size(), 2u);
    ASSERT_EQ(predictionPoints[0].size(), 0u);
    for (size_t i = 1; i + 1 < predictionPoints.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        ASSERT_EQ(predictionPoints[i].size(), TEST_MAX_NUM_PREDICTIONS);
    }

    // Pass ground truth points and predictions (for all except first and last ground truth).
    for (size_t i = 0; i < groundTruthPoints.size(); ++i) {
        metricsManager.onRecord(makeMotionEvent(groundTruthPoints[i]));
        if ((i > 0) && (i + 1 < predictionPoints.size())) {
            metricsManager.onPredict(makeMotionEvent(predictionPoints[i]));
        }
    }
    // Send a stroke-end event to trigger the logging call.
    metricsManager.onRecord(makeLiftMotionEvent());
}

// Vacuous test:
//  • Input: no prediction data.
//  • Expectation: no metrics should be logged.
TEST(MotionPredictorMetricsManagerTest, NoPredictions) {
    std::vector<AtomFields> reportedAtomFields;
    MotionPredictorMetricsManager metricsManager(TEST_PREDICTION_INTERVAL_NANOS,
                                                 TEST_MAX_NUM_PREDICTIONS,
                                                 createMockReportAtomFunction(reportedAtomFields));

    metricsManager.onRecord(makeMotionEvent(
            GroundTruthPoint{{.position = Eigen::Vector2f(0, 0), .pressure = 0}, .timestamp = 0}));
    metricsManager.onRecord(makeLiftMotionEvent());

    // Check that reportedAtomFields is still empty (as it was initialized empty), ensuring that
    // no metrics were logged.
    EXPECT_EQ(0u, reportedAtomFields.size());
}

// Perfect predictions test:
//  • Input: constant input events, perfect predictions matching the input events.
//  • Expectation: all error metrics should be zero, or NO_DATA_SENTINEL for "unreported" metrics.
//    (For example, scale-invariant errors are only reported for the final time bucket.)
TEST(MotionPredictorMetricsManagerTest, ConstantGroundTruthPerfectPredictions) {
    GroundTruthPoint groundTruthPoint{{.position = Eigen::Vector2f(10.0f, 20.0f), .pressure = 0.6f},
                                      .timestamp = TEST_INITIAL_TIMESTAMP};

    // Generate ground truth and prediction points as described by the runMetricsManager comment.
    std::vector<GroundTruthPoint> groundTruthPoints;
    std::vector<std::vector<PredictionPoint>> predictionPoints;
    for (size_t i = 0; i < TEST_MAX_NUM_PREDICTIONS + 2; ++i) {
        groundTruthPoints.push_back(groundTruthPoint);
        predictionPoints.push_back(i > 0 ? generateConstantPredictions(groundTruthPoint)
                                         : std::vector<PredictionPoint>{});
        groundTruthPoint.timestamp += TEST_PREDICTION_INTERVAL_NANOS;
    }

    std::vector<AtomFields> reportedAtomFields;
    runMetricsManager(groundTruthPoints, predictionPoints, reportedAtomFields);

    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, reportedAtomFields.size());
    // Check that errors are all zero, or NO_DATA_SENTINEL for unreported metrics.
    for (size_t i = 0; i < reportedAtomFields.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        const AtomFields& atom = reportedAtomFields[i];
        const nsecs_t deltaTimeBucketNanos = TEST_PREDICTION_INTERVAL_NANOS * (i + 1);
        EXPECT_EQ(deltaTimeBucketNanos / NANOS_PER_MILLIS, atom.deltaTimeBucketMilliseconds);
        // General errors: reported for every time bucket.
        EXPECT_EQ(0, atom.alongTrajectoryErrorMeanMillipixels);
        EXPECT_EQ(0, atom.alongTrajectoryErrorStdMillipixels);
        EXPECT_EQ(0, atom.offTrajectoryRmseMillipixels);
        EXPECT_EQ(0, atom.pressureRmseMilliunits);
        // High-velocity errors: reported only for the last two time buckets.
        // However, this data has zero velocity, so these metrics should all be NO_DATA_SENTINEL.
        EXPECT_EQ(NO_DATA_SENTINEL, atom.highVelocityAlongTrajectoryRmse);
        EXPECT_EQ(NO_DATA_SENTINEL, atom.highVelocityOffTrajectoryRmse);
        // Scale-invariant errors: reported only for the last time bucket.
        if (i + 1 == reportedAtomFields.size()) {
            EXPECT_EQ(0, atom.scaleInvariantAlongTrajectoryRmse);
            EXPECT_EQ(0, atom.scaleInvariantOffTrajectoryRmse);
        } else {
            EXPECT_EQ(NO_DATA_SENTINEL, atom.scaleInvariantAlongTrajectoryRmse);
            EXPECT_EQ(NO_DATA_SENTINEL, atom.scaleInvariantOffTrajectoryRmse);
        }
    }
}

TEST(MotionPredictorMetricsManagerTest, QuadraticPressureLinearPredictions) {
    // Generate ground truth points.
    //
    // Ground truth pressures are a quadratically increasing function from some initial value.
    const float initialPressure = 0.5f;
    const float quadraticCoefficient = 0.01f;
    std::vector<GroundTruthPoint> groundTruthPoints;
    nsecs_t timestamp = TEST_INITIAL_TIMESTAMP;
    // As described in the runMetricsManager comment, we should have TEST_MAX_NUM_PREDICTIONS + 2
    // ground truth points.
    for (size_t i = 0; i < TEST_MAX_NUM_PREDICTIONS + 2; ++i) {
        const float pressure = initialPressure + quadraticCoefficient * static_cast<float>(i * i);
        groundTruthPoints.push_back(
                GroundTruthPoint{{.position = Eigen::Vector2f(0, 0), .pressure = pressure},
                                 .timestamp = timestamp});
        timestamp += TEST_PREDICTION_INTERVAL_NANOS;
    }

    // Note: the first index is the source ground truth index, and the second is the prediction
    // target index.
    std::vector<std::vector<PredictionPoint>> predictionPoints =
            generateAllPredictionsByLinearExtrapolation(groundTruthPoints);

    const std::vector<float> pressureErrors =
            computePressureRmses(groundTruthPoints, predictionPoints);

    // Run test.
    std::vector<AtomFields> reportedAtomFields;
    runMetricsManager(groundTruthPoints, predictionPoints, reportedAtomFields);

    // Check logged metrics match expectations.
    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, reportedAtomFields.size());
    for (size_t i = 0; i < reportedAtomFields.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        const AtomFields& atom = reportedAtomFields[i];
        // Check time bucket delta matches expectation based on index and prediction interval.
        const nsecs_t deltaTimeBucketNanos = TEST_PREDICTION_INTERVAL_NANOS * (i + 1);
        EXPECT_EQ(deltaTimeBucketNanos / NANOS_PER_MILLIS, atom.deltaTimeBucketMilliseconds);
        // Check pressure error matches expectation.
        EXPECT_NEAR(static_cast<int>(1000 * pressureErrors[i]), atom.pressureRmseMilliunits, 1);
    }
}

TEST(MotionPredictorMetricsManagerTest, QuadraticPositionLinearPredictionsGeneralErrors) {
    // Generate ground truth points.
    //
    // Each component of the ground truth positions are an independent quadratically increasing
    // function from some initial value.
    const Eigen::Vector2f initialPosition(200, 300);
    const Eigen::Vector2f quadraticCoefficients(-2, 3);
    std::vector<GroundTruthPoint> groundTruthPoints;
    nsecs_t timestamp = TEST_INITIAL_TIMESTAMP;
    // As described in the runMetricsManager comment, we should have TEST_MAX_NUM_PREDICTIONS + 2
    // ground truth points.
    for (size_t i = 0; i < TEST_MAX_NUM_PREDICTIONS + 2; ++i) {
        const Eigen::Vector2f position =
                initialPosition + quadraticCoefficients * static_cast<float>(i * i);
        groundTruthPoints.push_back(
                GroundTruthPoint{{.position = position, .pressure = 0.5}, .timestamp = timestamp});
        timestamp += TEST_PREDICTION_INTERVAL_NANOS;
    }

    // Note: the first index is the source ground truth index, and the second is the prediction
    // target index.
    std::vector<std::vector<PredictionPoint>> predictionPoints =
            generateAllPredictionsByLinearExtrapolation(groundTruthPoints);

    std::vector<GeneralPositionErrors> generalPositionErrors =
            computeGeneralPositionErrors(groundTruthPoints, predictionPoints);

    // Run test.
    std::vector<AtomFields> reportedAtomFields;
    runMetricsManager(groundTruthPoints, predictionPoints, reportedAtomFields);

    // Check logged metrics match expectations.
    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, reportedAtomFields.size());
    for (size_t i = 0; i < reportedAtomFields.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        const AtomFields& atom = reportedAtomFields[i];
        // Check time bucket delta matches expectation based on index and prediction interval.
        const nsecs_t deltaTimeBucketNanos = TEST_PREDICTION_INTERVAL_NANOS * (i + 1);
        EXPECT_EQ(deltaTimeBucketNanos / NANOS_PER_MILLIS, atom.deltaTimeBucketMilliseconds);
        // Check general position errors match expectation.
        EXPECT_NEAR(static_cast<int>(1000 * generalPositionErrors[i].alongTrajectoryErrorMean),
                    atom.alongTrajectoryErrorMeanMillipixels, 1);
        EXPECT_NEAR(static_cast<int>(1000 * generalPositionErrors[i].alongTrajectoryErrorStd),
                    atom.alongTrajectoryErrorStdMillipixels, 1);
        EXPECT_NEAR(static_cast<int>(1000 * generalPositionErrors[i].offTrajectoryRmse),
                    atom.offTrajectoryRmseMillipixels, 1);
    }
}

// Counterclockwise regular octagonal section test:
//  • Input – ground truth: constantly-spaced input events starting at a trajectory pointing exactly
//    rightwards, and rotating by 45° counterclockwise after each input.
//  • Input – predictions: simple linear extrapolations of previous two ground truth points.
//
// The code below uses the following terminology to distinguish references to ground truth events:
//  • Source ground truth: the most recent ground truth point received at the time the prediction
//    was made.
//  • Target ground truth: the ground truth event that the prediction was attempting to match.
TEST(MotionPredictorMetricsManagerTest, CounterclockwiseOctagonGroundTruthLinearPredictions) {
    // Select a stroke velocity that exceeds the high-velocity threshold of 1100 px/sec.
    // For an input rate of 240 hz, 1100 px/sec * (1/240) sec/input ≈ 4.58 pixels per input.
    const float strokeVelocity = 10; // pixels per input

    // As described in the runMetricsManager comment, we should have TEST_MAX_NUM_PREDICTIONS + 2
    // ground truth points.
    std::vector<GroundTruthPoint> groundTruthPoints = generateCircularArcGroundTruthPoints(
            /*initialPosition=*/Eigen::Vector2f(100, 100),
            /*initialAngle=*/M_PI_2,
            /*velocity=*/strokeVelocity,
            /*turningAngle=*/-M_PI_4,
            /*numPoints=*/TEST_MAX_NUM_PREDICTIONS + 2);

    std::vector<std::vector<PredictionPoint>> predictionPoints =
            generateAllPredictionsByLinearExtrapolation(groundTruthPoints);

    std::vector<GeneralPositionErrors> generalPositionErrors =
            computeGeneralPositionErrors(groundTruthPoints, predictionPoints);

    // Run test.
    std::vector<AtomFields> reportedAtomFields;
    runMetricsManager(groundTruthPoints, predictionPoints, reportedAtomFields);

    // Check logged metrics match expectations.
    ASSERT_EQ(TEST_MAX_NUM_PREDICTIONS, reportedAtomFields.size());
    for (size_t i = 0; i < reportedAtomFields.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "i = " << i);
        const AtomFields& atom = reportedAtomFields[i];
        const nsecs_t deltaTimeBucketNanos = TEST_PREDICTION_INTERVAL_NANOS * (i + 1);
        EXPECT_EQ(deltaTimeBucketNanos / NANOS_PER_MILLIS, atom.deltaTimeBucketMilliseconds);

        // General errors: reported for every time bucket.
        EXPECT_NEAR(static_cast<int>(1000 * generalPositionErrors[i].alongTrajectoryErrorMean),
                    atom.alongTrajectoryErrorMeanMillipixels, 1);
        // We allow for some floating point error in standard deviation (0.02 pixels).
        EXPECT_NEAR(1000 * generalPositionErrors[i].alongTrajectoryErrorStd,
                    atom.alongTrajectoryErrorStdMillipixels, 20);
        // All position errors are equal, so the standard deviation should be approximately zero.
        EXPECT_NEAR(0, atom.alongTrajectoryErrorStdMillipixels, 20);
        // Absolute value for RMSE, since it must be non-negative.
        EXPECT_NEAR(static_cast<int>(1000 * generalPositionErrors[i].offTrajectoryRmse),
                    atom.offTrajectoryRmseMillipixels, 1);

        // High-velocity errors: reported only for the last two time buckets.
        //
        // Since our input stroke velocity is chosen to be above the high-velocity threshold, all
        // data contributes to high-velocity errors, and thus high-velocity errors should be equal
        // to general errors (where reported).
        //
        // As above, use absolute value for RMSE, since it must be non-negative.
        if (i + 2 >= reportedAtomFields.size()) {
            EXPECT_NEAR(static_cast<int>(
                                1000 * std::abs(generalPositionErrors[i].alongTrajectoryErrorMean)),
                        atom.highVelocityAlongTrajectoryRmse, 1);
            EXPECT_NEAR(static_cast<int>(1000 *
                                         std::abs(generalPositionErrors[i].offTrajectoryRmse)),
                        atom.highVelocityOffTrajectoryRmse, 1);
        } else {
            EXPECT_EQ(NO_DATA_SENTINEL, atom.highVelocityAlongTrajectoryRmse);
            EXPECT_EQ(NO_DATA_SENTINEL, atom.highVelocityOffTrajectoryRmse);
        }

        // Scale-invariant errors: reported only for the last time bucket, where the reported value
        // is the aggregation across all time buckets.
        //
        // The MetricsManager stores mMaxNumPredictions recent ground truth segments. Our ground
        // truth segments here all have a length of strokeVelocity, so we can convert general errors
        // to scale-invariant errors by dividing by `strokeVelocty * TEST_MAX_NUM_PREDICTIONS`.
        //
        // As above, use absolute value for RMSE, since it must be non-negative.
        if (i + 1 == reportedAtomFields.size()) {
            const float pathLength = strokeVelocity * TEST_MAX_NUM_PREDICTIONS;
            std::vector<float> alongTrajectoryAbsoluteErrors;
            std::vector<float> offTrajectoryAbsoluteErrors;
            for (size_t j = 0; j < TEST_MAX_NUM_PREDICTIONS; ++j) {
                alongTrajectoryAbsoluteErrors.push_back(
                        std::abs(generalPositionErrors[j].alongTrajectoryErrorMean));
                offTrajectoryAbsoluteErrors.push_back(
                        std::abs(generalPositionErrors[j].offTrajectoryRmse));
            }
            EXPECT_NEAR(static_cast<int>(1000 * average(alongTrajectoryAbsoluteErrors) /
                                         pathLength),
                        atom.scaleInvariantAlongTrajectoryRmse, 1);
            EXPECT_NEAR(static_cast<int>(1000 * average(offTrajectoryAbsoluteErrors) / pathLength),
                        atom.scaleInvariantOffTrajectoryRmse, 1);
        } else {
            EXPECT_EQ(NO_DATA_SENTINEL, atom.scaleInvariantAlongTrajectoryRmse);
            EXPECT_EQ(NO_DATA_SENTINEL, atom.scaleInvariantOffTrajectoryRmse);
        }
    }
}

} // namespace
} // namespace android
