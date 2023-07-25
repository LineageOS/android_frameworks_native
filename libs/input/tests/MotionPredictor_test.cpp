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

#include <chrono>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/constants.h>
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
    event.initialize(InputEvent::nextId(), deviceId, AINPUT_SOURCE_STYLUS, ADISPLAY_ID_DEFAULT, {0},
                     action, /*actionButton=*/0, /*flags=*/0, AMOTION_EVENT_EDGE_FLAG_NONE,
                     AMETA_NONE, /*buttonState=*/0, MotionClassification::NONE, identityTransform,
                     /*xPrecision=*/0.1,
                     /*yPrecision=*/0.2, /*xCursorPosition=*/280, /*yCursorPosition=*/540,
                     identityTransform, /*downTime=*/100, eventTime.count(), pointerCount,
                     pointerProperties.data(), pointerCoords.data());
    return event;
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

    // MOVE without a DOWN is ignored.
    predictor.record(getMotionEvent(MOVE, 1, 3, 10ms));
    EXPECT_EQ(nullptr, predictor.predict(20 * NSEC_PER_MSEC));

    predictor.record(getMotionEvent(DOWN, 2, 5, 20ms));
    predictor.record(getMotionEvent(MOVE, 2, 7, 30ms));
    predictor.record(getMotionEvent(MOVE, 3, 9, 40ms));
    EXPECT_NE(nullptr, predictor.predict(50 * NSEC_PER_MSEC));

    predictor.record(getMotionEvent(UP, 4, 11, 50ms));
    EXPECT_EQ(nullptr, predictor.predict(20 * NSEC_PER_MSEC));
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

} // namespace android
