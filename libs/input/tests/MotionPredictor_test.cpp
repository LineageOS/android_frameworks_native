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

#include <gtest/gtest.h>
#include <gui/constants.h>
#include <input/Input.h>
#include <input/MotionPredictor.h>

namespace android {

constexpr int32_t DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr int32_t MOVE = AMOTION_EVENT_ACTION_MOVE;

static MotionEvent getMotionEvent(int32_t action, float x, float y, nsecs_t eventTime) {
    MotionEvent event;
    constexpr size_t pointerCount = 1;
    std::vector<PointerProperties> pointerProperties;
    std::vector<PointerCoords> pointerCoords;
    for (size_t i = 0; i < pointerCount; i++) {
        PointerProperties properties;
        properties.clear();
        properties.id = i;
        pointerProperties.push_back(properties);
        PointerCoords coords;
        coords.clear();
        coords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        pointerCoords.push_back(coords);
    }

    ui::Transform identityTransform;
    event.initialize(InputEvent::nextId(), /*deviceId=*/0, AINPUT_SOURCE_STYLUS,
                     ADISPLAY_ID_DEFAULT, {0}, action, /*actionButton=*/0, /*flags=*/0,
                     AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE, /*buttonState=*/0,
                     MotionClassification::NONE, identityTransform, /*xPrecision=*/0.1,
                     /*yPrecision=*/0.2, /*xCursorPosition=*/280, /*yCursorPosition=*/540,
                     identityTransform, /*downTime=*/100, eventTime, pointerCount,
                     pointerProperties.data(), pointerCoords.data());
    return event;
}

/**
 * A linear motion should be predicted to be linear in the future
 */
TEST(MotionPredictorTest, LinearPrediction) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    predictor.record(getMotionEvent(DOWN, 0, 1, 0));
    predictor.record(getMotionEvent(MOVE, 1, 3, 10));
    predictor.record(getMotionEvent(MOVE, 2, 5, 20));
    predictor.record(getMotionEvent(MOVE, 3, 7, 30));
    predictor.setExpectedPresentationTimeNanos(40);
    std::vector<std::unique_ptr<MotionEvent>> predicted = predictor.predict();
    ASSERT_EQ(1u, predicted.size());
    ASSERT_EQ(predicted[0]->getX(0), 4);
    ASSERT_EQ(predicted[0]->getY(0), 9);
}

/**
 * A still motion should be predicted to remain still
 */
TEST(MotionPredictorTest, StationaryPrediction) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });

    predictor.record(getMotionEvent(DOWN, 0, 1, 0));
    predictor.record(getMotionEvent(MOVE, 0, 1, 10));
    predictor.record(getMotionEvent(MOVE, 0, 1, 20));
    predictor.record(getMotionEvent(MOVE, 0, 1, 30));
    predictor.setExpectedPresentationTimeNanos(40);
    std::vector<std::unique_ptr<MotionEvent>> predicted = predictor.predict();
    ASSERT_EQ(1u, predicted.size());
    ASSERT_EQ(predicted[0]->getX(0), 0);
    ASSERT_EQ(predicted[0]->getY(0), 1);
}

TEST(MotionPredictorTest, IsPredictionAvailable) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return true /*enable prediction*/; });
    ASSERT_TRUE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_STYLUS));
    ASSERT_FALSE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_TOUCHSCREEN));
}

TEST(MotionPredictorTest, Offset) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/1,
                              []() { return true /*enable prediction*/; });
    predictor.setExpectedPresentationTimeNanos(40);
    predictor.record(getMotionEvent(DOWN, 0, 1, 30));
    predictor.record(getMotionEvent(MOVE, 0, 1, 35));
    std::vector<std::unique_ptr<MotionEvent>> predicted = predictor.predict();
    ASSERT_EQ(1u, predicted.size());
    ASSERT_GE(predicted[0]->getEventTime(), 41);
}

TEST(MotionPredictionTest, FlagDisablesPrediction) {
    MotionPredictor predictor(/*predictionTimestampOffsetNanos=*/0,
                              []() { return false /*disable prediction*/; });
    predictor.setExpectedPresentationTimeNanos(40);
    predictor.record(getMotionEvent(DOWN, 0, 1, 30));
    predictor.record(getMotionEvent(MOVE, 0, 1, 35));
    std::vector<std::unique_ptr<MotionEvent>> predicted = predictor.predict();
    ASSERT_EQ(0u, predicted.size());
    ASSERT_FALSE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_STYLUS));
    ASSERT_FALSE(predictor.isPredictionAvailable(/*deviceId=*/1, AINPUT_SOURCE_TOUCHSCREEN));
}

} // namespace android
