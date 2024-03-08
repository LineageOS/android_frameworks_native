/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <algorithm>
#include <cmath>
#include <fstream>
#include <ios>
#include <iterator>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/TfLiteMotionPredictor.h>

namespace android {
namespace {

using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::FloatNear;

TEST(TfLiteMotionPredictorTest, BuffersReadiness) {
    TfLiteMotionPredictorBuffers buffers(/*inputLength=*/5);
    ASSERT_FALSE(buffers.isReady());

    buffers.pushSample(/*timestamp=*/0, {.position = {.x = 100, .y = 100}});
    ASSERT_FALSE(buffers.isReady());

    buffers.pushSample(/*timestamp=*/1, {.position = {.x = 100, .y = 100}});
    ASSERT_FALSE(buffers.isReady());

    // Two samples with distinct positions are required.
    buffers.pushSample(/*timestamp=*/2, {.position = {.x = 100, .y = 110}});
    ASSERT_TRUE(buffers.isReady());

    buffers.reset();
    ASSERT_FALSE(buffers.isReady());
}

TEST(TfLiteMotionPredictorTest, BuffersRecentData) {
    TfLiteMotionPredictorBuffers buffers(/*inputLength=*/5);

    buffers.pushSample(/*timestamp=*/1, {.position = {.x = 100, .y = 200}});
    ASSERT_EQ(buffers.lastTimestamp(), 1);

    buffers.pushSample(/*timestamp=*/2, {.position = {.x = 150, .y = 250}});
    ASSERT_EQ(buffers.lastTimestamp(), 2);
    ASSERT_TRUE(buffers.isReady());
    ASSERT_EQ(buffers.axisFrom().position.x, 100);
    ASSERT_EQ(buffers.axisFrom().position.y, 200);
    ASSERT_EQ(buffers.axisTo().position.x, 150);
    ASSERT_EQ(buffers.axisTo().position.y, 250);

    // Position doesn't change, so neither do the axes.
    buffers.pushSample(/*timestamp=*/3, {.position = {.x = 150, .y = 250}});
    ASSERT_EQ(buffers.lastTimestamp(), 3);
    ASSERT_TRUE(buffers.isReady());
    ASSERT_EQ(buffers.axisFrom().position.x, 100);
    ASSERT_EQ(buffers.axisFrom().position.y, 200);
    ASSERT_EQ(buffers.axisTo().position.x, 150);
    ASSERT_EQ(buffers.axisTo().position.y, 250);

    buffers.pushSample(/*timestamp=*/4, {.position = {.x = 180, .y = 280}});
    ASSERT_EQ(buffers.lastTimestamp(), 4);
    ASSERT_TRUE(buffers.isReady());
    ASSERT_EQ(buffers.axisFrom().position.x, 150);
    ASSERT_EQ(buffers.axisFrom().position.y, 250);
    ASSERT_EQ(buffers.axisTo().position.x, 180);
    ASSERT_EQ(buffers.axisTo().position.y, 280);
}

TEST(TfLiteMotionPredictorTest, BuffersCopyTo) {
    std::unique_ptr<TfLiteMotionPredictorModel> model = TfLiteMotionPredictorModel::create();
    TfLiteMotionPredictorBuffers buffers(model->inputLength());

    buffers.pushSample(/*timestamp=*/1,
                       {.position = {.x = 10, .y = 10},
                        .pressure = 0,
                        .orientation = 0,
                        .tilt = 0.2});
    buffers.pushSample(/*timestamp=*/2,
                       {.position = {.x = 10, .y = 50},
                        .pressure = 0.4,
                        .orientation = M_PI / 4,
                        .tilt = 0.3});
    buffers.pushSample(/*timestamp=*/3,
                       {.position = {.x = 30, .y = 50},
                        .pressure = 0.5,
                        .orientation = -M_PI / 4,
                        .tilt = 0.4});
    buffers.pushSample(/*timestamp=*/3,
                       {.position = {.x = 30, .y = 60},
                        .pressure = 0,
                        .orientation = 0,
                        .tilt = 0.5});
    buffers.copyTo(*model);

    const int zeroPadding = model->inputLength() - 3;
    ASSERT_GE(zeroPadding, 0);

    EXPECT_THAT(model->inputR().subspan(0, zeroPadding), Each(0));
    EXPECT_THAT(model->inputPhi().subspan(0, zeroPadding), Each(0));
    EXPECT_THAT(model->inputPressure().subspan(0, zeroPadding), Each(0));
    EXPECT_THAT(model->inputTilt().subspan(0, zeroPadding), Each(0));
    EXPECT_THAT(model->inputOrientation().subspan(0, zeroPadding), Each(0));

    EXPECT_THAT(model->inputR().subspan(zeroPadding), ElementsAre(40, 20, 10));
    EXPECT_THAT(model->inputPhi().subspan(zeroPadding), ElementsAre(0, -M_PI / 2, M_PI / 2));
    EXPECT_THAT(model->inputPressure().subspan(zeroPadding), ElementsAre(0.4, 0.5, 0));
    EXPECT_THAT(model->inputTilt().subspan(zeroPadding), ElementsAre(0.3, 0.4, 0.5));
    EXPECT_THAT(model->inputOrientation().subspan(zeroPadding),
                ElementsAre(FloatNear(-M_PI / 4, 1e-5), FloatNear(M_PI / 4, 1e-5),
                            FloatNear(M_PI / 2, 1e-5)));
}

TEST(TfLiteMotionPredictorTest, ModelInputOutputLength) {
    std::unique_ptr<TfLiteMotionPredictorModel> model = TfLiteMotionPredictorModel::create();
    ASSERT_GT(model->inputLength(), 0u);

    const size_t inputLength = model->inputLength();
    ASSERT_EQ(inputLength, static_cast<size_t>(model->inputR().size()));
    ASSERT_EQ(inputLength, static_cast<size_t>(model->inputPhi().size()));
    ASSERT_EQ(inputLength, static_cast<size_t>(model->inputPressure().size()));
    ASSERT_EQ(inputLength, static_cast<size_t>(model->inputOrientation().size()));
    ASSERT_EQ(inputLength, static_cast<size_t>(model->inputTilt().size()));

    ASSERT_TRUE(model->invoke());

    const size_t outputLength = model->outputLength();
    ASSERT_EQ(outputLength, static_cast<size_t>(model->outputR().size()));
    ASSERT_EQ(outputLength, static_cast<size_t>(model->outputPhi().size()));
    ASSERT_EQ(outputLength, static_cast<size_t>(model->outputPressure().size()));
}

TEST(TfLiteMotionPredictorTest, ModelOutput) {
    std::unique_ptr<TfLiteMotionPredictorModel> model = TfLiteMotionPredictorModel::create();
    TfLiteMotionPredictorBuffers buffers(model->inputLength());

    buffers.pushSample(/*timestamp=*/1, {.position = {.x = 100, .y = 200}, .pressure = 0.2});
    buffers.pushSample(/*timestamp=*/2, {.position = {.x = 150, .y = 250}, .pressure = 0.4});
    buffers.pushSample(/*timestamp=*/3, {.position = {.x = 180, .y = 280}, .pressure = 0.6});
    buffers.copyTo(*model);

    ASSERT_TRUE(model->invoke());

    // The actual model output is implementation-defined, but it should at least be non-zero and
    // non-NaN.
    const auto is_valid = [](float value) { return !isnan(value) && value != 0; };
    ASSERT_TRUE(std::all_of(model->outputR().begin(), model->outputR().end(), is_valid));
    ASSERT_TRUE(std::all_of(model->outputPhi().begin(), model->outputPhi().end(), is_valid));
    ASSERT_TRUE(
            std::all_of(model->outputPressure().begin(), model->outputPressure().end(), is_valid));
}

} // namespace
} // namespace android
