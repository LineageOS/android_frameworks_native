/*
 * Copyright 2021 The Android Open Source Project
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

#include "DisplayHardware/Hal.h"
#undef LOG_TAG
#define LOG_TAG "LayerStateTest"

#include <compositionengine/impl/planner/Predictor.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gtest/gtest.h>
#include <log/log.h>

namespace android::compositionengine::impl::planner {
namespace {

const FloatRect sFloatRectOne = FloatRect(100.f, 200.f, 300.f, 400.f);
const FloatRect sFloatRectTwo = FloatRect(400.f, 300.f, 200.f, 100.f);
const Rect sRectOne = Rect(1, 2, 3, 4);
const Rect sRectTwo = Rect(4, 3, 2, 1);
const constexpr int32_t sZOne = 100;
const constexpr int32_t sZTwo = 101;
const constexpr float sAlphaOne = 0.25f;
const constexpr float sAlphaTwo = 0.5f;
const Region sRegionOne = Region(sRectOne);
const Region sRegionTwo = Region(sRectTwo);
const mat4 sMat4One = mat4::scale(vec4(2.f, 3.f, 1.f, 1.f));

using testing::Return;
using testing::ReturnRef;

const std::string sDebugName = std::string("Test LayerFE");
const constexpr int32_t sSequenceId = 12345;

struct LayerStackTest : public testing::Test {
    LayerStackTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~LayerStackTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void setupMocksForLayer(mock::OutputLayer& layer, mock::LayerFE& layerFE,
                            const OutputLayerCompositionState& outputLayerState,
                            const LayerFECompositionState& layerFEState) {
        EXPECT_CALL(layer, getLayerFE()).WillRepeatedly(ReturnRef(layerFE));
        EXPECT_CALL(layer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
        EXPECT_CALL(layerFE, getSequence()).WillRepeatedly(Return(sSequenceId));
        EXPECT_CALL(layerFE, getDebugName()).WillRepeatedly(Return(sDebugName.c_str()));
        EXPECT_CALL(layerFE, getCompositionState()).WillRepeatedly(Return(&layerFEState));
    }
};

TEST_F(LayerStackTest, getApproximateMatch_doesNotMatchSizeDifferences) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne;
    LayerFECompositionState layerFECompositionStateOne;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    LayerFECompositionState layerFECompositionStateTwo;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    mock::OutputLayer outputLayerThree;
    mock::LayerFE layerFEThree;
    OutputLayerCompositionState outputLayerCompositionStateThree;
    LayerFECompositionState layerFECompositionStateThree;
    setupMocksForLayer(outputLayerThree, layerFEThree, outputLayerCompositionStateThree,
                       layerFECompositionStateThree);
    LayerState layerStateThree(&outputLayerThree);

    LayerStack stack({&layerStateOne});

    EXPECT_FALSE(stack.getApproximateMatch({}));
    EXPECT_FALSE(stack.getApproximateMatch({&layerStateOne, &layerStateThree}));
}

TEST_F(LayerStackTest, getApproximateMatch_doesNotMatchDifferentCompositionTypes) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne;
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.compositionType = hal::Composition::DEVICE;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.compositionType = hal::Composition::SOLID_COLOR;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    LayerStack stack({&layerStateOne});

    EXPECT_FALSE(stack.getApproximateMatch({&layerStateTwo}));
}

TEST_F(LayerStackTest, getApproximateMatch_matchesSingleDifferenceInSingleLayer) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne{
            .sourceCrop = sFloatRectOne,
    };
    LayerFECompositionState layerFECompositionStateOne;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo{
            .sourceCrop = sFloatRectTwo,
    };
    LayerFECompositionState layerFECompositionStateTwo;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    LayerStack stack({&layerStateOne});

    const auto match = stack.getApproximateMatch({&layerStateTwo});
    EXPECT_TRUE(match);
    LayerStack::ApproximateMatch expectedMatch;
    expectedMatch.differingIndex = 0;
    expectedMatch.differingFields = LayerStateField::SourceCrop;
    EXPECT_EQ(expectedMatch, *match);
}

TEST_F(LayerStackTest, getApproximateMatch_matchesSingleDifferenceInMultiLayerStack) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne{
            .sourceCrop = sFloatRectOne,
    };
    LayerFECompositionState layerFECompositionStateOne;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo{
            .sourceCrop = sFloatRectTwo,
    };
    LayerFECompositionState layerFECompositionStateTwo;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    LayerStack stack({&layerStateOne, &layerStateOne});

    const auto match = stack.getApproximateMatch({&layerStateOne, &layerStateTwo});
    EXPECT_TRUE(match);
    LayerStack::ApproximateMatch expectedMatch;
    expectedMatch.differingIndex = 1;
    expectedMatch.differingFields = LayerStateField::SourceCrop;
    EXPECT_EQ(expectedMatch, *match);
}

TEST_F(LayerStackTest, getApproximateMatch_doesNotMatchManyDifferences) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne{
            .visibleRegion = sRegionOne,
            .displayFrame = sRectOne,
            .sourceCrop = sFloatRectOne,
            .dataspace = ui::Dataspace::SRGB,
            .z = sZOne,
    };
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.alpha = sAlphaOne;
    layerFECompositionStateOne.colorTransformIsIdentity = true;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo{
            .visibleRegion = sRegionTwo,
            .displayFrame = sRectTwo,
            .sourceCrop = sFloatRectTwo,
            .dataspace = ui::Dataspace::DISPLAY_P3,
            .z = sZTwo,
    };
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    LayerStack stack({&layerStateOne});

    EXPECT_FALSE(stack.getApproximateMatch({&layerStateTwo}));
}

TEST_F(LayerStackTest, getApproximateMatch_exactMatchesSameBuffer) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne;
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.buffer = buffer;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = buffer;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    LayerStack stack({&layerStateOne});

    const auto match = stack.getApproximateMatch({&layerStateTwo});
    EXPECT_TRUE(match);
    LayerStack::ApproximateMatch expectedMatch;
    expectedMatch.differingIndex = 0;
    expectedMatch.differingFields = LayerStateField::None;
    EXPECT_EQ(expectedMatch, *match);
}

TEST_F(LayerStackTest, getApproximateMatch_alwaysMatchesClientComposition) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne{
            .visibleRegion = sRegionOne,
            .forceClientComposition = true,
            .displayFrame = sRectOne,
            .sourceCrop = sFloatRectOne,
            .dataspace = ui::Dataspace::SRGB,
            .z = sZOne,
    };
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.buffer = new GraphicBuffer();
    layerFECompositionStateOne.alpha = sAlphaOne;
    layerFECompositionStateOne.colorTransformIsIdentity = true;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo{
            .visibleRegion = sRegionTwo,
            .forceClientComposition = true,
            .displayFrame = sRectTwo,
            .sourceCrop = sFloatRectTwo,
            .dataspace = ui::Dataspace::DISPLAY_P3,
            .z = sZTwo,
    };
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = new GraphicBuffer();
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    LayerStack stack({&layerStateOne});

    const auto match = stack.getApproximateMatch({&layerStateTwo});
    EXPECT_TRUE(match);
    LayerStack::ApproximateMatch expectedMatch;
    expectedMatch.differingIndex = 0;
    expectedMatch.differingFields = LayerStateField::None;
    EXPECT_EQ(expectedMatch, *match);
}

TEST_F(LayerStackTest, getApproximateMatch_doesNotMatchMultipleApproximations) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne{
            .sourceCrop = sFloatRectOne,
    };
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.buffer = new GraphicBuffer();
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    mock::OutputLayer outputLayerTwo;
    mock::LayerFE layerFETwo;
    OutputLayerCompositionState outputLayerCompositionStateTwo{
            .sourceCrop = sFloatRectTwo,
    };
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = new GraphicBuffer();
    setupMocksForLayer(outputLayerTwo, layerFETwo, outputLayerCompositionStateTwo,
                       layerFECompositionStateTwo);
    LayerState layerStateTwo(&outputLayerTwo);

    EXPECT_TRUE(LayerStack({&layerStateOne}).getApproximateMatch({&layerStateTwo}));

    LayerStack stack({&layerStateOne, &layerStateOne});
    EXPECT_FALSE(stack.getApproximateMatch({&layerStateTwo, &layerStateTwo}));
}

} // namespace
} // namespace android::compositionengine::impl::planner