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
#define LOG_TAG "PredictorTest"

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
const constexpr float sAlphaOne = 0.25f;
const constexpr float sAlphaTwo = 0.5f;
const Region sRegionOne = Region(sRectOne);
const Region sRegionTwo = Region(sRectTwo);
const mat4 sMat4One = mat4::scale(vec4(2.f, 3.f, 1.f, 1.f));

using testing::Return;
using testing::ReturnRef;

const std::string sDebugName = std::string("Test LayerFE");
const constexpr int32_t sSequenceId = 12345;

void setupMocksForLayer(mock::OutputLayer& layer, mock::LayerFE& layerFE,
                        const OutputLayerCompositionState& outputLayerState,
                        const LayerFECompositionState& layerFEState) {
    EXPECT_CALL(layer, getLayerFE()).WillRepeatedly(ReturnRef(layerFE));
    EXPECT_CALL(layer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
    EXPECT_CALL(layerFE, getSequence()).WillRepeatedly(Return(sSequenceId));
    EXPECT_CALL(layerFE, getDebugName()).WillRepeatedly(Return(sDebugName.c_str()));
    EXPECT_CALL(layerFE, getCompositionState()).WillRepeatedly(Return(&layerFEState));
}

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
    };
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.alpha = sAlphaOne;
    layerFECompositionStateOne.colorTransformIsIdentity = true;
    layerFECompositionStateOne.blendMode = hal::BlendMode::NONE;
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
    };
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    layerFECompositionStateTwo.blendMode = hal::BlendMode::PREMULTIPLIED;
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

struct PredictionTest : public testing::Test {
    PredictionTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~PredictionTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }
};

TEST_F(LayerStackTest, reorderingChangesNonBufferHash) {
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

    NonBufferHash hash = getNonBufferHash({&layerStateOne, &layerStateTwo});
    NonBufferHash hashReverse = getNonBufferHash({&layerStateTwo, &layerStateOne});
    EXPECT_NE(hash, hashReverse);
}

TEST_F(PredictionTest, constructPrediction) {
    Plan plan;
    plan.addLayerType(hal::Composition::DEVICE);

    Prediction prediction({}, plan);

    EXPECT_EQ(plan, prediction.getPlan());

    // check that dump doesn't crash
    std::string result;
    prediction.dump(result);
}

TEST_F(PredictionTest, recordHits) {
    Prediction prediction({}, {});

    const constexpr uint32_t kExactMatches = 2;
    for (uint32_t i = 0; i < kExactMatches; i++) {
        prediction.recordHit(Prediction::Type::Exact);
    }

    const constexpr uint32_t kApproximateMatches = 3;
    for (uint32_t i = 0; i < kApproximateMatches; i++) {
        prediction.recordHit(Prediction::Type::Approximate);
    }

    EXPECT_EQ(kExactMatches, prediction.getHitCount(Prediction::Type::Exact));
    EXPECT_EQ(kApproximateMatches, prediction.getHitCount(Prediction::Type::Approximate));
    EXPECT_EQ(kExactMatches + kApproximateMatches, prediction.getHitCount(Prediction::Type::Total));
}

TEST_F(PredictionTest, recordMisses) {
    Prediction prediction({}, {});

    const constexpr uint32_t kExactMatches = 2;
    for (uint32_t i = 0; i < kExactMatches; i++) {
        prediction.recordMiss(Prediction::Type::Exact);
    }

    const constexpr uint32_t kApproximateMatches = 3;
    for (uint32_t i = 0; i < kApproximateMatches; i++) {
        prediction.recordMiss(Prediction::Type::Approximate);
    }

    EXPECT_EQ(kExactMatches, prediction.getMissCount(Prediction::Type::Exact));
    EXPECT_EQ(kApproximateMatches, prediction.getMissCount(Prediction::Type::Approximate));
    EXPECT_EQ(kExactMatches + kApproximateMatches,
              prediction.getMissCount(Prediction::Type::Total));
}

struct PredictorTest : public testing::Test {
    PredictorTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~PredictorTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }
};

TEST_F(PredictorTest, getPredictedPlan_emptyLayersWithoutExactMatch_returnsNullopt) {
    Predictor predictor;
    EXPECT_FALSE(predictor.getPredictedPlan({}, 0));
}

TEST_F(PredictorTest, getPredictedPlan_recordCandidateAndRetrieveExactMatch) {
    mock::OutputLayer outputLayerOne;
    mock::LayerFE layerFEOne;
    OutputLayerCompositionState outputLayerCompositionStateOne;
    LayerFECompositionState layerFECompositionStateOne;
    layerFECompositionStateOne.compositionType = hal::Composition::DEVICE;
    setupMocksForLayer(outputLayerOne, layerFEOne, outputLayerCompositionStateOne,
                       layerFECompositionStateOne);
    LayerState layerStateOne(&outputLayerOne);

    Plan plan;
    plan.addLayerType(hal::Composition::DEVICE);

    Predictor predictor;

    NonBufferHash hash = getNonBufferHash({&layerStateOne});

    predictor.recordResult(std::nullopt, hash, {&layerStateOne}, false, plan);

    auto predictedPlan = predictor.getPredictedPlan({}, hash);
    EXPECT_TRUE(predictedPlan);
    Predictor::PredictedPlan expectedPlan{hash, plan, Prediction::Type::Exact};
    EXPECT_EQ(expectedPlan, predictedPlan);
}

TEST_F(PredictorTest, getPredictedPlan_recordCandidateAndRetrieveApproximateMatch) {
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

    Plan plan;
    plan.addLayerType(hal::Composition::DEVICE);

    Predictor predictor;

    NonBufferHash hashOne = getNonBufferHash({&layerStateOne});
    NonBufferHash hashTwo = getNonBufferHash({&layerStateTwo});

    predictor.recordResult(std::nullopt, hashOne, {&layerStateOne}, false, plan);

    auto predictedPlan = predictor.getPredictedPlan({&layerStateTwo}, hashTwo);
    EXPECT_TRUE(predictedPlan);
    Predictor::PredictedPlan expectedPlan{hashOne, plan, Prediction::Type::Approximate};
    EXPECT_EQ(expectedPlan, predictedPlan);
}

TEST_F(PredictorTest, recordMissedPlan_skipsApproximateMatch) {
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

    Plan plan;
    plan.addLayerType(hal::Composition::DEVICE);

    Predictor predictor;

    NonBufferHash hashOne = getNonBufferHash({&layerStateOne});
    NonBufferHash hashTwo = getNonBufferHash({&layerStateTwo});

    predictor.recordResult(std::nullopt, hashOne, {&layerStateOne}, false, plan);

    auto predictedPlan = predictor.getPredictedPlan({&layerStateTwo}, hashTwo);
    ASSERT_TRUE(predictedPlan);
    EXPECT_EQ(Prediction::Type::Approximate, predictedPlan->type);

    Plan planTwo;
    planTwo.addLayerType(hal::Composition::CLIENT);
    predictor.recordResult(predictedPlan, hashTwo, {&layerStateTwo}, false, planTwo);
    // Now trying to retrieve the predicted plan again returns a nullopt instead.
    // TODO(b/158790260): Even though this is enforced in this test, we might want to reassess this.
    // One of the implications around this implementation is that if we miss a prediction then we
    // can never actually correct our mistake if we see the same layer stack again, which doesn't
    // seem robust.
    auto predictedPlanTwo = predictor.getPredictedPlan({&layerStateTwo}, hashTwo);
    EXPECT_FALSE(predictedPlanTwo);
}

} // namespace
} // namespace android::compositionengine::impl::planner
