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

#undef LOG_TAG
#define LOG_TAG "LayerStateTest"

#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gtest/gtest.h>
#include <log/log.h>

namespace android::compositionengine::impl::planner {
namespace {

using testing::Return;
using testing::ReturnRef;

const std::string sDebugName = std::string("Test LayerFE");
const std::string sDebugNameTwo = std::string("Test LayerFE2");
const constexpr int32_t sSequenceId = 12345;
const constexpr int32_t sSequenceIdTwo = 123456;
const Rect sRectOne = Rect(10, 20, 30, 40);
const Rect sRectTwo = Rect(40, 30, 20, 10);
const FloatRect sFloatRectOne = FloatRect(100.f, 200.f, 300.f, 400.f);
const FloatRect sFloatRectTwo = FloatRect(400.f, 300.f, 200.f, 100.f);
const constexpr int32_t sZOne = 100;
const constexpr int32_t sZTwo = 101;
const constexpr float sAlphaOne = 0.25f;
const constexpr float sAlphaTwo = 0.5f;
const Region sRegionOne = Region(sRectOne);
const Region sRegionTwo = Region(sRectTwo);
const mat4 sMat4One = mat4::scale(vec4(2.f, 3.f, 1.f, 1.f));
native_handle_t* const sFakeSidebandStreamOne = reinterpret_cast<native_handle_t*>(10);
native_handle_t* const sFakeSidebandStreamTwo = reinterpret_cast<native_handle_t*>(11);
const half4 sHalf4One = half4(0.2f, 0.3f, 0.4f, 0.5f);
const half4 sHalf4Two = half4(0.5f, 0.4f, 0.43, 0.2f);

struct LayerStateTest : public testing::Test {
    LayerStateTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~LayerStateTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void setupMocksForLayer(mock::OutputLayer& layer, mock::LayerFE& layerFE,
                            const OutputLayerCompositionState& outputLayerState,
                            const LayerFECompositionState& layerFEState,
                            int32_t sequenceId = sSequenceId,
                            const std::string& debugName = sDebugName) {
        EXPECT_CALL(layer, getLayerFE()).WillRepeatedly(ReturnRef(layerFE));
        EXPECT_CALL(layer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
        EXPECT_CALL(layerFE, getSequence()).WillRepeatedly(Return(sequenceId));
        EXPECT_CALL(layerFE, getDebugName()).WillRepeatedly(Return(debugName.c_str()));
        EXPECT_CALL(layerFE, getCompositionState()).WillRepeatedly(Return(&layerFEState));
    }

    mock::LayerFE mLayerFE;
    mock::OutputLayer mOutputLayer;
    std::unique_ptr<LayerState> mLayerState;
};

TEST_F(LayerStateTest, getOutputLayer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(&mOutputLayer, mLayerState->getOutputLayer());
}

TEST_F(LayerStateTest, getId) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(sSequenceId, mLayerState->getId());
}

TEST_F(LayerStateTest, updateId) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceIdTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(sSequenceIdTwo, mLayerState->getId());
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Id), updates);
}

TEST_F(LayerStateTest, compareId) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceIdTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getId(), otherLayerState->getId());

    // Id is a unique field, so it's not computed in the hash for a layer state.
    EXPECT_EQ(mLayerState->getHash(), otherLayerState->getHash());

    // Similarly, Id cannot be included in differing fields.
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::None),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::None),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_FALSE(mLayerState->compare(*otherLayerState));
    EXPECT_FALSE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getName) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(sDebugName, mLayerState->getName());
}

TEST_F(LayerStateTest, updateName) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceId, sDebugNameTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(sDebugNameTwo, mLayerState->getName());
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Name), updates);
}

TEST_F(LayerStateTest, compareName) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceId, sDebugNameTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getName(), otherLayerState->getName());

    // Name is a unique field, so it's not computed in the hash for a layer state.
    EXPECT_EQ(mLayerState->getHash(), otherLayerState->getHash());

    // Similarly, Name cannot be included in differing fields.
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::None),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::None),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_FALSE(mLayerState->compare(*otherLayerState));
    EXPECT_FALSE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getDisplayFrame) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(sRectOne, mLayerState->getDisplayFrame());
}

TEST_F(LayerStateTest, updateDisplayFrame) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(sRectTwo, mLayerState->getDisplayFrame());
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::DisplayFrame), updates);
}

TEST_F(LayerStateTest, compareDisplayFrame) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getDisplayFrame(), otherLayerState->getDisplayFrame());

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::DisplayFrame),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::DisplayFrame),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getCompositionType) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType =
            hardware::graphics::composer::hal::Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(hardware::graphics::composer::hal::Composition::DEVICE,
              mLayerState->getCompositionType());
}

TEST_F(LayerStateTest, getCompositionType_forcedClient) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.forceClientComposition = true;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType =
            hardware::graphics::composer::hal::Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(hardware::graphics::composer::hal::Composition::CLIENT,
              mLayerState->getCompositionType());
}

TEST_F(LayerStateTest, updateCompositionType) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType =
            hardware::graphics::composer::hal::Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.compositionType =
            hardware::graphics::composer::hal::Composition::SOLID_COLOR;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(hardware::graphics::composer::hal::Composition::SOLID_COLOR,
              mLayerState->getCompositionType());
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::CompositionType), updates);
}

TEST_F(LayerStateTest, compareCompositionType) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType =
            hardware::graphics::composer::hal::Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.compositionType =
            hardware::graphics::composer::hal::Composition::SOLID_COLOR;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getCompositionType(), otherLayerState->getCompositionType());

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::CompositionType),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::CompositionType),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBuffer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = new GraphicBuffer();
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = new GraphicBuffer();
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Buffer), updates);
}

TEST_F(LayerStateTest, compareBuffer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = new GraphicBuffer();
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = new GraphicBuffer();
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    // Buffers are not included in differing fields or in hashes.
    EXPECT_EQ(mLayerState->getHash(), otherLayerState->getHash());
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::None),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::None),
              otherLayerState->getDifferingFields(*mLayerState));

    // Buffers are explicitly excluded from comparison
    EXPECT_FALSE(mLayerState->compare(*otherLayerState));
    EXPECT_FALSE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateSourceCrop) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.sourceCrop = sFloatRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.sourceCrop = sFloatRectTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SourceCrop), updates);
}

TEST_F(LayerStateTest, compareSourceCrop) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.sourceCrop = sFloatRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.sourceCrop = sFloatRectTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SourceCrop),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SourceCrop),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateZOrder) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.z = sZOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.z = sZTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::ZOrder), updates);
}

TEST_F(LayerStateTest, compareZOrder) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.z = sZOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.z = sZTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::ZOrder),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::ZOrder),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBufferTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.bufferTransform = Hwc2::Transform::FLIP_H;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.bufferTransform = Hwc2::Transform::FLIP_V;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::BufferTransform), updates);
}

TEST_F(LayerStateTest, compareBufferTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.bufferTransform = Hwc2::Transform::FLIP_H;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.bufferTransform = Hwc2::Transform::FLIP_V;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::BufferTransform),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::BufferTransform),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBlendMode) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blendMode = hal::BlendMode::COVERAGE;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.blendMode = hal::BlendMode::PREMULTIPLIED;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::BlendMode), updates);
}

TEST_F(LayerStateTest, compareBlendMode) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blendMode = hal::BlendMode::COVERAGE;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.blendMode = hal::BlendMode::PREMULTIPLIED;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::BlendMode),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::BlendMode),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateAlpha) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.alpha = sAlphaOne;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Alpha), updates);
}

TEST_F(LayerStateTest, compareAlpha) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.alpha = sAlphaOne;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Alpha),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Alpha),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getVisibleRegion) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.visibleRegion = sRegionOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_TRUE(mLayerState->getVisibleRegion().hasSameRects(sRegionOne));
}

TEST_F(LayerStateTest, updateVisibleRegion) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.visibleRegion = sRegionOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.visibleRegion = sRegionTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::VisibleRegion), updates);
}

TEST_F(LayerStateTest, compareVisibleRegion) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.visibleRegion = sRegionOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.visibleRegion = sRegionTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::VisibleRegion),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::VisibleRegion),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateDataspace) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.dataspace = ui::Dataspace::SRGB;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.dataspace = ui::Dataspace::DISPLAY_P3;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Dataspace), updates);
}

TEST_F(LayerStateTest, compareDataspace) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.dataspace = ui::Dataspace::SRGB;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.dataspace = ui::Dataspace::DISPLAY_P3;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Dataspace),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::Dataspace),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateColorTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.colorTransformIsIdentity = true;
    layerFECompositionState.colorTransform = mat4();
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::ColorTransform), updates);
}

TEST_F(LayerStateTest, compareColorTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.colorTransformIsIdentity = true;
    layerFECompositionState.colorTransform = mat4();
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::ColorTransform),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::ColorTransform),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateSidebandStream) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.sidebandStream = NativeHandle::create(sFakeSidebandStreamOne, false);
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.sidebandStream = NativeHandle::create(sFakeSidebandStreamTwo, false);
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SidebandStream), updates);
}

TEST_F(LayerStateTest, compareSidebandStream) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.sidebandStream = NativeHandle::create(sFakeSidebandStreamOne, false);
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.sidebandStream = NativeHandle::create(sFakeSidebandStreamTwo, false);
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SidebandStream),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SidebandStream),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateSolidColor) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.color = sHalf4One;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.color = sHalf4Two;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SolidColor), updates);
}

TEST_F(LayerStateTest, compareSolidColor) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.color = sHalf4One;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.color = sHalf4Two;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getHash(), otherLayerState->getHash());

    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SolidColor),
              mLayerState->getDifferingFields(*otherLayerState));
    EXPECT_EQ(Flags<LayerStateField>(LayerStateField::SolidColor),
              otherLayerState->getDifferingFields(*mLayerState));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, dumpDoesNotCrash) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    std::string dump;
    mLayerState->dump(dump);
    EXPECT_TRUE(dump.size() > 0);
}

TEST_F(LayerStateTest, framesSinceBufferUpdate) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    EXPECT_EQ(0, mLayerState->getFramesSinceBufferUpdate());
    mLayerState->incrementFramesSinceBufferUpdate();
    EXPECT_EQ(1, mLayerState->getFramesSinceBufferUpdate());
    mLayerState->resetFramesSinceBufferUpdate();
    EXPECT_EQ(0, mLayerState->getFramesSinceBufferUpdate());
}

TEST_F(LayerStateTest, getNonBufferHash_doesNotCommute) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(getNonBufferHash({mLayerState.get(), otherLayerState.get()}),
              getNonBufferHash({otherLayerState.get(), mLayerState.get()}));
}

TEST_F(LayerStateTest, getNonBufferHash_isIdempotent) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_EQ(getNonBufferHash({mLayerState.get(), otherLayerState.get()}),
              getNonBufferHash({mLayerState.get(), otherLayerState.get()}));
}

TEST_F(LayerStateTest, getNonBufferHash_filtersOutBuffers) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = new GraphicBuffer();
    setupMocksForLayer(mOutputLayer, mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    mock::LayerFE newLayerFE;
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = new GraphicBuffer();
    setupMocksForLayer(newOutputLayer, newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_EQ(getNonBufferHash({mLayerState.get()}), getNonBufferHash({otherLayerState.get()}));
}

} // namespace
} // namespace android::compositionengine::impl::planner