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

#include <aidl/android/hardware/graphics/common/BufferUsage.h>
#include <common/include/common/test/FlagUtils.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include "android/hardware_buffer.h"
#include "com_android_graphics_surfaceflinger_flags.h"
#include "compositionengine/LayerFECompositionState.h"

#include <aidl/android/hardware/graphics/composer3/Composition.h>

using ::aidl::android::hardware::graphics::common::BufferUsage;
using ::aidl::android::hardware::graphics::composer3::Composition;

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
const constexpr float sAlphaOne = 0.25f;
const constexpr float sAlphaTwo = 0.5f;
const Region sRegionOne = Region(sRectOne);
const Region sRegionTwo = Region(sRectTwo);
const mat4 sMat4One = mat4::scale(vec4(2.f, 3.f, 1.f, 1.f));
native_handle_t* const sFakeSidebandStreamOne = reinterpret_cast<native_handle_t*>(10);
native_handle_t* const sFakeSidebandStreamTwo = reinterpret_cast<native_handle_t*>(11);
const half4 sHalf4One = half4(0.2f, 0.3f, 0.4f, 0.5f);
const half4 sHalf4Two = half4(0.5f, 0.4f, 0.3f, 0.2f);
const std::string sMetadataKeyOne = std::string("Meta!");
const std::string sMetadataKeyTwo = std::string("Data!");
const GenericLayerMetadataEntry sMetadataValueOne = GenericLayerMetadataEntry{
        .value = std::vector<uint8_t>({1, 2}),
};
const GenericLayerMetadataEntry sMetadataValueTwo = GenericLayerMetadataEntry{
        .value = std::vector<uint8_t>({1, 3}),
};
const constexpr int32_t sBgBlurRadiusOne = 3;
const constexpr int32_t sBgBlurRadiusTwo = 4;
const BlurRegion sBlurRegionOne = BlurRegion{1, 2.f, 3.f, 4.f, 5.f, 6.f, 7, 8, 9, 10};
const BlurRegion sBlurRegionTwo = BlurRegion{2, 3.f, 4.f, 5.f, 6.f, 7.f, 8, 9, 10, 11};

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

    void verifyUniqueDifferingFields(const LayerState& lhs, const LayerState& rhs) {
        EXPECT_EQ(lhs.getHash(), rhs.getHash());

        EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::None), lhs.getDifferingFields(rhs));
        EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::None), rhs.getDifferingFields(lhs));
    }

    void verifyNonUniqueDifferingFields(const LayerState& lhs, const LayerState& rhs,
                                        ftl::Flags<LayerStateField> fields) {
        EXPECT_NE(lhs.getHash(), rhs.getHash());

        EXPECT_EQ(fields, lhs.getDifferingFields(rhs));
        EXPECT_EQ(fields, rhs.getDifferingFields(lhs));
    }

    sp<mock::LayerFE> mLayerFE = sp<mock::LayerFE>::make();
    mock::OutputLayer mOutputLayer;
    std::unique_ptr<LayerState> mLayerState;

    static constexpr auto kUsageFlags = static_cast<uint32_t>(
            AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN);
};

TEST_F(LayerStateTest, getOutputLayer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(&mOutputLayer, mLayerState->getOutputLayer());
}

TEST_F(LayerStateTest, updateOutputLayer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(&mOutputLayer, mLayerState->getOutputLayer());

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState->update(&newOutputLayer);
    EXPECT_EQ(&newOutputLayer, mLayerState->getOutputLayer());
}

TEST_F(LayerStateTest, getId) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(sSequenceId, mLayerState->getId());
}

TEST_F(LayerStateTest, updateId) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceIdTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(sSequenceIdTwo, mLayerState->getId());
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Id), updates);
}

TEST_F(LayerStateTest, compareId) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceIdTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getId(), otherLayerState->getId());

    // Id is a unique field, so it's not computed in the hash for a layer state.
    verifyUniqueDifferingFields(*mLayerState, *otherLayerState);
    EXPECT_FALSE(mLayerState->compare(*otherLayerState));
    EXPECT_FALSE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getName) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(sDebugName, mLayerState->getName());
}

TEST_F(LayerStateTest, updateName) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceId, sDebugNameTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(sDebugNameTwo, mLayerState->getName());
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Name), updates);
}

TEST_F(LayerStateTest, compareName) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionState, sSequenceId, sDebugNameTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getName(), otherLayerState->getName());

    // Name is a unique field, so it's not computed in the hash for a layer state.
    verifyUniqueDifferingFields(*mLayerState, *otherLayerState);
    EXPECT_FALSE(mLayerState->compare(*otherLayerState));
    EXPECT_FALSE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getDisplayFrame) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(sRectOne, mLayerState->getDisplayFrame());
}

TEST_F(LayerStateTest, updateDisplayFrame) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(sRectTwo, mLayerState->getDisplayFrame());
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::DisplayFrame), updates);
}

TEST_F(LayerStateTest, compareDisplayFrame) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getDisplayFrame(), otherLayerState->getDisplayFrame());

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::DisplayFrame);
    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getCompositionType) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType = Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(Composition::DEVICE, mLayerState->getCompositionType());
}

TEST_F(LayerStateTest, getCompositionType_forcedClient) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.forceClientComposition = true;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType = Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(Composition::CLIENT, mLayerState->getCompositionType());
}

TEST_F(LayerStateTest, getHdrSdrRatio) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.currentHdrSdrRatio = 2.f;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_EQ(2.f, mLayerState->getHdrSdrRatio());
}

TEST_F(LayerStateTest, updateCompositionType) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType = Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.compositionType = Composition::SOLID_COLOR;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(Composition::SOLID_COLOR, mLayerState->getCompositionType());
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::CompositionType), updates);
}

TEST_F(LayerStateTest, compareCompositionType) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.compositionType = Composition::DEVICE;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.compositionType = Composition::SOLID_COLOR;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(mLayerState->getCompositionType(), otherLayerState->getCompositionType());

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState,
                                   LayerStateField::CompositionType);
    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBuffer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Buffer), updates);
}

TEST_F(LayerStateTest, updateBufferSingleBufferedLegacy) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);

    for (uint64_t i = 0; i < 10; i++) {
        layerFECompositionStateTwo.frameNumber = i;
        setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                           layerFECompositionStateTwo);
        ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
        EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Buffer), updates);
    }
}

TEST_F(LayerStateTest, updateBufferSingleBufferedUsage) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = sp<GraphicBuffer>::make();
    layerFECompositionStateTwo.buffer->usage = static_cast<uint64_t>(BufferUsage::FRONT_BUFFER);
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);

    for (uint64_t i = 0; i < 10; i++) {
        setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                           layerFECompositionStateTwo);
        ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
        EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Buffer), updates);
    }
}

TEST_F(LayerStateTest, compareBuffer) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    // A buffer is not a unique field, but the assertions are the same.
    verifyUniqueDifferingFields(*mLayerState, *otherLayerState);

    // Buffers are explicitly excluded from comparison
    EXPECT_FALSE(mLayerState->compare(*otherLayerState));
    EXPECT_FALSE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateSourceCrop) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.sourceCrop = sFloatRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.sourceCrop = sFloatRectTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::SourceCrop), updates);
}

TEST_F(LayerStateTest, compareSourceCrop) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::
                              cache_when_source_crop_layer_only_moved,
                      false);
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.sourceCrop = sFloatRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.sourceCrop = sFloatRectTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::SourceCrop);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBufferTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.bufferTransform = Hwc2::Transform::FLIP_H;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.bufferTransform = Hwc2::Transform::FLIP_V;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::BufferTransform), updates);
}

TEST_F(LayerStateTest, compareBufferTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.bufferTransform = Hwc2::Transform::FLIP_H;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.bufferTransform = Hwc2::Transform::FLIP_V;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState,
                                   LayerStateField::BufferTransform);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBlendMode) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blendMode = hal::BlendMode::COVERAGE;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.blendMode = hal::BlendMode::PREMULTIPLIED;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::BlendMode), updates);
}

TEST_F(LayerStateTest, compareBlendMode) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blendMode = hal::BlendMode::COVERAGE;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.blendMode = hal::BlendMode::PREMULTIPLIED;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::BlendMode);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateAlpha) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.alpha = sAlphaOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Alpha), updates);
}

TEST_F(LayerStateTest, compareAlpha) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.alpha = sAlphaOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.alpha = sAlphaTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::Alpha);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateLayerMetadata) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.metadata[sMetadataKeyOne] = sMetadataValueOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.metadata[sMetadataKeyTwo] = sMetadataValueTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::LayerMetadata), updates);
}

TEST_F(LayerStateTest, compareLayerMetadata) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.metadata[sMetadataKeyOne] = sMetadataValueOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.metadata[sMetadataKeyTwo] = sMetadataValueTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::LayerMetadata);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, getVisibleRegion) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.visibleRegion = sRegionOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_TRUE(mLayerState->getVisibleRegion().hasSameRects(sRegionOne));
}

TEST_F(LayerStateTest, updateVisibleRegion) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.visibleRegion = sRegionOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.visibleRegion = sRegionTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::VisibleRegion), updates);
}

TEST_F(LayerStateTest, compareVisibleRegion) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.visibleRegion = sRegionOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.visibleRegion = sRegionTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::VisibleRegion);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateDataspace) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.dataspace = ui::Dataspace::SRGB;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.dataspace = ui::Dataspace::DISPLAY_P3;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Dataspace), updates);
}

TEST_F(LayerStateTest, compareDataspace) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.dataspace = ui::Dataspace::SRGB;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.dataspace = ui::Dataspace::DISPLAY_P3;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::Dataspace);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updatePixelFormat) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer =
            sp<GraphicBuffer>::make(1u, 1u, PIXEL_FORMAT_RGBA_8888, kUsageFlags, "buffer1");
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer =
            sp<GraphicBuffer>::make(1u, 1u, PIXEL_FORMAT_RGBX_8888, kUsageFlags, "buffer2");
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::Buffer) |
                      ftl::Flags<LayerStateField>(LayerStateField::PixelFormat),
              updates);
}

TEST_F(LayerStateTest, comparePixelFormat) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer =
            sp<GraphicBuffer>::make(1u, 1u, PIXEL_FORMAT_RGBA_8888, kUsageFlags, "buffer1");
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer =
            sp<GraphicBuffer>::make(1u, 1u, PIXEL_FORMAT_RGBX_8888, kUsageFlags, "buffer2");
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState,
                                   ftl::Flags<LayerStateField>(LayerStateField::PixelFormat));

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateColorTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.colorTransformIsIdentity = true;
    layerFECompositionState.colorTransform = mat4();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::ColorTransform), updates);
}

TEST_F(LayerStateTest, compareColorTransform) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.colorTransformIsIdentity = true;
    layerFECompositionState.colorTransform = mat4();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.colorTransformIsIdentity = false;
    layerFECompositionStateTwo.colorTransform = sMat4One;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::ColorTransform);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateSidebandStream) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.sidebandStream = NativeHandle::create(sFakeSidebandStreamOne, false);
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.sidebandStream = NativeHandle::create(sFakeSidebandStreamTwo, false);
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::SidebandStream), updates);
}

TEST_F(LayerStateTest, compareSidebandStream) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.sidebandStream = NativeHandle::create(sFakeSidebandStreamOne, false);
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.sidebandStream = NativeHandle::create(sFakeSidebandStreamTwo, false);
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::SidebandStream);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateSolidColor) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.color = sHalf4One;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.color = sHalf4Two;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::SolidColor), updates);
}

TEST_F(LayerStateTest, compareSolidColor) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.color = sHalf4One;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.color = sHalf4Two;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::SolidColor);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBackgroundBlur) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.backgroundBlurRadius = sBgBlurRadiusOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.backgroundBlurRadius = sBgBlurRadiusTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::BackgroundBlurRadius), updates);
}

TEST_F(LayerStateTest, compareBackgroundBlur) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.backgroundBlurRadius = sBgBlurRadiusOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.backgroundBlurRadius = sBgBlurRadiusTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState,
                                   LayerStateField::BackgroundBlurRadius);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateBlurRegions) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blurRegions.push_back(sBlurRegionOne);
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.blurRegions.push_back(sBlurRegionTwo);
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::BlurRegions), updates);
}

TEST_F(LayerStateTest, compareBlurRegions) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blurRegions.push_back(sBlurRegionOne);
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.blurRegions.push_back(sBlurRegionTwo);
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::BlurRegions);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, hasBlurBehind_noBlur_returnsFalse) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_FALSE(mLayerState->hasBlurBehind());
}

TEST_F(LayerStateTest, hasBlurBehind_withBackgroundBlur_returnsTrue) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.backgroundBlurRadius = sBgBlurRadiusOne;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_TRUE(mLayerState->hasBlurBehind());
}

TEST_F(LayerStateTest, hasBlurBehind_withBlurRegion_returnsTrue) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.blurRegions.push_back(sBlurRegionOne);
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_TRUE(mLayerState->hasBlurBehind());
}

TEST_F(LayerStateTest, updateCachingHint) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.cachingHint = gui::CachingHint::Enabled;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.cachingHint = gui::CachingHint::Disabled;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::CachingHint), updates);
}

TEST_F(LayerStateTest, compareCachingHint) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.cachingHint = gui::CachingHint::Enabled;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.cachingHint = gui::CachingHint::Disabled;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::CachingHint);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, updateDimmingEnabled) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.dimmingEnabled = true;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    EXPECT_TRUE(mLayerState->isDimmingEnabled());

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.dimmingEnabled = false;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    ftl::Flags<LayerStateField> updates = mLayerState->update(&newOutputLayer);
    EXPECT_EQ(ftl::Flags<LayerStateField>(LayerStateField::DimmingEnabled), updates);
    EXPECT_FALSE(mLayerState->isDimmingEnabled());
}

TEST_F(LayerStateTest, compareDimmingEnabled) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.dimmingEnabled = true;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.dimmingEnabled = false;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    verifyNonUniqueDifferingFields(*mLayerState, *otherLayerState, LayerStateField::DimmingEnabled);

    EXPECT_TRUE(mLayerState->compare(*otherLayerState));
    EXPECT_TRUE(otherLayerState->compare(*mLayerState));
}

TEST_F(LayerStateTest, dumpDoesNotCrash) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    std::string dump;
    mLayerState->dump(dump);
    EXPECT_TRUE(dump.size() > 0);
}

TEST_F(LayerStateTest, framesSinceBufferUpdate) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
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
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_NE(getNonBufferHash({mLayerState.get(), otherLayerState.get()}),
              getNonBufferHash({otherLayerState.get(), mLayerState.get()}));
}

TEST_F(LayerStateTest, getNonBufferHash_isIdempotent) {
    OutputLayerCompositionState outputLayerCompositionState;
    outputLayerCompositionState.displayFrame = sRectOne;
    LayerFECompositionState layerFECompositionState;
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);
    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    OutputLayerCompositionState outputLayerCompositionStateTwo;
    outputLayerCompositionStateTwo.displayFrame = sRectTwo;
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionStateTwo,
                       layerFECompositionState);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_EQ(getNonBufferHash({mLayerState.get(), otherLayerState.get()}),
              getNonBufferHash({mLayerState.get(), otherLayerState.get()}));
}

TEST_F(LayerStateTest, getNonBufferHash_filtersOutBuffers) {
    OutputLayerCompositionState outputLayerCompositionState;
    LayerFECompositionState layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(mOutputLayer, *mLayerFE, outputLayerCompositionState,
                       layerFECompositionState);
    mLayerState = std::make_unique<LayerState>(&mOutputLayer);

    mock::OutputLayer newOutputLayer;
    sp<mock::LayerFE> newLayerFE = sp<mock::LayerFE>::make();
    LayerFECompositionState layerFECompositionStateTwo;
    layerFECompositionStateTwo.buffer = sp<GraphicBuffer>::make();
    setupMocksForLayer(newOutputLayer, *newLayerFE, outputLayerCompositionState,
                       layerFECompositionStateTwo);
    auto otherLayerState = std::make_unique<LayerState>(&newOutputLayer);

    EXPECT_EQ(getNonBufferHash({mLayerState.get()}), getNonBufferHash({otherLayerState.get()}));
}

} // namespace
} // namespace android::compositionengine::impl::planner
