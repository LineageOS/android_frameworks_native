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

#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/planner/CachedSet.h>
#include <compositionengine/impl/planner/Flattener.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gtest/gtest.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/LayerSettings.h>
#include <renderengine/impl/ExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>
#include <chrono>

#include "tests/TestUtils.h"

namespace android::compositionengine {
using namespace std::chrono_literals;
using impl::planner::CachedSet;
using impl::planner::Flattener;
using impl::planner::LayerState;
using impl::planner::NonBufferHash;

using testing::_;
using testing::ByMove;
using testing::ByRef;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;
using testing::Sequence;
using testing::SetArgPointee;

namespace {

class TestableFlattener : public Flattener {
public:
    TestableFlattener(renderengine::RenderEngine& renderEngine, const Tunables& tunables)
          : Flattener(renderEngine, tunables) {}
    const std::optional<CachedSet>& getNewCachedSetForTesting() const { return mNewCachedSet; }
};

class FlattenerTest : public testing::Test {
public:
    FlattenerTest()
          : FlattenerTest(Flattener::Tunables{
                    .mActiveLayerTimeout = 100ms,
                    .mRenderScheduling = std::nullopt,
                    .mEnableHolePunch = true,
            }) {}
    void SetUp() override;

protected:
    FlattenerTest(const Flattener::Tunables& tunables)
          : mFlattener(std::make_unique<TestableFlattener>(mRenderEngine, tunables)) {}
    void initializeOverrideBuffer(const std::vector<const LayerState*>& layers);
    void initializeFlattener(const std::vector<const LayerState*>& layers);
    void expectAllLayersFlattened(const std::vector<const LayerState*>& layers);

    // mRenderEngine is held as a reference in mFlattener, so explicitly destroy mFlattener first.
    renderengine::mock::RenderEngine mRenderEngine;
    std::unique_ptr<TestableFlattener> mFlattener;

    const std::chrono::steady_clock::time_point kStartTime = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point mTime = kStartTime;

    struct TestLayer {
        std::string name;
        mock::OutputLayer outputLayer;
        impl::OutputLayerCompositionState outputLayerCompositionState;
        // LayerFE inherits from RefBase and must be held by an sp<>
        sp<mock::LayerFE> layerFE;
        LayerFECompositionState layerFECompositionState;

        std::unique_ptr<LayerState> layerState;
    };

    static constexpr size_t kNumLayers = 5;
    std::vector<std::unique_ptr<TestLayer>> mTestLayers;
    impl::OutputCompositionState mOutputState;
};

void FlattenerTest::SetUp() {
    mFlattener->setDisplaySize({1, 1});
    for (size_t i = 0; i < kNumLayers; i++) {
        auto testLayer = std::make_unique<TestLayer>();
        auto pos = static_cast<int32_t>(i);
        std::stringstream ss;
        ss << "testLayer" << i;
        testLayer->name = ss.str();

        testLayer->outputLayerCompositionState.displayFrame = Rect(pos, pos, pos + 1, pos + 1);
        testLayer->outputLayerCompositionState.visibleRegion =
                Region(Rect(pos + 1, pos + 1, pos + 2, pos + 2));

        testLayer->layerFECompositionState.buffer =
                new GraphicBuffer(100, 100, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                  GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                                          GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE,
                                  "output");

        testLayer->layerFE = sp<mock::LayerFE>::make();

        EXPECT_CALL(*testLayer->layerFE, getSequence)
                .WillRepeatedly(Return(static_cast<int32_t>(i)));
        EXPECT_CALL(*testLayer->layerFE, getDebugName)
                .WillRepeatedly(Return(testLayer->name.c_str()));
        EXPECT_CALL(*testLayer->layerFE, getCompositionState)
                .WillRepeatedly(Return(&testLayer->layerFECompositionState));

        std::vector<LayerFE::LayerSettings> clientCompositionList = {
                LayerFE::LayerSettings{},
        };

        EXPECT_CALL(*testLayer->layerFE, prepareClientCompositionList)
                .WillRepeatedly(Return(clientCompositionList));
        EXPECT_CALL(testLayer->outputLayer, getLayerFE)
                .WillRepeatedly(ReturnRef(*testLayer->layerFE));
        EXPECT_CALL(testLayer->outputLayer, getState)
                .WillRepeatedly(ReturnRef(testLayer->outputLayerCompositionState));
        EXPECT_CALL(testLayer->outputLayer, editState)
                .WillRepeatedly(ReturnRef(testLayer->outputLayerCompositionState));

        testLayer->layerState = std::make_unique<LayerState>(&testLayer->outputLayer);
        testLayer->layerState->incrementFramesSinceBufferUpdate();

        mTestLayers.emplace_back(std::move(testLayer));

        // set up minimium params needed for rendering
        mOutputState.dataspace = ui::Dataspace::SRGB;
        mOutputState.framebufferSpace = ProjectionSpace(ui::Size(10, 20), Rect(10, 5));
        mOutputState.framebufferSpace.setOrientation(ui::ROTATION_90);
    }
}

void FlattenerTest::initializeOverrideBuffer(const std::vector<const LayerState*>& layers) {
    for (const auto layer : layers) {
        layer->getOutputLayer()->editState().overrideInfo = {};
    }
}

void FlattenerTest::initializeFlattener(const std::vector<const LayerState*>& layers) {
    // layer stack is unknown, reset current geomentry
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // same geometry, update the internal layer stack
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);
}

void FlattenerTest::expectAllLayersFlattened(const std::vector<const LayerState*>& layers) {
    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }

    // the new flattened layer is replaced
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    const auto buffer = layers[0]->getOutputLayer()->getState().overrideInfo.buffer;
    EXPECT_NE(nullptr, buffer);
    for (const auto layer : layers) {
        EXPECT_EQ(buffer, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }
}

TEST_F(FlattenerTest, flattenLayers_NewLayerStack) {
    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };
    initializeFlattener(layers);
}

TEST_F(FlattenerTest, flattenLayers_ActiveLayersAreNotFlattened) {
    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);

    // layers cannot be flattened yet, since they are still active
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);
}

TEST_F(FlattenerTest, flattenLayers_ActiveLayersWithLowFpsAreFlattened) {
    mTestLayers[0]->layerFECompositionState.fps = Flattener::kFpsActiveThreshold / 2;
    mTestLayers[1]->layerFECompositionState.fps = Flattener::kFpsActiveThreshold;

    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);
    expectAllLayersFlattened(layers);
}

TEST_F(FlattenerTest, flattenLayers_basicFlatten) {
    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;
    auto& layerState3 = mTestLayers[2]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);
}

TEST_F(FlattenerTest, flattenLayers_FlattenedLayersStayFlattenWhenNoUpdate) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_FlattenedLayersSetsProjectionSpace) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideDisplaySpace =
            layerState1->getOutputLayer()->getState().overrideInfo.displaySpace;

    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);

    EXPECT_EQ(overrideDisplaySpace, mOutputState.framebufferSpace);
}

TEST_F(FlattenerTest, flattenLayers_FlattenedLayersSetsDamageRegions) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideDamageRegion =
            layerState1->getOutputLayer()->getState().overrideInfo.damageRegion;

    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);
    EXPECT_TRUE(overrideDamageRegion.isRect() &&
                overrideDamageRegion.bounds() == Rect::INVALID_RECT);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    EXPECT_TRUE(overrideDamageRegion.isRect() && overrideDamageRegion.bounds() == Rect::EMPTY_RECT);
}

TEST_F(FlattenerTest, flattenLayers_FlattenedLayersSetsVisibleRegion) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideVisibleRegion =
            layerState1->getOutputLayer()->getState().overrideInfo.visibleRegion;

    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);
    Region expectedRegion;
    expectedRegion.orSelf(Rect(1, 1, 2, 2));
    expectedRegion.orSelf(Rect(2, 2, 3, 3));
    EXPECT_TRUE(overrideVisibleRegion.hasSameRects(expectedRegion));
}

TEST_F(FlattenerTest, flattenLayers_addLayerToFlattenedCauseReset) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;

    std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);
    // make all layers inactive
    mTime += 200ms;

    initializeOverrideBuffer(layers);
    expectAllLayersFlattened(layers);

    // add a new layer to the stack, this will cause all the flatenner to reset
    layers.push_back(layerState3.get());

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_BufferUpdateToFlatten) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);

    // Layer 1 posted a buffer update, layers would be decomposed, and a new drawFrame would be
    // caleed for Layer2 and Layer3
    layerState1->resetFramesSinceBufferUpdate();

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_NE(nullptr, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);

    layerState1->incrementFramesSinceBufferUpdate();
    mTime += 200ms;

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_NE(nullptr, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_BufferUpdateForMiddleLayer) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState4 = mTestLayers[3]->layerState;
    const auto& overrideBuffer4 = layerState4->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState5 = mTestLayers[4]->layerState;
    const auto& overrideBuffer5 = layerState5->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(), layerState2.get(), layerState3.get(),
            layerState4.get(), layerState5.get(),
    };

    initializeFlattener(layers);

    // make all layers inactive
    mTime += 200ms;
    expectAllLayersFlattened(layers);

    // Layer 3 posted a buffer update, layers would be decomposed, and a new drawFrame would be
    // called for Layer1 and Layer2
    layerState3->resetFramesSinceBufferUpdate();

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_EQ(nullptr, overrideBuffer4);
    EXPECT_EQ(nullptr, overrideBuffer5);

    // Layers 1 and 2 will be flattened a new drawFrame would be called for Layer4 and Layer5
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mOutputState.framebufferSpace.setOrientation(ui::ROTATION_90);
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_EQ(nullptr, overrideBuffer4);
    EXPECT_EQ(nullptr, overrideBuffer5);

    // Layers 4 and 5 will be flattened
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mOutputState.framebufferSpace.setOrientation(ui::ROTATION_180);
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_NE(nullptr, overrideBuffer4);
    EXPECT_EQ(overrideBuffer4, overrideBuffer5);

    layerState3->incrementFramesSinceBufferUpdate();
    mTime += 200ms;
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_NE(nullptr, overrideBuffer4);
    EXPECT_EQ(overrideBuffer4, overrideBuffer5);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mOutputState.framebufferSpace.setOrientation(ui::ROTATION_270);
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);
    EXPECT_EQ(overrideBuffer3, overrideBuffer4);
    EXPECT_EQ(overrideBuffer4, overrideBuffer5);
}

// Tests for a PIP
TEST_F(FlattenerTest, flattenLayers_pipRequiresRoundedCorners) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // 3 has a buffer update, so it will not be merged, but it has no round
    // corners, so it is not a PIP.
    mTime += 200ms;
    layerState3->resetFramesSinceBufferUpdate();

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_pip) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[2]->layerFECompositionState.blendMode = hal::BlendMode::NONE;

    EXPECT_CALL(*mTestLayers[2]->layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    std::vector<LayerFE::LayerSettings> clientCompositionList = {
            LayerFE::LayerSettings{},
    };
    clientCompositionList[0].source.buffer.buffer = std::make_shared<
            renderengine::impl::ExternalTexture>(mTestLayers[2]->layerFECompositionState.buffer,
                                                 mRenderEngine,
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         READABLE);
    EXPECT_CALL(*mTestLayers[2]->layerFE, prepareClientCompositionList(_))
            .WillOnce(Return(clientCompositionList));

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // 3 has a buffer update, so it will not be merged, and it has round
    // corners, so it is a PIP.
    mTime += 200ms;
    layerState3->resetFramesSinceBufferUpdate();

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    const auto* peekThroughLayer1 =
            layerState1->getOutputLayer()->getState().overrideInfo.peekThroughLayer;
    const auto* peekThroughLayer2 =
            layerState2->getOutputLayer()->getState().overrideInfo.peekThroughLayer;
    EXPECT_EQ(&mTestLayers[2]->outputLayer, peekThroughLayer1);
    EXPECT_EQ(peekThroughLayer1, peekThroughLayer2);
}

// A test that verifies the hole puch optimization can be done on a single layer.
TEST_F(FlattenerTest, flattenLayers_holePunchSingleLayer) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);

    // An opaque static background
    auto& layerState0 = mTestLayers[0]->layerState;
    const auto& overrideBuffer0 = layerState0->getOutputLayer()->getState().overrideInfo.buffer;

    // a rounded updating layer
    auto& layerState1 = mTestLayers[1]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[1]->layerFECompositionState.blendMode = hal::BlendMode::NONE;

    EXPECT_CALL(*mTestLayers[1]->layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    std::vector<LayerFE::LayerSettings> clientCompositionList = {
            LayerFE::LayerSettings{},
    };
    clientCompositionList[0].source.buffer.buffer = std::make_shared<
            renderengine::impl::ExternalTexture>(mTestLayers[1]->layerFECompositionState.buffer,
                                                 mRenderEngine,
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         READABLE);
    EXPECT_CALL(*mTestLayers[1]->layerFE, prepareClientCompositionList(_))
            .WillOnce(Return(clientCompositionList));

    const std::vector<const LayerState*> layers = {
            layerState0.get(),
            layerState1.get(),
    };

    initializeFlattener(layers);

    // layer 1 satisfies every condition in CachedSet::requiresHolePunch()
    mTime += 200ms;
    layerState1->resetFramesSinceBufferUpdate(); // it is updating

    initializeOverrideBuffer(layers);
    // Expect no cache invalidation the first time (there's no cache yet)
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet of layer 0. Though it is just one layer, it satisfies the
    // exception that there would be a hole punch above it.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer0);

    // This time we merge the CachedSet in and we should still have only two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer0); // got overridden
    EXPECT_EQ(nullptr, overrideBuffer1); // did not

    // expect 0's peek though layer to be 1's output layer
    const auto* peekThroughLayer0 =
            layerState0->getOutputLayer()->getState().overrideInfo.peekThroughLayer;
    const auto* peekThroughLayer1 =
            layerState1->getOutputLayer()->getState().overrideInfo.peekThroughLayer;
    EXPECT_EQ(&mTestLayers[1]->outputLayer, peekThroughLayer0);
    EXPECT_EQ(nullptr, peekThroughLayer1);
}

TEST_F(FlattenerTest, flattenLayers_holePunchSingleColorLayer) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    mTestLayers[0]->layerFECompositionState.color = half4(255.f, 0.f, 0.f, 255.f);
    mTestLayers[0]->layerFECompositionState.buffer = nullptr;

    // An opaque static background
    auto& layerState0 = mTestLayers[0]->layerState;
    const auto& overrideBuffer0 = layerState0->getOutputLayer()->getState().overrideInfo.buffer;

    // a rounded updating layer
    auto& layerState1 = mTestLayers[1]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[1]->layerFECompositionState.blendMode = hal::BlendMode::NONE;

    EXPECT_CALL(*mTestLayers[1]->layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    std::vector<LayerFE::LayerSettings> clientCompositionList = {
            LayerFE::LayerSettings{},
    };
    clientCompositionList[0].source.buffer.buffer = std::make_shared<
            renderengine::impl::ExternalTexture>(mTestLayers[1]->layerFECompositionState.buffer,
                                                 mRenderEngine,
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         READABLE);
    EXPECT_CALL(*mTestLayers[1]->layerFE, prepareClientCompositionList(_))
            .WillOnce(Return(clientCompositionList));

    const std::vector<const LayerState*> layers = {
            layerState0.get(),
            layerState1.get(),
    };

    initializeFlattener(layers);

    // layer 1 satisfies every condition in CachedSet::requiresHolePunch()
    mTime += 200ms;
    layerState1->resetFramesSinceBufferUpdate(); // it is updating

    initializeOverrideBuffer(layers);
    // Expect no cache invalidation the first time (there's no cache yet)
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet of layer 0. Though it is just one layer, it satisfies the
    // exception that there would be a hole punch above it.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer0);

    // This time we merge the CachedSet in and we should still have only two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer0); // got overridden
    EXPECT_EQ(nullptr, overrideBuffer1); // did not

    // expect 0's peek though layer to be 1's output layer
    const auto* peekThroughLayer0 =
            layerState0->getOutputLayer()->getState().overrideInfo.peekThroughLayer;
    const auto* peekThroughLayer1 =
            layerState1->getOutputLayer()->getState().overrideInfo.peekThroughLayer;
    EXPECT_EQ(&mTestLayers[1]->outputLayer, peekThroughLayer0);
    EXPECT_EQ(nullptr, peekThroughLayer1);
}

TEST_F(FlattenerTest, flattenLayers_flattensBlurBehindRunIfFirstRun) {
    auto& layerState1 = mTestLayers[0]->layerState;

    auto& layerState2 = mTestLayers[1]->layerState;
    mTestLayers[1]->layerFECompositionState.backgroundBlurRadius = 1;
    layerState2->update(&mTestLayers[1]->outputLayer);

    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // Mark the first two layers inactive, which contain the blur behind
    mTime += 200ms;
    layerState3->resetFramesSinceBufferUpdate();

    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }

    // the new flattened layer is replaced
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);
    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_doesNotFlattenBlurBehindRun) {
    auto& layerState1 = mTestLayers[0]->layerState;

    auto& layerState2 = mTestLayers[1]->layerState;
    mTestLayers[1]->layerFECompositionState.backgroundBlurRadius = 1;
    layerState2->update(&mTestLayers[1]->outputLayer);

    auto& layerState3 = mTestLayers[2]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    // Mark the last two layers inactive, which contains the blur layer, but does not contain the
    // first layer
    mTime += 200ms;
    layerState1->resetFramesSinceBufferUpdate();

    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillRepeatedly(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }

    // nothing is flattened because the last two frames cannot be cached due to containing a blur
    // layer
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);
    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }
}

TEST_F(FlattenerTest, flattenLayers_flattenSkipsLayerWithBlurBehind) {
    auto& layerState1 = mTestLayers[0]->layerState;

    auto& layerStateWithBlurBehind = mTestLayers[1]->layerState;
    mTestLayers[1]->layerFECompositionState.backgroundBlurRadius = 1;
    layerStateWithBlurBehind->update(&mTestLayers[1]->outputLayer);

    auto& layerState3 = mTestLayers[2]->layerState;
    auto& layerState4 = mTestLayers[3]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& blurOverrideBuffer =
            layerStateWithBlurBehind->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& overrideBuffer4 = layerState4->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerStateWithBlurBehind.get(),
            layerState3.get(),
            layerState4.get(),
    };

    initializeFlattener(layers);

    // Mark the last three layers inactive, which contains the blur layer, but does not contain the
    // first layer
    mTime += 200ms;
    layerState1->resetFramesSinceBufferUpdate();

    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }

    // the new flattened layer is replaced
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, blurOverrideBuffer);
    EXPECT_NE(nullptr, overrideBuffer3);
    EXPECT_EQ(overrideBuffer3, overrideBuffer4);
}

TEST_F(FlattenerTest, flattenLayers_whenBlurLayerIsChanging_appliesBlurToInactiveBehindLayers) {
    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;

    auto& layerStateWithBlurBehind = mTestLayers[2]->layerState;
    mTestLayers[2]->layerFECompositionState.backgroundBlurRadius = 1;
    layerStateWithBlurBehind->update(&mTestLayers[2]->outputLayer);
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& blurOverrideBuffer =
            layerStateWithBlurBehind->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerStateWithBlurBehind.get(),
    };

    initializeFlattener(layers);

    // Mark the first two layers inactive, but update the blur layer
    mTime += 200ms;
    layerStateWithBlurBehind->resetFramesSinceBufferUpdate();

    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    const auto& cachedSet = mFlattener->getNewCachedSetForTesting();
    ASSERT_NE(std::nullopt, cachedSet);
    EXPECT_EQ(&mTestLayers[2]->outputLayer, cachedSet->getBlurLayer());

    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }

    // the new flattened layer is replaced
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);
    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer2, overrideBuffer1);
    EXPECT_EQ(nullptr, blurOverrideBuffer);
}

TEST_F(FlattenerTest, flattenLayers_renderCachedSets_doesNotRenderTwice) {
    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);

    // Mark the layers inactive
    mTime += 200ms;
    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);

    // Simulate attempting to render prior to merging the new cached set with the layer stack.
    // Here we should not try to re-render.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We provide the override buffer now that it's rendered
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer2, overrideBuffer1);
}

const constexpr std::chrono::nanoseconds kCachedSetRenderDuration = 0ms;
const constexpr size_t kMaxDeferRenderAttempts = 2;

class FlattenerRenderSchedulingTest : public FlattenerTest {
public:
    FlattenerRenderSchedulingTest()
          : FlattenerTest(
                    Flattener::Tunables{.mActiveLayerTimeout = 100ms,
                                        .mRenderScheduling = Flattener::Tunables::
                                                RenderScheduling{.cachedSetRenderDuration =
                                                                         kCachedSetRenderDuration,
                                                                 .maxDeferRenderAttempts =
                                                                         kMaxDeferRenderAttempts},
                                        .mEnableHolePunch = true}) {}
};

TEST_F(FlattenerRenderSchedulingTest, flattenLayers_renderCachedSets_defersUpToMaxAttempts) {
    auto& layerState1 = mTestLayers[0]->layerState;
    auto& layerState2 = mTestLayers[1]->layerState;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
    };

    initializeFlattener(layers);

    // Mark the layers inactive
    mTime += 200ms;

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    for (size_t i = 0; i < kMaxDeferRenderAttempts; i++) {
        EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
        mFlattener->renderCachedSets(mOutputState,
                                     std::chrono::steady_clock::now() -
                                             (kCachedSetRenderDuration + 10ms),
                                     true);
    }

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState,
                                 std::chrono::steady_clock::now() -
                                         (kCachedSetRenderDuration + 10ms),
                                 true);
}

TEST_F(FlattenerTest, flattenLayers_skipsBT601_625) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    // The third layer uses a dataspace that will not be flattened due to
    // possible mismatch with DPU rendering.
    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[2]->outputLayerCompositionState.dataspace = ui::Dataspace::STANDARD_BT601_625;
    mTestLayers[2]->layerState->update(&mTestLayers[2]->outputLayer);

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    mTime += 200ms;
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_skipsHDR) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    // The third layer uses a dataspace that will not be flattened due to
    // possible mismatch with DPU rendering.
    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[2]->outputLayerCompositionState.dataspace = ui::Dataspace::BT2020_ITU_HLG;
    mTestLayers[2]->layerState->update(&mTestLayers[2]->outputLayer);

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    mTime += 200ms;
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_skipsHDR2) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    // The third layer uses a dataspace that will not be flattened due to
    // possible mismatch with DPU rendering.
    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[2]->outputLayerCompositionState.dataspace = ui::Dataspace::BT2020_PQ;
    mTestLayers[2]->layerState->update(&mTestLayers[2]->outputLayer);

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    mTime += 200ms;
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
}

TEST_F(FlattenerTest, flattenLayers_skipsColorLayers) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;
    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;
    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    auto& layerState4 = mTestLayers[3]->layerState;
    const auto& overrideBuffer4 = layerState4->getOutputLayer()->getState().overrideInfo.buffer;

    // Rewrite the first two layers to just be a solid color.
    mTestLayers[0]->layerFECompositionState.color = half4(255.f, 0.f, 0.f, 255.f);
    mTestLayers[0]->layerFECompositionState.buffer = nullptr;
    mTestLayers[1]->layerFECompositionState.color = half4(0.f, 255.f, 0.f, 255.f);
    mTestLayers[1]->layerFECompositionState.buffer = nullptr;

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
            layerState4.get(),
    };

    initializeFlattener(layers);

    mTime += 200ms;
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_EQ(nullptr, overrideBuffer4);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(overrideBuffer3, overrideBuffer4);
    EXPECT_NE(nullptr, overrideBuffer4);
}

TEST_F(FlattenerTest, flattenLayers_includes_DISPLAY_DECORATION) {
    auto& layerState1 = mTestLayers[0]->layerState;
    const auto& overrideBuffer1 = layerState1->getOutputLayer()->getState().overrideInfo.buffer;

    auto& layerState2 = mTestLayers[1]->layerState;
    const auto& overrideBuffer2 = layerState2->getOutputLayer()->getState().overrideInfo.buffer;

    // The third layer uses DISPLAY_DECORATION, which should be cached.
    auto& layerState3 = mTestLayers[2]->layerState;
    const auto& overrideBuffer3 = layerState3->getOutputLayer()->getState().overrideInfo.buffer;
    mTestLayers[2]->layerFECompositionState.compositionType =
            aidl::android::hardware::graphics::composer3::Composition::DISPLAY_DECORATION;
    mTestLayers[2]->layerState->update(&mTestLayers[2]->outputLayer);

    const std::vector<const LayerState*> layers = {
            layerState1.get(),
            layerState2.get(),
            layerState3.get(),
    };

    initializeFlattener(layers);

    mTime += 200ms;
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));

    // This will render a CachedSet.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _))
            .WillOnce(Return(ByMove(
                    futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()}))));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    // We've rendered a CachedSet, but we haven't merged it in.
    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    // This time we merge the CachedSet in, so we have a new hash, and we should
    // only have two sets.
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).Times(0);
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mOutputState, std::nullopt, true);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(overrideBuffer1, overrideBuffer3);
}

} // namespace
} // namespace android::compositionengine
