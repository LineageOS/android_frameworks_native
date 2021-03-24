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
#include <compositionengine/impl/planner/Predictor.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gtest/gtest.h>
#include <renderengine/mock/RenderEngine.h>

namespace android::compositionengine {
using namespace std::chrono_literals;
using impl::planner::Flattener;
using impl::planner::LayerState;
using impl::planner::NonBufferHash;
using impl::planner::Predictor;

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

class FlattenerTest : public testing::Test {
public:
    FlattenerTest() : mFlattener(std::make_unique<Flattener>(mPredictor)) {}
    void SetUp() override;

protected:
    void initializeOverrideBuffer(const std::vector<const LayerState*>& layers);
    void initializeFlattener(const std::vector<const LayerState*>& layers);
    void expectAllLayersFlattened(const std::vector<const LayerState*>& layers);

    // TODO(b/181192467): Once Flattener starts to do something useful with Predictor,
    // mPredictor should be mocked and checked for expectations.
    Predictor mPredictor;

    // mRenderEngine may be held as a pointer to mFlattener, so mFlattener must be destroyed first.
    renderengine::mock::RenderEngine mRenderEngine;
    std::unique_ptr<Flattener> mFlattener;

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
        mOutputState.framebufferSpace.orientation = ui::ROTATION_90;
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
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    // same geometry, update the internal layer stack
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);
}

void FlattenerTest::expectAllLayersFlattened(const std::vector<const LayerState*>& layers) {
    // layers would be flattened but the buffer would not be overridden
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _, _)).WillOnce(Return(NO_ERROR));

    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    for (const auto layer : layers) {
        EXPECT_EQ(nullptr, layer->getOutputLayer()->getState().overrideInfo.buffer);
    }

    // the new flattened layer is replaced
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

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
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);
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
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

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

    EXPECT_EQ(overrideDisplaySpace.bounds,
              Rect(mOutputState.framebufferSpace.bounds.getWidth(),
                   mOutputState.framebufferSpace.bounds.getHeight()));
    EXPECT_EQ(overrideDisplaySpace.content, Rect(0, 0, 2, 2));
    EXPECT_EQ(overrideDisplaySpace.orientation, mOutputState.framebufferSpace.orientation);
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
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

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

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _, _)).WillOnce(Return(NO_ERROR));
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_NE(nullptr, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);

    layerState1->incrementFramesSinceBufferUpdate();
    mTime += 200ms;

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _, _)).WillOnce(Return(NO_ERROR));
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_NE(nullptr, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

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

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _, _)).WillOnce(Return(NO_ERROR));
    initializeOverrideBuffer(layers);
    EXPECT_EQ(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_EQ(nullptr, overrideBuffer1);
    EXPECT_EQ(nullptr, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_EQ(nullptr, overrideBuffer4);
    EXPECT_EQ(nullptr, overrideBuffer5);

    // Layers 1 and 2 will be flattened a new drawFrame would be called for Layer4 and Layer5
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _, _)).WillOnce(Return(NO_ERROR));
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mOutputState.framebufferSpace.orientation = ui::ROTATION_90;
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_EQ(nullptr, overrideBuffer4);
    EXPECT_EQ(nullptr, overrideBuffer5);

    // Layers 4 and 5 will be flattened
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mOutputState.framebufferSpace.orientation = ui::ROTATION_180;
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_NE(nullptr, overrideBuffer4);
    EXPECT_EQ(overrideBuffer4, overrideBuffer5);

    layerState3->incrementFramesSinceBufferUpdate();
    mTime += 200ms;

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _, _)).WillOnce(Return(NO_ERROR));
    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(nullptr, overrideBuffer3);
    EXPECT_NE(nullptr, overrideBuffer4);
    EXPECT_EQ(overrideBuffer4, overrideBuffer5);

    initializeOverrideBuffer(layers);
    EXPECT_NE(getNonBufferHash(layers),
              mFlattener->flattenLayers(layers, getNonBufferHash(layers), mTime));
    mOutputState.framebufferSpace.orientation = ui::ROTATION_270;
    mFlattener->renderCachedSets(mRenderEngine, mOutputState);

    EXPECT_NE(nullptr, overrideBuffer1);
    EXPECT_EQ(overrideBuffer1, overrideBuffer2);
    EXPECT_EQ(overrideBuffer2, overrideBuffer3);
    EXPECT_EQ(overrideBuffer3, overrideBuffer4);
    EXPECT_EQ(overrideBuffer4, overrideBuffer5);
}

} // namespace
} // namespace android::compositionengine
