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
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gmock/gmock-actions.h>
#include <gtest/gtest.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/mock/FakeExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>
#include <ui/GraphicTypes.h>
#include <utils/Errors.h>
#include <memory>

#include "tests/TestUtils.h"

namespace android::compositionengine {
using namespace std::chrono_literals;

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;

using impl::planner::CachedSet;
using impl::planner::LayerState;
using impl::planner::LayerStateField;
using impl::planner::TexturePool;

namespace {

MATCHER_P(ClientCompositionTargetSettingsBlurSettingsEq, expectedBlurSetting, "") {
    *result_listener << "ClientCompositionTargetSettings' BlurSettings aren't equal \n";
    *result_listener << "expected " << expectedBlurSetting << "\n";
    *result_listener << "actual " << arg.blurSetting << "\n";

    return expectedBlurSetting == arg.blurSetting;
}

MATCHER_P(ClientCompositionTargetSettingsSecureEq, expectedSecureSetting, "") {
    *result_listener << "ClientCompositionTargetSettings' isSecure bits aren't equal \n";
    *result_listener << "expected " << expectedSecureSetting << "\n";
    *result_listener << "actual " << arg.isSecure << "\n";

    return expectedSecureSetting == arg.isSecure;
}

MATCHER_P(ClientCompositionTargetSettingsWhitePointEq, expectedWhitePoint, "") {
    *result_listener << "ClientCompositionTargetSettings' white points aren't equal \n";
    *result_listener << "expected " << expectedWhitePoint << "\n";
    *result_listener << "actual " << arg.whitePointNits << "\n";

    return expectedWhitePoint == arg.whitePointNits;
}

static const ui::Size kOutputSize = ui::Size(1, 1);

class CachedSetTest : public testing::Test {
public:
    CachedSetTest() = default;
    void SetUp() override;
    void TearDown() override;

protected:
    const std::chrono::steady_clock::time_point kStartTime = std::chrono::steady_clock::now();

    struct TestLayer {
        mock::OutputLayer outputLayer;
        impl::OutputLayerCompositionState outputLayerCompositionState;
        // LayerFE inherits from RefBase and must be held by an sp<>
        sp<mock::LayerFE> layerFE;
        LayerFECompositionState layerFECompositionState;

        std::unique_ptr<LayerState> layerState;
        std::unique_ptr<CachedSet::Layer> cachedSetLayer;
    };

    static constexpr size_t kNumLayers = 5;
    std::vector<std::unique_ptr<TestLayer>> mTestLayers;
    impl::OutputCompositionState mOutputState;

    android::renderengine::mock::RenderEngine mRenderEngine;
    TexturePool mTexturePool = TexturePool(mRenderEngine);
};

void CachedSetTest::SetUp() {
    mTexturePool.setDisplaySize(kOutputSize);
    for (size_t i = 0; i < kNumLayers; i++) {
        auto testLayer = std::make_unique<TestLayer>();
        auto pos = static_cast<int32_t>(i);
        testLayer->outputLayerCompositionState.displayFrame = Rect(pos, pos, pos + 1, pos + 1);
        testLayer->outputLayerCompositionState.visibleRegion =
                Region(Rect(pos + 1, pos + 1, pos + 2, pos + 2));

        testLayer->layerFE = sp<mock::LayerFE>::make();

        EXPECT_CALL(*testLayer->layerFE, getSequence)
                .WillRepeatedly(Return(static_cast<int32_t>(i)));
        EXPECT_CALL(*testLayer->layerFE, getDebugName).WillRepeatedly(Return("testLayer"));
        EXPECT_CALL(*testLayer->layerFE, getCompositionState)
                .WillRepeatedly(Return(&testLayer->layerFECompositionState));
        EXPECT_CALL(testLayer->outputLayer, getLayerFE)
                .WillRepeatedly(ReturnRef(*testLayer->layerFE));
        EXPECT_CALL(testLayer->outputLayer, getState)
                .WillRepeatedly(ReturnRef(testLayer->outputLayerCompositionState));

        testLayer->layerState = std::make_unique<LayerState>(&testLayer->outputLayer);
        testLayer->layerState->incrementFramesSinceBufferUpdate();
        testLayer->cachedSetLayer =
                std::make_unique<CachedSet::Layer>(testLayer->layerState.get(), kStartTime);

        mTestLayers.emplace_back(std::move(testLayer));

        // set up minimium params needed for rendering
        mOutputState.dataspace = ui::Dataspace::SRGB;
        mOutputState.framebufferSpace = ProjectionSpace(ui::Size(10, 20), Rect(10, 5));
        mOutputState.framebufferSpace.setOrientation(ui::ROTATION_90);
        mOutputState.layerStackSpace = ProjectionSpace(ui::Size(20, 10), Rect(5, 10));
    }
}

void CachedSetTest::TearDown() {
    mTestLayers.clear();
}

void expectEqual(const CachedSet& cachedSet, const CachedSet::Layer& layer) {
    EXPECT_EQ(layer.getLastUpdate(), cachedSet.getLastUpdate());
    EXPECT_EQ(layer.getDisplayFrame(), cachedSet.getBounds());
    EXPECT_TRUE(layer.getVisibleRegion().hasSameRects(cachedSet.getVisibleRegion()));
    EXPECT_EQ(1u, cachedSet.getLayerCount());
    EXPECT_EQ(layer.getState(), cachedSet.getFirstLayer().getState());
    EXPECT_EQ(0u, cachedSet.getAge());
    EXPECT_EQ(layer.getHash(), cachedSet.getNonBufferHash());
}

void expectEqual(const CachedSet& cachedSet, const LayerState& layerState,
                 std::chrono::steady_clock::time_point lastUpdate) {
    CachedSet::Layer layer(&layerState, lastUpdate);
    expectEqual(cachedSet, layer);
}

void expectNoBuffer(const CachedSet& cachedSet) {
    EXPECT_EQ(nullptr, cachedSet.getBuffer());
    EXPECT_EQ(nullptr, cachedSet.getDrawFence());
    EXPECT_FALSE(cachedSet.hasReadyBuffer());
}

void expectReadyBuffer(const CachedSet& cachedSet) {
    EXPECT_NE(nullptr, cachedSet.getBuffer());
    EXPECT_NE(nullptr, cachedSet.getDrawFence());
    EXPECT_TRUE(cachedSet.hasReadyBuffer());
    EXPECT_TRUE(cachedSet.hasRenderedBuffer());
}

TEST_F(CachedSetTest, createFromLayer) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet cachedSet(layer);
    expectEqual(cachedSet, layer);
    expectNoBuffer(cachedSet);
}

TEST_F(CachedSetTest, createFromLayerState) {
    LayerState& layerState = *mTestLayers[0]->layerState.get();
    CachedSet cachedSet(&layerState, kStartTime);
    expectEqual(cachedSet, layerState, kStartTime);
    expectNoBuffer(cachedSet);
}

TEST_F(CachedSetTest, addLayer) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    EXPECT_EQ(kStartTime, cachedSet.getLastUpdate());
    EXPECT_EQ(Rect(0, 0, 2, 2), cachedSet.getBounds());
    Region expectedRegion;
    expectedRegion.orSelf(Rect(1, 1, 2, 2));
    expectedRegion.orSelf(Rect(2, 2, 3, 3));
    EXPECT_TRUE(cachedSet.getVisibleRegion().hasSameRects(expectedRegion));
    EXPECT_EQ(2u, cachedSet.getLayerCount());
    EXPECT_EQ(0u, cachedSet.getAge());
    expectNoBuffer(cachedSet);
    // TODO(b/181192080): check that getNonBufferHash returns the correct hash value
    // EXPECT_EQ(android::hashCombine(layer1.getHash(), layer2.getHash()),
    // cachedSet.getNonBufferHash());
}

TEST_F(CachedSetTest, decompose) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);
    cachedSet.addLayer(layer3.getState(), kStartTime + 20ms);

    std::vector<CachedSet> decomposed = cachedSet.decompose();
    EXPECT_EQ(3u, decomposed.size());
    expectEqual(decomposed[0], *layer1.getState(), kStartTime);
    expectNoBuffer(decomposed[0]);

    expectEqual(decomposed[1], *layer2.getState(), kStartTime + 10ms);
    expectNoBuffer(decomposed[1]);

    expectEqual(decomposed[2], *layer3.getState(), kStartTime + 20ms);
    expectNoBuffer(decomposed[2]);
}

TEST_F(CachedSetTest, setLastUpdate) {
    LayerState& layerState = *mTestLayers[0]->layerState.get();
    CachedSet cachedSet(&layerState, kStartTime);
    cachedSet.setLastUpdate(kStartTime + 10ms);
    expectEqual(cachedSet, layerState, kStartTime + 10ms);
}

TEST_F(CachedSetTest, incrementAge) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet cachedSet(layer);
    EXPECT_EQ(0u, cachedSet.getAge());
    cachedSet.incrementAge();
    EXPECT_EQ(1u, cachedSet.getAge());
    cachedSet.incrementAge();
    EXPECT_EQ(2u, cachedSet.getAge());
}

TEST_F(CachedSetTest, incrementSkipCount) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet cachedSet(layer);
    EXPECT_EQ(0u, cachedSet.getSkipCount());
    cachedSet.incrementSkipCount();
    EXPECT_EQ(1u, cachedSet.getSkipCount());
    cachedSet.incrementSkipCount();
    EXPECT_EQ(2u, cachedSet.getSkipCount());
}

TEST_F(CachedSetTest, hasBufferUpdate_NoUpdate) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);
    cachedSet.addLayer(layer3.getState(), kStartTime + 20ms);

    EXPECT_FALSE(cachedSet.hasBufferUpdate());
}

TEST_F(CachedSetTest, hasBufferUpdate_BufferUpdate) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);
    cachedSet.addLayer(layer3.getState(), kStartTime + 20ms);

    mTestLayers[1]->layerState->resetFramesSinceBufferUpdate();

    EXPECT_TRUE(cachedSet.hasBufferUpdate());
}

TEST_F(CachedSetTest, append) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet1(layer1);
    CachedSet cachedSet2(layer2);
    cachedSet1.addLayer(layer3.getState(), kStartTime + 10ms);
    cachedSet1.incrementSkipCount();
    EXPECT_EQ(1u, cachedSet1.getSkipCount());
    cachedSet1.append(cachedSet2);

    EXPECT_EQ(kStartTime, cachedSet1.getLastUpdate());
    EXPECT_EQ(Rect(0, 0, 3, 3), cachedSet1.getBounds());
    Region expectedRegion;
    expectedRegion.orSelf(Rect(1, 1, 2, 2));
    expectedRegion.orSelf(Rect(2, 2, 3, 3));
    expectedRegion.orSelf(Rect(3, 3, 4, 4));
    EXPECT_TRUE(cachedSet1.getVisibleRegion().hasSameRects(expectedRegion));
    EXPECT_EQ(3u, cachedSet1.getLayerCount());
    EXPECT_EQ(0u, cachedSet1.getAge());
    EXPECT_EQ(0u, cachedSet1.getSkipCount());

    expectNoBuffer(cachedSet1);
    // TODO(b/181192080): check that getNonBufferHash returns the correct hash value
    // EXPECT_EQ(android::hashCombine(layer1.getHash(), layer2.getHash()),
    // cachedSet1.getNonBufferHash());
}

TEST_F(CachedSetTest, updateAge_NoUpdate) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();

    CachedSet cachedSet(layer);
    cachedSet.incrementAge();
    EXPECT_EQ(kStartTime, cachedSet.getLastUpdate());
    EXPECT_EQ(1u, cachedSet.getAge());

    cachedSet.updateAge(kStartTime + 10ms);
    EXPECT_EQ(kStartTime, cachedSet.getLastUpdate());
    EXPECT_EQ(1u, cachedSet.getAge());
}

TEST_F(CachedSetTest, updateAge_BufferUpdate) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    mTestLayers[0]->layerState->resetFramesSinceBufferUpdate();

    CachedSet cachedSet(layer);
    cachedSet.incrementAge();
    EXPECT_EQ(kStartTime, cachedSet.getLastUpdate());
    EXPECT_EQ(1u, cachedSet.getAge());

    cachedSet.updateAge(kStartTime + 10ms);
    EXPECT_EQ(kStartTime + 10ms, cachedSet.getLastUpdate());
    EXPECT_EQ(0u, cachedSet.getAge());
}

TEST_F(CachedSetTest, renderUnsecureOutput) {
    // Skip the 0th layer to ensure that the bounding box of the layers is offset from (0, 0)
    CachedSet::Layer& layer1 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[1]->layerFE;
    CachedSet::Layer& layer2 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.append(CachedSet(layer2));

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});
    clientCompList1[0].alpha = 0.5f;

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});
    clientCompList2[0].alpha = 0.75f;

    const auto drawLayers =
            [&](const renderengine::DisplaySettings& displaySettings,
                const std::vector<renderengine::LayerSettings>& layers,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        EXPECT_EQ(mOutputState.framebufferSpace.getContent(), displaySettings.physicalDisplay);
        EXPECT_EQ(mOutputState.layerStackSpace.getContent(), displaySettings.clip);
        EXPECT_EQ(ui::Transform::toRotationFlags(mOutputState.framebufferSpace.getOrientation()),
                  displaySettings.orientation);
        EXPECT_EQ(0.5f, layers[0].alpha);
        EXPECT_EQ(0.75f, layers[1].alpha);
        EXPECT_EQ(ui::Dataspace::SRGB, displaySettings.outputDataspace);
        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(*layerFE1,
                prepareClientCompositionList(ClientCompositionTargetSettingsSecureEq(false)))
            .WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2,
                prepareClientCompositionList(ClientCompositionTargetSettingsSecureEq(false)))
            .WillOnce(Return(clientCompList2));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    mOutputState.isSecure = false;
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
    expectReadyBuffer(cachedSet);

    EXPECT_EQ(mOutputState.framebufferSpace, cachedSet.getOutputSpace());
    EXPECT_EQ(Rect(kOutputSize.width, kOutputSize.height), cachedSet.getTextureBounds());

    // Now check that appending a new cached set properly cleans up RenderEngine resources.
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    cachedSet.append(CachedSet(layer3));
}

TEST_F(CachedSetTest, renderSecureOutput) {
    // Skip the 0th layer to ensure that the bounding box of the layers is offset from (0, 0)
    CachedSet::Layer& layer1 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[1]->layerFE;
    CachedSet::Layer& layer2 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.append(CachedSet(layer2));

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});
    clientCompList1[0].alpha = 0.5f;

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});
    clientCompList2[0].alpha = 0.75f;

    const auto drawLayers =
            [&](const renderengine::DisplaySettings& displaySettings,
                const std::vector<renderengine::LayerSettings>& layers,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        EXPECT_EQ(mOutputState.framebufferSpace.getContent(), displaySettings.physicalDisplay);
        EXPECT_EQ(mOutputState.layerStackSpace.getContent(), displaySettings.clip);
        EXPECT_EQ(ui::Transform::toRotationFlags(mOutputState.framebufferSpace.getOrientation()),
                  displaySettings.orientation);
        EXPECT_EQ(0.5f, layers[0].alpha);
        EXPECT_EQ(0.75f, layers[1].alpha);
        EXPECT_EQ(ui::Dataspace::SRGB, displaySettings.outputDataspace);

        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(*layerFE1,
                prepareClientCompositionList(ClientCompositionTargetSettingsSecureEq(true)))
            .WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2,
                prepareClientCompositionList(ClientCompositionTargetSettingsSecureEq(true)))
            .WillOnce(Return(clientCompList2));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    mOutputState.isSecure = true;
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
    expectReadyBuffer(cachedSet);

    EXPECT_EQ(mOutputState.framebufferSpace, cachedSet.getOutputSpace());
    EXPECT_EQ(Rect(kOutputSize.width, kOutputSize.height), cachedSet.getTextureBounds());

    // Now check that appending a new cached set properly cleans up RenderEngine resources.
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    cachedSet.append(CachedSet(layer3));
}

TEST_F(CachedSetTest, renderWhitePoint) {
    // Skip the 0th layer to ensure that the bounding box of the layers is offset from (0, 0)
    CachedSet::Layer& layer1 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[1]->layerFE;
    CachedSet::Layer& layer2 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.append(CachedSet(layer2));

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});

    mOutputState.displayBrightnessNits = 400.f;

    const auto drawLayers =
            [&](const renderengine::DisplaySettings& displaySettings,
                const std::vector<renderengine::LayerSettings>&,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        EXPECT_EQ(mOutputState.displayBrightnessNits, displaySettings.targetLuminanceNits);
        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(*layerFE1,
                prepareClientCompositionList(ClientCompositionTargetSettingsWhitePointEq(
                        mOutputState.displayBrightnessNits)))
            .WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2,
                prepareClientCompositionList(ClientCompositionTargetSettingsWhitePointEq(
                        mOutputState.displayBrightnessNits)))
            .WillOnce(Return(clientCompList2));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    mOutputState.isSecure = true;
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
    expectReadyBuffer(cachedSet);

    EXPECT_EQ(mOutputState.framebufferSpace, cachedSet.getOutputSpace());
    EXPECT_EQ(Rect(kOutputSize.width, kOutputSize.height), cachedSet.getTextureBounds());

    // Now check that appending a new cached set properly cleans up RenderEngine resources.
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    cachedSet.append(CachedSet(layer3));
}

TEST_F(CachedSetTest, renderWhitePointNoColorTransform) {
    // Skip the 0th layer to ensure that the bounding box of the layers is offset from (0, 0)
    // This is a duplicate of the "renderWhitePoint" test, but setting "deviceHandlesColorTransform"
    // to false, in the render call.

    CachedSet::Layer& layer1 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[1]->layerFE;
    CachedSet::Layer& layer2 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.append(CachedSet(layer2));

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});

    mOutputState.displayBrightnessNits = 400.f;

    const auto drawLayers =
            [&](const renderengine::DisplaySettings& displaySettings,
                const std::vector<renderengine::LayerSettings>&,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        EXPECT_EQ(mOutputState.displayBrightnessNits, displaySettings.targetLuminanceNits);
        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(*layerFE1,
                prepareClientCompositionList(ClientCompositionTargetSettingsWhitePointEq(
                        mOutputState.displayBrightnessNits)))
            .WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2,
                prepareClientCompositionList(ClientCompositionTargetSettingsWhitePointEq(
                        mOutputState.displayBrightnessNits)))
            .WillOnce(Return(clientCompList2));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    mOutputState.isSecure = true;
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, false);
    expectReadyBuffer(cachedSet);

    EXPECT_EQ(mOutputState.framebufferSpace, cachedSet.getOutputSpace());
    EXPECT_EQ(Rect(kOutputSize.width, kOutputSize.height), cachedSet.getTextureBounds());

    // Now check that appending a new cached set properly cleans up RenderEngine resources.
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    cachedSet.append(CachedSet(layer3));
}

TEST_F(CachedSetTest, rendersWithOffsetFramebufferContent) {
    // Skip the 0th layer to ensure that the bounding box of the layers is offset from (0, 0)
    CachedSet::Layer& layer1 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[1]->layerFE;
    CachedSet::Layer& layer2 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.append(CachedSet(layer2));

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});
    clientCompList1[0].alpha = 0.5f;

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});
    clientCompList2[0].alpha = 0.75f;

    mOutputState.framebufferSpace = ProjectionSpace(ui::Size(10, 20), Rect(2, 3, 10, 5));

    const auto drawLayers =
            [&](const renderengine::DisplaySettings& displaySettings,
                const std::vector<renderengine::LayerSettings>& layers,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        EXPECT_EQ(mOutputState.framebufferSpace.getContent(), displaySettings.physicalDisplay);
        EXPECT_EQ(mOutputState.layerStackSpace.getContent(), displaySettings.clip);
        EXPECT_EQ(ui::Transform::toRotationFlags(mOutputState.framebufferSpace.getOrientation()),
                  displaySettings.orientation);
        EXPECT_EQ(0.5f, layers[0].alpha);
        EXPECT_EQ(0.75f, layers[1].alpha);
        EXPECT_EQ(ui::Dataspace::SRGB, displaySettings.outputDataspace);

        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(*layerFE1, prepareClientCompositionList(_)).WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2, prepareClientCompositionList(_)).WillOnce(Return(clientCompList2));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
    expectReadyBuffer(cachedSet);

    EXPECT_EQ(mOutputState.framebufferSpace, cachedSet.getOutputSpace());

    // Now check that appending a new cached set properly cleans up RenderEngine resources.
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    cachedSet.append(CachedSet(layer3));
}

TEST_F(CachedSetTest, holePunch_requiresBuffer) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.blendMode = hal::BlendMode::NONE;
    sp<mock::LayerFE> layerFE1 = mTestLayers[0]->layerFE;

    CachedSet cachedSet(layer1);
    EXPECT_CALL(*layerFE1, hasRoundedCorners()).WillRepeatedly(Return(true));

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, holePunch_requiresRoundedCorners) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::NONE;

    CachedSet cachedSet(layer1);

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, holePunch_requiresSingleLayer) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::NONE;
    sp<mock::LayerFE> layerFE = mTestLayers[0]->layerFE;
    EXPECT_CALL(*layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.append(layer2);

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, holePunch_requiresNonHdr) {
    mTestLayers[0]->outputLayerCompositionState.dataspace = ui::Dataspace::BT2020_PQ;
    mTestLayers[0]->layerState->update(&mTestLayers[0]->outputLayer);

    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::NONE;
    sp<mock::LayerFE> layerFE = mTestLayers[0]->layerFE;

    CachedSet cachedSet(layer);
    EXPECT_CALL(*layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, holePunch_requiresNonBT601_625) {
    mTestLayers[0]->outputLayerCompositionState.dataspace = ui::Dataspace::STANDARD_BT601_625;
    mTestLayers[0]->layerState->update(&mTestLayers[0]->outputLayer);

    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::NONE;
    sp<mock::LayerFE> layerFE = mTestLayers[0]->layerFE;

    CachedSet cachedSet(layer);
    EXPECT_CALL(*layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, holePunch_requiresNoBlending) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::PREMULTIPLIED;
    sp<mock::LayerFE> layerFE = mTestLayers[0]->layerFE;

    CachedSet cachedSet(layer);
    EXPECT_CALL(*layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, requiresHolePunch) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::NONE;
    sp<mock::LayerFE> layerFE = mTestLayers[0]->layerFE;

    CachedSet cachedSet(layer);
    EXPECT_CALL(*layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    EXPECT_TRUE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, holePunch_requiresDeviceComposition) {
    CachedSet::Layer& layer = *mTestLayers[0]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE = mTestLayers[0]->layerFE;
    auto& layerFECompositionState = mTestLayers[0]->layerFECompositionState;
    layerFECompositionState.buffer = sp<GraphicBuffer>::make();
    layerFECompositionState.blendMode = hal::BlendMode::NONE;
    layerFECompositionState.forceClientComposition = true;

    CachedSet cachedSet(layer);
    EXPECT_CALL(*layerFE, hasRoundedCorners()).WillRepeatedly(Return(true));

    EXPECT_FALSE(cachedSet.requiresHolePunch());
}

TEST_F(CachedSetTest, addHolePunch_requiresOverlap) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, true);

    ASSERT_EQ(nullptr, cachedSet.getHolePunchLayer());
}

TEST_F(CachedSetTest, addHolePunch_requiresOpaque) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    mTestLayers[0]->layerFECompositionState.isOpaque = false;
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, false);

    ASSERT_EQ(nullptr, cachedSet.getHolePunchLayer());
}

TEST_F(CachedSetTest, addHolePunch_opaque) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    mTestLayers[0]->layerFECompositionState.isOpaque = true;
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, false);

    ASSERT_EQ(&mTestLayers[2]->outputLayer, cachedSet.getHolePunchLayer());
}

TEST_F(CachedSetTest, addHolePunch_firstLayer) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    mTestLayers[0]->layerFECompositionState.isOpaque = false;
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, true);

    ASSERT_EQ(&mTestLayers[2]->outputLayer, cachedSet.getHolePunchLayer());
}

TEST_F(CachedSetTest, addHolePunch) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[0]->layerFE;

    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[1]->layerFE;

    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE3 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, true);

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList3;
    clientCompList3.push_back({});

    clientCompList3[0].source.buffer.buffer =
            std::make_shared<renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                                      1ULL /* bufferId */,
                                                                      HAL_PIXEL_FORMAT_RGBA_8888,
                                                                      0ULL /*usage*/);

    EXPECT_CALL(*layerFE1, prepareClientCompositionList(_)).WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2, prepareClientCompositionList(_)).WillOnce(Return(clientCompList2));
    EXPECT_CALL(*layerFE3, prepareClientCompositionList(_)).WillOnce(Return(clientCompList3));

    const auto drawLayers =
            [&](const renderengine::DisplaySettings&,
                const std::vector<renderengine::LayerSettings>& layers,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        // If the highlight layer is enabled, it will increase the size by 1.
        // We're interested in the third layer either way.
        EXPECT_GE(layers.size(), 4u);
        {
            const auto holePunchSettings = layers[3];
            EXPECT_EQ(nullptr, holePunchSettings.source.buffer.buffer);
            EXPECT_EQ(half3(0.0f, 0.0f, 0.0f), holePunchSettings.source.solidColor);
            EXPECT_TRUE(holePunchSettings.disableBlending);
            EXPECT_EQ(0.0f, holePunchSettings.alpha);
        }

        {
            const auto holePunchBackgroundSettings = layers[0];
            EXPECT_EQ(nullptr, holePunchBackgroundSettings.source.buffer.buffer);
            EXPECT_EQ(half3(0.0f, 0.0f, 0.0f), holePunchBackgroundSettings.source.solidColor);
            EXPECT_FALSE(holePunchBackgroundSettings.disableBlending);
            EXPECT_EQ(1.0f, holePunchBackgroundSettings.alpha);
        }

        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
}

TEST_F(CachedSetTest, addHolePunch_noBuffer) {
    // Same as addHolePunch, except that clientCompList3 does not contain a
    // buffer. This imitates the case where the buffer had protected content, so
    // BufferLayer did not add it to the LayerSettings. This should not assert.
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[0]->layerFE;

    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[1]->layerFE;

    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE3 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, true);

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList3;
    clientCompList3.push_back({});

    EXPECT_CALL(*layerFE1, prepareClientCompositionList(_)).WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2, prepareClientCompositionList(_)).WillOnce(Return(clientCompList2));
    EXPECT_CALL(*layerFE3, prepareClientCompositionList(_)).WillOnce(Return(clientCompList3));

    const auto drawLayers =
            [&](const renderengine::DisplaySettings&,
                const std::vector<renderengine::LayerSettings>& layers,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        // If the highlight layer is enabled, it will increase the size by 1.
        // We're interested in the third layer either way.
        EXPECT_GE(layers.size(), 4u);

        {
            const auto holePunchSettings = layers[3];
            EXPECT_EQ(nullptr, holePunchSettings.source.buffer.buffer);
            EXPECT_EQ(half3(0.0f, 0.0f, 0.0f), holePunchSettings.source.solidColor);
            EXPECT_TRUE(holePunchSettings.disableBlending);
            EXPECT_EQ(0.0f, holePunchSettings.alpha);
        }

        {
            const auto holePunchBackgroundSettings = layers[0];
            EXPECT_EQ(nullptr, holePunchBackgroundSettings.source.buffer.buffer);
            EXPECT_EQ(half3(0.0f, 0.0f, 0.0f), holePunchBackgroundSettings.source.solidColor);
            EXPECT_FALSE(holePunchBackgroundSettings.disableBlending);
            EXPECT_EQ(1.0f, holePunchBackgroundSettings.alpha);
        }

        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
}

TEST_F(CachedSetTest, append_removesHolePunch) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    mTestLayers[0]->layerFECompositionState.isOpaque = true;
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, false);

    ASSERT_EQ(&mTestLayers[2]->outputLayer, cachedSet.getHolePunchLayer());

    CachedSet cachedSet3(layer3);
    cachedSet.append(cachedSet3);
    ASSERT_EQ(nullptr, cachedSet.getHolePunchLayer());
}

TEST_F(CachedSetTest, decompose_removesHolePunch) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addHolePunchLayerIfFeasible(layer3, true);

    ASSERT_EQ(&mTestLayers[2]->outputLayer, cachedSet.getHolePunchLayer());

    std::vector<CachedSet> decomposed = cachedSet.decompose();
    EXPECT_EQ(2u, decomposed.size());
    for (const auto& set : decomposed) {
        EXPECT_EQ(nullptr, set.getHolePunchLayer());
    }
}

TEST_F(CachedSetTest, hasBlurBehind) {
    mTestLayers[1]->layerFECompositionState.backgroundBlurRadius = 1;
    mTestLayers[1]->layerState->update(&mTestLayers[1]->outputLayer);
    mTestLayers[2]->layerFECompositionState.blurRegions.push_back(
            BlurRegion{1, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    mTestLayers[2]->layerState->update(&mTestLayers[2]->outputLayer);

    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();

    CachedSet cachedSet1(layer1);
    CachedSet cachedSet2(layer2);
    CachedSet cachedSet3(layer3);

    // Cached set 4 will consist of layers 1 and 2, which will contain a blur behind
    CachedSet cachedSet4(layer1);
    cachedSet4.addLayer(layer2.getState(), kStartTime);

    EXPECT_FALSE(cachedSet1.hasBlurBehind());
    EXPECT_TRUE(cachedSet2.hasBlurBehind());
    EXPECT_TRUE(cachedSet3.hasBlurBehind());
    EXPECT_TRUE(cachedSet4.hasBlurBehind());
}

TEST_F(CachedSetTest, addBackgroundBlurLayer) {
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    CachedSet cachedSet(layer1);

    EXPECT_EQ(nullptr, cachedSet.getBlurLayer());

    cachedSet.addBackgroundBlurLayer(layer2);
    EXPECT_EQ(layer2.getState()->getOutputLayer(), cachedSet.getBlurLayer());
}

TEST_F(CachedSetTest, addBlur) {
    mTestLayers[0]->outputLayerCompositionState.displayFrame = Rect(0, 0, 5, 5);
    CachedSet::Layer& layer1 = *mTestLayers[0]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE1 = mTestLayers[0]->layerFE;

    CachedSet::Layer& layer2 = *mTestLayers[1]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE2 = mTestLayers[1]->layerFE;

    CachedSet::Layer& layer3 = *mTestLayers[2]->cachedSetLayer.get();
    sp<mock::LayerFE> layerFE3 = mTestLayers[2]->layerFE;

    CachedSet cachedSet(layer1);
    cachedSet.addLayer(layer2.getState(), kStartTime + 10ms);

    cachedSet.addBackgroundBlurLayer(layer3);

    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList1;
    clientCompList1.push_back({});
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList2;
    clientCompList2.push_back({});
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompList3;
    clientCompList3.push_back({});

    clientCompList3[0].source.buffer.buffer =
            std::make_shared<renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                                      1ULL /* bufferId */,
                                                                      HAL_PIXEL_FORMAT_RGBA_8888,
                                                                      0ULL /*usage*/);

    EXPECT_CALL(*layerFE1,
                prepareClientCompositionList(ClientCompositionTargetSettingsBlurSettingsEq(
                        compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                Enabled)))
            .WillOnce(Return(clientCompList1));
    EXPECT_CALL(*layerFE2,
                prepareClientCompositionList(ClientCompositionTargetSettingsBlurSettingsEq(
                        compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                Enabled)))
            .WillOnce(Return(clientCompList2));
    EXPECT_CALL(*layerFE3,
                prepareClientCompositionList(ClientCompositionTargetSettingsBlurSettingsEq(
                        compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                BackgroundBlurOnly)))
            .WillOnce(Return(clientCompList3));

    const auto drawLayers =
            [&](const renderengine::DisplaySettings&,
                const std::vector<renderengine::LayerSettings>& layers,
                const std::shared_ptr<renderengine::ExternalTexture>&, const bool,
                base::unique_fd&&) -> std::future<renderengine::RenderEngineResult> {
        // If the highlight layer is enabled, it will increase the size by 1.
        // We're interested in the third layer either way.
        EXPECT_GE(layers.size(), 3u);
        const auto blurSettings = layers[2];
        EXPECT_TRUE(blurSettings.skipContentDraw);
        EXPECT_EQ(half3(0.0f, 0.0f, 0.0f), blurSettings.source.solidColor);
        EXPECT_EQ(0.0f, blurSettings.alpha);

        return futureOf<renderengine::RenderEngineResult>({NO_ERROR, base::unique_fd()});
    };

    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _, _)).WillOnce(Invoke(drawLayers));
    cachedSet.render(mRenderEngine, mTexturePool, mOutputState, true);
}

} // namespace
} // namespace android::compositionengine
