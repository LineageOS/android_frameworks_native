/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerMetadata.h>

#include "Layer.h"
#include "LayerTestUtils.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"

namespace android {

using testing::DoAll;
using testing::Mock;
using testing::SetArgPointee;

using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

using scheduler::LayerHistory;

using FrameRate = Layer::FrameRate;
using FrameRateCompatibility = Layer::FrameRateCompatibility;
using FrameRateSelectionStrategy = scheduler::LayerInfo::FrameRateSelectionStrategy;

/**
 * This class tests the behaviour of Layer::setFrameRateSelectionStrategy.
 */
class FrameRateSelectionStrategyTest : public BaseLayerTest {
protected:
    const FrameRate FRAME_RATE_VOTE1 = FrameRate(11_Hz, FrameRateCompatibility::Default);
    const FrameRate FRAME_RATE_VOTE2 = FrameRate(22_Hz, FrameRateCompatibility::Default);
    const FrameRate FRAME_RATE_VOTE3 = FrameRate(33_Hz, FrameRateCompatibility::Default);
    const FrameRate FRAME_RATE_DEFAULT = FrameRate(Fps(), FrameRateCompatibility::Default);
    const FrameRate FRAME_RATE_TREE = FrameRate(Fps(), FrameRateCompatibility::NoVote);

    FrameRateSelectionStrategyTest();

    void addChild(sp<Layer> layer, sp<Layer> child);
    void removeChild(sp<Layer> layer, sp<Layer> child);
    void commitTransaction();

    std::vector<sp<Layer>> mLayers;
};

FrameRateSelectionStrategyTest::FrameRateSelectionStrategyTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    mFlinger.setupComposer(std::make_unique<Hwc2::mock::Composer>());
}

void FrameRateSelectionStrategyTest::addChild(sp<Layer> layer, sp<Layer> child) {
    layer->addChild(child);
}

void FrameRateSelectionStrategyTest::removeChild(sp<Layer> layer, sp<Layer> child) {
    layer->removeChild(child);
}

void FrameRateSelectionStrategyTest::commitTransaction() {
    for (auto layer : mLayers) {
        layer->commitTransaction();
    }
}

namespace {

INSTANTIATE_TEST_SUITE_P(PerLayerType, FrameRateSelectionStrategyTest,
                         testing::Values(std::make_shared<BufferStateLayerFactory>(),
                                         std::make_shared<EffectLayerFactory>()),
                         PrintToStringParamName);

TEST_P(FrameRateSelectionStrategyTest, SetAndGet) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();
    auto layer = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    layer->setFrameRate(FRAME_RATE_VOTE1.vote);
    layer->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::OverrideChildren);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, layer->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              layer->getDrawingState().frameRateSelectionStrategy);
}

TEST_P(FrameRateSelectionStrategyTest, SetChildOverrideChildren) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();
    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    addChild(parent, child1);
    addChild(child1, child2);

    child2->setFrameRate(FRAME_RATE_VOTE1.vote);
    child2->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::OverrideChildren);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              parent->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              child1->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              child2->getDrawingState().frameRateSelectionStrategy);
}

TEST_P(FrameRateSelectionStrategyTest, SetParentOverrideChildren) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();
    auto layer1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto layer2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto layer3 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    addChild(layer1, layer2);
    addChild(layer2, layer3);

    layer1->setFrameRate(FRAME_RATE_VOTE1.vote);
    layer1->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::OverrideChildren);
    layer2->setFrameRate(FRAME_RATE_VOTE2.vote);
    layer2->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::OverrideChildren);
    layer3->setFrameRate(FRAME_RATE_VOTE3.vote);
    commitTransaction();

    EXPECT_EQ(FRAME_RATE_VOTE1, layer1->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              layer1->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE1, layer2->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              layer2->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE1, layer3->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer3->getDrawingState().frameRateSelectionStrategy);

    layer1->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::Propagate);
    commitTransaction();

    EXPECT_EQ(FRAME_RATE_VOTE1, layer1->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer1->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE2, layer2->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              layer2->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE2, layer3->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer3->getDrawingState().frameRateSelectionStrategy);
}

TEST_P(FrameRateSelectionStrategyTest, OverrideChildrenAndSelf) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();
    auto layer1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto layer2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto layer3 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    addChild(layer1, layer2);
    addChild(layer2, layer3);

    layer1->setFrameRate(FRAME_RATE_VOTE1.vote);
    layer2->setFrameRate(FRAME_RATE_VOTE2.vote);
    layer2->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::Self);
    commitTransaction();

    EXPECT_EQ(FRAME_RATE_VOTE1, layer1->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer1->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE2, layer2->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Self,
              layer2->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_DEFAULT, layer3->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer3->getDrawingState().frameRateSelectionStrategy);

    layer1->setFrameRateSelectionStrategy(FrameRateSelectionStrategy::OverrideChildren);
    commitTransaction();

    EXPECT_EQ(FRAME_RATE_VOTE1, layer1->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              layer1->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE1, layer2->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Self,
              layer2->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE1, layer3->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer3->getDrawingState().frameRateSelectionStrategy);

    layer1->setFrameRate(FRAME_RATE_DEFAULT.vote);
    commitTransaction();

    EXPECT_EQ(FRAME_RATE_TREE, layer1->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::OverrideChildren,
              layer1->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE2, layer2->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Self,
              layer2->getDrawingState().frameRateSelectionStrategy);
    EXPECT_EQ(FRAME_RATE_VOTE2, layer3->getFrameRateForLayerTree());
    EXPECT_EQ(FrameRateSelectionStrategy::Propagate,
              layer3->getDrawingState().frameRateSelectionStrategy);
}

} // namespace
} // namespace android