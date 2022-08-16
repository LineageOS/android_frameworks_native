/*
 * Copyright 2020 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include "BufferStateLayer.h"
#include "EffectLayer.h"
#include "Layer.h"
// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
#include "FpsOps.h"
#include "LayerTestUtils.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/MockVsyncController.h"

namespace android {

using testing::DoAll;
using testing::Mock;
using testing::SetArgPointee;

using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

using scheduler::LayerHistory;

using FrameRate = Layer::FrameRate;
using FrameRateCompatibility = Layer::FrameRateCompatibility;

/**
 * This class tests the behaviour of Layer::SetFrameRate and Layer::GetFrameRate
 */
class SetFrameRateTest : public BaseLayerTest {
protected:
    const FrameRate FRAME_RATE_VOTE1 = FrameRate(67_Hz, FrameRateCompatibility::Default);
    const FrameRate FRAME_RATE_VOTE2 = FrameRate(14_Hz, FrameRateCompatibility::ExactOrMultiple);
    const FrameRate FRAME_RATE_VOTE3 = FrameRate(99_Hz, FrameRateCompatibility::NoVote);
    const FrameRate FRAME_RATE_TREE = FrameRate(Fps(), FrameRateCompatibility::NoVote);
    const FrameRate FRAME_RATE_NO_VOTE = FrameRate(Fps(), FrameRateCompatibility::Default);

    SetFrameRateTest();

    void addChild(sp<Layer> layer, sp<Layer> child);
    void removeChild(sp<Layer> layer, sp<Layer> child);
    void commitTransaction();

    std::vector<sp<Layer>> mLayers;
};

SetFrameRateTest::SetFrameRateTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    mFlinger.setupComposer(std::make_unique<Hwc2::mock::Composer>());
}

void SetFrameRateTest::addChild(sp<Layer> layer, sp<Layer> child) {
    layer.get()->addChild(child.get());
}

void SetFrameRateTest::removeChild(sp<Layer> layer, sp<Layer> child) {
    layer.get()->removeChild(child.get());
}

void SetFrameRateTest::commitTransaction() {
    for (auto layer : mLayers) {
        auto c = layer->getDrawingState();
        layer->commitTransaction(c);
    }
}

namespace {

TEST_P(SetFrameRateTest, SetAndGet) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto layer = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    layer->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, layer->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetParent) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);

    child2->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    child2->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetParentAllVote) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);

    child2->setFrameRate(FRAME_RATE_VOTE1);
    child1->setFrameRate(FRAME_RATE_VOTE2);
    parent->setFrameRate(FRAME_RATE_VOTE3);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE3, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE2, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    child2->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE3, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE2, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE2, child2->getFrameRateForLayerTree());

    child1->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE3, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE3, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE3, child2->getFrameRateForLayerTree());

    parent->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetChild) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);

    parent->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    parent->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetChildAllVote) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);

    child2->setFrameRate(FRAME_RATE_VOTE1);
    child1->setFrameRate(FRAME_RATE_VOTE2);
    parent->setFrameRate(FRAME_RATE_VOTE3);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE3, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE2, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    parent->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE2, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    child1->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    child2->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetChildAddAfterVote) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);

    parent->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());

    addChild(child1, child2);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    parent->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetChildRemoveAfterVote) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);

    parent->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    removeChild(child1, child2);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());

    parent->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetParentNotInTree) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2_1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);
    addChild(child1, child2_1);

    child2->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2_1->getFrameRateForLayerTree());

    child2->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2_1->getFrameRateForLayerTree());
}

INSTANTIATE_TEST_SUITE_P(PerLayerType, SetFrameRateTest,
                         testing::Values(std::make_shared<BufferStateLayerFactory>(),
                                         std::make_shared<EffectLayerFactory>()),
                         PrintToStringParamName);

TEST_F(SetFrameRateTest, ValidateFrameRate) {
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Privileged APIs.
    EXPECT_FALSE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    constexpr bool kPrivileged = true;
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, "",
                                  kPrivileged));
    EXPECT_TRUE(ValidateFrameRate(0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, "",
                                  kPrivileged));

    // Invalid frame rate.
    EXPECT_FALSE(ValidateFrameRate(-1, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(1.0f / 0.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(0.0f / 0.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Invalid compatibility.
    EXPECT_FALSE(
            ValidateFrameRate(60.0f, -1, ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(60.0f, 2, ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Invalid change frame rate strategy.
    EXPECT_FALSE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT, -1, ""));
    EXPECT_FALSE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT, 2, ""));
}

TEST_P(SetFrameRateTest, SetOnParentActivatesTree) {
    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    if (!parent->isVisible()) {
        // This is a hack as all the test layers except EffectLayer are not visible,
        // but since the logic is unified in Layer, it should be fine.
        return;
    }

    auto child = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    addChild(parent, child);

    parent->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();

    auto& history = mFlinger.mutableScheduler().mutableLayerHistory();
    history.record(parent.get(), 0, 0, LayerHistory::LayerUpdateType::Buffer);
    history.record(child.get(), 0, 0, LayerHistory::LayerUpdateType::Buffer);

    const auto configs = mFlinger.mutableScheduler().refreshRateConfigs();
    const auto summary = history.summarize(*configs, 0);

    ASSERT_EQ(2u, summary.size());
    EXPECT_EQ(FRAME_RATE_VOTE1.rate, summary[0].desiredRefreshRate);
    EXPECT_EQ(FRAME_RATE_VOTE1.rate, summary[1].desiredRefreshRate);
}

TEST_P(SetFrameRateTest, addChildForParentWithTreeVote) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    const auto& layerFactory = GetParam();

    const auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    const auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    const auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    const auto childOfChild1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, childOfChild1);

    childOfChild1->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, childOfChild1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());

    addChild(parent, child2);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, childOfChild1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());

    childOfChild1->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, childOfChild1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

} // namespace
} // namespace android
