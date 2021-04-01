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
#include "BufferQueueLayer.h"
#include "BufferStateLayer.h"
#include "EffectLayer.h"
#include "Layer.h"
// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/MockEventThread.h"
#include "mock/MockMessageQueue.h"
#include "mock/MockVsyncController.h"

namespace android {

using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

using FrameRate = Layer::FrameRate;
using FrameRateCompatibility = Layer::FrameRateCompatibility;

class LayerFactory {
public:
    virtual ~LayerFactory() = default;

    virtual std::string name() = 0;
    virtual sp<Layer> createLayer(TestableSurfaceFlinger& flinger) = 0;

protected:
    static constexpr uint32_t WIDTH = 100;
    static constexpr uint32_t HEIGHT = 100;
    static constexpr uint32_t LAYER_FLAGS = 0;
};

class BufferQueueLayerFactory : public LayerFactory {
public:
    std::string name() override { return "BufferQueueLayer"; }
    sp<Layer> createLayer(TestableSurfaceFlinger& flinger) override {
        sp<Client> client;
        LayerCreationArgs args(flinger.flinger(), client, "buffer-queue-layer", WIDTH, HEIGHT,
                               LAYER_FLAGS, LayerMetadata());
        return new BufferQueueLayer(args);
    }
};

class BufferStateLayerFactory : public LayerFactory {
public:
    std::string name() override { return "BufferStateLayer"; }
    sp<Layer> createLayer(TestableSurfaceFlinger& flinger) override {
        sp<Client> client;
        LayerCreationArgs args(flinger.flinger(), client, "buffer-state-layer", WIDTH, HEIGHT,
                               LAYER_FLAGS, LayerMetadata());
        return new BufferStateLayer(args);
    }
};

class EffectLayerFactory : public LayerFactory {
public:
    std::string name() override { return "EffectLayer"; }
    sp<Layer> createLayer(TestableSurfaceFlinger& flinger) override {
        sp<Client> client;
        LayerCreationArgs args(flinger.flinger(), client, "color-layer", WIDTH, HEIGHT, LAYER_FLAGS,
                               LayerMetadata());
        return new EffectLayer(args);
    }
};

std::string PrintToStringParamName(
        const ::testing::TestParamInfo<std::shared_ptr<LayerFactory>>& info) {
    return info.param->name();
}

/**
 * This class tests the behaviour of Layer::SetFrameRate and Layer::GetFrameRate
 */
class SetFrameRateTest : public ::testing::TestWithParam<std::shared_ptr<LayerFactory>> {
protected:
    const FrameRate FRAME_RATE_VOTE1 = FrameRate(Fps(67.f), FrameRateCompatibility::Default);
    const FrameRate FRAME_RATE_VOTE2 =
            FrameRate(Fps(14.f), FrameRateCompatibility::ExactOrMultiple);
    const FrameRate FRAME_RATE_VOTE3 = FrameRate(Fps(99.f), FrameRateCompatibility::NoVote);
    const FrameRate FRAME_RATE_TREE = FrameRate(Fps(0.f), FrameRateCompatibility::NoVote);
    const FrameRate FRAME_RATE_NO_VOTE = FrameRate(Fps(0.f), FrameRateCompatibility::Default);

    SetFrameRateTest();

    void setupScheduler();
    void setupComposer(uint32_t virtualDisplayCount);

    void addChild(sp<Layer> layer, sp<Layer> child);
    void removeChild(sp<Layer> layer, sp<Layer> child);
    void reparentChildren(sp<Layer> layer, sp<Layer> child);
    void commitTransaction();

    TestableSurfaceFlinger mFlinger;
    Hwc2::mock::Composer* mComposer = nullptr;
    mock::MessageQueue* mMessageQueue = new mock::MessageQueue();

    std::vector<sp<Layer>> mLayers;
};

SetFrameRateTest::SetFrameRateTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    mFlinger.mutableUseFrameRateApi() = true;

    setupScheduler();
    setupComposer(0);

    mFlinger.mutableEventQueue().reset(mMessageQueue);
}
void SetFrameRateTest::addChild(sp<Layer> layer, sp<Layer> child) {
    layer.get()->addChild(child.get());
}

void SetFrameRateTest::removeChild(sp<Layer> layer, sp<Layer> child) {
    layer.get()->removeChild(child.get());
}

void SetFrameRateTest::reparentChildren(sp<Layer> parent, sp<Layer> newParent) {
    parent.get()->reparentChildren(newParent);
}

void SetFrameRateTest::commitTransaction() {
    for (auto layer : mLayers) {
        layer->pushPendingState();
        auto c = layer->getCurrentState();
        if (layer->applyPendingStates(&c)) {
            layer->commitTransaction(c);
        }
    }
}

void SetFrameRateTest::setupScheduler() {
    auto eventThread = std::make_unique<mock::EventThread>();
    auto sfEventThread = std::make_unique<mock::EventThread>();

    EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*eventThread, createEventConnection(_, _))
            .WillOnce(Return(new EventThreadConnection(eventThread.get(), /*callingUid=*/0,
                                                       ResyncCallback())));

    EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
            .WillOnce(Return(new EventThreadConnection(sfEventThread.get(), /*callingUid=*/0,
                                                       ResyncCallback())));

    auto vsyncController = std::make_unique<mock::VsyncController>();
    auto vsyncTracker = std::make_unique<mock::VSyncTracker>();

    EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*vsyncTracker, currentPeriod())
            .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));
    EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
    mFlinger.setupScheduler(std::move(vsyncController), std::move(vsyncTracker),
                            std::move(eventThread), std::move(sfEventThread), /*callback*/ nullptr,
                            /*hasMultipleModes*/ true);
}

void SetFrameRateTest::setupComposer(uint32_t virtualDisplayCount) {
    mComposer = new Hwc2::mock::Composer();
    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    Mock::VerifyAndClear(mComposer);
}

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_P(SetFrameRateTest, SetAndGet) {
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    const auto& layerFactory = GetParam();

    auto layer = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    layer->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_VOTE1, layer->getFrameRateForLayerTree());
}

TEST_P(SetFrameRateTest, SetAndGetParent) {
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

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

TEST_P(SetFrameRateTest, SetAndGetReparentChildren) {
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    const auto& layerFactory = GetParam();

    auto parent = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto parent2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child1 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));
    auto child2 = mLayers.emplace_back(layerFactory->createLayer(mFlinger));

    addChild(parent, child1);
    addChild(child1, child2);

    child2->setFrameRate(FRAME_RATE_VOTE1);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_TREE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent2->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    reparentChildren(parent, parent2);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, parent2->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_TREE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_VOTE1, child2->getFrameRateForLayerTree());

    child2->setFrameRate(FRAME_RATE_NO_VOTE);
    commitTransaction();
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, parent2->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child1->getFrameRateForLayerTree());
    EXPECT_EQ(FRAME_RATE_NO_VOTE, child2->getFrameRateForLayerTree());
}

INSTANTIATE_TEST_SUITE_P(PerLayerType, SetFrameRateTest,
                         testing::Values(std::make_shared<BufferQueueLayerFactory>(),
                                         std::make_shared<BufferStateLayerFactory>(),
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
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, "",
                                  /*privileged=*/true));

    EXPECT_FALSE(ValidateFrameRate(-1, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(1.0f / 0.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(0.0f / 0.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    EXPECT_FALSE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Invalid compatibility
    EXPECT_FALSE(
            ValidateFrameRate(60.0f, -1, ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(60.0f, 2, ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Invalid change frame rate strategy
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

    const auto layerHistorySummary =
            mFlinger.mutableScheduler().mutableLayerHistory()->summarize(0);
    ASSERT_EQ(2u, layerHistorySummary.size());
    EXPECT_TRUE(FRAME_RATE_VOTE1.rate.equalsWithMargin(layerHistorySummary[0].desiredRefreshRate));
    EXPECT_TRUE(FRAME_RATE_VOTE1.rate.equalsWithMargin(layerHistorySummary[1].desiredRefreshRate));
}

} // namespace
} // namespace android
