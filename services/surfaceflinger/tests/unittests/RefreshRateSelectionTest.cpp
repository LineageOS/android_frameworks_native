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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerMetadata.h>

#include "BufferQueueLayer.h"
#include "BufferStateLayer.h"
#include "EffectLayer.h"
#include "Layer.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/MockDispSync.h"
#include "mock/MockEventControlThread.h"
#include "mock/MockEventThread.h"

namespace android {

using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

/**
 * This class covers all the test that are related to refresh rate selection.
 */
class RefreshRateSelectionTest : public testing::Test {
public:
    RefreshRateSelectionTest();
    ~RefreshRateSelectionTest() override;

protected:
    static constexpr int DEFAULT_DISPLAY_WIDTH = 1920;
    static constexpr int DEFAULT_DISPLAY_HEIGHT = 1024;
    static constexpr uint32_t WIDTH = 100;
    static constexpr uint32_t HEIGHT = 100;
    static constexpr uint32_t LAYER_FLAGS = 0;
    static constexpr int32_t PRIORITY_UNSET = -1;

    void setupScheduler();
    void setupComposer(int virtualDisplayCount);
    sp<BufferQueueLayer> createBufferQueueLayer();
    sp<BufferStateLayer> createBufferStateLayer();
    sp<EffectLayer> createEffectLayer();

    void setParent(Layer* child, Layer* parent);
    void commitTransaction(Layer* layer);

    TestableSurfaceFlinger mFlinger;
    Hwc2::mock::Composer* mComposer = nullptr;

    sp<Client> mClient;
    sp<Layer> mParent;
    sp<Layer> mChild;
    sp<Layer> mGrandChild;
};

RefreshRateSelectionTest::RefreshRateSelectionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    setupScheduler();
    setupComposer(0);
}

RefreshRateSelectionTest::~RefreshRateSelectionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

sp<BufferQueueLayer> RefreshRateSelectionTest::createBufferQueueLayer() {
    sp<Client> client;
    LayerCreationArgs args(mFlinger.flinger(), client, "buffer-queue-layer", WIDTH, HEIGHT,
                           LAYER_FLAGS, LayerMetadata());
    return new BufferQueueLayer(args);
}

sp<BufferStateLayer> RefreshRateSelectionTest::createBufferStateLayer() {
    sp<Client> client;
    LayerCreationArgs args(mFlinger.flinger(), client, "buffer-queue-layer", WIDTH, HEIGHT,
                           LAYER_FLAGS, LayerMetadata());
    return new BufferStateLayer(args);
}

sp<EffectLayer> RefreshRateSelectionTest::createEffectLayer() {
    sp<Client> client;
    LayerCreationArgs args(mFlinger.flinger(), client, "color-layer", WIDTH, HEIGHT, LAYER_FLAGS,
                           LayerMetadata());
    return new EffectLayer(args);
}

void RefreshRateSelectionTest::setParent(Layer* child, Layer* parent) {
    child->setParent(parent);
}

void RefreshRateSelectionTest::commitTransaction(Layer* layer) {
    layer->commitTransaction(layer->getCurrentState());
}

void RefreshRateSelectionTest::setupScheduler() {
    auto eventThread = std::make_unique<mock::EventThread>();
    auto sfEventThread = std::make_unique<mock::EventThread>();

    EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*eventThread, createEventConnection(_, _))
            .WillOnce(Return(new EventThreadConnection(eventThread.get(), ResyncCallback(),
                                                       ISurfaceComposer::eConfigChangedSuppress)));

    EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
            .WillOnce(Return(new EventThreadConnection(sfEventThread.get(), ResyncCallback(),
                                                       ISurfaceComposer::eConfigChangedSuppress)));

    auto primaryDispSync = std::make_unique<mock::DispSync>();

    EXPECT_CALL(*primaryDispSync, computeNextRefresh(0, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*primaryDispSync, getPeriod())
            .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_REFRESH_RATE));
    EXPECT_CALL(*primaryDispSync, expectedPresentTime(_)).WillRepeatedly(Return(0));
    mFlinger.setupScheduler(std::move(primaryDispSync),
                            std::make_unique<mock::EventControlThread>(), std::move(eventThread),
                            std::move(sfEventThread));
}

void RefreshRateSelectionTest::setupComposer(int virtualDisplayCount) {
    mComposer = new Hwc2::mock::Composer();
    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    Mock::VerifyAndClear(mComposer);
}

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(RefreshRateSelectionTest, testPriorityOnBufferQueueLayers) {
    mParent = createBufferQueueLayer();
    mChild = createBufferQueueLayer();
    setParent(mChild.get(), mParent.get());
    mGrandChild = createBufferQueueLayer();
    setParent(mGrandChild.get(), mChild.get());

    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mGrandChild->getFrameRateSelectionPriority());

    // Child has its own priority.
    mGrandChild->setFrameRateSelectionPriority(1);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());

    // Child inherits from his parent.
    mChild->setFrameRateSelectionPriority(1);
    commitTransaction(mChild.get());
    mGrandChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mGrandChild.get());

    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());

    // Grandchild inherits from his grand parent.
    mParent->setFrameRateSelectionPriority(1);
    commitTransaction(mParent.get());
    mChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mChild.get());
    mGrandChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(1, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());
}

TEST_F(RefreshRateSelectionTest, testPriorityOnBufferStateLayers) {
    mParent = createBufferStateLayer();
    mChild = createBufferStateLayer();
    setParent(mChild.get(), mParent.get());
    mGrandChild = createBufferStateLayer();
    setParent(mGrandChild.get(), mChild.get());

    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mGrandChild->getFrameRateSelectionPriority());

    // Child has its own priority.
    mGrandChild->setFrameRateSelectionPriority(1);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());

    // Child inherits from his parent.
    mChild->setFrameRateSelectionPriority(1);
    commitTransaction(mChild.get());
    mGrandChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());

    // Grandchild inherits from his grand parent.
    mParent->setFrameRateSelectionPriority(1);
    commitTransaction(mParent.get());
    mChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mChild.get());
    mGrandChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(1, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());
}

TEST_F(RefreshRateSelectionTest, testPriorityOnEffectLayers) {
    mParent = createEffectLayer();
    mChild = createEffectLayer();
    setParent(mChild.get(), mParent.get());
    mGrandChild = createEffectLayer();
    setParent(mGrandChild.get(), mChild.get());

    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mGrandChild->getFrameRateSelectionPriority());

    // Child has its own priority.
    mGrandChild->setFrameRateSelectionPriority(1);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(PRIORITY_UNSET, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());

    // Child inherits from his parent.
    mChild->setFrameRateSelectionPriority(1);
    commitTransaction(mChild.get());
    mGrandChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(PRIORITY_UNSET, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());

    // Grandchild inherits from his grand parent.
    mParent->setFrameRateSelectionPriority(1);
    commitTransaction(mParent.get());
    mChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mChild.get());
    mGrandChild->setFrameRateSelectionPriority(PRIORITY_UNSET);
    commitTransaction(mGrandChild.get());
    ASSERT_EQ(1, mParent->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mChild->getFrameRateSelectionPriority());
    ASSERT_EQ(1, mGrandChild->getFrameRateSelectionPriority());
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
