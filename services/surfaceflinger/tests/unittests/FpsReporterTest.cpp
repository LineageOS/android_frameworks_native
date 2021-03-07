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
#define LOG_TAG "FpsReporterTest"

#include <android/gui/BnFpsListener.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerMetadata.h>

#include "BufferQueueLayer.h"
#include "BufferStateLayer.h"
#include "EffectLayer.h"
#include "FpsReporter.h"
#include "Layer.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/MockEventThread.h"
#include "mock/MockFrameTimeline.h"
#include "mock/MockVsyncController.h"

namespace android {

using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;
using testing::UnorderedElementsAre;

using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

struct TestableFpsListener : public gui::BnFpsListener {
    TestableFpsListener() {}

    float lastReportedFps = 0;

    binder::Status onFpsReported(float fps) override {
        lastReportedFps = fps;
        return binder::Status::ok();
    }
};

/**
 * This class covers all the test that are related to refresh rate selection.
 */
class FpsReporterTest : public testing::Test {
public:
    FpsReporterTest();
    ~FpsReporterTest() override;

protected:
    static constexpr int DEFAULT_DISPLAY_WIDTH = 1920;
    static constexpr int DEFAULT_DISPLAY_HEIGHT = 1024;
    static constexpr uint32_t WIDTH = 100;
    static constexpr uint32_t HEIGHT = 100;
    static constexpr uint32_t LAYER_FLAGS = 0;
    static constexpr int32_t PRIORITY_UNSET = -1;

    void setupScheduler();
    void setupComposer(uint32_t virtualDisplayCount);
    sp<BufferStateLayer> createBufferStateLayer(LayerMetadata metadata);

    TestableSurfaceFlinger mFlinger;
    Hwc2::mock::Composer* mComposer = nullptr;
    mock::FrameTimeline mFrameTimeline =
            mock::FrameTimeline(std::make_shared<impl::TimeStats>(), 0);

    sp<Client> mClient;
    sp<Layer> mParent;
    sp<Layer> mTarget;
    sp<Layer> mChild;
    sp<Layer> mGrandChild;
    sp<Layer> mUnrelated;

    sp<TestableFpsListener> mFpsListener;
    sp<FpsReporter> mFpsReporter = new FpsReporter(mFrameTimeline, *(mFlinger.flinger()));
};

FpsReporterTest::FpsReporterTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    setupScheduler();
    setupComposer(0);
    mFpsListener = new TestableFpsListener();
}

FpsReporterTest::~FpsReporterTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

sp<BufferStateLayer> FpsReporterTest::createBufferStateLayer(LayerMetadata metadata = {}) {
    sp<Client> client;
    LayerCreationArgs args(mFlinger.flinger(), client, "buffer-state-layer", WIDTH, HEIGHT,
                           LAYER_FLAGS, metadata);
    return new BufferStateLayer(args);
}

void FpsReporterTest::setupScheduler() {
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
                            std::move(eventThread), std::move(sfEventThread));
}

void FpsReporterTest::setupComposer(uint32_t virtualDisplayCount) {
    mComposer = new Hwc2::mock::Composer();
    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    Mock::VerifyAndClear(mComposer);
}

namespace {

TEST_F(FpsReporterTest, callsListeners) {
    mParent = createBufferStateLayer();
    const constexpr int32_t kTaskId = 12;
    LayerMetadata targetMetadata;
    targetMetadata.setInt32(METADATA_TASK_ID, kTaskId);
    mTarget = createBufferStateLayer(targetMetadata);
    mChild = createBufferStateLayer();
    mGrandChild = createBufferStateLayer();
    mUnrelated = createBufferStateLayer();
    mParent->addChild(mTarget);
    mTarget->addChild(mChild);
    mChild->addChild(mGrandChild);
    mParent->commitChildList();
    mFlinger.mutableCurrentState().layersSortedByZ.add(mParent);
    mFlinger.mutableCurrentState().layersSortedByZ.add(mTarget);
    mFlinger.mutableCurrentState().layersSortedByZ.add(mChild);
    mFlinger.mutableCurrentState().layersSortedByZ.add(mGrandChild);

    float expectedFps = 44.0;

    EXPECT_CALL(mFrameTimeline,
                computeFps(UnorderedElementsAre(mTarget->getSequence(), mChild->getSequence(),
                                                mGrandChild->getSequence())))
            .WillOnce(Return(expectedFps));

    mFpsReporter->addListener(mFpsListener, kTaskId);
    mFpsReporter->dispatchLayerFps();
    EXPECT_EQ(expectedFps, mFpsListener->lastReportedFps);
    mFpsReporter->removeListener(mFpsListener);
    Mock::VerifyAndClearExpectations(&mFrameTimeline);

    EXPECT_CALL(mFrameTimeline, computeFps(_)).Times(0);
    mFpsReporter->dispatchLayerFps();
}

} // namespace
} // namespace android
