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
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include <log/log.h>
#include <utils/String8.h>

#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/MockEventThread.h"
#include "mock/MockVsyncController.h"

namespace android {

using testing::_;
using testing::Mock;
using testing::Return;
using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;
using PresentState = frametimeline::SurfaceFrame::PresentState;

class TransactionSurfaceFrameTest : public testing::Test {
public:
    TransactionSurfaceFrameTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        setupScheduler();
        setupComposer(0);
    }

    ~TransactionSurfaceFrameTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    sp<BufferStateLayer> createBufferStateLayer() {
        sp<Client> client;
        LayerCreationArgs args(mFlinger.flinger(), client, "buffer-state-layer", 100, 100, 0,
                               LayerMetadata());
        return new BufferStateLayer(args);
    }

    void commitTransaction(Layer* layer) {
        layer->pushPendingState();
        // After pushing the state, the currentState should not store any BufferlessSurfaceFrames
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        auto c = layer->getCurrentState();
        if (layer->applyPendingStates(&c)) {
            layer->commitTransaction(c);
        }
    }

    void setupScheduler() {
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

    void setupComposer(uint32_t virtualDisplayCount) {
        mComposer = new Hwc2::mock::Composer();
        EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
        mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

        Mock::VerifyAndClear(mComposer);
    }

    TestableSurfaceFlinger mFlinger;
    Hwc2::mock::Composer* mComposer = nullptr;
    FenceToFenceTimeMap fenceFactory;
    client_cache_t mClientCache;

    void PresentedSurfaceFrameForBufferlessTransaction() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             10);
        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_TRUE(layer->mCurrentState.bufferSurfaceFrameTX == nullptr);
        const auto surfaceFrame = layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*token*/ 1);
        commitTransaction(layer.get());
        EXPECT_EQ(1, surfaceFrame->getToken());
        EXPECT_EQ(false, surfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, surfaceFrame->getPresentState());
    }

    void PresentedSurfaceFrameForBufferTransaction() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        sp<Fence> fence(new Fence());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        sp<GraphicBuffer> buffer{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        layer->setBuffer(buffer, fence, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        acquireFence->signalForTest(12);

        commitTransaction(layer.get());
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto& surfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;
        // Buffers are presented only at latch time.
        EXPECT_EQ(PresentState::Unknown, surfaceFrame->getPresentState());

        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);

        EXPECT_EQ(1, surfaceFrame->getToken());
        EXPECT_EQ(true, surfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, surfaceFrame->getPresentState());
    }

    void DroppedSurfaceFrameForBufferTransaction() {
        sp<BufferStateLayer> layer = createBufferStateLayer();

        sp<Fence> fence1(new Fence());
        auto acquireFence1 = fenceFactory.createFenceTimeForTest(fence1);
        sp<GraphicBuffer> buffer1{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        layer->setBuffer(buffer1, fence1, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;

        sp<Fence> fence2(new Fence());
        auto acquireFence2 = fenceFactory.createFenceTimeForTest(fence2);
        sp<GraphicBuffer> buffer2{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        nsecs_t start = systemTime();
        layer->setBuffer(buffer2, fence2, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        nsecs_t end = systemTime();
        acquireFence2->signalForTest(12);

        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto& presentedSurfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);

        EXPECT_EQ(1, droppedSurfaceFrame->getToken());
        EXPECT_EQ(true, droppedSurfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Dropped, droppedSurfaceFrame->getPresentState());
        EXPECT_EQ(0u, droppedSurfaceFrame->getActuals().endTime);
        auto dropTime = droppedSurfaceFrame->getDropTime();
        EXPECT_TRUE(dropTime > start && dropTime < end);

        EXPECT_EQ(1, presentedSurfaceFrame->getToken());
        EXPECT_EQ(true, presentedSurfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, presentedSurfaceFrame->getPresentState());
    }

    void BufferlessSurfaceFramePromotedToBufferSurfaceFrame() {
        sp<BufferStateLayer> layer = createBufferStateLayer();

        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             10);

        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);

        sp<Fence> fence(new Fence());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        sp<GraphicBuffer> buffer{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};

        layer->setBuffer(buffer, fence, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        acquireFence->signalForTest(12);

        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto& surfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        EXPECT_EQ(1, surfaceFrame->getToken());
        EXPECT_EQ(true, surfaceFrame->getIsBuffer());
        // Buffers are presented only at latch time.
        EXPECT_EQ(PresentState::Unknown, surfaceFrame->getPresentState());

        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);

        EXPECT_EQ(PresentState::Presented, surfaceFrame->getPresentState());
    }

    void BufferlessSurfaceFrameNotCreatedIfBufferSufaceFrameExists() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        sp<Fence> fence(new Fence());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        sp<GraphicBuffer> buffer{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};

        layer->setBuffer(buffer, fence, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);

        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             10);
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
    }

    void MultipleSurfaceFramesPresentedTogether() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             10);
        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame1 =
                layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*token*/ 1);

        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 4, /*inputEventId*/ 0},
                                                             10);
        EXPECT_EQ(2u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame2 = layer->mCurrentState.bufferlessSurfaceFramesTX[4];

        sp<Fence> fence(new Fence());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        sp<GraphicBuffer> buffer{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};

        layer->setBuffer(buffer, fence, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 3, /*inputEventId*/ 0});
        EXPECT_EQ(2u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto& bufferSurfaceFrameTX = layer->mCurrentState.bufferSurfaceFrameTX;

        acquireFence->signalForTest(12);

        commitTransaction(layer.get());

        EXPECT_EQ(1, bufferlessSurfaceFrame1->getToken());
        EXPECT_EQ(false, bufferlessSurfaceFrame1->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, bufferlessSurfaceFrame1->getPresentState());

        EXPECT_EQ(4, bufferlessSurfaceFrame2->getToken());
        EXPECT_EQ(false, bufferlessSurfaceFrame2->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, bufferlessSurfaceFrame2->getPresentState());

        EXPECT_EQ(3, bufferSurfaceFrameTX->getToken());
        EXPECT_EQ(true, bufferSurfaceFrameTX->getIsBuffer());
        // Buffers are presented only at latch time.
        EXPECT_EQ(PresentState::Unknown, bufferSurfaceFrameTX->getPresentState());

        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);

        EXPECT_EQ(PresentState::Presented, bufferSurfaceFrameTX->getPresentState());
    }

    void MergePendingStates_BufferlessSurfaceFramesWithoutOverlappingToken() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             10);
        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame1 =
                layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*token*/ 1);

        layer->pushPendingState();
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());

        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 2, /*inputEventId*/ 0},
                                                             12);
        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame2 =
                layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*token*/ 2);

        commitTransaction(layer.get());

        EXPECT_EQ(1, bufferlessSurfaceFrame1->getToken());
        EXPECT_EQ(false, bufferlessSurfaceFrame1->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, bufferlessSurfaceFrame1->getPresentState());
        EXPECT_EQ(10, bufferlessSurfaceFrame1->getActuals().endTime);

        EXPECT_EQ(2, bufferlessSurfaceFrame2->getToken());
        EXPECT_EQ(false, bufferlessSurfaceFrame2->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, bufferlessSurfaceFrame2->getPresentState());
        EXPECT_EQ(12, bufferlessSurfaceFrame2->getActuals().endTime);
    }

    void MergePendingStates_BufferlessSurfaceFramesWithOverlappingToken() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             10);
        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame1 =
                layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*token*/ 1);

        layer->pushPendingState();
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());

        layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 1, /*inputEventId*/ 0},
                                                             12);
        EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame2 =
                layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*token*/ 1);

        commitTransaction(layer.get());

        EXPECT_EQ(1, bufferlessSurfaceFrame1->getToken());
        EXPECT_EQ(false, bufferlessSurfaceFrame1->getIsBuffer());
        EXPECT_EQ(PresentState::Unknown, bufferlessSurfaceFrame1->getPresentState());

        EXPECT_EQ(1, bufferlessSurfaceFrame2->getToken());
        EXPECT_EQ(false, bufferlessSurfaceFrame2->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, bufferlessSurfaceFrame2->getPresentState());
        EXPECT_EQ(12, bufferlessSurfaceFrame2->getActuals().endTime);
    }

    void PendingSurfaceFramesRemovedAfterClassification() {
        sp<BufferStateLayer> layer = createBufferStateLayer();

        sp<Fence> fence1(new Fence());
        auto acquireFence1 = fenceFactory.createFenceTimeForTest(fence1);
        sp<GraphicBuffer> buffer1{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        layer->setBuffer(buffer1, fence1, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;

        sp<Fence> fence2(new Fence());
        auto acquireFence2 = fenceFactory.createFenceTimeForTest(fence2);
        sp<GraphicBuffer> buffer2{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        layer->setBuffer(buffer2, fence2, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        acquireFence2->signalForTest(12);

        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        auto& presentedSurfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);

        // Both the droppedSurfaceFrame and presentedSurfaceFrame should be in
        // pendingJankClassifications.
        EXPECT_EQ(2u, layer->mPendingJankClassifications.size());
        presentedSurfaceFrame->onPresent(20, JankType::None, Fps::fromPeriodNsecs(11),
                                         /*displayDeadlineDelta*/ 0, /*displayPresentDelta*/ 0);
        layer->releasePendingBuffer(25);

        EXPECT_EQ(0u, layer->mPendingJankClassifications.size());
    }

    void BufferSurfaceFrame_ReplaceValidTokenBufferWithInvalidTokenBuffer() {
        sp<BufferStateLayer> layer = createBufferStateLayer();

        sp<Fence> fence1(new Fence());
        auto acquireFence1 = fenceFactory.createFenceTimeForTest(fence1);
        sp<GraphicBuffer> buffer1{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        layer->setBuffer(buffer1, fence1, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 1, /*inputEventId*/ 0});
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame1 = layer->mCurrentState.bufferSurfaceFrameTX;

        sp<Fence> fence2(new Fence());
        auto acquireFence2 = fenceFactory.createFenceTimeForTest(fence2);
        sp<GraphicBuffer> buffer2{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        auto dropStartTime1 = systemTime();
        layer->setBuffer(buffer2, fence2, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ FrameTimelineInfo::INVALID_VSYNC_ID, /*inputEventId*/ 0});
        auto dropEndTime1 = systemTime();
        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame2 = layer->mCurrentState.bufferSurfaceFrameTX;

        sp<Fence> fence3(new Fence());
        auto acquireFence3 = fenceFactory.createFenceTimeForTest(fence3);
        sp<GraphicBuffer> buffer3{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        auto dropStartTime2 = systemTime();
        layer->setBuffer(buffer3, fence3, 10, 20, false, mClientCache, 1, std::nullopt,
                         {/*vsyncId*/ 2, /*inputEventId*/ 0});
        auto dropEndTime2 = systemTime();
        acquireFence3->signalForTest(12);

        EXPECT_EQ(0u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
        const auto& presentedSurfaceFrame = layer->mCurrentState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);

        EXPECT_EQ(1, droppedSurfaceFrame1->getToken());
        EXPECT_EQ(true, droppedSurfaceFrame1->getIsBuffer());
        EXPECT_EQ(PresentState::Dropped, droppedSurfaceFrame1->getPresentState());
        EXPECT_EQ(0u, droppedSurfaceFrame1->getActuals().endTime);
        auto dropTime1 = droppedSurfaceFrame1->getDropTime();
        EXPECT_TRUE(dropTime1 > dropStartTime1 && dropTime1 < dropEndTime1);

        EXPECT_EQ(FrameTimelineInfo::INVALID_VSYNC_ID, droppedSurfaceFrame2->getToken());
        EXPECT_EQ(true, droppedSurfaceFrame2->getIsBuffer());
        EXPECT_EQ(PresentState::Dropped, droppedSurfaceFrame2->getPresentState());
        EXPECT_EQ(0u, droppedSurfaceFrame2->getActuals().endTime);
        auto dropTime2 = droppedSurfaceFrame2->getDropTime();
        EXPECT_TRUE(dropTime2 > dropStartTime2 && dropTime2 < dropEndTime2);

        EXPECT_EQ(2, presentedSurfaceFrame->getToken());
        EXPECT_EQ(true, presentedSurfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, presentedSurfaceFrame->getPresentState());
    }

    void MultipleCommitsBeforeLatch() {
        sp<BufferStateLayer> layer = createBufferStateLayer();
        uint32_t surfaceFramesPendingClassification = 0;
        std::vector<std::shared_ptr<frametimeline::SurfaceFrame>> bufferlessSurfaceFrames;
        for (int i = 0; i < 10; i += 2) {
            sp<Fence> fence1(new Fence());
            sp<GraphicBuffer> buffer1{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
            layer->setBuffer(buffer1, fence1, 10, 20, false, mClientCache, 1, std::nullopt,
                             {/*vsyncId*/ 1, /*inputEventId*/ 0});
            layer->setFrameTimelineVsyncForBufferlessTransaction({/*vsyncId*/ 2,
                                                                  /*inputEventId*/ 0},
                                                                 10);
            ASSERT_NE(nullptr, layer->mCurrentState.bufferSurfaceFrameTX);
            EXPECT_EQ(1u, layer->mCurrentState.bufferlessSurfaceFramesTX.size());
            auto& bufferlessSurfaceFrame =
                    layer->mCurrentState.bufferlessSurfaceFramesTX.at(/*vsyncId*/ 2);
            bufferlessSurfaceFrames.push_back(bufferlessSurfaceFrame);

            commitTransaction(layer.get());
            surfaceFramesPendingClassification += 2;
            EXPECT_EQ(surfaceFramesPendingClassification,
                      layer->mPendingJankClassifications.size());
        }

        auto presentedBufferSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;
        bool computeVisisbleRegions;
        layer->updateTexImage(computeVisisbleRegions, 15, 0);
        // BufferlessSurfaceFrames are immediately set to presented and added to the DisplayFrame.
        // Since we don't have access to DisplayFrame here, trigger an onPresent directly.
        for (auto& surfaceFrame : bufferlessSurfaceFrames) {
            surfaceFrame->onPresent(20, JankType::None, Fps::fromPeriodNsecs(11),
                                    /*displayDeadlineDelta*/ 0, /*displayPresentDelta*/ 0);
        }
        presentedBufferSurfaceFrame->onPresent(20, JankType::None, Fps::fromPeriodNsecs(11),
                                               /*displayDeadlineDelta*/ 0,
                                               /*displayPresentDelta*/ 0);

        // There should be 10 bufferlessSurfaceFrames and 1 bufferSurfaceFrame
        ASSERT_EQ(10u, surfaceFramesPendingClassification);
        ASSERT_EQ(surfaceFramesPendingClassification, layer->mPendingJankClassifications.size());

        // For the frames upto 8, the bufferSurfaceFrame should have been dropped while the
        // bufferlessSurfaceFrame presented
        for (uint32_t i = 0; i < 8; i += 2) {
            auto& bufferSurfaceFrame = layer->mPendingJankClassifications[i];
            auto& bufferlessSurfaceFrame = layer->mPendingJankClassifications[i + 1];
            EXPECT_EQ(bufferSurfaceFrame->getPresentState(), PresentState::Dropped);
            EXPECT_EQ(bufferlessSurfaceFrame->getPresentState(), PresentState::Presented);
        }
        {
            auto& bufferSurfaceFrame = layer->mPendingJankClassifications[8u];
            auto& bufferlessSurfaceFrame = layer->mPendingJankClassifications[9u];
            EXPECT_EQ(bufferSurfaceFrame->getPresentState(), PresentState::Presented);
            EXPECT_EQ(bufferlessSurfaceFrame->getPresentState(), PresentState::Presented);
        }

        layer->releasePendingBuffer(25);

        // There shouldn't be any pending classifications. Everything should have been cleared.
        EXPECT_EQ(0u, layer->mPendingJankClassifications.size());
    }
};

TEST_F(TransactionSurfaceFrameTest, PresentedBufferlessSurfaceFrame) {
    PresentedSurfaceFrameForBufferlessTransaction();
}

TEST_F(TransactionSurfaceFrameTest, PresentedBufferSurfaceFrame) {
    PresentedSurfaceFrameForBufferTransaction();
}

TEST_F(TransactionSurfaceFrameTest, DroppedBufferSurfaceFrame) {
    DroppedSurfaceFrameForBufferTransaction();
}

TEST_F(TransactionSurfaceFrameTest, BufferlessSurfaceFramePromotedToBufferSurfaceFrame) {
    BufferlessSurfaceFramePromotedToBufferSurfaceFrame();
}

TEST_F(TransactionSurfaceFrameTest, BufferlessSurfaceFrameNotCreatedIfBufferSufaceFrameExists) {
    BufferlessSurfaceFrameNotCreatedIfBufferSufaceFrameExists();
}

TEST_F(TransactionSurfaceFrameTest, MultipleSurfaceFramesPresentedTogether) {
    MultipleSurfaceFramesPresentedTogether();
}

TEST_F(TransactionSurfaceFrameTest,
       MergePendingStates_BufferlessSurfaceFramesWithoutOverlappingToken) {
    MergePendingStates_BufferlessSurfaceFramesWithoutOverlappingToken();
}

TEST_F(TransactionSurfaceFrameTest,
       MergePendingStates_BufferlessSurfaceFramesWithOverlappingToken) {
    MergePendingStates_BufferlessSurfaceFramesWithOverlappingToken();
}

TEST_F(TransactionSurfaceFrameTest, PendingSurfaceFramesRemovedAfterClassification) {
    PendingSurfaceFramesRemovedAfterClassification();
}

TEST_F(TransactionSurfaceFrameTest,
       BufferSurfaceFrame_ReplaceValidTokenBufferWithInvalidTokenBuffer) {
    BufferSurfaceFrame_ReplaceValidTokenBufferWithInvalidTokenBuffer();
}

TEST_F(TransactionSurfaceFrameTest, MultipleCommitsBeforeLatch) {
    MultipleCommitsBeforeLatch();
}

} // namespace android