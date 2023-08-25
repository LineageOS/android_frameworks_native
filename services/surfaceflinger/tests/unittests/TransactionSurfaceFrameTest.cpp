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
#include <renderengine/ExternalTexture.h>
#include <renderengine/mock/FakeExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>
#include <utils/String8.h>

#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"

namespace android {

using testing::_;
using testing::Mock;
using testing::Return;

using PresentState = frametimeline::SurfaceFrame::PresentState;

class TransactionSurfaceFrameTest : public testing::Test {
public:
    TransactionSurfaceFrameTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        mFlinger.setupMockScheduler();
        mFlinger.setupComposer(std::make_unique<Hwc2::mock::Composer>());
        mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    }

    ~TransactionSurfaceFrameTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    sp<Layer> createLayer() {
        sp<Client> client;
        LayerCreationArgs args(mFlinger.flinger(), client, "layer", 0, LayerMetadata());
        return sp<Layer>::make(args);
    }

    void commitTransaction(Layer* layer) {
        auto c = layer->getDrawingState();
        layer->commitTransaction(c);
    }

    TestableSurfaceFlinger mFlinger;
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();

    FenceToFenceTimeMap fenceFactory;

    void PresentedSurfaceFrameForBufferlessTransaction() {
        sp<Layer> layer = createLayer();
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setFrameTimelineVsyncForBufferlessTransaction(ftInfo, 10);
        EXPECT_EQ(1u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_TRUE(layer->mDrawingState.bufferSurfaceFrameTX == nullptr);
        const auto surfaceFrame = layer->mDrawingState.bufferlessSurfaceFramesTX.at(/*token*/ 1);
        commitTransaction(layer.get());
        EXPECT_EQ(1, surfaceFrame->getToken());
        EXPECT_EQ(false, surfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, surfaceFrame->getPresentState());
    }

    void PresentedSurfaceFrameForBufferTransaction() {
        sp<Layer> layer = createLayer();
        sp<Fence> fence(sp<Fence>::make());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        BufferData bufferData;
        bufferData.acquireFence = fence;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setBuffer(externalTexture, bufferData, 10, 20, false, std::nullopt, ftInfo);
        acquireFence->signalForTest(12);

        commitTransaction(layer.get());
        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto surfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;
        // Buffers are presented only at latch time.
        EXPECT_EQ(PresentState::Unknown, surfaceFrame->getPresentState());

        layer->updateTexImage(15);

        EXPECT_EQ(1, surfaceFrame->getToken());
        EXPECT_EQ(true, surfaceFrame->getIsBuffer());
        EXPECT_EQ(PresentState::Presented, surfaceFrame->getPresentState());
    }

    void DroppedSurfaceFrameForBufferTransaction() {
        sp<Layer> layer = createLayer();

        sp<Fence> fence1(sp<Fence>::make());
        auto acquireFence1 = fenceFactory.createFenceTimeForTest(fence1);
        BufferData bufferData;
        bufferData.acquireFence = fence1;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture1 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setBuffer(externalTexture1, bufferData, 10, 20, false, std::nullopt, ftInfo);
        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;

        sp<Fence> fence2(sp<Fence>::make());
        auto acquireFence2 = fenceFactory.createFenceTimeForTest(fence2);
        nsecs_t start = systemTime();
        bufferData.acquireFence = fence2;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture2 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         2ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        layer->setBuffer(externalTexture2, bufferData, 10, 20, false, std::nullopt, ftInfo);
        nsecs_t end = systemTime();
        acquireFence2->signalForTest(12);

        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto presentedSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        layer->updateTexImage(15);

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
        sp<Layer> layer = createLayer();
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;

        layer->setFrameTimelineVsyncForBufferlessTransaction(ftInfo, 10);

        EXPECT_EQ(1u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);

        sp<Fence> fence(sp<Fence>::make());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        BufferData bufferData;
        bufferData.acquireFence = fence;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        layer->setBuffer(externalTexture, bufferData, 10, 20, false, std::nullopt, ftInfo);
        acquireFence->signalForTest(12);

        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto surfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        EXPECT_EQ(1, surfaceFrame->getToken());
        EXPECT_EQ(true, surfaceFrame->getIsBuffer());
        // Buffers are presented only at latch time.
        EXPECT_EQ(PresentState::Unknown, surfaceFrame->getPresentState());

        layer->updateTexImage(15);

        EXPECT_EQ(PresentState::Presented, surfaceFrame->getPresentState());
    }

    void BufferlessSurfaceFrameNotCreatedIfBufferSufaceFrameExists() {
        sp<Layer> layer = createLayer();
        sp<Fence> fence(sp<Fence>::make());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        BufferData bufferData;
        bufferData.acquireFence = fence;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setBuffer(externalTexture, bufferData, 10, 20, false, std::nullopt, ftInfo);
        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);

        layer->setFrameTimelineVsyncForBufferlessTransaction(ftInfo, 10);
        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
    }

    void MultipleSurfaceFramesPresentedTogether() {
        sp<Layer> layer = createLayer();
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setFrameTimelineVsyncForBufferlessTransaction(ftInfo, 10);
        EXPECT_EQ(1u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame1 =
                layer->mDrawingState.bufferlessSurfaceFramesTX.at(/*token*/ 1);

        FrameTimelineInfo ftInfo2;
        ftInfo2.vsyncId = 4;
        ftInfo2.inputEventId = 0;
        layer->setFrameTimelineVsyncForBufferlessTransaction(ftInfo2, 10);
        EXPECT_EQ(2u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_EQ(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto bufferlessSurfaceFrame2 = layer->mDrawingState.bufferlessSurfaceFramesTX[4];

        sp<Fence> fence(sp<Fence>::make());
        auto acquireFence = fenceFactory.createFenceTimeForTest(fence);
        BufferData bufferData;
        bufferData.acquireFence = fence;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo3;
        ftInfo3.vsyncId = 3;
        ftInfo3.inputEventId = 0;
        layer->setBuffer(externalTexture, bufferData, 10, 20, false, std::nullopt, ftInfo3);
        EXPECT_EQ(2u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto bufferSurfaceFrameTX = layer->mDrawingState.bufferSurfaceFrameTX;

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

        layer->updateTexImage(15);

        EXPECT_EQ(PresentState::Presented, bufferSurfaceFrameTX->getPresentState());
    }

    void PendingSurfaceFramesRemovedAfterClassification() {
        sp<Layer> layer = createLayer();

        sp<Fence> fence1(sp<Fence>::make());
        auto acquireFence1 = fenceFactory.createFenceTimeForTest(fence1);
        BufferData bufferData;
        bufferData.acquireFence = fence1;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture1 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setBuffer(externalTexture1, bufferData, 10, 20, false, std::nullopt, ftInfo);
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;

        sp<Fence> fence2(sp<Fence>::make());
        auto acquireFence2 = fenceFactory.createFenceTimeForTest(fence2);
        bufferData.acquireFence = fence2;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture2 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        layer->setBuffer(externalTexture2, bufferData, 10, 20, false, std::nullopt, ftInfo);
        acquireFence2->signalForTest(12);

        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        auto presentedSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        layer->updateTexImage(15);

        // Both the droppedSurfaceFrame and presentedSurfaceFrame should be in
        // pendingJankClassifications.
        EXPECT_EQ(2u, layer->mPendingJankClassifications.size());
        presentedSurfaceFrame->onPresent(20, JankType::None, 90_Hz,
                                         /*displayDeadlineDelta*/ 0, /*displayPresentDelta*/ 0);
        layer->releasePendingBuffer(25);

        EXPECT_EQ(0u, layer->mPendingJankClassifications.size());
    }

    void BufferSurfaceFrame_ReplaceValidTokenBufferWithInvalidTokenBuffer() {
        sp<Layer> layer = createLayer();

        sp<Fence> fence1(sp<Fence>::make());
        auto acquireFence1 = fenceFactory.createFenceTimeForTest(fence1);
        BufferData bufferData;
        bufferData.acquireFence = fence1;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture1 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo;
        ftInfo.vsyncId = 1;
        ftInfo.inputEventId = 0;
        layer->setBuffer(externalTexture1, bufferData, 10, 20, false, std::nullopt, ftInfo);
        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame1 = layer->mDrawingState.bufferSurfaceFrameTX;

        sp<Fence> fence2(sp<Fence>::make());
        auto acquireFence2 = fenceFactory.createFenceTimeForTest(fence2);
        auto dropStartTime1 = systemTime();
        bufferData.acquireFence = fence2;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture2 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfoInv;
        ftInfoInv.vsyncId = FrameTimelineInfo::INVALID_VSYNC_ID;
        ftInfoInv.inputEventId = 0;
        layer->setBuffer(externalTexture2, bufferData, 10, 20, false, std::nullopt, ftInfoInv);
        auto dropEndTime1 = systemTime();
        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto droppedSurfaceFrame2 = layer->mDrawingState.bufferSurfaceFrameTX;

        sp<Fence> fence3(sp<Fence>::make());
        auto acquireFence3 = fenceFactory.createFenceTimeForTest(fence3);
        auto dropStartTime2 = systemTime();
        bufferData.acquireFence = fence3;
        bufferData.frameNumber = 1;
        bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
        bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
        std::shared_ptr<renderengine::ExternalTexture> externalTexture3 = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
        FrameTimelineInfo ftInfo2;
        ftInfo2.vsyncId = 2;
        ftInfo2.inputEventId = 0;
        layer->setBuffer(externalTexture3, bufferData, 10, 20, false, std::nullopt, ftInfo2);
        auto dropEndTime2 = systemTime();
        acquireFence3->signalForTest(12);

        EXPECT_EQ(0u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
        ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
        const auto presentedSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;

        commitTransaction(layer.get());
        layer->updateTexImage(15);

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
        sp<Layer> layer = createLayer();
        uint32_t surfaceFramesPendingClassification = 0;
        std::vector<std::shared_ptr<frametimeline::SurfaceFrame>> bufferlessSurfaceFrames;
        for (int i = 0; i < 10; i += 2) {
            sp<Fence> fence(sp<Fence>::make());
            BufferData bufferData;
            bufferData.acquireFence = fence;
            bufferData.frameNumber = 1;
            bufferData.flags |= BufferData::BufferDataChange::fenceChanged;
            bufferData.flags |= BufferData::BufferDataChange::frameNumberChanged;
            std::shared_ptr<renderengine::ExternalTexture> externalTexture = std::make_shared<
                    renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                             1ULL /* bufferId */,
                                                             HAL_PIXEL_FORMAT_RGBA_8888,
                                                             0ULL /*usage*/);
            FrameTimelineInfo ftInfo;
            ftInfo.vsyncId = 1;
            ftInfo.inputEventId = 0;
            layer->setBuffer(externalTexture, bufferData, 10, 20, false, std::nullopt, ftInfo);
            FrameTimelineInfo ftInfo2;
            ftInfo2.vsyncId = 2;
            ftInfo2.inputEventId = 0;
            layer->setFrameTimelineVsyncForBufferlessTransaction(ftInfo2, 10);
            ASSERT_NE(nullptr, layer->mDrawingState.bufferSurfaceFrameTX);
            EXPECT_EQ(1u, layer->mDrawingState.bufferlessSurfaceFramesTX.size());
            auto& bufferlessSurfaceFrame =
                    layer->mDrawingState.bufferlessSurfaceFramesTX.at(/*vsyncId*/ 2);
            bufferlessSurfaceFrames.push_back(bufferlessSurfaceFrame);

            commitTransaction(layer.get());
            surfaceFramesPendingClassification += 2;
            EXPECT_EQ(surfaceFramesPendingClassification,
                      layer->mPendingJankClassifications.size());
        }

        auto presentedBufferSurfaceFrame = layer->mDrawingState.bufferSurfaceFrameTX;
        layer->updateTexImage(15);
        // BufferlessSurfaceFrames are immediately set to presented and added to the DisplayFrame.
        // Since we don't have access to DisplayFrame here, trigger an onPresent directly.
        for (auto& surfaceFrame : bufferlessSurfaceFrames) {
            surfaceFrame->onPresent(20, JankType::None, 90_Hz,
                                    /*displayDeadlineDelta*/ 0, /*displayPresentDelta*/ 0);
        }
        presentedBufferSurfaceFrame->onPresent(20, JankType::None, 90_Hz,
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
