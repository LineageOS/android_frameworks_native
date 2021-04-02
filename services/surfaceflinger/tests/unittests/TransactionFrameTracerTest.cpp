/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include <renderengine/mock/RenderEngine.h>
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

class TransactionFrameTracerTest : public testing::Test {
public:
    TransactionFrameTracerTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        setupScheduler();
        setupComposer(0);
    }

    ~TransactionFrameTracerTest() {
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
    renderengine::mock::RenderEngine mRenderEngine;
    FenceToFenceTimeMap fenceFactory;
    client_cache_t mClientCache;

    void BLASTTransactionSendsFrameTracerEvents() {
        sp<BufferStateLayer> layer = createBufferStateLayer();

        sp<Fence> fence(new Fence());
        const auto buffer = std::make_shared<
                renderengine::ExternalTexture>(new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888,
                                                                 1, 0),
                                               mRenderEngine, false);
        int32_t layerId = layer->getSequence();
        uint64_t bufferId = buffer->getBuffer()->getId();
        uint64_t frameNumber = 5;
        nsecs_t dequeueTime = 10;
        nsecs_t postTime = 20;
        EXPECT_CALL(*mFlinger.getFrameTracer(), traceNewLayer(layerId, "buffer-state-layer"));
        EXPECT_CALL(*mFlinger.getFrameTracer(),
                    traceTimestamp(layerId, bufferId, frameNumber, dequeueTime,
                                   FrameTracer::FrameEvent::DEQUEUE, /*duration*/ 0));
        EXPECT_CALL(*mFlinger.getFrameTracer(),
                    traceTimestamp(layerId, bufferId, frameNumber, postTime,
                                   FrameTracer::FrameEvent::QUEUE, /*duration*/ 0));
        layer->setBuffer(buffer, fence, postTime, /*desiredPresentTime*/ 30, false, mClientCache,
                         frameNumber, dequeueTime, FrameTimelineInfo{},
                         nullptr /* releaseBufferCallback */);

        commitTransaction(layer.get());
        bool computeVisisbleRegions;
        nsecs_t latchTime = 25;
        EXPECT_CALL(*mFlinger.getFrameTracer(),
                    traceFence(layerId, bufferId, frameNumber, _,
                               FrameTracer::FrameEvent::ACQUIRE_FENCE, /*startTime*/ 0));
        EXPECT_CALL(*mFlinger.getFrameTracer(),
                    traceTimestamp(layerId, bufferId, frameNumber, latchTime,
                                   FrameTracer::FrameEvent::LATCH, /*duration*/ 0));
        layer->updateTexImage(computeVisisbleRegions, latchTime, /*expectedPresentTime*/ 0);

        auto glDoneFence = fenceFactory.createFenceTimeForTest(fence);
        auto presentFence = fenceFactory.createFenceTimeForTest(fence);
        CompositorTiming compositorTiming;
        EXPECT_CALL(*mFlinger.getFrameTracer(),
                    traceFence(layerId, bufferId, frameNumber, presentFence,
                               FrameTracer::FrameEvent::PRESENT_FENCE, /*startTime*/ 0));
        layer->onPostComposition(nullptr, glDoneFence, presentFence, compositorTiming);
    }
};

TEST_F(TransactionFrameTracerTest, BLASTTransactionSendsFrameTracerEvents) {
    BLASTTransactionSendsFrameTracerEvents();
}

} // namespace android