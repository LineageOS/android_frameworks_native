/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include "DummyConsumer.h"

#include <gtest/gtest.h>

#include <binder/IMemory.h>
#include <binder/ProcessState.h>
#include <gui/IDisplayEventConnection.h>
#include <gui/ISurfaceComposer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/BufferItemConsumer.h>
#include <private/gui/ComposerService.h>
#include <ui/Rect.h>
#include <utils/String8.h>

#include <limits>
#include <thread>

namespace android {

using namespace std::chrono_literals;

class FakeSurfaceComposer;
class FakeProducerFrameEventHistory;

static constexpr uint64_t NO_FRAME_INDEX = std::numeric_limits<uint64_t>::max();

class SurfaceTest : public ::testing::Test {
protected:

    SurfaceTest() {
        ProcessState::self()->startThreadPool();
    }

    virtual void SetUp() {
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

        mSurfaceControl = mComposerClient->createSurface(
                String8("Test Surface"), 32, 32, PIXEL_FORMAT_RGBA_8888, 0);

        ASSERT_TRUE(mSurfaceControl != NULL);
        ASSERT_TRUE(mSurfaceControl->isValid());

        SurfaceComposerClient::openGlobalTransaction();
        ASSERT_EQ(NO_ERROR, mSurfaceControl->setLayer(0x7fffffff));
        ASSERT_EQ(NO_ERROR, mSurfaceControl->show());
        SurfaceComposerClient::closeGlobalTransaction();

        mSurface = mSurfaceControl->getSurface();
        ASSERT_TRUE(mSurface != NULL);
    }

    virtual void TearDown() {
        mComposerClient->dispose();
    }

    sp<Surface> mSurface;
    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mSurfaceControl;
};

TEST_F(SurfaceTest, QueuesToWindowComposerIsTrueWhenVisible) {
    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER,
            &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(1, result);
}

TEST_F(SurfaceTest, QueuesToWindowComposerIsTrueWhenPurgatorized) {
    mSurfaceControl.clear();
    // Wait for the async clean-up to complete.
    std::this_thread::sleep_for(50ms);

    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER,
            &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(1, result);
}

// This test probably doesn't belong here.
TEST_F(SurfaceTest, ScreenshotsOfProtectedBuffersSucceed) {
    sp<ANativeWindow> anw(mSurface);

    // Verify the screenshot works with no protected buffers.
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    sp<CpuConsumer> cpuConsumer = new CpuConsumer(consumer, 1);
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    sp<IBinder> display(sf->getBuiltInDisplay(
            ISurfaceComposer::eDisplayIdMain));
    ASSERT_EQ(NO_ERROR, sf->captureScreen(display, producer, Rect(),
            64, 64, 0, 0x7fffffff, false));

    ASSERT_EQ(NO_ERROR, native_window_api_connect(anw.get(),
            NATIVE_WINDOW_API_CPU));
    // Set the PROTECTED usage bit and verify that the screenshot fails.  Note
    // that we need to dequeue a buffer in order for it to actually get
    // allocated in SurfaceFlinger.
    ASSERT_EQ(NO_ERROR, native_window_set_usage(anw.get(),
            GRALLOC_USAGE_PROTECTED));
    ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(anw.get(), 3));
    ANativeWindowBuffer* buf = 0;

    status_t err = native_window_dequeue_buffer_and_wait(anw.get(), &buf);
    if (err) {
        // we could fail if GRALLOC_USAGE_PROTECTED is not supported.
        // that's okay as long as this is the reason for the failure.
        // try again without the GRALLOC_USAGE_PROTECTED bit.
        ASSERT_EQ(NO_ERROR, native_window_set_usage(anw.get(), 0));
        ASSERT_EQ(NO_ERROR, native_window_dequeue_buffer_and_wait(anw.get(),
                &buf));
        return;
    }
    ASSERT_EQ(NO_ERROR, anw->cancelBuffer(anw.get(), buf, -1));

    for (int i = 0; i < 4; i++) {
        // Loop to make sure SurfaceFlinger has retired a protected buffer.
        ASSERT_EQ(NO_ERROR, native_window_dequeue_buffer_and_wait(anw.get(),
                &buf));
        ASSERT_EQ(NO_ERROR, anw->queueBuffer(anw.get(), buf, -1));
    }
    ASSERT_EQ(NO_ERROR, sf->captureScreen(display, producer, Rect(),
            64, 64, 0, 0x7fffffff, false));
}

TEST_F(SurfaceTest, ConcreteTypeIsSurface) {
    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_CONCRETE_TYPE, &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(NATIVE_WINDOW_SURFACE, result);
}

TEST_F(SurfaceTest, LayerCountIsOne) {
    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_LAYER_COUNT, &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(1, result);
}

TEST_F(SurfaceTest, QueryConsumerUsage) {
    const int TEST_USAGE_FLAGS =
            GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER;
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    sp<BufferItemConsumer> c = new BufferItemConsumer(consumer,
            TEST_USAGE_FLAGS);
    sp<Surface> s = new Surface(producer);

    sp<ANativeWindow> anw(s);

    int flags = -1;
    int err = anw->query(anw.get(), NATIVE_WINDOW_CONSUMER_USAGE_BITS, &flags);

    ASSERT_EQ(NO_ERROR, err);
    ASSERT_EQ(TEST_USAGE_FLAGS, flags);
}

TEST_F(SurfaceTest, QueryDefaultBuffersDataSpace) {
    const android_dataspace TEST_DATASPACE = HAL_DATASPACE_SRGB;
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    sp<CpuConsumer> cpuConsumer = new CpuConsumer(consumer, 1);

    cpuConsumer->setDefaultBufferDataSpace(TEST_DATASPACE);

    sp<Surface> s = new Surface(producer);

    sp<ANativeWindow> anw(s);

    android_dataspace dataSpace;

    int err = anw->query(anw.get(), NATIVE_WINDOW_DEFAULT_DATASPACE,
            reinterpret_cast<int*>(&dataSpace));

    ASSERT_EQ(NO_ERROR, err);
    ASSERT_EQ(TEST_DATASPACE, dataSpace);
}

TEST_F(SurfaceTest, SettingGenerationNumber) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    sp<CpuConsumer> cpuConsumer = new CpuConsumer(consumer, 1);
    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);

    // Allocate a buffer with a generation number of 0
    ANativeWindowBuffer* buffer;
    int fenceFd;
    ASSERT_EQ(NO_ERROR, native_window_api_connect(window.get(),
            NATIVE_WINDOW_API_CPU));
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fenceFd));
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fenceFd));

    // Detach the buffer and check its generation number
    sp<GraphicBuffer> graphicBuffer;
    sp<Fence> fence;
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&graphicBuffer, &fence));
    ASSERT_EQ(0U, graphicBuffer->getGenerationNumber());

    ASSERT_EQ(NO_ERROR, surface->setGenerationNumber(1));
    buffer = static_cast<ANativeWindowBuffer*>(graphicBuffer.get());

    // This should change the generation number of the GraphicBuffer
    ASSERT_EQ(NO_ERROR, surface->attachBuffer(buffer));

    // Check that the new generation number sticks with the buffer
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, -1));
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fenceFd));
    graphicBuffer = static_cast<GraphicBuffer*>(buffer);
    ASSERT_EQ(1U, graphicBuffer->getGenerationNumber());
}

TEST_F(SurfaceTest, GetConsumerName) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<DummyConsumer> dummyConsumer(new DummyConsumer);
    consumer->consumerConnect(dummyConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU);

    EXPECT_STREQ("TestConsumer", surface->getConsumerName().string());
}

TEST_F(SurfaceTest, DynamicSetBufferCount) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<DummyConsumer> dummyConsumer(new DummyConsumer);
    consumer->consumerConnect(dummyConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);

    ASSERT_EQ(NO_ERROR, native_window_api_connect(window.get(),
            NATIVE_WINDOW_API_CPU));
    native_window_set_buffer_count(window.get(), 4);

    int fence;
    ANativeWindowBuffer* buffer;
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    native_window_set_buffer_count(window.get(), 3);
    ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, fence));
    native_window_set_buffer_count(window.get(), 2);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, fence));
}


class FakeConsumer : public BnConsumerListener {
public:
    void onFrameAvailable(const BufferItem& /*item*/) override {}
    void onBuffersReleased() override {}
    void onSidebandStreamChanged() override {}

    void addAndGetFrameTimestamps(
            const NewFrameEventsEntry* newTimestamps,
            FrameEventHistoryDelta* outDelta) override {
        if (newTimestamps) {
            if (mGetFrameTimestampsEnabled) {
                EXPECT_GT(mNewFrameEntryOverride.frameNumber, 0u) <<
                        "Test should set mNewFrameEntryOverride before queuing "
                        "a frame.";
                EXPECT_EQ(newTimestamps->frameNumber,
                        mNewFrameEntryOverride.frameNumber) <<
                        "Test attempting to add NewFrameEntryOverride with "
                        "incorrect frame number.";
                mFrameEventHistory.addQueue(mNewFrameEntryOverride);
                mNewFrameEntryOverride.frameNumber = 0;
            }
            mAddFrameTimestampsCount++;
            mLastAddedFrameNumber = newTimestamps->frameNumber;
        }
        if (outDelta) {
            mFrameEventHistory.getAndResetDelta(outDelta);
            mGetFrameTimestampsCount++;
        }
        mAddAndGetFrameTimestampsCallCount++;
    }

    bool mGetFrameTimestampsEnabled = false;

    ConsumerFrameEventHistory mFrameEventHistory;
    int mAddAndGetFrameTimestampsCallCount = 0;
    int mAddFrameTimestampsCount = 0;
    int mGetFrameTimestampsCount = 0;
    uint64_t mLastAddedFrameNumber = NO_FRAME_INDEX;

    NewFrameEventsEntry mNewFrameEntryOverride = { 0, 0, 0, nullptr };
};


class FakeSurfaceComposer : public ISurfaceComposer{
public:
    ~FakeSurfaceComposer() override {}

    void setSupportedTimestamps(bool supportsPresent, bool supportsRetire) {
        mSupportsPresent = supportsPresent;
        mSupportsRetire = supportsRetire;
    }

    sp<ISurfaceComposerClient> createConnection() override { return nullptr; }
    sp<IGraphicBufferAlloc> createGraphicBufferAlloc() override {
        return nullptr;
    }
    sp<IDisplayEventConnection> createDisplayEventConnection() override {
        return nullptr;
    }
    sp<IBinder> createDisplay(const String8& /*displayName*/,
            bool /*secure*/) override { return nullptr; }
    void destroyDisplay(const sp<IBinder>& /*display */) override {}
    sp<IBinder> getBuiltInDisplay(int32_t /*id*/) override { return nullptr; }
    void setTransactionState(const Vector<ComposerState>& /*state*/,
            const Vector<DisplayState>& /*displays*/, uint32_t /*flags*/)
            override {}
    void bootFinished() override {}
    bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& /*surface*/) const override {
        return false;
    }

    status_t getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported)
            const override {
        *outSupported = {
                FrameEvent::REQUESTED_PRESENT,
                FrameEvent::ACQUIRE,
                FrameEvent::FIRST_REFRESH_START,
                FrameEvent::GL_COMPOSITION_DONE,
                FrameEvent::RELEASE
        };
        if (mSupportsPresent) {
            outSupported->push_back(
                        FrameEvent::DISPLAY_PRESENT);
        }
        if (mSupportsRetire) {
            outSupported->push_back(
                        FrameEvent::DISPLAY_RETIRE);
        }
        return NO_ERROR;
    }

    void setPowerMode(const sp<IBinder>& /*display*/, int /*mode*/) override {}
    status_t getDisplayConfigs(const sp<IBinder>& /*display*/,
            Vector<DisplayInfo>* /*configs*/) override { return NO_ERROR; }
    status_t getDisplayStats(const sp<IBinder>& /*display*/,
            DisplayStatInfo* /*stats*/) override { return NO_ERROR; }
    int getActiveConfig(const sp<IBinder>& /*display*/) override { return 0; }
    status_t setActiveConfig(const sp<IBinder>& /*display*/, int /*id*/)
            override {
        return NO_ERROR;
    }
    status_t getDisplayColorModes(const sp<IBinder>& /*display*/,
            Vector<android_color_mode_t>* /*outColorModes*/) override {
        return NO_ERROR;
    }
    android_color_mode_t getActiveColorMode(const sp<IBinder>& /*display*/)
            override {
        return HAL_COLOR_MODE_NATIVE;
    }
    status_t setActiveColorMode(const sp<IBinder>& /*display*/,
            android_color_mode_t /*colorMode*/) override { return NO_ERROR; }
    status_t captureScreen(const sp<IBinder>& /*display*/,
            const sp<IGraphicBufferProducer>& /*producer*/,
            Rect /*sourceCrop*/, uint32_t /*reqWidth*/, uint32_t /*reqHeight*/,
            uint32_t /*minLayerZ*/, uint32_t /*maxLayerZ*/,
            bool /*useIdentityTransform*/,
            Rotation /*rotation*/) override { return NO_ERROR; }
    status_t clearAnimationFrameStats() override { return NO_ERROR; }
    status_t getAnimationFrameStats(FrameStats* /*outStats*/) const override {
        return NO_ERROR;
    }
    status_t getHdrCapabilities(const sp<IBinder>& /*display*/,
            HdrCapabilities* /*outCapabilities*/) const override {
        return NO_ERROR;
    }
    status_t enableVSyncInjections(bool /*enable*/) override {
        return NO_ERROR;
    }
    status_t injectVSync(nsecs_t /*when*/) override { return NO_ERROR; }

protected:
    IBinder* onAsBinder() override { return nullptr; }

private:
    bool mSupportsPresent{true};
    bool mSupportsRetire{true};
};

class FakeProducerFrameEventHistory : public ProducerFrameEventHistory {
public:
    FakeProducerFrameEventHistory(FenceToFenceTimeMap* fenceMap)
        : mFenceMap(fenceMap) {}

    ~FakeProducerFrameEventHistory() {}

    void updateAcquireFence(uint64_t frameNumber,
            std::shared_ptr<FenceTime>&& acquire) override {
        // Verify the acquire fence being added isn't the one from the consumer.
        EXPECT_NE(mConsumerAcquireFence, acquire);
        // Override the fence, so we can verify this was called by the
        // producer after the frame is queued.
        ProducerFrameEventHistory::updateAcquireFence(frameNumber,
                std::shared_ptr<FenceTime>(mAcquireFenceOverride));
    }

    void setAcquireFenceOverride(
            const std::shared_ptr<FenceTime>& acquireFenceOverride,
            const std::shared_ptr<FenceTime>& consumerAcquireFence) {
        mAcquireFenceOverride = acquireFenceOverride;
        mConsumerAcquireFence = consumerAcquireFence;
    }

protected:
    std::shared_ptr<FenceTime> createFenceTime(const sp<Fence>& fence)
            const override {
        return mFenceMap->createFenceTimeForTest(fence);
    }

    FenceToFenceTimeMap* mFenceMap{nullptr};

    std::shared_ptr<FenceTime> mAcquireFenceOverride{FenceTime::NO_FENCE};
    std::shared_ptr<FenceTime> mConsumerAcquireFence{FenceTime::NO_FENCE};
};


class TestSurface : public Surface {
public:
    TestSurface(const sp<IGraphicBufferProducer>& bufferProducer,
            FenceToFenceTimeMap* fenceMap)
        : Surface(bufferProducer),
          mFakeSurfaceComposer(new FakeSurfaceComposer) {
        mFakeFrameEventHistory = new FakeProducerFrameEventHistory(fenceMap);
        mFrameEventHistory.reset(mFakeFrameEventHistory);
    }

    ~TestSurface() override {}

    sp<ISurfaceComposer> composerService() const override {
        return mFakeSurfaceComposer;
    }

public:
    sp<FakeSurfaceComposer> mFakeSurfaceComposer;

    // mFrameEventHistory owns the instance of FakeProducerFrameEventHistory,
    // but this raw pointer gives access to test functionality.
    FakeProducerFrameEventHistory* mFakeFrameEventHistory;
};


class GetFrameTimestampsTest : public SurfaceTest {
protected:
    struct FenceAndFenceTime {
        explicit FenceAndFenceTime(FenceToFenceTimeMap& fenceMap)
           : mFence(new Fence),
             mFenceTime(fenceMap.createFenceTimeForTest(mFence)) {}
        sp<Fence> mFence { nullptr };
        std::shared_ptr<FenceTime> mFenceTime { nullptr };
    };

    struct RefreshEvents {
        RefreshEvents(FenceToFenceTimeMap& fenceMap, nsecs_t refreshStart)
            : mFenceMap(fenceMap),
              kStartTime(refreshStart + 1),
              kGpuCompositionDoneTime(refreshStart + 2),
              kPresentTime(refreshStart + 3) {}

        void signalPostCompositeFences() {
            mFenceMap.signalAllForTest(
                        mGpuCompositionDone.mFence, kGpuCompositionDoneTime);
            mFenceMap.signalAllForTest(mPresent.mFence, kPresentTime);
        }

        FenceToFenceTimeMap& mFenceMap;

        FenceAndFenceTime mGpuCompositionDone { mFenceMap };
        FenceAndFenceTime mPresent { mFenceMap };

        const nsecs_t kStartTime;
        const nsecs_t kGpuCompositionDoneTime;
        const nsecs_t kPresentTime;
    };

    struct FrameEvents {
        FrameEvents(FenceToFenceTimeMap& fenceMap, nsecs_t frameStartTime)
            : mFenceMap(fenceMap),
              kPostedTime(frameStartTime + 100),
              kRequestedPresentTime(frameStartTime + 200),
              kProducerAcquireTime(frameStartTime + 300),
              kConsumerAcquireTime(frameStartTime + 301),
              kLatchTime(frameStartTime + 500),
              kDequeueReadyTime(frameStartTime + 600),
              kRetireTime(frameStartTime + 700),
              kReleaseTime(frameStartTime + 800),
              mRefreshes {
                    { mFenceMap, frameStartTime + 410 },
                    { mFenceMap, frameStartTime + 420 },
                    { mFenceMap, frameStartTime + 430 } } {}

        void signalQueueFences() {
            mFenceMap.signalAllForTest(
                        mAcquireConsumer.mFence, kConsumerAcquireTime);
            mFenceMap.signalAllForTest(
                        mAcquireProducer.mFence, kProducerAcquireTime);
        }

        void signalRefreshFences() {
            for (auto& re : mRefreshes) {
                re.signalPostCompositeFences();
            }
        }

        void signalReleaseFences() {
            mFenceMap.signalAllForTest(mRetire.mFence, kRetireTime);
            mFenceMap.signalAllForTest(mRelease.mFence, kReleaseTime);
        }

        FenceToFenceTimeMap& mFenceMap;

        FenceAndFenceTime mAcquireConsumer { mFenceMap };
        FenceAndFenceTime mAcquireProducer { mFenceMap };
        FenceAndFenceTime mRetire { mFenceMap };
        FenceAndFenceTime mRelease { mFenceMap };

        const nsecs_t kPostedTime;
        const nsecs_t kRequestedPresentTime;
        const nsecs_t kProducerAcquireTime;
        const nsecs_t kConsumerAcquireTime;
        const nsecs_t kLatchTime;
        const nsecs_t kDequeueReadyTime;
        const nsecs_t kRetireTime;
        const nsecs_t kReleaseTime;

        RefreshEvents mRefreshes[3];
    };

    GetFrameTimestampsTest() : SurfaceTest() {}

    virtual void SetUp() {
        SurfaceTest::SetUp();

        BufferQueue::createBufferQueue(&mProducer, &mConsumer);
        mFakeConsumer = new FakeConsumer;
        mCfeh = &mFakeConsumer->mFrameEventHistory;
        mConsumer->consumerConnect(mFakeConsumer, false);
        mConsumer->setConsumerName(String8("TestConsumer"));
        mSurface = new TestSurface(mProducer, &mFenceMap);
        mWindow = mSurface;

        ASSERT_EQ(NO_ERROR, native_window_api_connect(mWindow.get(),
                NATIVE_WINDOW_API_CPU));
        native_window_set_buffer_count(mWindow.get(), 4);
    }

    void enableFrameTimestamps() {
        mFakeConsumer->mGetFrameTimestampsEnabled = true;
        native_window_enable_frame_timestamps(mWindow.get(), 1);
        mFrameTimestampsEnabled = true;
    }

    void resetTimestamps() {
        outRequestedPresentTime = -1;
        outAcquireTime = -1;
        outRefreshStartTime = -1;
        outGpuCompositionDoneTime = -1;
        outDisplayPresentTime = -1;
        outDisplayRetireTime = -1;
        outReleaseTime = -1;
    }

    void dequeueAndQueue(uint64_t frameIndex) {
        int fence = -1;
        ANativeWindowBuffer* buffer = nullptr;
        ASSERT_EQ(NO_ERROR,
                mWindow->dequeueBuffer(mWindow.get(), &buffer, &fence));

        int oldAddFrameTimestampsCount =
                mFakeConsumer->mAddFrameTimestampsCount;

        FrameEvents* frame = &mFrames[frameIndex];
        uint64_t frameNumber = frameIndex + 1;

        NewFrameEventsEntry fe;
        fe.frameNumber = frameNumber;
        fe.postedTime = frame->kPostedTime;
        fe.requestedPresentTime = frame->kRequestedPresentTime;
        fe.acquireFence = frame->mAcquireConsumer.mFenceTime;
        mFakeConsumer->mNewFrameEntryOverride = fe;

        mSurface->mFakeFrameEventHistory->setAcquireFenceOverride(
                    frame->mAcquireProducer.mFenceTime,
                    frame->mAcquireConsumer.mFenceTime);

        ASSERT_EQ(NO_ERROR, mWindow->queueBuffer(mWindow.get(), buffer, fence));

        EXPECT_EQ(frameNumber, mFakeConsumer->mLastAddedFrameNumber);

        EXPECT_EQ(
                oldAddFrameTimestampsCount + (mFrameTimestampsEnabled ? 1 : 0),
                mFakeConsumer->mAddFrameTimestampsCount);
    }

    void addFrameEvents(
            bool gpuComposited, uint64_t iOldFrame, int64_t iNewFrame) {
        FrameEvents* oldFrame =
                (iOldFrame == NO_FRAME_INDEX) ? nullptr : &mFrames[iOldFrame];
        FrameEvents* newFrame = &mFrames[iNewFrame];

        uint64_t nOldFrame = iOldFrame + 1;
        uint64_t nNewFrame = iNewFrame + 1;

        // Latch, Composite, Retire, and Release the frames in a plausible
        // order. Note: The timestamps won't necessarily match the order, but
        // that's okay for the purposes of this test.
        std::shared_ptr<FenceTime> gpuDoneFenceTime = FenceTime::NO_FENCE;

        mCfeh->addLatch(nNewFrame, newFrame->kLatchTime);

        mCfeh->addPreComposition(nNewFrame, newFrame->mRefreshes[0].kStartTime);
        gpuDoneFenceTime = gpuComposited ?
                newFrame->mRefreshes[0].mGpuCompositionDone.mFenceTime :
                FenceTime::NO_FENCE;
        // HWC2 releases the previous buffer after a new latch just before
        // calling postComposition.
        if (oldFrame != nullptr) {
            mCfeh->addRelease(nOldFrame, oldFrame->kDequeueReadyTime,
                    std::shared_ptr<FenceTime>(oldFrame->mRelease.mFenceTime));
        }
        mCfeh->addPostComposition(nNewFrame, gpuDoneFenceTime,
                newFrame->mRefreshes[0].mPresent.mFenceTime);

        // Retire the previous buffer just after compositing the new buffer.
        if (oldFrame != nullptr) {
            mCfeh->addRetire(nOldFrame, oldFrame->mRetire.mFenceTime);
        }

        mCfeh->addPreComposition(nNewFrame, newFrame->mRefreshes[1].kStartTime);
        gpuDoneFenceTime = gpuComposited ?
                newFrame->mRefreshes[1].mGpuCompositionDone.mFenceTime :
                FenceTime::NO_FENCE;
        mCfeh->addPostComposition(nNewFrame, gpuDoneFenceTime,
                newFrame->mRefreshes[1].mPresent.mFenceTime);
        mCfeh->addPreComposition(nNewFrame, newFrame->mRefreshes[2].kStartTime);
        gpuDoneFenceTime = gpuComposited ?
                newFrame->mRefreshes[2].mGpuCompositionDone.mFenceTime :
                FenceTime::NO_FENCE;
        mCfeh->addPostComposition(nNewFrame, gpuDoneFenceTime,
                newFrame->mRefreshes[2].mPresent.mFenceTime);
    }

    void QueryPresentRetireSupported(
            bool displayPresentSupported, bool displayRetireSupported);
    void PresentOrRetireUnsupportedNoSyncTest(
            bool displayPresentSupported, bool displayRetireSupported);

    sp<IGraphicBufferProducer> mProducer;
    sp<IGraphicBufferConsumer> mConsumer;
    sp<FakeConsumer> mFakeConsumer;
    ConsumerFrameEventHistory* mCfeh;
    sp<TestSurface> mSurface;
    sp<ANativeWindow> mWindow;

    FenceToFenceTimeMap mFenceMap;

    bool mFrameTimestampsEnabled = false;

    int64_t outRequestedPresentTime = -1;
    int64_t outAcquireTime = -1;
    int64_t outRefreshStartTime = -1;
    int64_t outGpuCompositionDoneTime = -1;
    int64_t outDisplayPresentTime = -1;
    int64_t outDisplayRetireTime = -1;
    int64_t outReleaseTime = -1;

    FrameEvents mFrames[2] { { mFenceMap, 1000 }, { mFenceMap, 2000 } };
};


// This test verifies that the frame timestamps are not retrieved when not
// explicitly enabled via native_window_enable_frame_timestamps.
// We want to check this to make sure there's no overhead for users
// that don't need the timestamp information.
TEST_F(GetFrameTimestampsTest, DefaultDisabled) {
    int fence;
    ANativeWindowBuffer* buffer;

    EXPECT_EQ(0, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(0, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify the producer doesn't get frame timestamps piggybacked on dequeue.
    ASSERT_EQ(NO_ERROR, mWindow->dequeueBuffer(mWindow.get(), &buffer, &fence));
    EXPECT_EQ(0, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(0, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify the producer doesn't get frame timestamps piggybacked on queue.
    // It is okay that frame timestamps are added in the consumer since it is
    // still needed for SurfaceFlinger dumps.
    ASSERT_EQ(NO_ERROR, mWindow->queueBuffer(mWindow.get(), buffer, fence));
    EXPECT_EQ(1, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(0, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify attempts to get frame timestamps fail.
    const uint32_t framesAgo = 0;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(INVALID_OPERATION, result);
    EXPECT_EQ(0, mFakeConsumer->mGetFrameTimestampsCount);
}

// This test verifies that the frame timestamps are retrieved if explicitly
// enabled via native_window_enable_frame_timestamps.
TEST_F(GetFrameTimestampsTest, EnabledSimple) {
    enableFrameTimestamps();

    int fence;
    ANativeWindowBuffer* buffer;

    EXPECT_EQ(0, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(0, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify getFrameTimestamps is piggybacked on dequeue.
    ASSERT_EQ(NO_ERROR, mWindow->dequeueBuffer(mWindow.get(), &buffer, &fence));
    EXPECT_EQ(0, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(1, mFakeConsumer->mGetFrameTimestampsCount);

    NewFrameEventsEntry f1;
    f1.frameNumber = 1;
    f1.postedTime = mFrames[0].kPostedTime;
    f1.requestedPresentTime = mFrames[0].kRequestedPresentTime;
    f1.acquireFence = mFrames[0].mAcquireConsumer.mFenceTime;
    mSurface->mFakeFrameEventHistory->setAcquireFenceOverride(
            mFrames[0].mAcquireProducer.mFenceTime,
            mFrames[0].mAcquireConsumer.mFenceTime);
    mFakeConsumer->mNewFrameEntryOverride = f1;
    mFrames[0].signalQueueFences();

    // Verify getFrameTimestamps is piggybacked on queue.
    ASSERT_EQ(NO_ERROR, mWindow->queueBuffer(mWindow.get(), buffer, fence));
    EXPECT_EQ(1, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(1u, mFakeConsumer->mLastAddedFrameNumber);
    EXPECT_EQ(2, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify queries for timestamps that the producer doesn't know about
    // triggers a call to see if the consumer has any new timestamps.
    const uint32_t framesAgo = 0;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(3, mFakeConsumer->mGetFrameTimestampsCount);
}

void GetFrameTimestampsTest::QueryPresentRetireSupported(
        bool displayPresentSupported, bool displayRetireSupported) {
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(
            displayPresentSupported, displayRetireSupported);

    // Verify supported bits are forwarded.
    int supportsPresent = -1;
    mWindow.get()->query(mWindow.get(),
            NATIVE_WINDOW_FRAME_TIMESTAMPS_SUPPORTS_PRESENT, &supportsPresent);
    EXPECT_EQ(displayPresentSupported, supportsPresent);

    int supportsRetire = -1;
    mWindow.get()->query(mWindow.get(),
            NATIVE_WINDOW_FRAME_TIMESTAMPS_SUPPORTS_RETIRE, &supportsRetire);
    EXPECT_EQ(displayRetireSupported, supportsRetire);
}

TEST_F(GetFrameTimestampsTest, QueryPresentSupported) {
   QueryPresentRetireSupported(true, false);
}

TEST_F(GetFrameTimestampsTest, QueryRetireSupported) {
   QueryPresentRetireSupported(false, true);
}

// This test verifies that:
// 1) The timestamps recorded in the consumer's FrameTimestampsHistory are
//    properly retrieved by the producer for the correct frames.
// 2) When framesAgo is 0, it is querying for the most recently queued frame.
TEST_F(GetFrameTimestampsTest, TimestampsAssociatedWithCorrectFrame) {
    enableFrameTimestamps();

    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(true, NO_FRAME_INDEX, 0);
    mFrames[0].signalRefreshFences();
    addFrameEvents(true, 0, 1);
    mFrames[0].signalReleaseFences();
    mFrames[1].signalRefreshFences();

    // Verify timestamps are correct for frame 1.
    uint32_t framesAgo = 1;
    resetTimestamps();
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kGpuCompositionDoneTime,
            outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kRetireTime, outDisplayRetireTime);
    EXPECT_EQ(mFrames[0].kReleaseTime, outReleaseTime);

    // Verify timestamps are correct for frame 2.
    framesAgo = 0;
    resetTimestamps();
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[1].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kGpuCompositionDoneTime,
            outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(0, outDisplayRetireTime);
    EXPECT_EQ(0, outReleaseTime);
}

// This test verifies the acquire fence recorded by the consumer is not sent
// back to the producer and the producer saves its own fence.
TEST_F(GetFrameTimestampsTest, QueueTimestampsNoSync) {
    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(true, true);

    const uint32_t framesAgo = 0;

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);

    // Verify queue-related timestamps for f1 are available immediately in the
    // producer without asking the consumer again, even before signaling the
    // acquire fence.
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(0, outAcquireTime);

    // Signal acquire fences. Verify a sync call still isn't necessary.
    mFrames[0].signalQueueFences();

    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);

    // Dequeue and queue frame 2.
    dequeueAndQueue(1);

    // Verify queue-related timestamps for f2 are available immediately in the
    // producer without asking the consumer again, even before signaling the
    // acquire fence.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(0, outAcquireTime);

    // Signal acquire fences. Verify a sync call still isn't necessary.
    mFrames[1].signalQueueFences();

    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[1].kProducerAcquireTime, outAcquireTime);
}

TEST_F(GetFrameTimestampsTest, ZeroRequestedTimestampsNoSync) {
    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(true, true);

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    // Dequeue and queue frame 2.
    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(true, NO_FRAME_INDEX, 0);
    mFrames[0].signalRefreshFences();
    addFrameEvents(true, 0, 1);
    mFrames[0].signalReleaseFences();
    mFrames[1].signalRefreshFences();

    // Verify a request for no timestamps doesn't result in a sync call.
    const uint32_t framesAgo = 0;
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
}

// This test verifies that fences can signal and update timestamps producer
// side without an additional sync call to the consumer.
TEST_F(GetFrameTimestampsTest, FencesInProducerNoSync) {
    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(true, true);

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    // Dequeue and queue frame 2.
    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(true, NO_FRAME_INDEX, 0);
    addFrameEvents(true, 0, 1);

    // Verify available timestamps are correct for frame 1, before any
    // fence has been signaled.
    // Note: A sync call is necessary here since the events triggered by
    // addFrameEvents didn't get to piggyback on the earlier queues/dequeues.
    uint32_t framesAgo = 1;
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount + 1, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(0, outGpuCompositionDoneTime);
    EXPECT_EQ(0, outDisplayPresentTime);
    EXPECT_EQ(0, outDisplayRetireTime);
    EXPECT_EQ(0, outReleaseTime);

    // Verify available timestamps are correct for frame 1 again, before any
    // fence has been signaled.
    // This time a sync call should not be necessary.
    framesAgo = 1;
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(0, outGpuCompositionDoneTime);
    EXPECT_EQ(0, outDisplayPresentTime);
    EXPECT_EQ(0, outDisplayRetireTime);
    EXPECT_EQ(0, outReleaseTime);

    // Signal the fences for frame 1.
    mFrames[0].signalRefreshFences();
    mFrames[0].signalReleaseFences();

    // Verify all timestamps are available without a sync call.
    framesAgo = 1;
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kGpuCompositionDoneTime,
            outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kRetireTime, outDisplayRetireTime);
    EXPECT_EQ(mFrames[0].kReleaseTime, outReleaseTime);
}

// This test verifies that if the frame wasn't GPU composited but has a refresh
// event a sync call isn't made to get the GPU composite done time since it will
// never exist.
TEST_F(GetFrameTimestampsTest, NoGpuNoSync) {
    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(true, true);

    const uint32_t framesAgo = 1;

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    // Dequeue and queue frame 2.
    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(false, NO_FRAME_INDEX, 0);
    addFrameEvents(false, 0, 1);

    // Verify available timestamps are correct for frame 1, before any
    // fence has been signaled.
    // Note: A sync call is necessary here since the events triggered by
    // addFrameEvents didn't get to piggyback on the earlier queues/dequeues.
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount + 1, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(0, outGpuCompositionDoneTime);
    EXPECT_EQ(0, outDisplayPresentTime);
    EXPECT_EQ(0, outDisplayRetireTime);
    EXPECT_EQ(0, outReleaseTime);

    // Signal the fences for frame 1.
    mFrames[0].signalRefreshFences();
    mFrames[0].signalReleaseFences();

    // Verify all timestamps, except GPU composition, are available without a
    // sync call.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(0, outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kRetireTime, outDisplayRetireTime);
    EXPECT_EQ(mFrames[0].kReleaseTime, outReleaseTime);
}

// This test verifies that if the retire/release info can't possibly exist,
// a sync call is not done.
TEST_F(GetFrameTimestampsTest, NoRetireOrReleaseNoSync) {
    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(true, true);

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    // Dequeue and queue frame 2.
    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(false, NO_FRAME_INDEX, 0);
    addFrameEvents(false, 0, 1);

    // Verify available timestamps are correct for frame 1, before any
    // fence has been signaled.
    // Note: A sync call is necessary here since the events triggered by
    // addFrameEvents didn't get to piggyback on the earlier queues/dequeues.
    uint32_t framesAgo = 1;
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount + 1, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(0, outGpuCompositionDoneTime);
    EXPECT_EQ(0, outDisplayPresentTime);
    EXPECT_EQ(0, outDisplayRetireTime);
    EXPECT_EQ(0, outReleaseTime);

    mFrames[0].signalRefreshFences();
    mFrames[0].signalReleaseFences();
    mFrames[1].signalRefreshFences();

    // Verify querying for all timestmaps of f2 does not do a sync call.
    // Even though the retire and release times aren't available, a sync call
    // should not occur because it's not possible for it to be retired or
    // released until another frame is queued.
    framesAgo = 0;
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            &outRequestedPresentTime, &outAcquireTime, &outRefreshStartTime,
            &outGpuCompositionDoneTime, &outDisplayPresentTime,
            &outDisplayRetireTime, &outReleaseTime);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[1].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kStartTime, outRefreshStartTime);
    EXPECT_EQ(0, outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(0, outDisplayRetireTime);
    EXPECT_EQ(0, outReleaseTime);
}

// This test verifies there are no sync calls for present or retire times
// when they aren't supported and that an error is returned.
void GetFrameTimestampsTest::PresentOrRetireUnsupportedNoSyncTest(
        bool displayPresentSupported, bool displayRetireSupported) {

    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportedTimestamps(
        displayPresentSupported, displayRetireSupported);

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);

    // Verify a query for the Present and Retire times do not trigger
    // a sync call if they are not supported.
    const uint32_t framesAgo = 0;
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), framesAgo,
            nullptr, nullptr, nullptr, nullptr,
            displayPresentSupported ? nullptr : &outDisplayPresentTime,
            displayRetireSupported ? nullptr : &outDisplayRetireTime,
            nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(BAD_VALUE, result);
    EXPECT_EQ(-1, outDisplayRetireTime);
    EXPECT_EQ(-1, outDisplayPresentTime);
}

TEST_F(GetFrameTimestampsTest, PresentUnsupportedNoSync) {
   PresentOrRetireUnsupportedNoSyncTest(false, true);
}

TEST_F(GetFrameTimestampsTest, RetireUnsupportedNoSync) {
   PresentOrRetireUnsupportedNoSyncTest(true, false);
}

}
