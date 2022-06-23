/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "BLASTBufferQueue_test"

#include <gui/BLASTBufferQueue.h>

#include <android/hardware/graphics/common/1.2/types.h>
#include <gui/BufferQueueCore.h>
#include <gui/BufferQueueProducer.h>
#include <gui/FrameTimestamps.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SyncScreenCaptureListener.h>
#include <gui/test/CallbackUtils.h>
#include <private/gui/ComposerService.h>
#include <private/gui/ComposerServiceAIDL.h>
#include <ui/DisplayMode.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include <gtest/gtest.h>

using namespace std::chrono_literals;

namespace android {

using Transaction = SurfaceComposerClient::Transaction;
using android::hardware::graphics::common::V1_2::BufferUsage;

class CountProducerListener : public BnProducerListener {
public:
    void onBufferReleased() override {
        std::scoped_lock<std::mutex> lock(mMutex);
        mNumReleased++;
        mReleaseCallback.notify_one();
    }

    void waitOnNumberReleased(int32_t expectedNumReleased) {
        std::unique_lock<std::mutex> lock(mMutex);
        while (mNumReleased < expectedNumReleased) {
            ASSERT_NE(mReleaseCallback.wait_for(lock, std::chrono::seconds(3)),
                      std::cv_status::timeout)
                    << "did not receive release";
        }
    }

private:
    std::mutex mMutex;
    std::condition_variable mReleaseCallback;
    int32_t mNumReleased GUARDED_BY(mMutex) = 0;
};

class TestBLASTBufferQueue : public BLASTBufferQueue {
public:
    TestBLASTBufferQueue(const std::string& name, const sp<SurfaceControl>& surface, int width,
                         int height, int32_t format)
          : BLASTBufferQueue(name, surface, width, height, format) {}

    void transactionCallback(nsecs_t latchTime, const sp<Fence>& presentFence,
                             const std::vector<SurfaceControlStats>& stats) override {
        BLASTBufferQueue::transactionCallback(latchTime, presentFence, stats);
        uint64_t frameNumber = stats[0].frameEventStats.frameNumber;

        {
            std::unique_lock lock{frameNumberMutex};
            mLastTransactionFrameNumber = frameNumber;
            mWaitForCallbackCV.notify_all();
        }
    }

    void waitForCallback(int64_t frameNumber) {
        std::unique_lock lock{frameNumberMutex};
        // Wait until all but one of the submitted buffers have been released.
        while (mLastTransactionFrameNumber < frameNumber) {
            mWaitForCallbackCV.wait(lock);
        }
    }

private:
    std::mutex frameNumberMutex;
    std::condition_variable mWaitForCallbackCV;
    int64_t mLastTransactionFrameNumber = -1;
};

class BLASTBufferQueueHelper {
public:
    BLASTBufferQueueHelper(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter = new TestBLASTBufferQueue("TestBLASTBufferQueue", sc, width,
                                                            height, PIXEL_FORMAT_RGBA_8888);
    }

    void update(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter->update(sc, width, height, PIXEL_FORMAT_RGBA_8888);
    }

    void setSyncTransaction(Transaction& next, bool acquireSingleBuffer = true) {
        auto callback = [&next](Transaction* t) { next.merge(std::move(*t)); };
        mBlastBufferQueueAdapter->syncNextTransaction(callback, acquireSingleBuffer);
    }

    void syncNextTransaction(std::function<void(Transaction*)> callback,
                             bool acquireSingleBuffer = true) {
        mBlastBufferQueueAdapter->syncNextTransaction(callback, acquireSingleBuffer);
    }

    void stopContinuousSyncTransaction() {
        mBlastBufferQueueAdapter->stopContinuousSyncTransaction();
    }

    int getWidth() { return mBlastBufferQueueAdapter->mSize.width; }

    int getHeight() { return mBlastBufferQueueAdapter->mSize.height; }

    std::function<void(Transaction*)> getTransactionReadyCallback() {
        return mBlastBufferQueueAdapter->mTransactionReadyCallback;
    }

    sp<IGraphicBufferProducer> getIGraphicBufferProducer() {
        return mBlastBufferQueueAdapter->getIGraphicBufferProducer();
    }

    const sp<SurfaceControl> getSurfaceControl() {
        return mBlastBufferQueueAdapter->mSurfaceControl;
    }

    sp<Surface> getSurface() {
        return mBlastBufferQueueAdapter->getSurface(false /* includeSurfaceControlHandle */);
    }

    void waitForCallbacks() {
        std::unique_lock lock{mBlastBufferQueueAdapter->mMutex};
        // Wait until all but one of the submitted buffers have been released.
        while (mBlastBufferQueueAdapter->mSubmitted.size() > 1) {
            mBlastBufferQueueAdapter->mCallbackCV.wait(lock);
        }
    }

    void waitForCallback(int64_t frameNumber) {
        mBlastBufferQueueAdapter->waitForCallback(frameNumber);
    }

    void validateNumFramesSubmitted(int64_t numFramesSubmitted) {
        std::unique_lock lock{mBlastBufferQueueAdapter->mMutex};
        ASSERT_EQ(numFramesSubmitted, mBlastBufferQueueAdapter->mSubmitted.size());
    }

    void mergeWithNextTransaction(Transaction* merge, uint64_t frameNumber) {
        mBlastBufferQueueAdapter->mergeWithNextTransaction(merge, frameNumber);
    }

private:
    sp<TestBLASTBufferQueue> mBlastBufferQueueAdapter;
};

class BLASTBufferQueueTest : public ::testing::Test {
public:
protected:
    BLASTBufferQueueTest() {
        const ::testing::TestInfo* const testInfo =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("Begin test: %s.%s", testInfo->test_case_name(), testInfo->name());
    }

    ~BLASTBufferQueueTest() {
        const ::testing::TestInfo* const testInfo =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("End test:   %s.%s", testInfo->test_case_name(), testInfo->name());
    }

    void SetUp() {
        mComposer = ComposerService::getComposerService();
        mClient = new SurfaceComposerClient();
        mDisplayToken = mClient->getInternalDisplayToken();
        ASSERT_NE(nullptr, mDisplayToken.get());
        Transaction t;
        t.setDisplayLayerStack(mDisplayToken, ui::DEFAULT_LAYER_STACK);
        t.apply();
        t.clear();

        ui::DisplayMode mode;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayMode(mDisplayToken, &mode));
        const ui::Size& resolution = mode.resolution;
        mDisplayWidth = resolution.getWidth();
        mDisplayHeight = resolution.getHeight();

        mSurfaceControl = mClient->createSurface(String8("TestSurface"), mDisplayWidth,
                                                 mDisplayHeight, PIXEL_FORMAT_RGBA_8888,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState,
                                                 /*parent*/ nullptr);
        t.setLayerStack(mSurfaceControl, ui::DEFAULT_LAYER_STACK)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .show(mSurfaceControl)
                .setDataspace(mSurfaceControl, ui::Dataspace::V0_SRGB)
                .apply();

        mCaptureArgs.displayToken = mDisplayToken;
        mCaptureArgs.dataspace = ui::Dataspace::V0_SRGB;
    }

    void setUpProducer(BLASTBufferQueueHelper& adapter, sp<IGraphicBufferProducer>& producer,
                       int32_t maxBufferCount = 2) {
        producer = adapter.getIGraphicBufferProducer();
        setUpProducer(producer, maxBufferCount);
    }

    void setUpProducer(sp<IGraphicBufferProducer>& igbProducer, int32_t maxBufferCount) {
        ASSERT_NE(nullptr, igbProducer.get());
        ASSERT_EQ(NO_ERROR, igbProducer->setMaxDequeuedBufferCount(maxBufferCount));
        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        mProducerListener = new CountProducerListener();
        ASSERT_EQ(NO_ERROR,
                  igbProducer->connect(mProducerListener, NATIVE_WINDOW_API_CPU, false, &qbOutput));
        ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);
    }

    void fillBuffer(uint32_t* bufData, Rect rect, uint32_t stride, uint8_t r, uint8_t g,
                    uint8_t b) {
        for (uint32_t row = rect.top; row < rect.bottom; row++) {
            for (uint32_t col = rect.left; col < rect.right; col++) {
                uint8_t* pixel = (uint8_t*)(bufData + (row * stride) + col);
                *pixel = r;
                *(pixel + 1) = g;
                *(pixel + 2) = b;
                *(pixel + 3) = 255;
            }
        }
    }

    void fillQuadrants(sp<GraphicBuffer>& buf) {
        const auto bufWidth = buf->getWidth();
        const auto bufHeight = buf->getHeight();
        uint32_t* bufData;
        buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
                  reinterpret_cast<void**>(&bufData));
        fillBuffer(bufData, Rect(0, 0, bufWidth / 2, bufHeight / 2), buf->getStride(), 0, 0, 0);
        fillBuffer(bufData, Rect(bufWidth / 2, 0, bufWidth, bufHeight / 2), buf->getStride(), 255,
                   0, 0);
        fillBuffer(bufData, Rect(bufWidth / 2, bufHeight / 2, bufWidth, bufHeight),
                   buf->getStride(), 0, 255, 0);
        fillBuffer(bufData, Rect(0, bufHeight / 2, bufWidth / 2, bufHeight), buf->getStride(), 0, 0,
                   255);
        buf->unlock();
    }

    void checkScreenCapture(uint8_t r, uint8_t g, uint8_t b, Rect region, int32_t border = 0,
                            bool outsideRegion = false) {
        sp<GraphicBuffer>& captureBuf = mCaptureResults.buffer;
        const auto epsilon = 3;
        const auto width = captureBuf->getWidth();
        const auto height = captureBuf->getHeight();
        const auto stride = captureBuf->getStride();

        uint32_t* bufData;
        captureBuf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_READ_OFTEN),
                         reinterpret_cast<void**>(&bufData));

        for (uint32_t row = 0; row < height; row++) {
            for (uint32_t col = 0; col < width; col++) {
                uint8_t* pixel = (uint8_t*)(bufData + (row * stride) + col);
                ASSERT_NE(nullptr, pixel);
                bool inRegion;
                if (!outsideRegion) {
                    inRegion = row >= region.top + border && row < region.bottom - border &&
                            col >= region.left + border && col < region.right - border;
                } else {
                    inRegion = row >= region.top - border && row < region.bottom + border &&
                            col >= region.left - border && col < region.right + border;
                }
                if (!outsideRegion && inRegion) {
                    ASSERT_GE(epsilon, abs(r - *(pixel)));
                    ASSERT_GE(epsilon, abs(g - *(pixel + 1)));
                    ASSERT_GE(epsilon, abs(b - *(pixel + 2)));
                } else if (outsideRegion && !inRegion) {
                    ASSERT_GE(epsilon, abs(r - *(pixel)));
                    ASSERT_GE(epsilon, abs(g - *(pixel + 1)));
                    ASSERT_GE(epsilon, abs(b - *(pixel + 2)));
                }
                ASSERT_EQ(false, ::testing::Test::HasFailure());
            }
        }
        captureBuf->unlock();
    }

    static status_t captureDisplay(DisplayCaptureArgs& captureArgs,
                                   ScreenCaptureResults& captureResults) {
        const auto sf = ComposerServiceAIDL::getComposerService();
        SurfaceComposerClient::Transaction().apply(true);

        const sp<SyncScreenCaptureListener> captureListener = new SyncScreenCaptureListener();
        binder::Status status = sf->captureDisplay(captureArgs, captureListener);
        if (status.transactionError() != NO_ERROR) {
            return status.transactionError();
        }
        captureResults = captureListener->waitForResults();
        return captureResults.result;
    }

    void queueBuffer(sp<IGraphicBufferProducer> igbp, uint8_t r, uint8_t g, uint8_t b,
                     nsecs_t presentTimeDelay) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbp->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                       PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                       nullptr, nullptr);
        ASSERT_TRUE(ret == IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION || ret == NO_ERROR);
        ASSERT_EQ(OK, igbp->requestBuffer(slot, &buf));

        uint32_t* bufData;
        buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
                  reinterpret_cast<void**>(&bufData));
        fillBuffer(bufData, Rect(buf->getWidth(), buf->getHeight() / 2), buf->getStride(), r, g, b);
        buf->unlock();

        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        nsecs_t timestampNanos = systemTime() + presentTimeDelay;
        IGraphicBufferProducer::QueueBufferInput input(timestampNanos, false, HAL_DATASPACE_UNKNOWN,
                                                       Rect(mDisplayWidth, mDisplayHeight / 2),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE);
        igbp->queueBuffer(slot, input, &qbOutput);
    }

    sp<SurfaceComposerClient> mClient;
    sp<ISurfaceComposer> mComposer;

    sp<IBinder> mDisplayToken;

    sp<SurfaceControl> mSurfaceControl;

    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;

    DisplayCaptureArgs mCaptureArgs;
    ScreenCaptureResults mCaptureResults;
    sp<CountProducerListener> mProducerListener;
};

TEST_F(BLASTBufferQueueTest, CreateBLASTBufferQueue) {
    // create BLASTBufferQueue adapter associated with this surface
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    ASSERT_EQ(mSurfaceControl, adapter.getSurfaceControl());
    ASSERT_EQ(mDisplayWidth, adapter.getWidth());
    ASSERT_EQ(mDisplayHeight, adapter.getHeight());
    ASSERT_EQ(nullptr, adapter.getTransactionReadyCallback());
}

TEST_F(BLASTBufferQueueTest, Update) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<SurfaceControl> updateSurface =
            mClient->createSurface(String8("UpdateTest"), mDisplayWidth / 2, mDisplayHeight / 2,
                                   PIXEL_FORMAT_RGBA_8888);
    adapter.update(updateSurface, mDisplayWidth / 2, mDisplayHeight / 2);
    ASSERT_EQ(updateSurface, adapter.getSurfaceControl());
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    int32_t width;
    igbProducer->query(NATIVE_WINDOW_WIDTH, &width);
    ASSERT_EQ(mDisplayWidth / 2, width);
    int32_t height;
    igbProducer->query(NATIVE_WINDOW_HEIGHT, &height);
    ASSERT_EQ(mDisplayHeight / 2, height);
}

TEST_F(BLASTBufferQueueTest, SyncNextTransaction) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    ASSERT_EQ(nullptr, adapter.getTransactionReadyCallback());
    auto callback = [](Transaction*) {};
    adapter.syncNextTransaction(callback);
    ASSERT_NE(nullptr, adapter.getTransactionReadyCallback());
}

TEST_F(BLASTBufferQueueTest, DISABLED_onFrameAvailable_ApplyDesiredPresentTime) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buf;
    auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                          PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                          nullptr, nullptr);
    ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
    ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

    nsecs_t desiredPresentTime = systemTime() + nsecs_t(5 * 1e8);
    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(desiredPresentTime, true /* autotimestamp */,
                                                   HAL_DATASPACE_UNKNOWN,
                                                   Rect(mDisplayWidth, mDisplayHeight),
                                                   NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();
    ASSERT_GE(systemTime(), desiredPresentTime);
}

TEST_F(BLASTBufferQueueTest, onFrameAvailable_Apply) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buf;
    auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                          PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                          nullptr, nullptr);
    ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
    ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

    uint32_t* bufData;
    buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
              reinterpret_cast<void**>(&bufData));
    fillBuffer(bufData, Rect(buf->getWidth(), buf->getHeight()), buf->getStride(), r, g, b);
    buf->unlock();

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                   HAL_DATASPACE_UNKNOWN,
                                                   Rect(mDisplayWidth, mDisplayHeight),
                                                   NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();

    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

TEST_F(BLASTBufferQueueTest, TripleBuffering) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    std::vector<std::pair<int, sp<Fence>>> allocated;
    int minUndequeuedBuffers = 0;
    ASSERT_EQ(OK, igbProducer->query(NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, &minUndequeuedBuffers));
    const auto bufferCount = minUndequeuedBuffers + 2;

    for (int i = 0; i < bufferCount; i++) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));
        allocated.push_back({slot, fence});
    }
    for (int i = 0; i < allocated.size(); i++) {
        igbProducer->cancelBuffer(allocated[i].first, allocated[i].second);
    }

    for (int i = 0; i < 100; i++) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(NO_ERROR, ret);
        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                       HAL_DATASPACE_UNKNOWN,
                                                       Rect(mDisplayWidth, mDisplayHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE);
        igbProducer->queueBuffer(slot, input, &qbOutput);
    }
    adapter.waitForCallbacks();
}

TEST_F(BLASTBufferQueueTest, SetCrop_Item) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);
    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buf;
    auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                          PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                          nullptr, nullptr);
    ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
    ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

    uint32_t* bufData;
    buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
              reinterpret_cast<void**>(&bufData));
    fillBuffer(bufData, Rect(buf->getWidth(), buf->getHeight() / 2), buf->getStride(), r, g, b);
    buf->unlock();

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                   HAL_DATASPACE_UNKNOWN,
                                                   Rect(mDisplayWidth, mDisplayHeight / 2),
                                                   NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();
    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));

    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b,
                               {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight / 2}));
}

TEST_F(BLASTBufferQueueTest, SetCrop_ScalingModeScaleCrop) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    int32_t bufferSideLength =
            (mDisplayWidth < mDisplayHeight) ? mDisplayWidth / 2 : mDisplayHeight / 2;
    int32_t finalCropSideLength = bufferSideLength / 2;

    auto bg = mClient->createSurface(String8("BGTest"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                     ISurfaceComposerClient::eFXSurfaceEffect);
    ASSERT_NE(nullptr, bg.get());
    Transaction t;
    t.setLayerStack(bg, ui::DEFAULT_LAYER_STACK)
            .setCrop(bg, Rect(0, 0, mDisplayWidth, mDisplayHeight))
            .setColor(bg, half3{0, 0, 0})
            .setLayer(bg, 0)
            .apply();

    BLASTBufferQueueHelper adapter(mSurfaceControl, bufferSideLength, bufferSideLength);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);
    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buf;
    auto ret = igbProducer->dequeueBuffer(&slot, &fence, bufferSideLength, bufferSideLength,
                                          PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                          nullptr, nullptr);
    ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
    ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

    uint32_t* bufData;
    buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
              reinterpret_cast<void**>(&bufData));
    fillBuffer(bufData, Rect(buf->getWidth(), buf->getHeight()), buf->getStride(), 0, 0, 0);
    fillBuffer(bufData,
               Rect(finalCropSideLength / 2, 0, buf->getWidth() - finalCropSideLength / 2,
                    buf->getHeight()),
               buf->getStride(), r, g, b);
    buf->unlock();

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                   HAL_DATASPACE_UNKNOWN,
                                                   Rect(bufferSideLength, finalCropSideLength),
                                                   NATIVE_WINDOW_SCALING_MODE_SCALE_CROP, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();
    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(r, g, b,
                                               {10, 10, (int32_t)bufferSideLength - 10,
                                                (int32_t)bufferSideLength - 10}));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(0, 0, 0,
                               {0, 0, (int32_t)bufferSideLength, (int32_t)bufferSideLength},
                               /*border*/ 0, /*outsideRegion*/ true));
}

TEST_F(BLASTBufferQueueTest, ScaleCroppedBufferToBufferSize) {
    // add black background
    auto bg = mClient->createSurface(String8("BGTest"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                     ISurfaceComposerClient::eFXSurfaceEffect);
    ASSERT_NE(nullptr, bg.get());
    Transaction t;
    t.setLayerStack(bg, ui::DEFAULT_LAYER_STACK)
            .setCrop(bg, Rect(0, 0, mDisplayWidth, mDisplayHeight))
            .setColor(bg, half3{0, 0, 0})
            .setLayer(bg, 0)
            .apply();

    Rect windowSize(1000, 1000);
    Rect bufferSize(windowSize);
    Rect bufferCrop(200, 200, 700, 700);

    BLASTBufferQueueHelper adapter(mSurfaceControl, windowSize.getWidth(), windowSize.getHeight());
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);
    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buf;
    auto ret = igbProducer->dequeueBuffer(&slot, &fence, bufferSize.getWidth(),
                                          bufferSize.getHeight(), PIXEL_FORMAT_RGBA_8888,
                                          GRALLOC_USAGE_SW_WRITE_OFTEN, nullptr, nullptr);
    ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
    ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

    uint32_t* bufData;
    buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
              reinterpret_cast<void**>(&bufData));
    // fill buffer with grey
    fillBuffer(bufData, bufferSize, buf->getStride(), 127, 127, 127);

    // fill crop area with different colors so we can verify the cropped region has been scaled
    // correctly.
    fillBuffer(bufData, Rect(200, 200, 450, 450), buf->getStride(), /* rgb */ 255, 0, 0);
    fillBuffer(bufData, Rect(200, 451, 450, 700), buf->getStride(), /* rgb */ 0, 255, 0);
    fillBuffer(bufData, Rect(451, 200, 700, 450), buf->getStride(), /* rgb */ 0, 0, 255);
    fillBuffer(bufData, Rect(451, 451, 700, 700), buf->getStride(), /* rgb */ 255, 0, 0);
    buf->unlock();

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                   HAL_DATASPACE_UNKNOWN,
                                                   bufferCrop /* Rect::INVALID_RECT */,
                                                   NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();

    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));

    // Verify cropped region is scaled correctly.
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(255, 0, 0, {10, 10, 490, 490}));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 255, 0, {10, 510, 490, 990}));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 255, {510, 10, 990, 490}));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(255, 0, 0, {510, 510, 990, 990}));
    // Verify outside region is black.
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 0,
                                               {0, 0, (int32_t)windowSize.getWidth(),
                                                (int32_t)windowSize.getHeight()},
                                               /*border*/ 0, /*outsideRegion*/ true));
}

TEST_F(BLASTBufferQueueTest, ScaleCroppedBufferToWindowSize) {
    // add black background
    auto bg = mClient->createSurface(String8("BGTest"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                     ISurfaceComposerClient::eFXSurfaceEffect);
    ASSERT_NE(nullptr, bg.get());
    Transaction t;
    t.setLayerStack(bg, ui::DEFAULT_LAYER_STACK)
            .setCrop(bg, Rect(0, 0, mDisplayWidth, mDisplayHeight))
            .setColor(bg, half3{0, 0, 0})
            .setLayer(bg, 0)
            .apply();

    Rect windowSize(1000, 1000);
    Rect bufferSize(500, 500);
    Rect bufferCrop(100, 100, 350, 350);

    BLASTBufferQueueHelper adapter(mSurfaceControl, windowSize.getWidth(), windowSize.getHeight());
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);
    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buf;
    auto ret = igbProducer->dequeueBuffer(&slot, &fence, bufferSize.getWidth(),
                                          bufferSize.getHeight(), PIXEL_FORMAT_RGBA_8888,
                                          GRALLOC_USAGE_SW_WRITE_OFTEN, nullptr, nullptr);
    ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
    ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

    uint32_t* bufData;
    buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
              reinterpret_cast<void**>(&bufData));
    // fill buffer with grey
    fillBuffer(bufData, bufferSize, buf->getStride(), 127, 127, 127);

    // fill crop area with different colors so we can verify the cropped region has been scaled
    // correctly.
    fillBuffer(bufData, Rect(100, 100, 225, 225), buf->getStride(), /* rgb */ 255, 0, 0);
    fillBuffer(bufData, Rect(100, 226, 225, 350), buf->getStride(), /* rgb */ 0, 255, 0);
    fillBuffer(bufData, Rect(226, 100, 350, 225), buf->getStride(), /* rgb */ 0, 0, 255);
    fillBuffer(bufData, Rect(226, 226, 350, 350), buf->getStride(), /* rgb */ 255, 0, 0);
    buf->unlock();

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                   HAL_DATASPACE_UNKNOWN,
                                                   bufferCrop /* Rect::INVALID_RECT */,
                                                   NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();

    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    // Verify cropped region is scaled correctly.
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(255, 0, 0, {10, 10, 490, 490}));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 255, 0, {10, 510, 490, 990}));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 255, {510, 10, 990, 490}));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(255, 0, 0, {510, 510, 990, 990}));
    // Verify outside region is black.
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 0,
                                               {0, 0, (int32_t)windowSize.getWidth(),
                                                (int32_t)windowSize.getHeight()},
                                               /*border*/ 0, /*outsideRegion*/ true));
}

// b/196339769 verify we can can update the requested size while the in FREEZE scaling mode and
// scale the buffer properly when the mode changes to SCALE_TO_WINDOW
TEST_F(BLASTBufferQueueTest, ScalingModeChanges) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight / 4);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);
    {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight / 4,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

        uint32_t* bufData;
        buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
                  reinterpret_cast<void**>(&bufData));
        fillBuffer(bufData, Rect(buf->getWidth(), buf->getHeight()), buf->getStride(), r, g, b);
        buf->unlock();

        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                       HAL_DATASPACE_UNKNOWN, {},
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE);
        igbProducer->queueBuffer(slot, input, &qbOutput);
        adapter.waitForCallbacks();
    }
    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));

    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b,
                               {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight / 4}));

    // update the size to half the display and dequeue a buffer quarter of the display.
    adapter.update(mSurfaceControl, mDisplayWidth, mDisplayHeight / 2);

    {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight / 8,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

        uint32_t* bufData;
        buf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_WRITE_OFTEN),
                  reinterpret_cast<void**>(&bufData));
        g = 255;
        fillBuffer(bufData, Rect(buf->getWidth(), buf->getHeight()), buf->getStride(), r, g, b);
        buf->unlock();

        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                       HAL_DATASPACE_UNKNOWN, {},
                                                       NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW,
                                                       0, Fence::NO_FENCE);
        igbProducer->queueBuffer(slot, input, &qbOutput);
        adapter.waitForCallbacks();
    }
    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    // verify we still scale the buffer to the new size (half the screen height)
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b,
                               {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight / 2}));
}

TEST_F(BLASTBufferQueueTest, SyncThenNoSync) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    Transaction sync;
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, 0, 255, 0, 0);

    // queue non sync buffer, so this one should get blocked
    // Add a present delay to allow the first screenshot to get taken.
    nsecs_t presentTimeDelay = std::chrono::nanoseconds(500ms).count();
    queueBuffer(igbProducer, r, g, b, presentTimeDelay);

    CallbackHelper transactionCallback;
    sync.addTransactionCompletedCallback(transactionCallback.function,
                                         transactionCallback.getContext())
            .apply();

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);

    // capture screen and verify that it is green
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(0, 255, 0, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));

    mProducerListener->waitOnNumberReleased(1);
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

TEST_F(BLASTBufferQueueTest, MultipleSyncTransactions) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    Transaction mainTransaction;

    Transaction sync;
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, 0, 255, 0, 0);

    mainTransaction.merge(std::move(sync));

    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, r, g, b, 0);

    mainTransaction.merge(std::move(sync));
    // Expect 1 buffer to be released even before sending to SurfaceFlinger
    mProducerListener->waitOnNumberReleased(1);

    CallbackHelper transactionCallback;
    mainTransaction
            .addTransactionCompletedCallback(transactionCallback.function,
                                             transactionCallback.getContext())
            .apply();

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);

    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

TEST_F(BLASTBufferQueueTest, MultipleSyncTransactionWithNonSync) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    Transaction mainTransaction;

    Transaction sync;
    // queue a sync transaction
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, 0, 255, 0, 0);

    mainTransaction.merge(std::move(sync));

    // queue another buffer without setting sync transaction
    queueBuffer(igbProducer, 0, 0, 255, 0);

    // queue another sync transaction
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, r, g, b, 0);
    // Expect 1 buffer to be released because the non sync transaction should merge
    // with the sync
    mProducerListener->waitOnNumberReleased(1);

    mainTransaction.merge(std::move(sync));
    // Expect 2 buffers to be released due to merging the two syncs.
    mProducerListener->waitOnNumberReleased(2);

    CallbackHelper transactionCallback;
    mainTransaction
            .addTransactionCompletedCallback(transactionCallback.function,
                                             transactionCallback.getContext())
            .apply();

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);

    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

TEST_F(BLASTBufferQueueTest, MultipleSyncRunOutOfBuffers) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer, 3);

    Transaction mainTransaction;

    Transaction sync;
    // queue a sync transaction
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, 0, 255, 0, 0);

    mainTransaction.merge(std::move(sync));

    // queue a few buffers without setting sync transaction
    queueBuffer(igbProducer, 0, 0, 255, 0);
    queueBuffer(igbProducer, 0, 0, 255, 0);
    queueBuffer(igbProducer, 0, 0, 255, 0);

    // queue another sync transaction
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, r, g, b, 0);
    // Expect 3 buffers to be released because the non sync transactions should merge
    // with the sync
    mProducerListener->waitOnNumberReleased(3);

    mainTransaction.merge(std::move(sync));
    // Expect 4 buffers to be released due to merging the two syncs.
    mProducerListener->waitOnNumberReleased(4);

    CallbackHelper transactionCallback;
    mainTransaction
            .addTransactionCompletedCallback(transactionCallback.function,
                                             transactionCallback.getContext())
            .apply();

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);

    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

// Tests BBQ with a sync transaction when the buffers acquired reaches max and the only way to
// continue processing is for a release callback from SurfaceFlinger.
// This is done by sending a buffer to SF so it can release the previous one and allow BBQ to
// continue acquiring buffers.
TEST_F(BLASTBufferQueueTest, RunOutOfBuffersWaitingOnSF) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer, 4);

    Transaction mainTransaction;

    // Send a buffer to SF
    queueBuffer(igbProducer, 0, 255, 0, 0);

    Transaction sync;
    // queue a sync transaction
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, 0, 255, 0, 0);

    mainTransaction.merge(std::move(sync));

    // queue a few buffers without setting sync transaction
    queueBuffer(igbProducer, 0, 0, 255, 0);
    queueBuffer(igbProducer, 0, 0, 255, 0);
    queueBuffer(igbProducer, 0, 0, 255, 0);

    // apply the first synced buffer to ensure we have to wait on SF
    mainTransaction.apply();

    // queue another sync transaction
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, r, g, b, 0);
    // Expect 2 buffers to be released because the non sync transactions should merge
    // with the sync
    mProducerListener->waitOnNumberReleased(3);

    mainTransaction.merge(std::move(sync));

    CallbackHelper transactionCallback;
    mainTransaction
            .addTransactionCompletedCallback(transactionCallback.function,
                                             transactionCallback.getContext())
            .apply();

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);

    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

TEST_F(BLASTBufferQueueTest, SyncNextTransactionAcquireMultipleBuffers) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    Transaction next;
    adapter.setSyncTransaction(next, false);
    queueBuffer(igbProducer, 0, 255, 0, 0);
    queueBuffer(igbProducer, 0, 0, 255, 0);
    // There should only be one frame submitted since the first frame will be released.
    adapter.validateNumFramesSubmitted(1);
    adapter.stopContinuousSyncTransaction();

    // queue non sync buffer, so this one should get blocked
    // Add a present delay to allow the first screenshot to get taken.
    nsecs_t presentTimeDelay = std::chrono::nanoseconds(500ms).count();
    queueBuffer(igbProducer, 255, 0, 0, presentTimeDelay);

    CallbackHelper transactionCallback;
    next.addTransactionCompletedCallback(transactionCallback.function,
                                         transactionCallback.getContext())
            .apply();

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);

    // capture screen and verify that it is blue
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(0, 0, 255, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));

    mProducerListener->waitOnNumberReleased(2);
    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(255, 0, 0, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

TEST_F(BLASTBufferQueueTest, SyncNextTransactionOverwrite) {
    std::mutex mutex;
    std::condition_variable callbackReceivedCv;
    bool receivedCallback = false;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    ASSERT_EQ(nullptr, adapter.getTransactionReadyCallback());
    auto callback = [&](Transaction*) {
        std::unique_lock<std::mutex> lock(mutex);
        receivedCallback = true;
        callbackReceivedCv.notify_one();
    };
    adapter.syncNextTransaction(callback);
    ASSERT_NE(nullptr, adapter.getTransactionReadyCallback());

    auto callback2 = [](Transaction*) {};
    adapter.syncNextTransaction(callback2);

    std::unique_lock<std::mutex> lock(mutex);
    if (!receivedCallback) {
        ASSERT_NE(callbackReceivedCv.wait_for(lock, std::chrono::seconds(3)),
                  std::cv_status::timeout)
                << "did not receive callback";
    }

    ASSERT_TRUE(receivedCallback);
}

TEST_F(BLASTBufferQueueTest, SyncNextTransactionDropBuffer) {
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    Transaction sync;
    adapter.setSyncTransaction(sync);
    queueBuffer(igbProducer, 0, 255, 0, 0);

    // Merge a transaction that has a complete callback into the next frame so we can get notified
    // when to take a screenshot
    CallbackHelper transactionCallback;
    Transaction t;
    t.addTransactionCompletedCallback(transactionCallback.function,
                                      transactionCallback.getContext());
    adapter.mergeWithNextTransaction(&t, 2);
    queueBuffer(igbProducer, r, g, b, 0);

    // Drop the buffer, but ensure the next one continues to get processed.
    sync.setBuffer(mSurfaceControl, nullptr);

    CallbackData callbackData;
    transactionCallback.getCallbackData(&callbackData);
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
}

// This test will currently fail because the old surfacecontrol will steal the last presented buffer
// until the old surface control is destroyed. This is not necessarily a bug but to document a
// limitation with the update API and to test any changes to make the api more robust. The current
// approach for the client is to recreate the blastbufferqueue when the surfacecontrol updates.
TEST_F(BLASTBufferQueueTest, DISABLED_DisconnectProducerTest) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    std::vector<sp<SurfaceControl>> surfaceControls;
    sp<IGraphicBufferProducer> igbProducer;
    for (int i = 0; i < 10; i++) {
        sp<SurfaceControl> sc =
                mClient->createSurface(String8("TestSurface"), mDisplayWidth, mDisplayHeight,
                                       PIXEL_FORMAT_RGBA_8888,
                                       ISurfaceComposerClient::eFXSurfaceBufferState,
                                       /*parent*/ nullptr);
        Transaction()
                .setLayerStack(mSurfaceControl, ui::DEFAULT_LAYER_STACK)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .show(mSurfaceControl)
                .setDataspace(mSurfaceControl, ui::Dataspace::V0_SRGB)
                .apply(true);
        surfaceControls.push_back(sc);
        adapter.update(sc, mDisplayWidth, mDisplayHeight);

        setUpProducer(adapter, igbProducer);
        Transaction next;
        queueBuffer(igbProducer, 0, 255, 0, 0);
        queueBuffer(igbProducer, 0, 0, 255, 0);
        adapter.setSyncTransaction(next, true);
        queueBuffer(igbProducer, 255, 0, 0, 0);

        CallbackHelper transactionCallback;
        next.addTransactionCompletedCallback(transactionCallback.function,
                                             transactionCallback.getContext())
                .apply();

        CallbackData callbackData;
        transactionCallback.getCallbackData(&callbackData);
        // capture screen and verify that it is red
        ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
        ASSERT_NO_FATAL_FAILURE(
                checkScreenCapture(255, 0, 0,
                                   {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
        igbProducer->disconnect(NATIVE_WINDOW_API_CPU);
    }
}

// See DISABLED_DisconnectProducerTest
TEST_F(BLASTBufferQueueTest, DISABLED_UpdateSurfaceControlTest) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    std::vector<sp<SurfaceControl>> surfaceControls;
    sp<IGraphicBufferProducer> igbProducer;
    for (int i = 0; i < 10; i++) {
        sp<SurfaceControl> sc =
                mClient->createSurface(String8("TestSurface"), mDisplayWidth, mDisplayHeight,
                                       PIXEL_FORMAT_RGBA_8888,
                                       ISurfaceComposerClient::eFXSurfaceBufferState,
                                       /*parent*/ nullptr);
        Transaction()
                .setLayerStack(mSurfaceControl, ui::DEFAULT_LAYER_STACK)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .show(mSurfaceControl)
                .setDataspace(mSurfaceControl, ui::Dataspace::V0_SRGB)
                .apply(true);
        surfaceControls.push_back(sc);
        adapter.update(sc, mDisplayWidth, mDisplayHeight);
        setUpProducer(adapter, igbProducer);

        Transaction next;
        queueBuffer(igbProducer, 0, 255, 0, 0);
        queueBuffer(igbProducer, 0, 0, 255, 0);
        adapter.setSyncTransaction(next, true);
        queueBuffer(igbProducer, 255, 0, 0, 0);

        CallbackHelper transactionCallback;
        next.addTransactionCompletedCallback(transactionCallback.function,
                                             transactionCallback.getContext())
                .apply();

        CallbackData callbackData;
        transactionCallback.getCallbackData(&callbackData);
        // capture screen and verify that it is red
        ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));
        ASSERT_NO_FATAL_FAILURE(
                checkScreenCapture(255, 0, 0,
                                   {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
    }
}

class TestProducerListener : public BnProducerListener {
public:
    sp<IGraphicBufferProducer> mIgbp;
    TestProducerListener(const sp<IGraphicBufferProducer>& igbp) : mIgbp(igbp) {}
    void onBufferReleased() override {
        sp<GraphicBuffer> buffer;
        sp<Fence> fence;
        mIgbp->detachNextBuffer(&buffer, &fence);
    }
};

TEST_F(BLASTBufferQueueTest, CustomProducerListener) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer = adapter.getIGraphicBufferProducer();
    ASSERT_NE(nullptr, igbProducer.get());
    ASSERT_EQ(NO_ERROR, igbProducer->setMaxDequeuedBufferCount(2));
    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    ASSERT_EQ(NO_ERROR,
              igbProducer->connect(new TestProducerListener(igbProducer), NATIVE_WINDOW_API_CPU,
                                   false, &qbOutput));
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);
    for (int i = 0; i < 3; i++) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));
        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                       HAL_DATASPACE_UNKNOWN,
                                                       Rect(mDisplayWidth, mDisplayHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE);
        igbProducer->queueBuffer(slot, input, &qbOutput);
    }
    adapter.waitForCallbacks();
}

TEST_F(BLASTBufferQueueTest, QueryNativeWindowQueuesToWindowComposer) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    sp<android::Surface> surface = new Surface(adapter.getIGraphicBufferProducer());
    ANativeWindow* nativeWindow = (ANativeWindow*)(surface.get());
    int queuesToNativeWindow = 0;
    int err = nativeWindow->query(nativeWindow, NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER,
                                  &queuesToNativeWindow);
    ASSERT_EQ(NO_ERROR, err);
    ASSERT_EQ(queuesToNativeWindow, 1);
}

// Test a slow producer doesn't hold up a faster producer from the same client. Essentially tests
// BBQ uses separate transaction queues.
TEST_F(BLASTBufferQueueTest, OutOfOrderTransactionTest) {
    sp<SurfaceControl> bgSurface =
            mClient->createSurface(String8("BGTest"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceBufferState);
    ASSERT_NE(nullptr, bgSurface.get());
    Transaction t;
    t.setLayerStack(bgSurface, ui::DEFAULT_LAYER_STACK)
            .show(bgSurface)
            .setDataspace(bgSurface, ui::Dataspace::V0_SRGB)
            .setLayer(bgSurface, std::numeric_limits<int32_t>::max() - 1)
            .apply();

    BLASTBufferQueueHelper slowAdapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> slowIgbProducer;
    setUpProducer(slowAdapter, slowIgbProducer);
    nsecs_t presentTimeDelay = std::chrono::nanoseconds(500ms).count();
    queueBuffer(slowIgbProducer, 0 /* r */, 255 /* g */, 0 /* b */, presentTimeDelay);

    BLASTBufferQueueHelper fastAdapter(bgSurface, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> fastIgbProducer;
    setUpProducer(fastAdapter, fastIgbProducer);
    uint8_t r = 255;
    uint8_t g = 0;
    uint8_t b = 0;
    queueBuffer(fastIgbProducer, r, g, b, 0 /* presentTimeDelay */);
    fastAdapter.waitForCallbacks();

    // capture screen and verify that it is red
    ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));

    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b,
                               {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight / 2}));
}

TEST_F(BLASTBufferQueueTest, TransformHint) {
    // Transform hint is provided to BBQ via the surface control passed by WM
    mSurfaceControl->setTransformHint(ui::Transform::ROT_90);

    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer = adapter.getIGraphicBufferProducer();
    ASSERT_NE(nullptr, igbProducer.get());
    ASSERT_EQ(NO_ERROR, igbProducer->setMaxDequeuedBufferCount(2));
    sp<Surface> surface = adapter.getSurface();

    // Before connecting to the surface, we do not get a valid transform hint
    int transformHint;
    surface->query(NATIVE_WINDOW_TRANSFORM_HINT, &transformHint);
    ASSERT_EQ(ui::Transform::ROT_0, transformHint);

    ASSERT_EQ(NO_ERROR,
              surface->connect(NATIVE_WINDOW_API_CPU, new TestProducerListener(igbProducer)));

    // After connecting to the surface, we should get the correct hint.
    surface->query(NATIVE_WINDOW_TRANSFORM_HINT, &transformHint);
    ASSERT_EQ(ui::Transform::ROT_90, transformHint);

    ANativeWindow_Buffer buffer;
    surface->lock(&buffer, nullptr /* inOutDirtyBounds */);

    // Transform hint is updated via callbacks or surface control updates
    mSurfaceControl->setTransformHint(ui::Transform::ROT_0);
    adapter.update(mSurfaceControl, mDisplayWidth, mDisplayHeight);

    // The hint does not change and matches the value used when dequeueing the buffer.
    surface->query(NATIVE_WINDOW_TRANSFORM_HINT, &transformHint);
    ASSERT_EQ(ui::Transform::ROT_90, transformHint);

    surface->unlockAndPost();

    // After queuing the buffer, we get the updated transform hint
    surface->query(NATIVE_WINDOW_TRANSFORM_HINT, &transformHint);
    ASSERT_EQ(ui::Transform::ROT_0, transformHint);

    adapter.waitForCallbacks();
}

class BLASTBufferQueueTransformTest : public BLASTBufferQueueTest {
public:
    void test(uint32_t tr) {
        BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
        sp<IGraphicBufferProducer> igbProducer;
        setUpProducer(adapter, igbProducer);

        auto bufWidth = mDisplayWidth;
        auto bufHeight = mDisplayHeight;
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;

        auto ret = igbProducer->dequeueBuffer(&slot, &fence, bufWidth, bufHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

        fillQuadrants(buf);

        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), true /* autotimestamp */,
                                                       HAL_DATASPACE_UNKNOWN,
                                                       Rect(bufWidth, bufHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW,
                                                       tr, Fence::NO_FENCE);
        igbProducer->queueBuffer(slot, input, &qbOutput);
        ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

        adapter.waitForCallbacks();
        ASSERT_EQ(NO_ERROR, captureDisplay(mCaptureArgs, mCaptureResults));

        switch (tr) {
            case ui::Transform::ROT_0:
                ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 0,
                                                           {0, 0, (int32_t)mDisplayWidth / 2,
                                                            (int32_t)mDisplayHeight / 2},
                                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(255, 0, 0,
                                           {(int32_t)mDisplayWidth / 2, 0, (int32_t)mDisplayWidth,
                                            (int32_t)mDisplayHeight / 2},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 255, 0,
                                           {(int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth, (int32_t)mDisplayHeight},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 255,
                                           {0, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight},
                                           1));
                break;
            case ui::Transform::FLIP_H:
                ASSERT_NO_FATAL_FAILURE(checkScreenCapture(255, 0, 0,
                                                           {0, 0, (int32_t)mDisplayWidth / 2,
                                                            (int32_t)mDisplayHeight / 2},
                                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 0,
                                           {(int32_t)mDisplayWidth / 2, 0, (int32_t)mDisplayWidth,
                                            (int32_t)mDisplayHeight / 2},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 255,
                                           {(int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth, (int32_t)mDisplayHeight},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 255, 0,
                                           {0, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight},
                                           1));
                break;
            case ui::Transform::FLIP_V:
                ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 255,
                                                           {0, 0, (int32_t)mDisplayWidth / 2,
                                                            (int32_t)mDisplayHeight / 2},
                                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 255, 0,
                                           {(int32_t)mDisplayWidth / 2, 0, (int32_t)mDisplayWidth,
                                            (int32_t)mDisplayHeight / 2},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(255, 0, 0,
                                           {(int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth, (int32_t)mDisplayHeight},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 0,
                                           {0, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight},
                                           1));
                break;
            case ui::Transform::ROT_90:
                ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 0, 255,
                                                           {0, 0, (int32_t)mDisplayWidth / 2,
                                                            (int32_t)mDisplayHeight / 2},
                                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 0,
                                           {(int32_t)mDisplayWidth / 2, 0, (int32_t)mDisplayWidth,
                                            (int32_t)mDisplayHeight / 2},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(255, 0, 0,
                                           {(int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth, (int32_t)mDisplayHeight},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 255, 0,
                                           {0, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight},
                                           1));
                break;
            case ui::Transform::ROT_180:
                ASSERT_NO_FATAL_FAILURE(checkScreenCapture(0, 255, 0,
                                                           {0, 0, (int32_t)mDisplayWidth / 2,
                                                            (int32_t)mDisplayHeight / 2},
                                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 255,
                                           {(int32_t)mDisplayWidth / 2, 0, (int32_t)mDisplayWidth,
                                            (int32_t)mDisplayHeight / 2},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 0,
                                           {(int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth, (int32_t)mDisplayHeight},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(255, 0, 0,
                                           {0, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight},
                                           1));
                break;
            case ui::Transform::ROT_270:
                ASSERT_NO_FATAL_FAILURE(checkScreenCapture(255, 0, 0,
                                                           {0, 0, (int32_t)mDisplayWidth / 2,
                                                            (int32_t)mDisplayHeight / 2},
                                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 255, 0,
                                           {(int32_t)mDisplayWidth / 2, 0, (int32_t)mDisplayWidth,
                                            (int32_t)mDisplayHeight / 2},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 255,
                                           {(int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth, (int32_t)mDisplayHeight},
                                           1));
                ASSERT_NO_FATAL_FAILURE(
                        checkScreenCapture(0, 0, 0,
                                           {0, (int32_t)mDisplayHeight / 2,
                                            (int32_t)mDisplayWidth / 2, (int32_t)mDisplayHeight},
                                           1));
        }
    }
};

TEST_F(BLASTBufferQueueTransformTest, setTransform_ROT_0) {
    test(ui::Transform::ROT_0);
}

TEST_F(BLASTBufferQueueTransformTest, setTransform_FLIP_H) {
    test(ui::Transform::FLIP_H);
}

TEST_F(BLASTBufferQueueTransformTest, setTransform_FLIP_V) {
    test(ui::Transform::FLIP_V);
}

TEST_F(BLASTBufferQueueTransformTest, setTransform_ROT_90) {
    test(ui::Transform::ROT_90);
}

TEST_F(BLASTBufferQueueTransformTest, setTransform_ROT_180) {
    test(ui::Transform::ROT_180);
}

TEST_F(BLASTBufferQueueTransformTest, setTransform_ROT_270) {
    test(ui::Transform::ROT_270);
}

class BLASTFrameEventHistoryTest : public BLASTBufferQueueTest {
public:
    void setUpAndQueueBuffer(const sp<IGraphicBufferProducer>& igbProducer,
                             nsecs_t* outRequestedPresentTime, nsecs_t* postedTime,
                             IGraphicBufferProducer::QueueBufferOutput* qbOutput,
                             bool getFrameTimestamps, nsecs_t requestedPresentTime = systemTime()) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        if (IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION == ret) {
            ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));
        }

        *outRequestedPresentTime = requestedPresentTime;
        IGraphicBufferProducer::QueueBufferInput input(requestedPresentTime, false,
                                                       HAL_DATASPACE_UNKNOWN,
                                                       Rect(mDisplayWidth, mDisplayHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE, /*sticky*/ 0,
                                                       getFrameTimestamps);
        if (postedTime) *postedTime = systemTime();
        igbProducer->queueBuffer(slot, input, qbOutput);
    }
    sp<SurfaceControl> mBufferQueueSurfaceControl;
};

TEST_F(BLASTFrameEventHistoryTest, FrameEventHistory_Basic) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    ProducerFrameEventHistory history;
    setUpProducer(adapter, igbProducer);

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    nsecs_t requestedPresentTimeA = 0;
    nsecs_t postedTimeA = 0;
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeA, &postedTimeA, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);

    FrameEvents* events = nullptr;
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    adapter.waitForCallback(1);

    // queue another buffer so we query for frame event deltas
    nsecs_t requestedPresentTimeB = 0;
    nsecs_t postedTimeB = 0;
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeB, &postedTimeB, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);

    // frame number, requestedPresentTime, and postTime should not have changed
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    ASSERT_GE(events->latchTime, postedTimeA);
    ASSERT_GE(events->dequeueReadyTime, events->latchTime);
    ASSERT_NE(nullptr, events->gpuCompositionDoneFence);
    ASSERT_NE(nullptr, events->displayPresentFence);
    ASSERT_NE(nullptr, events->releaseFence);

    // we should also have gotten the initial values for the next frame
    events = history.getFrame(2);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(2, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeB, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeB);

    // wait for any callbacks that have not been received
    adapter.waitForCallbacks();
}

TEST_F(BLASTFrameEventHistoryTest, FrameEventHistory_DroppedFrame) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    ProducerFrameEventHistory history;
    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    nsecs_t requestedPresentTimeA = 0;
    nsecs_t postedTimeA = 0;
    // Present the frame sometime in the future so we can add two frames to the queue so the older
    // one will be dropped.
    nsecs_t presentTime = systemTime() + std::chrono::nanoseconds(500ms).count();
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeA, &postedTimeA, &qbOutput, true,
                        presentTime);
    history.applyDelta(qbOutput.frameTimestamps);

    FrameEvents* events = nullptr;
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    // queue another buffer so the first can be dropped
    nsecs_t requestedPresentTimeB = 0;
    nsecs_t postedTimeB = 0;
    presentTime = systemTime() + std::chrono::nanoseconds(1ms).count();
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeB, &postedTimeB, &qbOutput, true,
                        presentTime);
    history.applyDelta(qbOutput.frameTimestamps);
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);

    // frame number, requestedPresentTime, and postTime should not have changed
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    // a valid latchtime and pre and post composition info should not be set for the dropped frame
    ASSERT_FALSE(events->hasLatchInfo());
    ASSERT_FALSE(events->hasDequeueReadyInfo());
    ASSERT_FALSE(events->hasGpuCompositionDoneInfo());
    ASSERT_FALSE(events->hasDisplayPresentInfo());
    ASSERT_FALSE(events->hasReleaseInfo());

    // wait for the last transaction to be completed.
    adapter.waitForCallback(2);

    // queue another buffer so we query for frame event deltas
    nsecs_t requestedPresentTimeC = 0;
    nsecs_t postedTimeC = 0;
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeC, &postedTimeC, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);

    // frame number, requestedPresentTime, and postTime should not have changed
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    // a valid latchtime and pre and post composition info should not be set for the dropped frame
    ASSERT_FALSE(events->hasLatchInfo());
    ASSERT_FALSE(events->hasDequeueReadyInfo());
    ASSERT_FALSE(events->hasGpuCompositionDoneInfo());
    ASSERT_FALSE(events->hasDisplayPresentInfo());
    ASSERT_FALSE(events->hasReleaseInfo());

    // we should also have gotten values for the presented frame
    events = history.getFrame(2);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(2, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeB, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeB);
    ASSERT_GE(events->latchTime, postedTimeB);
    ASSERT_GE(events->dequeueReadyTime, events->latchTime);
    ASSERT_NE(nullptr, events->gpuCompositionDoneFence);
    ASSERT_NE(nullptr, events->displayPresentFence);
    ASSERT_NE(nullptr, events->releaseFence);

    // wait for any callbacks that have not been received
    adapter.waitForCallbacks();
}

TEST_F(BLASTFrameEventHistoryTest, FrameEventHistory_CompositorTimings) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    ProducerFrameEventHistory history;
    setUpProducer(adapter, igbProducer);

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    nsecs_t requestedPresentTimeA = 0;
    nsecs_t postedTimeA = 0;
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeA, &postedTimeA, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);
    adapter.waitForCallback(1);

    // queue another buffer so we query for frame event deltas
    nsecs_t requestedPresentTimeB = 0;
    nsecs_t postedTimeB = 0;
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeB, &postedTimeB, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);

    // check for a valid compositor deadline
    ASSERT_NE(0, history.getReportedCompositeDeadline());

    // wait for any callbacks that have not been received
    adapter.waitForCallbacks();
}

} // namespace android
