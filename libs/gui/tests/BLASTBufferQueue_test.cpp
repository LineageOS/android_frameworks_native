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
#include <private/gui/ComposerService.h>
#include <ui/DisplayMode.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include <gtest/gtest.h>

using namespace std::chrono_literals;

namespace android {

using Transaction = SurfaceComposerClient::Transaction;
using android::hardware::graphics::common::V1_2::BufferUsage;

class BLASTBufferQueueHelper {
public:
    BLASTBufferQueueHelper(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter = new BLASTBufferQueue("TestBLASTBufferQueue", sc, width, height,
                                                        PIXEL_FORMAT_RGBA_8888);
    }

    void update(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter->update(sc, width, height, PIXEL_FORMAT_RGBA_8888);
    }

    void setNextTransaction(Transaction* next) {
        mBlastBufferQueueAdapter->setNextTransaction(next);
    }

    int getWidth() { return mBlastBufferQueueAdapter->mSize.width; }

    int getHeight() { return mBlastBufferQueueAdapter->mSize.height; }

    Transaction* getNextTransaction() { return mBlastBufferQueueAdapter->mNextTransaction; }

    sp<IGraphicBufferProducer> getIGraphicBufferProducer() {
        return mBlastBufferQueueAdapter->getIGraphicBufferProducer();
    }

    const sp<SurfaceControl> getSurfaceControl() {
        return mBlastBufferQueueAdapter->mSurfaceControl;
    }

    void waitForCallbacks() {
        std::unique_lock lock{mBlastBufferQueueAdapter->mMutex};
        // Wait until all but one of the submitted buffers have been released.
        while (mBlastBufferQueueAdapter->mSubmitted.size() > 1) {
            mBlastBufferQueueAdapter->mCallbackCV.wait(lock);
        }
    }

    void setTransactionCompleteCallback(int64_t frameNumber) {
        mBlastBufferQueueAdapter->setTransactionCompleteCallback(frameNumber, [&](int64_t frame) {
            std::unique_lock lock{mMutex};
            mLastTransactionCompleteFrameNumber = frame;
            mCallbackCV.notify_all();
        });
    }

    void waitForCallback(int64_t frameNumber) {
        std::unique_lock lock{mMutex};
        // Wait until all but one of the submitted buffers have been released.
        while (mLastTransactionCompleteFrameNumber < frameNumber) {
            mCallbackCV.wait(lock);
        }
    }

private:
    sp<BLASTBufferQueue> mBlastBufferQueueAdapter;

    std::mutex mMutex;
    std::condition_variable mCallbackCV;
    int64_t mLastTransactionCompleteFrameNumber = -1;
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
        t.setDisplayLayerStack(mDisplayToken, 0);
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
        t.setLayerStack(mSurfaceControl, 0)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .show(mSurfaceControl)
                .setDataspace(mSurfaceControl, ui::Dataspace::V0_SRGB)
                .apply();

        mCaptureArgs.displayToken = mDisplayToken;
        mCaptureArgs.dataspace = ui::Dataspace::V0_SRGB;
    }

    void setUpProducer(BLASTBufferQueueHelper& adapter, sp<IGraphicBufferProducer>& producer) {
        producer = adapter.getIGraphicBufferProducer();
        setUpProducer(producer);
    }

    void setUpProducer(sp<IGraphicBufferProducer>& igbProducer) {
        ASSERT_NE(nullptr, igbProducer.get());
        ASSERT_EQ(NO_ERROR, igbProducer->setMaxDequeuedBufferCount(2));
        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        ASSERT_EQ(NO_ERROR,
                  igbProducer->connect(new StubProducerListener, NATIVE_WINDOW_API_CPU, false,
                                       &qbOutput));
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
        const auto sf = ComposerService::getComposerService();
        SurfaceComposerClient::Transaction().apply(true);

        const sp<SyncScreenCaptureListener> captureListener = new SyncScreenCaptureListener();
        status_t status = sf->captureDisplay(captureArgs, captureListener);
        if (status != NO_ERROR) {
            return status;
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
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
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
};

TEST_F(BLASTBufferQueueTest, CreateBLASTBufferQueue) {
    // create BLASTBufferQueue adapter associated with this surface
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    ASSERT_EQ(mSurfaceControl, adapter.getSurfaceControl());
    ASSERT_EQ(mDisplayWidth, adapter.getWidth());
    ASSERT_EQ(mDisplayHeight, adapter.getHeight());
    ASSERT_EQ(nullptr, adapter.getNextTransaction());
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

TEST_F(BLASTBufferQueueTest, SetNextTransaction) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    Transaction next;
    adapter.setNextTransaction(&next);
    ASSERT_EQ(&next, adapter.getNextTransaction());
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
    for (int i = 0; i < 3; i++) {
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
    t.setLayerStack(bg, 0)
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

    Rect bounds;
    bounds.left = finalCropSideLength / 2;
    bounds.top = 0;
    bounds.right = bounds.left + finalCropSideLength;
    bounds.bottom = finalCropSideLength;

    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(r, g, b, bounds));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(0, 0, 0, bounds, /*border*/ 0, /*outsideRegion*/ true));
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
    t.setLayerStack(bgSurface, 0)
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
                             nsecs_t* requestedPresentTime, nsecs_t* postedTime,
                             IGraphicBufferProducer::QueueBufferOutput* qbOutput,
                             bool getFrameTimestamps, nsecs_t requestedPresentTimeDelay = 0) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

        nsecs_t requestedTime = systemTime() + requestedPresentTimeDelay;
        if (requestedPresentTime) *requestedPresentTime = requestedTime;
        IGraphicBufferProducer::QueueBufferInput input(requestedTime, false, HAL_DATASPACE_UNKNOWN,
                                                       Rect(mDisplayWidth, mDisplayHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE, /*sticky*/ 0,
                                                       getFrameTimestamps);
        if (postedTime) *postedTime = systemTime();
        igbProducer->queueBuffer(slot, input, qbOutput);
    }

    void createBufferQueueProducer(sp<IGraphicBufferProducer>* bqIgbp) {
        mBufferQueueSurfaceControl =
                mClient->createSurface(String8("BqSurface"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                       ISurfaceComposerClient::eFXSurfaceBufferQueue);
        ASSERT_NE(nullptr, mBufferQueueSurfaceControl.get());
        Transaction()
                .setLayerStack(mBufferQueueSurfaceControl, 0)
                .show(mBufferQueueSurfaceControl)
                .setDataspace(mBufferQueueSurfaceControl, ui::Dataspace::V0_SRGB)
                .setSize(mBufferQueueSurfaceControl, mDisplayWidth, mDisplayHeight)
                .setLayer(mBufferQueueSurfaceControl, std::numeric_limits<int32_t>::max())
                .apply();

        sp<Surface> bqSurface = mBufferQueueSurfaceControl->getSurface();
        ASSERT_NE(nullptr, bqSurface.get());

        *bqIgbp = bqSurface->getIGraphicBufferProducer();
        setUpProducer(*bqIgbp);
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
    adapter.setTransactionCompleteCallback(1);
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

// Runs the same Frame Event History test
TEST_F(BLASTFrameEventHistoryTest, FrameEventHistory_Basic_BufferQueue) {
    sp<IGraphicBufferProducer> bqIgbp;
    createBufferQueueProducer(&bqIgbp);

    ProducerFrameEventHistory history;
    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    nsecs_t requestedPresentTimeA = 0;
    nsecs_t postedTimeA = 0;
    setUpAndQueueBuffer(bqIgbp, &requestedPresentTimeA, &postedTimeA, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);

    FrameEvents* events = nullptr;
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    // wait for buffer to be presented
    std::this_thread::sleep_for(200ms);

    nsecs_t requestedPresentTimeB = 0;
    nsecs_t postedTimeB = 0;
    setUpAndQueueBuffer(bqIgbp, &requestedPresentTimeB, &postedTimeB, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);

    // frame number, requestedPresentTime, and postTime should not have changed
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    ASSERT_GE(events->latchTime, postedTimeA);
    ASSERT_FALSE(events->hasDequeueReadyInfo());

    ASSERT_NE(nullptr, events->gpuCompositionDoneFence);
    ASSERT_NE(nullptr, events->displayPresentFence);
    ASSERT_NE(nullptr, events->releaseFence);

    // we should also have gotten the initial values for the next frame
    events = history.getFrame(2);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(2, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeB, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeB);
}

TEST_F(BLASTFrameEventHistoryTest, FrameEventHistory_DroppedFrame) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, mDisplayWidth, mDisplayHeight);
    sp<IGraphicBufferProducer> igbProducer;
    setUpProducer(adapter, igbProducer);

    ProducerFrameEventHistory history;
    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    nsecs_t requestedPresentTimeA = 0;
    nsecs_t postedTimeA = 0;
    nsecs_t presentTimeDelay = std::chrono::nanoseconds(500ms).count();
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeA, &postedTimeA, &qbOutput, true,
                        presentTimeDelay);
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
    setUpAndQueueBuffer(igbProducer, &requestedPresentTimeB, &postedTimeB, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);

    // frame number, requestedPresentTime, and postTime should not have changed
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    // a valid latchtime should not be set
    ASSERT_FALSE(events->hasLatchInfo());
    ASSERT_FALSE(events->hasDequeueReadyInfo());

    ASSERT_NE(nullptr, events->gpuCompositionDoneFence);
    ASSERT_NE(nullptr, events->displayPresentFence);
    ASSERT_NE(nullptr, events->releaseFence);

    // we should also have gotten the initial values for the next frame
    events = history.getFrame(2);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(2, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeB, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeB);
}

TEST_F(BLASTFrameEventHistoryTest, FrameEventHistory_DroppedFrame_BufferQueue) {
    sp<IGraphicBufferProducer> bqIgbp;
    createBufferQueueProducer(&bqIgbp);

    ProducerFrameEventHistory history;
    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    nsecs_t requestedPresentTimeA = 0;
    nsecs_t postedTimeA = 0;
    nsecs_t presentTimeDelay = std::chrono::nanoseconds(500ms).count();
    setUpAndQueueBuffer(bqIgbp, &requestedPresentTimeA, &postedTimeA, &qbOutput, true,
                        presentTimeDelay);
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
    setUpAndQueueBuffer(bqIgbp, &requestedPresentTimeB, &postedTimeB, &qbOutput, true);
    history.applyDelta(qbOutput.frameTimestamps);
    events = history.getFrame(1);
    ASSERT_NE(nullptr, events);

    // frame number, requestedPresentTime, and postTime should not have changed
    ASSERT_EQ(1, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeA, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeA);

    // a valid latchtime should not be set
    ASSERT_FALSE(events->hasLatchInfo());
    ASSERT_FALSE(events->hasDequeueReadyInfo());

    ASSERT_NE(nullptr, events->gpuCompositionDoneFence);
    ASSERT_NE(nullptr, events->displayPresentFence);
    ASSERT_NE(nullptr, events->releaseFence);

    // we should also have gotten the initial values for the next frame
    events = history.getFrame(2);
    ASSERT_NE(nullptr, events);
    ASSERT_EQ(2, events->frameNumber);
    ASSERT_EQ(requestedPresentTimeB, events->requestedPresentTime);
    ASSERT_GE(events->postedTime, postedTimeB);
}

} // namespace android
