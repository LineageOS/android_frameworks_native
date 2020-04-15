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
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <ui/DisplayConfig.h>
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
        mBlastBufferQueueAdapter = new BLASTBufferQueue(sc, width, height);
    }

    void update(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter->update(sc, width, height);
    }

    void setNextTransaction(Transaction* next) {
        mBlastBufferQueueAdapter->setNextTransaction(next);
    }

    int getWidth() { return mBlastBufferQueueAdapter->mWidth; }

    int getHeight() { return mBlastBufferQueueAdapter->mHeight; }

    Transaction* getNextTransaction() { return mBlastBufferQueueAdapter->mNextTransaction; }

    sp<IGraphicBufferProducer> getIGraphicBufferProducer() {
        return mBlastBufferQueueAdapter->getIGraphicBufferProducer();
    }

    const sp<SurfaceControl> getSurfaceControl() {
        return mBlastBufferQueueAdapter->mSurfaceControl;
    }

    void waitForCallbacks() {
        std::unique_lock lock{mBlastBufferQueueAdapter->mMutex};
        while (mBlastBufferQueueAdapter->mSubmitted.size() > 0) {
            mBlastBufferQueueAdapter->mCallbackCV.wait(lock);
        }
    }

private:
    sp<BLASTBufferQueue> mBlastBufferQueueAdapter;
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

        DisplayConfig config;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(mDisplayToken, &config));
        const ui::Size& resolution = config.resolution;
        mDisplayWidth = resolution.getWidth();
        mDisplayHeight = resolution.getHeight();

        mSurfaceControl = mClient->createSurface(String8("TestSurface"), mDisplayWidth,
                                                 mDisplayHeight, PIXEL_FORMAT_RGBA_8888,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState,
                                                 /*parent*/ nullptr);
        t.setLayerStack(mSurfaceControl, 0)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .setFrame(mSurfaceControl, Rect(resolution))
                .show(mSurfaceControl)
                .setDataspace(mSurfaceControl, ui::Dataspace::V0_SRGB)
                .apply();
    }

    void setUpProducer(BLASTBufferQueueHelper adapter, sp<IGraphicBufferProducer>& producer) {
        auto igbProducer = adapter.getIGraphicBufferProducer();
        ASSERT_NE(nullptr, igbProducer.get());
        ASSERT_EQ(NO_ERROR, igbProducer->setMaxDequeuedBufferCount(2));
        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        ASSERT_EQ(NO_ERROR,
                  igbProducer->connect(new DummyProducerListener, NATIVE_WINDOW_API_CPU, false,
                                       &qbOutput));
        ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);
        producer = igbProducer;
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
        const auto epsilon = 3;
        const auto width = mScreenCaptureBuf->getWidth();
        const auto height = mScreenCaptureBuf->getHeight();
        const auto stride = mScreenCaptureBuf->getStride();

        uint32_t* bufData;
        mScreenCaptureBuf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_READ_OFTEN),
                                reinterpret_cast<void**>(&bufData));

        for (uint32_t row = 0; row < height; row++) {
            for (uint32_t col = 0; col < width; col++) {
                uint8_t* pixel = (uint8_t*)(bufData + (row * stride) + col);
                bool inRegion;
                if (!outsideRegion) {
                    inRegion = row >= region.top + border && row < region.bottom - border &&
                            col >= region.left + border && col < region.right - border;
                } else {
                    inRegion = row >= region.top - border && row < region.bottom + border &&
                            col >= region.left - border && col < region.right + border;
                }
                if (!outsideRegion && inRegion) {
                    EXPECT_GE(epsilon, abs(r - *(pixel)));
                    EXPECT_GE(epsilon, abs(g - *(pixel + 1)));
                    EXPECT_GE(epsilon, abs(b - *(pixel + 2)));
                } else if (outsideRegion && !inRegion) {
                    EXPECT_GE(epsilon, abs(r - *(pixel)));
                    EXPECT_GE(epsilon, abs(g - *(pixel + 1)));
                    EXPECT_GE(epsilon, abs(b - *(pixel + 2)));
                }
            }
        }
        mScreenCaptureBuf->unlock();
        ASSERT_EQ(false, ::testing::Test::HasFailure());
    }

    sp<SurfaceComposerClient> mClient;
    sp<ISurfaceComposer> mComposer;

    sp<IBinder> mDisplayToken;

    sp<SurfaceControl> mSurfaceControl;
    sp<GraphicBuffer> mScreenCaptureBuf;

    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;
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
    ASSERT_EQ(mDisplayWidth / 2, adapter.getWidth());
    ASSERT_EQ(mDisplayHeight / 2, adapter.getHeight());
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
    IGraphicBufferProducer::QueueBufferInput input(desiredPresentTime, false, HAL_DATASPACE_UNKNOWN,
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
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), false, HAL_DATASPACE_UNKNOWN,
                                                   Rect(mDisplayWidth, mDisplayHeight),
                                                   NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();

    // capture screen and verify that it is red
    bool capturedSecureLayers;
    ASSERT_EQ(NO_ERROR,
              mComposer->captureScreen(mDisplayToken, &mScreenCaptureBuf, capturedSecureLayers,
                                       ui::Dataspace::V0_SRGB, ui::PixelFormat::RGBA_8888, Rect(),
                                       mDisplayWidth, mDisplayHeight,
                                       /*useIdentityTransform*/ false));
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
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), false, HAL_DATASPACE_UNKNOWN,
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
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), false, HAL_DATASPACE_UNKNOWN,
                                                   Rect(mDisplayWidth, mDisplayHeight / 2),
                                                   NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();
    // capture screen and verify that it is red
    bool capturedSecureLayers;
    ASSERT_EQ(NO_ERROR,
              mComposer->captureScreen(mDisplayToken, &mScreenCaptureBuf, capturedSecureLayers,
                                       ui::Dataspace::V0_SRGB, ui::PixelFormat::RGBA_8888, Rect(),
                                       mDisplayWidth, mDisplayHeight,
                                       /*useIdentityTransform*/ false));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b, {0, 0, (int32_t)mDisplayWidth, (int32_t)mDisplayHeight}));
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
            .setCrop_legacy(bg, Rect(0, 0, mDisplayWidth, mDisplayHeight))
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
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), false, HAL_DATASPACE_UNKNOWN,
                                                   Rect(bufferSideLength, finalCropSideLength),
                                                   NATIVE_WINDOW_SCALING_MODE_SCALE_CROP, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

    adapter.waitForCallbacks();
    // capture screen and verify that it is red
    bool capturedSecureLayers;
    ASSERT_EQ(NO_ERROR,
              mComposer->captureScreen(mDisplayToken, &mScreenCaptureBuf, capturedSecureLayers,
                                       ui::Dataspace::V0_SRGB, ui::PixelFormat::RGBA_8888, Rect(),
                                       mDisplayWidth, mDisplayHeight,
                                       /*useIdentityTransform*/ false));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(r, g, b,
                               {0, 0, (int32_t)bufferSideLength, (int32_t)bufferSideLength}));
    ASSERT_NO_FATAL_FAILURE(
            checkScreenCapture(0, 0, 0,
                               {0, 0, (int32_t)bufferSideLength, (int32_t)bufferSideLength},
                               /*border*/ 0, /*outsideRegion*/ true));
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
        IGraphicBufferProducer::QueueBufferInput input(systemTime(), false, HAL_DATASPACE_UNKNOWN,
                                                       Rect(bufWidth, bufHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, tr,
                                                       Fence::NO_FENCE);
        igbProducer->queueBuffer(slot, input, &qbOutput);
        ASSERT_NE(ui::Transform::ROT_INVALID, qbOutput.transformHint);

        adapter.waitForCallbacks();
        bool capturedSecureLayers;
        ASSERT_EQ(NO_ERROR,
                  mComposer->captureScreen(mDisplayToken, &mScreenCaptureBuf, capturedSecureLayers,
                                           ui::Dataspace::V0_SRGB, ui::PixelFormat::RGBA_8888,
                                           Rect(), mDisplayWidth, mDisplayHeight,
                                           /*useIdentityTransform*/ false));
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
                             bool getFrameTimestamps) {
        int slot;
        sp<Fence> fence;
        sp<GraphicBuffer> buf;
        auto ret = igbProducer->dequeueBuffer(&slot, &fence, mDisplayWidth, mDisplayHeight,
                                              PIXEL_FORMAT_RGBA_8888, GRALLOC_USAGE_SW_WRITE_OFTEN,
                                              nullptr, nullptr);
        ASSERT_EQ(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION, ret);
        ASSERT_EQ(OK, igbProducer->requestBuffer(slot, &buf));

        nsecs_t requestedTime = systemTime();
        if (requestedPresentTime) *requestedPresentTime = requestedTime;
        IGraphicBufferProducer::QueueBufferInput input(requestedTime, false, HAL_DATASPACE_UNKNOWN,
                                                       Rect(mDisplayWidth, mDisplayHeight),
                                                       NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                       Fence::NO_FENCE, /*sticky*/ 0,
                                                       getFrameTimestamps);
        if (postedTime) *postedTime = systemTime();
        igbProducer->queueBuffer(slot, input, qbOutput);
    }
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

    adapter.waitForCallbacks();

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
} // namespace android
