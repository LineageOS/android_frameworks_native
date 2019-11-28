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
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <ui/DisplayInfo.h>
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
        while (mBlastBufferQueueAdapter->mPendingCallbacks > 0) {
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

        DisplayInfo info;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayInfo(mDisplayToken, &info));
        mDisplayWidth = info.w;
        mDisplayHeight = info.h;

        mSurfaceControl = mClient->createSurface(String8("TestSurface"), mDisplayWidth,
                                                 mDisplayHeight, PIXEL_FORMAT_RGBA_8888,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState,
                                                 /*parent*/ nullptr);
        t.setLayerStack(mSurfaceControl, 0)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .setFrame(mSurfaceControl, Rect(0, 0, mDisplayWidth, mDisplayHeight))
                .show(mSurfaceControl)
                .setDataspace(mSurfaceControl, ui::Dataspace::V0_SRGB)
                .apply();
    }

    void setUpProducer(BLASTBufferQueueHelper adapter, sp<IGraphicBufferProducer>& producer) {
        auto igbProducer = adapter.getIGraphicBufferProducer();
        ASSERT_NE(nullptr, igbProducer.get());
        IGraphicBufferProducer::QueueBufferOutput qbOutput;
        ASSERT_EQ(NO_ERROR,
                  igbProducer->connect(new DummyProducerListener, NATIVE_WINDOW_API_CPU, false,
                                       &qbOutput));
        ASSERT_NE(ui::Transform::orientation_flags::ROT_INVALID, qbOutput.transformHint);
        producer = igbProducer;
    }

    void fillBuffer(uint32_t* bufData, uint32_t width, uint32_t height, uint32_t stride, uint8_t r,
                    uint8_t g, uint8_t b) {
        for (uint32_t row = 0; row < height; row++) {
            for (uint32_t col = 0; col < width; col++) {
                uint8_t* pixel = (uint8_t*)(bufData + (row * stride) + col);
                *pixel = r;
                *(pixel + 1) = g;
                *(pixel + 2) = b;
                *(pixel + 3) = 255;
            }
        }
    }

    void checkScreenCapture(uint8_t r, uint8_t g, uint8_t b) {
        const auto width = mScreenCaptureBuf->getWidth();
        const auto height = mScreenCaptureBuf->getHeight();
        const auto stride = mScreenCaptureBuf->getStride();

        uint32_t* bufData;
        mScreenCaptureBuf->lock(static_cast<uint32_t>(GraphicBuffer::USAGE_SW_READ_OFTEN),
                                reinterpret_cast<void**>(&bufData));

        for (uint32_t row = 0; row < height; row++) {
            for (uint32_t col = 0; col < width; col++) {
                uint8_t* pixel = (uint8_t*)(bufData + (row * stride) + col);
                EXPECT_EQ(r, *(pixel));
                EXPECT_EQ(g, *(pixel + 1));
                EXPECT_EQ(b, *(pixel + 2));
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
    fillBuffer(bufData, buf->getWidth(), buf->getHeight(), buf->getStride(), r, g, b);
    buf->unlock();

    IGraphicBufferProducer::QueueBufferOutput qbOutput;
    IGraphicBufferProducer::QueueBufferInput input(systemTime(), false, HAL_DATASPACE_UNKNOWN,
                                                   Rect(mDisplayWidth, mDisplayHeight),
                                                   NATIVE_WINDOW_SCALING_MODE_FREEZE, 0,
                                                   Fence::NO_FENCE);
    igbProducer->queueBuffer(slot, input, &qbOutput);
    ASSERT_NE(ui::Transform::orientation_flags::ROT_INVALID, qbOutput.transformHint);

    sleep(1);

    // capture screen and verify that it is red
    bool capturedSecureLayers;
    ASSERT_EQ(NO_ERROR,
              mComposer->captureScreen(mDisplayToken, &mScreenCaptureBuf, capturedSecureLayers,
                                       ui::Dataspace::V0_SRGB, ui::PixelFormat::RGBA_8888, Rect(),
                                       mDisplayWidth, mDisplayHeight,
                                       /*useIdentityTransform*/ false));
    ASSERT_NO_FATAL_FAILURE(checkScreenCapture(r, g, b));
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

    for (int i = 0; i < 10; i++) {
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
} // namespace android
