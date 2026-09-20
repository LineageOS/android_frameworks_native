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

#include <gtest/gtest.h>

#include <SurfaceFlingerProperties.h>
#include <android/gui/IActivePictureListener.h>
#include <android/gui/IDisplayEventConnection.h>
#include <android/gui/ISurfaceComposer.h>
#include <android/hardware_buffer.h>
#include <android/native_window.h>
#include <binder/ProcessState.h>
#include <com_android_graphics_libgui_flags.h>
#include <gui/AidlUtil.h>
#include <gui/BufferItemConsumer.h>
#include <gui/BufferQueue.h>
#include <gui/CpuConsumer.h>
#include <gui/IConsumerListener.h>
#include <gui/IGraphicBufferConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>
#include <gui/ISurfaceComposer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SyncScreenCaptureListener.h>
#include <gui/TransactionState.h>
#include <gui/view/Surface.h>
#include <nativebase/nativebase.h>
#include <private/gui/ComposerService.h>
#include <private/gui/ComposerServiceAIDL.h>
#include <sys/types.h>
#include <system/window.h>
#include <ui/BufferQueueDefs.h>
#include <ui/DisplayMode.h>
#include <ui/GraphicBuffer.h>
#include <ui/PixelFormat.h>
#include <ui/Rect.h>
#include <utils/Errors.h>
#include <utils/String8.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <future>
#include <iterator>
#include <limits>
#include <thread>

#include "Constants.h"
#include "MockConsumer.h"
#include "hardware/gralloc.h"
#include "testserver/TestServerClient.h"

namespace android {

using namespace std::chrono_literals;
using aidl::android::hardware::graphics::common::DisplayDecorationSupport;
using gui::IDisplayEventConnection;
using gui::IRegionSamplingListener;
using ui::ColorMode;

using Transaction = SurfaceComposerClient::Transaction;

static bool hasWideColorDisplay = android::sysprop::has_wide_color_display(false);

static bool hasHdrDisplay = android::sysprop::has_HDR_display(false);

class FakeSurfaceComposer;
class FakeProducerFrameEventHistory;

static constexpr uint64_t NO_FRAME_INDEX = std::numeric_limits<uint64_t>::max();

class FakeSurfaceListener : public SurfaceListener {
public:
    FakeSurfaceListener(bool enableReleasedCb = false)
          : mEnableReleaseCb(enableReleasedCb), mBuffersReleased(0) {}
    virtual ~FakeSurfaceListener() = default;

    virtual void onBufferReleased() {
        mBuffersReleased++;
    }
    virtual bool needsReleaseNotify() {
        return mEnableReleaseCb;
    }
    virtual void onBuffersDiscarded(const std::vector<sp<GraphicBuffer>>& buffers) {
        mDiscardedBuffers.insert(mDiscardedBuffers.end(), buffers.begin(), buffers.end());
    }
    virtual void onBufferDetached(uint64_t /*bufferId*/) {}
    int getReleaseNotifyCount() const {
        return mBuffersReleased;
    }
    const std::vector<sp<GraphicBuffer>>& getDiscardedBuffers() const {
        return mDiscardedBuffers;
    }
private:
    // No need to use lock given the test triggers the listener in the same
    // thread context.
    bool mEnableReleaseCb;
    int32_t mBuffersReleased;
    std::vector<sp<GraphicBuffer>> mDiscardedBuffers;
};

class DeathWatcherListener : public StubSurfaceListener {
public:
    virtual void onRemoteDied() { mDiedPromise.set_value(true); }

    virtual bool needsDeathNotify() { return true; }

    std::future<bool> getDiedFuture() { return mDiedPromise.get_future(); }

private:
    std::promise<bool> mDiedPromise;
};

class SurfaceTest : public ::testing::Test {
protected:
    void testSurfaceListener(bool hasSurfaceListener, bool enableReleasedCb,
                             int32_t extraDiscardedBuffers) {
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);

        sp<MockConsumer> mockConsumer(new MockConsumer);
        consumer->consumerConnect(mockConsumer, false);
        consumer->setConsumerName(String8("TestConsumer"));

        sp<Surface> surface = new Surface(producer);
        sp<ANativeWindow> window(surface);
        sp<FakeSurfaceListener> listener;
        if (hasSurfaceListener) {
            listener = new FakeSurfaceListener(enableReleasedCb);
        }
        ASSERT_EQ(OK,
                  surface->connect(NATIVE_WINDOW_API_CPU,
                                   /*listener*/ listener,
                                   /*reportBufferRemoval*/ true));
        const int BUFFER_COUNT = 4 + extraDiscardedBuffers;
        ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(window.get(), BUFFER_COUNT));
        ASSERT_EQ(NO_ERROR, native_window_set_usage(window.get(), TEST_PRODUCER_USAGE_BITS));

        ANativeWindowBuffer* buffers[BUFFER_COUNT];
        // Dequeue first to allocate a number of buffers
        for (int i = 0; i < BUFFER_COUNT; i++) {
            ASSERT_EQ(NO_ERROR, native_window_dequeue_buffer_and_wait(window.get(), &buffers[i]));
        }
        for (int i = 0; i < BUFFER_COUNT; i++) {
            ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffers[i], -1));
        }

        ANativeWindowBuffer* buffer;
        // Fill BUFFER_COUNT-1 buffers
        for (int i = 0; i < BUFFER_COUNT - 1; i++) {
            ASSERT_EQ(NO_ERROR, native_window_dequeue_buffer_and_wait(window.get(), &buffer));
            ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, -1));
        }

        // Dequeue 1 buffer
        ASSERT_EQ(NO_ERROR, native_window_dequeue_buffer_and_wait(window.get(), &buffer));

        // Acquire and free 1+extraDiscardedBuffers buffer, check onBufferReleased is called.
        std::vector<BufferItem> releasedItems;
        releasedItems.resize(1 + extraDiscardedBuffers);
        for (size_t i = 0; i < releasedItems.size(); i++) {
            ASSERT_EQ(NO_ERROR, consumer->acquireBuffer(&releasedItems[i], 0));
            ASSERT_EQ(NO_ERROR,
                      consumer->releaseBuffer(releasedItems[i].mSlot, releasedItems[i].mFrameNumber,
                                              Fence::NO_FENCE));
        }
        int32_t expectedReleaseCb = (enableReleasedCb ? releasedItems.size() : 0);
        if (hasSurfaceListener) {
            ASSERT_EQ(expectedReleaseCb, listener->getReleaseNotifyCount());
        }

        // Acquire 1 buffer, leaving 1+extraDiscardedBuffers filled buffer in queue
        BufferItem item;
        ASSERT_EQ(NO_ERROR, consumer->acquireBuffer(&item, 0));

        // Discard free buffers
        ASSERT_EQ(NO_ERROR, consumer->discardFreeBuffers());

        if (hasSurfaceListener) {
            ASSERT_EQ(expectedReleaseCb, listener->getReleaseNotifyCount());

            // Check onBufferDiscarded is called with correct buffer
            auto discardedBuffers = listener->getDiscardedBuffers();
            ASSERT_EQ(discardedBuffers.size(), releasedItems.size());
            for (size_t i = 0; i < releasedItems.size(); i++) {
                ASSERT_EQ(discardedBuffers[i], releasedItems[i].mGraphicBuffer);
            }

            ASSERT_EQ(expectedReleaseCb, listener->getReleaseNotifyCount());
        }

        // Disconnect the surface
        ASSERT_EQ(NO_ERROR, surface->disconnect(NATIVE_WINDOW_API_CPU));
    }
};

class SurfaceComposerSurfaceTest : public SurfaceTest {
protected:
    SurfaceComposerSurfaceTest() { ProcessState::self()->startThreadPool(); }

    virtual void SetUp() override {
        SurfaceTest::SetUp();

        mComposerClient = sp<SurfaceComposerClient>::make();
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

        // TODO(brianderson): The following sometimes fails and is a source of
        //   test flakiness.
        mSurfaceControl = mComposerClient->createSurface(String8("Test Surface"), 32, 32,
                                                         PIXEL_FORMAT_RGBA_8888, 0);
        SurfaceComposerClient::Transaction().apply(true);

        ASSERT_TRUE(mSurfaceControl != nullptr);
        ASSERT_TRUE(mSurfaceControl->isValid());

        Transaction t;
        ASSERT_EQ(NO_ERROR, t.setLayer(mSurfaceControl, 0x7fffffff).show(mSurfaceControl).apply());

        mSurface = mSurfaceControl->getSurface();
        ASSERT_TRUE(mSurface != nullptr);
    }

    virtual void TearDown() {
        SurfaceTest::TearDown();

        mComposerClient->dispose();
    }

    sp<Surface> mSurface;
    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mSurfaceControl;
};

TEST_F(SurfaceComposerSurfaceTest, CreateSurfaceReturnsErrorBadClient) {
    mComposerClient->dispose();
    ASSERT_EQ(NO_INIT, mComposerClient->initCheck());

    sp<SurfaceControl> sc;
    status_t err = mComposerClient->createSurfaceChecked(
            String8("Test Surface"), 32, 32, PIXEL_FORMAT_RGBA_8888, &sc, 0);
    ASSERT_EQ(NO_INIT, err);
}

TEST_F(SurfaceComposerSurfaceTest, QueuesToWindowComposerIsTrueWhenVisible) {
    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER,
            &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(1, result);
}

TEST_F(SurfaceComposerSurfaceTest, QueuesToWindowComposerIsTrueWhenPurgatorized) {
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

TEST_F(SurfaceComposerSurfaceTest, ConcreteTypeIsSurface) {
    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_CONCRETE_TYPE, &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(NATIVE_WINDOW_SURFACE, result);
}

TEST_F(SurfaceComposerSurfaceTest, LayerCountIsOne) {
    sp<ANativeWindow> anw(mSurface);
    int result = -123;
    int err = anw->query(anw.get(), NATIVE_WINDOW_LAYER_COUNT, &result);
    EXPECT_EQ(NO_ERROR, err);
    EXPECT_EQ(1, result);
}

TEST_F(SurfaceComposerSurfaceTest, QueryConsumerUsage) {
    const int TEST_USAGE_FLAGS =
            GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER;
    auto [c, s] = BufferItemConsumer::create(TEST_USAGE_FLAGS);
    sp<ANativeWindow> anw(s);

    int flags = -1;
    int err = anw->query(anw.get(), NATIVE_WINDOW_CONSUMER_USAGE_BITS, &flags);

    ASSERT_EQ(NO_ERROR, err);
    ASSERT_EQ(TEST_USAGE_FLAGS, flags);
}

TEST_F(SurfaceComposerSurfaceTest, QueryDefaultBuffersDataSpace) {
    const android_dataspace TEST_DATASPACE = HAL_DATASPACE_V0_SRGB;

    auto [cpuConsumer, s] = CpuConsumer::create(1);
    cpuConsumer->setDefaultBufferDataSpace(TEST_DATASPACE);
    sp<ANativeWindow> anw(s);

    android_dataspace dataSpace;

    int err = anw->query(anw.get(), NATIVE_WINDOW_DEFAULT_DATASPACE,
            reinterpret_cast<int*>(&dataSpace));

    ASSERT_EQ(NO_ERROR, err);
    ASSERT_EQ(TEST_DATASPACE, dataSpace);
}

TEST_F(SurfaceTest, SettingGenerationNumber) {
    auto [cpuConsumer, surface] = CpuConsumer::create(1);
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

TEST_F(SurfaceTest, GenerationNumberSurvivesReconnect) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);

    ASSERT_EQ(NO_ERROR, surface->connect(NATIVE_WINDOW_API_MEDIA, nullptr));
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(buffer, fence));
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&buffer, &fence));
    ASSERT_EQ(0U, buffer->getGenerationNumber());

    ASSERT_EQ(NO_ERROR, surface->setGenerationNumber(1));
    surface->setAutoGenerationUpdate(false);
    ASSERT_EQ(NO_ERROR, surface->disconnect(NATIVE_WINDOW_API_MEDIA));
    ASSERT_EQ(NO_ERROR, surface->connect(NATIVE_WINDOW_API_MEDIA, nullptr));

    // Reconnect must preserve the generation and re-enable automatic updates.
    ASSERT_EQ(NO_ERROR, surface->attachBuffer(buffer));
    ASSERT_EQ(1U, buffer->getGenerationNumber());
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(buffer, fence));
    ASSERT_EQ(NO_ERROR, surface->disconnect(NATIVE_WINDOW_API_MEDIA));
}

TEST_F(SurfaceTest, AutoGenerationUpdate) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);

    // Allocate a buffer.
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(NO_ERROR, surface->connect(NATIVE_WINDOW_API_CPU, nullptr));
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(buffer, fence));

    // Detach the buffer and check its generation number.
    sp<GraphicBuffer> graphicBuffer;
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&graphicBuffer, &fence));
    ASSERT_EQ(0U, graphicBuffer->getGenerationNumber());

    // Auto-generation is on by default. Attaching should update the generation number.
    ASSERT_EQ(NO_ERROR, surface->setGenerationNumber(1));
    ASSERT_EQ(NO_ERROR, surface->attachBuffer(graphicBuffer));
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(graphicBuffer, fence));
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(1U, buffer->getGenerationNumber());
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(buffer, fence));
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&graphicBuffer, &fence));
    ASSERT_EQ(1U, graphicBuffer->getGenerationNumber());

    // Turn auto-generation off. Attaching should not update the generation number. And,
    // importantly, attaching should fail for generation number mismatch.
    surface->setAutoGenerationUpdate(false);
    ASSERT_EQ(NO_ERROR, surface->setGenerationNumber(2));
    ASSERT_EQ(BAD_VALUE, surface->attachBuffer(graphicBuffer));

    graphicBuffer->setGenerationNumber(2);
    ASSERT_EQ(NO_ERROR, surface->attachBuffer(graphicBuffer));
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(graphicBuffer, fence));

    ASSERT_EQ(NO_ERROR, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(2U, buffer->getGenerationNumber());
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(buffer, fence));
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&graphicBuffer, &fence));
    ASSERT_EQ(2U, graphicBuffer->getGenerationNumber());

    // Turn auto-generation back on. Attaching should update the generation number again.
    surface->setAutoGenerationUpdate(true);
    ASSERT_EQ(NO_ERROR, surface->setGenerationNumber(3));
    ASSERT_EQ(NO_ERROR, surface->attachBuffer(graphicBuffer));
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(graphicBuffer, fence));
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(3U, buffer->getGenerationNumber());
    ASSERT_EQ(NO_ERROR, surface->cancelBuffer(buffer, fence));
}

TEST_F(SurfaceTest, GetConsumerName) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU);

    EXPECT_STREQ("TestConsumer", surface->getConsumerName().c_str());
}

TEST_F(SurfaceTest, GetWideColorSupport) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU);

    bool supported;
    surface->getWideColorSupport(&supported);

    // NOTE: This test assumes that device that supports
    // wide-color (as indicated by BoardConfig) must also
    // have a wide-color primary display.
    // That assumption allows this test to cover devices
    // that advertised a wide-color color mode without
    // actually supporting wide-color to pass this test
    // as well as the case of a device that does support
    // wide-color (via BoardConfig) and has a wide-color
    // primary display.
    // NOT covered at this time is a device that supports
    // wide color in the BoardConfig but does not support
    // a wide-color color mode on the primary display.
    ASSERT_EQ(hasWideColorDisplay, supported);
}

TEST_F(SurfaceTest, GetHdrSupport) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU);

    bool supported;
    status_t result = surface->getHdrSupport(&supported);
    ASSERT_EQ(NO_ERROR, result);

    // NOTE: This is not a CTS test.
    // This test verifies that when the BoardConfig TARGET_HAS_HDR_DISPLAY
    // is TRUE, getHdrSupport is also true.
    // TODO: Add check for an HDR color mode on the primary display.
    ASSERT_EQ(hasHdrDisplay, supported);
}

TEST_F(SurfaceTest, SetHdrMetadata) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU);

    bool supported;
    status_t result = surface->getHdrSupport(&supported);
    ASSERT_EQ(NO_ERROR, result);

    if (!hasHdrDisplay || !supported) {
        return;
    }
    const android_smpte2086_metadata smpte2086 = {
        {0.680, 0.320},
        {0.265, 0.690},
        {0.150, 0.060},
        {0.3127, 0.3290},
        100.0,
        0.1,
    };
    const android_cta861_3_metadata cta861_3 = {
        78.0,
        62.0,
    };

    std::vector<uint8_t> hdr10plus;
    hdr10plus.push_back(0xff);

    int error = native_window_set_buffers_smpte2086_metadata(window.get(), &smpte2086);
    ASSERT_EQ(error, NO_ERROR);
    error = native_window_set_buffers_cta861_3_metadata(window.get(), &cta861_3);
    ASSERT_EQ(error, NO_ERROR);
    error = native_window_set_buffers_hdr10_plus_metadata(window.get(), hdr10plus.size(),
                                                          hdr10plus.data());
    ASSERT_EQ(error, NO_ERROR);
}

TEST_F(SurfaceTest, DynamicSetBufferCount) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);

    ASSERT_EQ(NO_ERROR, native_window_api_connect(window.get(),
            NATIVE_WINDOW_API_CPU));
    ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(window.get(), 4));
    ASSERT_EQ(NO_ERROR, native_window_set_usage(window.get(), TEST_PRODUCER_USAGE_BITS));

    int fence;
    ANativeWindowBuffer* buffer;
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    native_window_set_buffer_count(window.get(), 3);
    ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, fence));
    native_window_set_buffer_count(window.get(), 2);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, fence));
}

TEST_F(SurfaceTest, GetAndFlushRemovedBuffers) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setConsumerName(String8("TestConsumer"));

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    sp<StubSurfaceListener> listener = new StubSurfaceListener();
    ASSERT_EQ(OK,
              surface->connect(NATIVE_WINDOW_API_CPU,
                               /*listener*/ listener,
                               /*reportBufferRemoval*/ true));
    const int BUFFER_COUNT = 4;
    ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(window.get(), BUFFER_COUNT));
    ASSERT_EQ(NO_ERROR, native_window_set_usage(window.get(), TEST_PRODUCER_USAGE_BITS));

    sp<GraphicBuffer> detachedBuffer;
    sp<Fence> outFence;
    int fences[BUFFER_COUNT];
    ANativeWindowBuffer* buffers[BUFFER_COUNT];
    // Allocate buffers because detachNextBuffer requires allocated buffers
    for (int i = 0; i < BUFFER_COUNT; i++) {
        ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffers[i], &fences[i]));
    }
    for (int i = 0; i < BUFFER_COUNT; i++) {
        ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffers[i], fences[i]));
    }

    // Test detached buffer is correctly reported
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&detachedBuffer, &outFence));
    std::vector<sp<GraphicBuffer>> removedBuffers;
    ASSERT_EQ(OK, surface->getAndFlushRemovedBuffers(&removedBuffers));
    ASSERT_EQ(1u, removedBuffers.size());
    ASSERT_EQ(detachedBuffer->handle, removedBuffers.at(0)->handle);
    // Test the list is flushed one getAndFlushRemovedBuffers returns
    ASSERT_EQ(OK, surface->getAndFlushRemovedBuffers(&removedBuffers));
    ASSERT_EQ(0u, removedBuffers.size());


    // Test removed buffer list is cleanup after next dequeueBuffer call
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&detachedBuffer, &outFence));
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffers[0], &fences[0]));
    ASSERT_EQ(OK, surface->getAndFlushRemovedBuffers(&removedBuffers));
    ASSERT_EQ(0u, removedBuffers.size());
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffers[0], fences[0]));

    // Test removed buffer list is cleanup after next detachNextBuffer call
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&detachedBuffer, &outFence));
    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&detachedBuffer, &outFence));
    ASSERT_EQ(OK, surface->getAndFlushRemovedBuffers(&removedBuffers));
    ASSERT_EQ(1u, removedBuffers.size());
    ASSERT_EQ(detachedBuffer->handle, removedBuffers.at(0)->handle);

    // Re-allocate buffers since all buffers are detached up to now
    for (int i = 0; i < BUFFER_COUNT; i++) {
        ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffers[i], &fences[i]));
    }
    for (int i = 0; i < BUFFER_COUNT; i++) {
        ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffers[i], fences[i]));
    }

    ASSERT_EQ(NO_ERROR, surface->detachNextBuffer(&detachedBuffer, &outFence));
    ASSERT_EQ(NO_ERROR, surface->attachBuffer(detachedBuffer.get()));
    ASSERT_EQ(OK, surface->getAndFlushRemovedBuffers(&removedBuffers));
    // Depends on which slot GraphicBufferProducer impl pick, the attach call might
    // get 0 or 1 buffer removed.
    ASSERT_LE(removedBuffers.size(), 1u);
}

TEST_F(SurfaceTest, SurfaceListenerTest) {
    // Test discarding 1 free buffers with no listener
    testSurfaceListener(/*hasListener*/false, /*enableReleaseCb*/false, /*extraDiscardedBuffers*/0);
    // Test discarding 2 free buffers with no listener
    testSurfaceListener(/*hasListener*/false, /*enableReleaseCb*/false, /*extraDiscardedBuffers*/1);
    // Test discarding 1 free buffers with a listener, disabling onBufferReleased
    testSurfaceListener(/*hasListener*/true, /*enableReleasedCb*/false, /*extraDiscardedBuffers*/0);
    // Test discarding 2 free buffers with a listener, disabling onBufferReleased
    testSurfaceListener(/*hasListener*/true, /*enableReleasedCb*/false, /*extraDiscardedBuffers*/1);
    // Test discarding 1 free buffers with a listener, enabling onBufferReleased
    testSurfaceListener(/*hasListener*/true, /*enableReleasedCb*/true, /*extraDiscardedBuffers*/0);
    // Test discarding 3 free buffers with a listener, enabling onBufferReleased
    testSurfaceListener(/*hasListener*/true, /*enableReleasedCb*/true, /*extraDiscardedBuffers*/2);
}

TEST_F(SurfaceComposerSurfaceTest, TestGetLastDequeueStartTime) {
    sp<ANativeWindow> anw(mSurface);
    ASSERT_EQ(NO_ERROR, native_window_api_connect(anw.get(), NATIVE_WINDOW_API_CPU));

    ANativeWindowBuffer* buffer = nullptr;
    int32_t fenceFd = -1;

    nsecs_t before = systemTime(CLOCK_MONOTONIC);
    anw->dequeueBuffer(anw.get(), &buffer, &fenceFd);
    nsecs_t after = systemTime(CLOCK_MONOTONIC);

    nsecs_t lastDequeueTime = ANativeWindow_getLastDequeueStartTime(anw.get());
    ASSERT_LE(before, lastDequeueTime);
    ASSERT_GE(after, lastDequeueTime);
}

TEST_F(SurfaceComposerSurfaceTest, SurfaceIsForCursor) {
    sp<SurfaceControl> control;
    ASSERT_EQ(NO_ERROR,
              mComposerClient->createSurfaceChecked(String8("Test Surface"), 32, 32,
                                                    PIXEL_FORMAT_BGRA_8888, &control, 0));
    sp<Surface> surface = control->getSurface();
    sp<ANativeWindow> anw(surface);

    surface->setIsForCursor(true);

    ANativeWindow_Buffer b;
    ASSERT_EQ(NO_ERROR, surface->lock(&b, nullptr));
    ASSERT_EQ(NO_ERROR, surface->unlockAndPost());

    int fence;
    ANativeWindowBuffer* buffer;
    ASSERT_EQ(NO_ERROR, anw->dequeueBuffer(anw.get(), &buffer, &fence));

    EXPECT_TRUE(buffer->usage & GRALLOC_USAGE_CURSOR);
}

class FakeConsumer : public IConsumerListener {
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

class FakeSurfaceComposer : public ISurfaceComposer {
public:
    ~FakeSurfaceComposer() override {}

    void setSupportsPresent(bool supportsPresent) {
        mSupportsPresent = supportsPresent;
    }

    status_t setTransactionState(TransactionState&& /*state*/, const sp<IBinder>& /*applyToken*/
                                 ) override {
        return NO_ERROR;
    }

    status_t registerGraphicBuffers(const gui::GraphicBuffersRegisterInfo&) override {
        return NO_ERROR;
    }

    status_t unregisterGraphicBuffers(const gui::GraphicBuffersUnregisterInfo&) override {
        return NO_ERROR;
    }

protected:
    IBinder* onAsBinder() override { return nullptr; }

private:
    bool mSupportsPresent{true};
};

class FakeSurfaceComposerAIDL : public gui::ISurfaceComposer {
public:
    ~FakeSurfaceComposerAIDL() override {}

    void setSupportsPresent(bool supportsPresent) { mSupportsPresent = supportsPresent; }

    binder::Status bootFinished() override { return binder::Status::ok(); }
    binder::Status createDisplayEventConnection(
            gui::ISurfaceComposer::EventRegistration /*eventRegistration*/,
            const sp<IBinder>& /*layerHandle*/,
            sp<gui::IDisplayEventConnection>* outConnection) override {
        *outConnection = nullptr;
        return binder::Status::ok();
    }

    binder::Status createConnection(sp<gui::ISurfaceComposerClient>* outClient) override {
        *outClient = nullptr;
        return binder::Status::ok();
    }

    binder::Status createVirtualDisplay(
            const std::string& /*displayName*/, bool /*isSecure*/,
            gui::ISurfaceComposer::OptimizationPolicy /*optimizationPolicy*/,
            const std::string& /*uniqueId*/, int32_t /*ownerUid*/, float /*requestedRefreshRate*/,
            sp<IBinder>* /*outDisplay*/) override {
        return binder::Status::ok();
    }

    binder::Status destroyVirtualDisplay(const sp<IBinder>& /*displayToken*/) override {
        return binder::Status::ok();
    }

    binder::Status getPhysicalDisplayIds(std::vector<int64_t>* /*outDisplayIds*/) override {
        return binder::Status::ok();
    }

    binder::Status getPhysicalDisplayToken(int64_t /*displayId*/,
                                           sp<IBinder>* /*outDisplay*/) override {
        return binder::Status::ok();
    }

    binder::Status setPowerMode(const sp<IBinder>& /*display*/, int /*mode*/) override {
        return binder::Status::ok();
    }

    binder::Status getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported) override {
        *outSupported = {FrameEvent::REQUESTED_PRESENT,
                         FrameEvent::ACQUIRE,
                         FrameEvent::LATCH,
                         FrameEvent::FIRST_REFRESH_START,
                         FrameEvent::LAST_REFRESH_START,
                         FrameEvent::GPU_COMPOSITION_DONE,
                         FrameEvent::DEQUEUE_READY,
                         FrameEvent::RELEASE};
        if (mSupportsPresent) {
            outSupported->push_back(FrameEvent::DISPLAY_PRESENT);
        }
        return binder::Status::ok();
    }

    binder::Status getDisplayStats(const sp<IBinder>& /*display*/,
                                   gui::DisplayStatInfo* /*outStatInfo*/) override {
        return binder::Status::ok();
    }

    binder::Status getDisplayState(const sp<IBinder>& /*display*/,
                                   gui::DisplayState* /*outState*/) override {
        return binder::Status::ok();
    }

    binder::Status getStaticDisplayInfo(int64_t /*displayId*/,
                                        gui::StaticDisplayInfo* /*outInfo*/) override {
        return binder::Status::ok();
    }

    binder::Status getDynamicDisplayInfoFromId(int64_t /*displayId*/,
                                               gui::DynamicDisplayInfo* /*outInfo*/) override {
        return binder::Status::ok();
    }

    binder::Status getDynamicDisplayInfoFromToken(const sp<IBinder>& /*display*/,
                                                  gui::DynamicDisplayInfo* /*outInfo*/) override {
        return binder::Status::ok();
    }

    binder::Status getDisplayNativePrimaries(const sp<IBinder>& /*display*/,
                                             gui::DisplayPrimaries* /*outPrimaries*/) override {
        return binder::Status::ok();
    }

    binder::Status setActiveColorMode(const sp<IBinder>& /*display*/, int /*colorMode*/) override {
        return binder::Status::ok();
    }

    binder::Status setBootDisplayMode(const sp<IBinder>& /*display*/,
                                      int /*displayModeId*/) override {
        return binder::Status::ok();
    }

    binder::Status clearBootDisplayMode(const sp<IBinder>& /*display*/) override {
        return binder::Status::ok();
    }

    binder::Status getBootDisplayModeSupport(bool* /*outMode*/) override {
        return binder::Status::ok();
    }

    binder::Status getHdrConversionCapabilities(
            std::vector<gui::HdrConversionCapability>*) override {
        return binder::Status::ok();
    }

    binder::Status setHdrConversionStrategy(
            const gui::HdrConversionStrategy& /*hdrConversionStrategy*/,
            int32_t* /*outPreferredHdrOutputType*/) override {
        return binder::Status::ok();
    }

    binder::Status getHdrOutputConversionSupport(bool* /*outSupport*/) override {
        return binder::Status::ok();
    }

    binder::Status setAutoLowLatencyMode(const sp<IBinder>& /*display*/, bool /*on*/) override {
        return binder::Status::ok();
    }

    binder::Status setGameContentType(const sp<IBinder>& /*display*/, bool /*on*/) override {
        return binder::Status::ok();
    }

    binder::Status captureDisplay(const DisplayCaptureArgs&,
                                  const sp<IScreenCaptureListener>&) override {
        return binder::Status::ok();
    }

    binder::Status captureDisplayById(int64_t, const gui::CaptureArgs&,
                                      const sp<IScreenCaptureListener>&) override {
        return binder::Status::ok();
    }

    binder::Status captureLayersSync(const LayerCaptureArgs&, ScreenCaptureResults*) override {
        return binder::Status::ok();
    }

    binder::Status captureLayers(const LayerCaptureArgs&,
                                 const sp<IScreenCaptureListener>&) override {
        return binder::Status::ok();
    }

    binder::Status clearAnimationFrameStats() override { return binder::Status::ok(); }

    binder::Status getAnimationFrameStats(gui::FrameStats* /*outStats*/) override {
        return binder::Status::ok();
    }

    binder::Status overrideHdrTypes(const sp<IBinder>& /*display*/,
                                    const std::vector<int32_t>& /*hdrTypes*/) override {
        return binder::Status::ok();
    }

    binder::Status onPullAtom(int32_t /*atomId*/, gui::PullAtomData* /*outPullData*/) override {
        return binder::Status::ok();
    }

    binder::Status getCompositionPreference(gui::CompositionPreference* /*outPref*/) override {
        return binder::Status::ok();
    }

    binder::Status getDisplayedContentSamplingAttributes(
            const sp<IBinder>& /*display*/, gui::ContentSamplingAttributes* /*outAttrs*/) override {
        return binder::Status::ok();
    }

    binder::Status setDisplayContentSamplingEnabled(const sp<IBinder>& /*display*/, bool /*enable*/,
                                                    int8_t /*componentMask*/,
                                                    int64_t /*maxFrames*/) override {
        return binder::Status::ok();
    }

    binder::Status getProtectedContentSupport(bool* /*outSupporte*/) override {
        return binder::Status::ok();
    }

    binder::Status getDisplayedContentSample(const sp<IBinder>& /*display*/, int64_t /*maxFrames*/,
                                             int64_t /*timestamp*/,
                                             gui::DisplayedFrameStats* /*outStats*/) override {
        return binder::Status::ok();
    }

    binder::Status isWideColorDisplay(const sp<IBinder>& /*token*/,
                                      bool* /*outIsWideColorDisplay*/) override {
        return binder::Status::ok();
    }

    binder::Status addRegionSamplingListener(
            const gui::ARect& /*samplingArea*/, const sp<IBinder>& /*stopLayerHandle*/,
            const sp<gui::IRegionSamplingListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status addRegionSamplingListenerWithStopLayerId(
            const gui::ARect& /*samplingArea*/, const int32_t /*stopLayerId*/,
            const sp<gui::IRegionSamplingListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status removeRegionSamplingListener(
            const sp<gui::IRegionSamplingListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status getRegionSamplingListeners(
            std::vector<gui::RegionSamplingDescriptor>*) override {
        return binder::Status::ok();
    }

    binder::Status addFpsListener(int32_t /*taskId*/,
                                  const sp<gui::IFpsListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status removeFpsListener(const sp<gui::IFpsListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status addTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status removeTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status setDesiredDisplayModeSpecs(
            const sp<IBinder>& /*applyToken*/,
            const std::vector<gui::DisplayModeSpecs>&) override {
        return binder::Status::ok();
    }

    binder::Status getDesiredDisplayModeSpecs(const sp<IBinder>& /*displayToken*/,
                                              gui::DisplayModeSpecs*) override {
        return binder::Status::ok();
    }

    binder::Status getDisplayBrightnessSupport(const sp<IBinder>& /*displayToken*/,
                                               bool* /*outSupport*/) override {
        return binder::Status::ok();
    }

    binder::Status setDisplayBrightness(const sp<IBinder>& /*displayToken*/,
                                        const gui::DisplayBrightness& /*brightness*/) override {
        return binder::Status::ok();
    }

    binder::Status addHdrLayerInfoListener(
            const sp<IBinder>& /*displayToken*/,
            const sp<gui::IHdrLayerInfoListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status removeHdrLayerInfoListener(
            const sp<IBinder>& /*displayToken*/,
            const sp<gui::IHdrLayerInfoListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status notifyPowerBoost(int /*boostId*/) override { return binder::Status::ok(); }

    binder::Status setGlobalShadowSettings(const gui::Color& /*ambientColor*/,
                                           const gui::Color& /*spotColor*/, float /*lightPosY*/,
                                           float /*lightPosZ*/, float /*lightRadius*/) override {
        return binder::Status::ok();
    }

    binder::Status getDisplayDecorationSupport(
            const sp<IBinder>& /*displayToken*/,
            std::optional<gui::DisplayDecorationSupport>* /*outSupport*/) override {
        return binder::Status::ok();
    }

    binder::Status setGameModeFrameRateOverride(int32_t /*uid*/, float /*frameRate*/) override {
        return binder::Status::ok();
    }

    binder::Status setGameDefaultFrameRateOverride(int32_t /*uid*/, float /*frameRate*/) override {
        return binder::Status::ok();
    }

    binder::Status enableRefreshRateOverlay(bool /*active*/) override {
        return binder::Status::ok();
    }

    binder::Status setDebugFlash(int /*delay*/) override { return binder::Status::ok(); }

    binder::Status scheduleComposite() override { return binder::Status::ok(); }

    binder::Status scheduleCommit() override { return binder::Status::ok(); }

    binder::Status forceClientComposition(bool /*enabled*/) override {
        return binder::Status::ok();
    }

    binder::Status updateSmallAreaDetection(const std::vector<int32_t>& /*appIds*/,
                                            const std::vector<float>& /*thresholds*/) {
        return binder::Status::ok();
    }

    binder::Status setSmallAreaDetectionThreshold(int32_t /*appId*/, float /*threshold*/) {
        return binder::Status::ok();
    }

    binder::Status getGpuContextPriority(int32_t* /*outPriority*/) override {
        return binder::Status::ok();
    }

    binder::Status getMaxAcquiredBufferCount(int32_t* /*buffers*/) override {
        return binder::Status::ok();
    }

    binder::Status addWindowInfosListener(
            const sp<gui::IWindowInfosListener>& /*windowInfosListener*/,
            gui::WindowInfosListenerInfo* /*outInfo*/) override {
        return binder::Status::ok();
    }

    binder::Status removeWindowInfosListener(
            const sp<gui::IWindowInfosListener>& /*windowInfosListener*/) override {
        return binder::Status::ok();
    }

    binder::Status getOverlaySupport(gui::OverlayProperties* /*properties*/) override {
        return binder::Status::ok();
    }

    binder::Status getStalledTransactionInfo(
            int32_t /*pid*/, std::optional<gui::StalledTransactionInfo>* /*result*/) override {
        return binder::Status::ok();
    }

    binder::Status getSchedulingPolicy(gui::SchedulingPolicy*) override {
        return binder::Status::ok();
    }

    binder::Status notifyShutdown() override { return binder::Status::ok(); }

    binder::Status addJankListener(const sp<IBinder>& /*layer*/,
                                   const sp<gui::IJankListener>& /*listener*/) override {
        return binder::Status::ok();
    }

    binder::Status flushJankData(int32_t /*layerId*/) override { return binder::Status::ok(); }

    binder::Status removeJankListener(int32_t /*layerId*/,
                                      const sp<gui::IJankListener>& /*listener*/,
                                      int64_t /*afterVsync*/) override {
        return binder::Status::ok();
    }

    binder::Status addActivePictureListener(const sp<gui::IActivePictureListener>&) {
        return binder::Status::ok();
    }

    binder::Status removeActivePictureListener(const sp<gui::IActivePictureListener>&) {
        return binder::Status::ok();
    }

    binder::Status getMaxLayerPictureProfiles(const sp<IBinder>& /*display*/,
                                              int32_t* /*outMaxProfiles*/) {
        return binder::Status::ok();
    }

    binder::Status forcePacesetter(int64_t) { return binder::Status::ok(); }

    binder::Status resetForcedPacesetter() { return binder::Status::ok(); }

    binder::Status registerShader(const sp<IBinder>& shaderToken, const std::string& debugName,
                                  const std::string& shaderString) override {
        return binder::Status::ok();
    }

    binder::Status unregisterShader(const sp<IBinder>& shader) override {
        return binder::Status::ok();
    }

protected:
    IBinder* onAsBinder() override { return nullptr; }

private:
    bool mSupportsPresent{true};
};

class FakeProducerFrameEventHistory : public ProducerFrameEventHistory {
public:
    explicit FakeProducerFrameEventHistory(FenceToFenceTimeMap* fenceMap) : mFenceMap(fenceMap) {}

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
    TestSurface(const sp<IGraphicBufferProducer>& bufferProducer, FenceToFenceTimeMap* fenceMap)
          : Surface(bufferProducer),
            mFakeSurfaceComposer(new FakeSurfaceComposer),
            mFakeSurfaceComposerAIDL(new FakeSurfaceComposerAIDL) {
        mFakeFrameEventHistory = new FakeProducerFrameEventHistory(fenceMap);
        mFrameEventHistory.reset(mFakeFrameEventHistory);
    }

    ~TestSurface() override {}

    sp<ISurfaceComposer> composerService() const override {
        return mFakeSurfaceComposer;
    }

    sp<gui::ISurfaceComposer> composerServiceAIDL() const override {
        return mFakeSurfaceComposerAIDL;
    }

    nsecs_t now() const override {
        return mNow;
    }

    void setNow(nsecs_t now) {
        mNow = now;
    }

public:
    sp<FakeSurfaceComposer> mFakeSurfaceComposer;
    sp<FakeSurfaceComposerAIDL> mFakeSurfaceComposerAIDL;
    nsecs_t mNow = 0;

    // mFrameEventHistory owns the instance of FakeProducerFrameEventHistory,
    // but this raw pointer gives access to test functionality.
    FakeProducerFrameEventHistory* mFakeFrameEventHistory;
};


class GetFrameTimestampsTest : public ::testing::Test {
protected:
    struct FenceAndFenceTime {
        explicit FenceAndFenceTime(FenceToFenceTimeMap& fenceMap)
              : mFenceTime(fenceMap.createFenceTimeForTest(mFence)) {}

        sp<Fence> mFence = sp<Fence>::make();
        std::shared_ptr<FenceTime> mFenceTime;
    };

    static CompositorTiming makeCompositorTiming(nsecs_t deadline = 1'000'000'000,
                                                 nsecs_t interval = 16'666'667,
                                                 nsecs_t presentLatency = 50'000'000) {
        CompositorTiming timing;
        timing.deadline = deadline;
        timing.interval = interval;
        timing.presentLatency = presentLatency;
        return timing;
    }

    struct RefreshEvents {
        RefreshEvents(FenceToFenceTimeMap& fenceMap, nsecs_t refreshStart)
              : mFenceMap(fenceMap),
                kCompositorTiming(
                        makeCompositorTiming(refreshStart, refreshStart + 1, refreshStart + 2)),
                kStartTime(refreshStart + 3),
                kGpuCompositionDoneTime(refreshStart + 4),
                kPresentTime(refreshStart + 5) {}

        void signalPostCompositeFences() {
            mFenceMap.signalAllForTest(
                        mGpuCompositionDone.mFence, kGpuCompositionDoneTime);
            mFenceMap.signalAllForTest(mPresent.mFence, kPresentTime);
        }

        FenceToFenceTimeMap& mFenceMap;

        FenceAndFenceTime mGpuCompositionDone{mFenceMap};
        FenceAndFenceTime mPresent{mFenceMap};

        const CompositorTiming kCompositorTiming;

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
              kReleaseTime(frameStartTime + 700),
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
            mFenceMap.signalAllForTest(mRelease.mFence, kReleaseTime);
        }

        FenceToFenceTimeMap& mFenceMap;

        FenceAndFenceTime mAcquireConsumer { mFenceMap };
        FenceAndFenceTime mAcquireProducer { mFenceMap };
        FenceAndFenceTime mRelease { mFenceMap };

        const nsecs_t kPostedTime;
        const nsecs_t kRequestedPresentTime;
        const nsecs_t kProducerAcquireTime;
        const nsecs_t kConsumerAcquireTime;
        const nsecs_t kLatchTime;
        const nsecs_t kDequeueReadyTime;
        const nsecs_t kReleaseTime;

        RefreshEvents mRefreshes[3];
    };

    GetFrameTimestampsTest() {}

    virtual void SetUp() {
        BufferQueue::createBufferQueue(&mProducer, &mConsumer);
        mFakeConsumer = new FakeConsumer;
        mCfeh = &mFakeConsumer->mFrameEventHistory;
        mConsumer->consumerConnect(mFakeConsumer, false);
        mConsumer->setConsumerName(String8("TestConsumer"));
        mSurface = new TestSurface(mProducer, &mFenceMap);
        mWindow = mSurface;

        ASSERT_EQ(NO_ERROR, native_window_api_connect(mWindow.get(),
                NATIVE_WINDOW_API_CPU));
        ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(mWindow.get(), 4));
        ASSERT_EQ(NO_ERROR, native_window_set_usage(mWindow.get(), TEST_PRODUCER_USAGE_BITS));
    }

    void disableFrameTimestamps() {
        mFakeConsumer->mGetFrameTimestampsEnabled = false;
        native_window_enable_frame_timestamps(mWindow.get(), 0);
        mFrameTimestampsEnabled = false;
    }

    void enableFrameTimestamps() {
        mFakeConsumer->mGetFrameTimestampsEnabled = true;
        native_window_enable_frame_timestamps(mWindow.get(), 1);
        mFrameTimestampsEnabled = true;
    }

    int getAllFrameTimestamps(uint64_t frameId) {
        return native_window_get_frame_timestamps(mWindow.get(), frameId,
                &outRequestedPresentTime, &outAcquireTime, &outLatchTime,
                &outFirstRefreshStartTime, &outLastRefreshStartTime,
                &outGpuCompositionDoneTime, &outDisplayPresentTime,
                &outDequeueReadyTime, &outReleaseTime);
    }

    void resetTimestamps() {
        outRequestedPresentTime = -1;
        outAcquireTime = -1;
        outLatchTime = -1;
        outFirstRefreshStartTime = -1;
        outLastRefreshStartTime = -1;
        outGpuCompositionDoneTime = -1;
        outDisplayPresentTime = -1;
        outDequeueReadyTime = -1;
        outReleaseTime = -1;
    }

    uint64_t getNextFrameId() {
        uint64_t frameId = -1;
        int status = native_window_get_next_frame_id(mWindow.get(), &frameId);
        EXPECT_EQ(status, NO_ERROR);
        return frameId;
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

        uint64_t nOldFrame = (iOldFrame == NO_FRAME_INDEX) ? 0 : iOldFrame + 1;
        uint64_t nNewFrame = iNewFrame + 1;

        // Latch, Composite, and Release the frames in a plausible order.
        // Note: The timestamps won't necessarily match the order, but
        // that's okay for the purposes of this test.
        std::shared_ptr<FenceTime> gpuDoneFenceTime = FenceTime::NO_FENCE;

        // Composite the previous frame one more time, which helps verify
        // LastRefresh is updated properly.
        if (oldFrame != nullptr) {
            mCfeh->addPreComposition(nOldFrame,
                                     oldFrame->mRefreshes[2].kStartTime);
            gpuDoneFenceTime = gpuComposited ?
                    oldFrame->mRefreshes[2].mGpuCompositionDone.mFenceTime :
                    FenceTime::NO_FENCE;
            mCfeh->addPostComposition(nOldFrame, gpuDoneFenceTime,
                    oldFrame->mRefreshes[2].mPresent.mFenceTime,
                    oldFrame->mRefreshes[2].kCompositorTiming);
        }

        // Latch the new frame.
        mCfeh->addLatch(nNewFrame, newFrame->kLatchTime);

        mCfeh->addPreComposition(nNewFrame, newFrame->mRefreshes[0].kStartTime);
        gpuDoneFenceTime = gpuComposited ?
                newFrame->mRefreshes[0].mGpuCompositionDone.mFenceTime :
                FenceTime::NO_FENCE;
        // HWC2 releases the previous buffer after a new latch just before
        // calling onCompositionPresented.
        if (oldFrame != nullptr) {
            mCfeh->addRelease(nOldFrame, oldFrame->kDequeueReadyTime,
                    std::shared_ptr<FenceTime>(oldFrame->mRelease.mFenceTime));
        }
        mCfeh->addPostComposition(nNewFrame, gpuDoneFenceTime,
                newFrame->mRefreshes[0].mPresent.mFenceTime,
                newFrame->mRefreshes[0].kCompositorTiming);

        mCfeh->addPreComposition(nNewFrame, newFrame->mRefreshes[1].kStartTime);
        gpuDoneFenceTime = gpuComposited ?
                newFrame->mRefreshes[1].mGpuCompositionDone.mFenceTime :
                FenceTime::NO_FENCE;
        mCfeh->addPostComposition(nNewFrame, gpuDoneFenceTime,
                newFrame->mRefreshes[1].mPresent.mFenceTime,
                newFrame->mRefreshes[1].kCompositorTiming);
    }

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
    int64_t outLatchTime = -1;
    int64_t outFirstRefreshStartTime = -1;
    int64_t outLastRefreshStartTime = -1;
    int64_t outGpuCompositionDoneTime = -1;
    int64_t outDisplayPresentTime = -1;
    int64_t outDequeueReadyTime = -1;
    int64_t outReleaseTime = -1;

    FrameEvents mFrames[3] {
        { mFenceMap, 1000 }, { mFenceMap, 2000 }, { mFenceMap, 3000 } };
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

    const uint64_t fId = getNextFrameId();

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
    int result = getAllFrameTimestamps(fId);
    EXPECT_EQ(INVALID_OPERATION, result);
    EXPECT_EQ(0, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify compositor timing query fails.
    nsecs_t compositeDeadline = 0;
    nsecs_t compositeInterval = 0;
    nsecs_t compositeToPresentLatency = 0;
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(INVALID_OPERATION, result);
}

// This test verifies that the frame timestamps are retrieved if explicitly
// enabled via native_window_enable_frame_timestamps.
TEST_F(GetFrameTimestampsTest, EnabledSimple) {
    const CompositorTiming initialCompositorTiming = makeCompositorTiming();
    mCfeh->initializeCompositorTiming(initialCompositorTiming);

    enableFrameTimestamps();

    // Verify the compositor timing query gets the initial compositor values
    // after timststamps are enabled; even before the first frame is queued
    // or dequeued.
    nsecs_t compositeDeadline = 0;
    nsecs_t compositeInterval = 0;
    nsecs_t compositeToPresentLatency = 0;
    mSurface->setNow(initialCompositorTiming.deadline - 1);
    int result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(initialCompositorTiming.deadline, compositeDeadline);
    EXPECT_EQ(initialCompositorTiming.interval, compositeInterval);
    EXPECT_EQ(initialCompositorTiming.presentLatency,
              compositeToPresentLatency);

    int fence;
    ANativeWindowBuffer* buffer;

    EXPECT_EQ(0, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(1, mFakeConsumer->mGetFrameTimestampsCount);

    const uint64_t fId1 = getNextFrameId();

    // Verify getFrameTimestamps is piggybacked on dequeue.
    ASSERT_EQ(NO_ERROR, mWindow->dequeueBuffer(mWindow.get(), &buffer, &fence));
    EXPECT_EQ(0, mFakeConsumer->mAddFrameTimestampsCount);
    EXPECT_EQ(2, mFakeConsumer->mGetFrameTimestampsCount);

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
    EXPECT_EQ(3, mFakeConsumer->mGetFrameTimestampsCount);

    // Verify queries for timestamps that the producer doesn't know about
    // triggers a call to see if the consumer has any new timestamps.
    result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(4, mFakeConsumer->mGetFrameTimestampsCount);
}

TEST_F(GetFrameTimestampsTest, QueryPresentSupported) {
    bool displayPresentSupported = true;
    mSurface->mFakeSurfaceComposer->setSupportsPresent(displayPresentSupported);
    mSurface->mFakeSurfaceComposerAIDL->setSupportsPresent(displayPresentSupported);

    // Verify supported bits are forwarded.
    int supportsPresent = -1;
    mWindow.get()->query(mWindow.get(),
            NATIVE_WINDOW_FRAME_TIMESTAMPS_SUPPORTS_PRESENT, &supportsPresent);
    EXPECT_EQ(displayPresentSupported, supportsPresent);
}

TEST_F(GetFrameTimestampsTest, QueryPresentNotSupported) {
    bool displayPresentSupported = false;
    mSurface->mFakeSurfaceComposer->setSupportsPresent(displayPresentSupported);
    mSurface->mFakeSurfaceComposerAIDL->setSupportsPresent(displayPresentSupported);

    // Verify supported bits are forwarded.
    int supportsPresent = -1;
    mWindow.get()->query(mWindow.get(),
            NATIVE_WINDOW_FRAME_TIMESTAMPS_SUPPORTS_PRESENT, &supportsPresent);
    EXPECT_EQ(displayPresentSupported, supportsPresent);
}

TEST_F(GetFrameTimestampsTest, SnapToNextTickBasic) {
    nsecs_t phase = 4000;
    nsecs_t interval = 1000;

    // Timestamp in previous interval.
    nsecs_t timestamp = 3500;
    EXPECT_EQ(4000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));

    // Timestamp in next interval.
    timestamp = 4500;
    EXPECT_EQ(5000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));

    // Timestamp multiple intervals before.
    timestamp = 2500;
    EXPECT_EQ(3000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));

    // Timestamp multiple intervals after.
    timestamp = 6500;
    EXPECT_EQ(7000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));

    // Timestamp on previous interval.
    timestamp = 3000;
    EXPECT_EQ(3000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));

    // Timestamp on next interval.
    timestamp = 5000;
    EXPECT_EQ(5000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));

    // Timestamp equal to phase.
    timestamp = 4000;
    EXPECT_EQ(4000, ProducerFrameEventHistory::snapToNextTick(
            timestamp, phase, interval));
}

// int(big_timestamp / interval) < 0, which can cause a crash or invalid result
// if the number of intervals elapsed is internally stored in an int.
TEST_F(GetFrameTimestampsTest, SnapToNextTickOverflow) {
      nsecs_t phase = 0;
      nsecs_t interval = 4000;
      nsecs_t big_timestamp = 8635916564000;
      int32_t intervals = big_timestamp / interval;

      EXPECT_LT(intervals, 0);
      EXPECT_EQ(8635916564000, ProducerFrameEventHistory::snapToNextTick(
            big_timestamp, phase, interval));
      EXPECT_EQ(8635916564000, ProducerFrameEventHistory::snapToNextTick(
            big_timestamp, big_timestamp, interval));
}

// This verifies the compositor timing is updated by refresh events
// and piggy backed on a queue, dequeue, and enabling of timestamps..
TEST_F(GetFrameTimestampsTest, CompositorTimingUpdatesBasic) {
    const CompositorTiming initialCompositorTiming = makeCompositorTiming();
    mCfeh->initializeCompositorTiming(initialCompositorTiming);

    enableFrameTimestamps();

    // We get the initial values before any frames are submitted.
    nsecs_t compositeDeadline = 0;
    nsecs_t compositeInterval = 0;
    nsecs_t compositeToPresentLatency = 0;
    mSurface->setNow(initialCompositorTiming.deadline - 1);
    int result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(initialCompositorTiming.deadline, compositeDeadline);
    EXPECT_EQ(initialCompositorTiming.interval, compositeInterval);
    EXPECT_EQ(initialCompositorTiming.presentLatency,
              compositeToPresentLatency);

    dequeueAndQueue(0);
    addFrameEvents(true, NO_FRAME_INDEX, 0);

    // Still get the initial values because the frame events for frame 0
    // didn't get a chance to piggyback on a queue or dequeue yet.
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(initialCompositorTiming.deadline, compositeDeadline);
    EXPECT_EQ(initialCompositorTiming.interval, compositeInterval);
    EXPECT_EQ(initialCompositorTiming.presentLatency,
              compositeToPresentLatency);

    dequeueAndQueue(1);
    addFrameEvents(true, 0, 1);

    // Now expect the composite values associated with frame 1.
    mSurface->setNow(mFrames[0].mRefreshes[1].kCompositorTiming.deadline);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].mRefreshes[1].kCompositorTiming.deadline,
            compositeDeadline);
    EXPECT_EQ(mFrames[0].mRefreshes[1].kCompositorTiming.interval,
            compositeInterval);
    EXPECT_EQ(mFrames[0].mRefreshes[1].kCompositorTiming.presentLatency,
            compositeToPresentLatency);

    dequeueAndQueue(2);
    addFrameEvents(true, 1, 2);

    // Now expect the composite values associated with frame 2.
    mSurface->setNow(mFrames[1].mRefreshes[1].kCompositorTiming.deadline);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].mRefreshes[1].kCompositorTiming.deadline,
            compositeDeadline);
    EXPECT_EQ(mFrames[1].mRefreshes[1].kCompositorTiming.interval,
            compositeInterval);
    EXPECT_EQ(mFrames[1].mRefreshes[1].kCompositorTiming.presentLatency,
            compositeToPresentLatency);

    // Re-enabling frame timestamps should get the latest values.
    disableFrameTimestamps();
    enableFrameTimestamps();

    // Now expect the composite values associated with frame 3.
    mSurface->setNow(mFrames[2].mRefreshes[1].kCompositorTiming.deadline);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[2].mRefreshes[1].kCompositorTiming.deadline,
            compositeDeadline);
    EXPECT_EQ(mFrames[2].mRefreshes[1].kCompositorTiming.interval,
            compositeInterval);
    EXPECT_EQ(mFrames[2].mRefreshes[1].kCompositorTiming.presentLatency,
            compositeToPresentLatency);
}

// This verifies the compositor deadline properly snaps to the the next
// deadline based on the current time.
TEST_F(GetFrameTimestampsTest, CompositorTimingDeadlineSnaps) {
    const CompositorTiming initialCompositorTiming = makeCompositorTiming();
    mCfeh->initializeCompositorTiming(initialCompositorTiming);

    enableFrameTimestamps();

    nsecs_t compositeDeadline = 0;
    nsecs_t compositeInterval = 0;
    nsecs_t compositeToPresentLatency = 0;

    // A "now" just before the deadline snaps to the deadline.
    mSurface->setNow(initialCompositorTiming.deadline - 1);
    int result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(initialCompositorTiming.deadline, compositeDeadline);
    nsecs_t expectedDeadline = initialCompositorTiming.deadline;
    EXPECT_EQ(expectedDeadline, compositeDeadline);

    dequeueAndQueue(0);
    addFrameEvents(true, NO_FRAME_INDEX, 0);

    // A "now" just after the deadline snaps properly.
    mSurface->setNow(initialCompositorTiming.deadline + 1);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    expectedDeadline =
            initialCompositorTiming.deadline +initialCompositorTiming.interval;
    EXPECT_EQ(expectedDeadline, compositeDeadline);

    dequeueAndQueue(1);
    addFrameEvents(true, 0, 1);

    // A "now" just after the next interval snaps properly.
    mSurface->setNow(
            mFrames[0].mRefreshes[1].kCompositorTiming.deadline +
            mFrames[0].mRefreshes[1].kCompositorTiming.interval + 1);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    expectedDeadline =
            mFrames[0].mRefreshes[1].kCompositorTiming.deadline +
            mFrames[0].mRefreshes[1].kCompositorTiming.interval * 2;
    EXPECT_EQ(expectedDeadline, compositeDeadline);

    dequeueAndQueue(2);
    addFrameEvents(true, 1, 2);

    // A "now" over 1 interval before the deadline snaps properly.
    mSurface->setNow(
            mFrames[1].mRefreshes[1].kCompositorTiming.deadline -
            mFrames[1].mRefreshes[1].kCompositorTiming.interval - 1);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    expectedDeadline =
            mFrames[1].mRefreshes[1].kCompositorTiming.deadline -
            mFrames[1].mRefreshes[1].kCompositorTiming.interval;
    EXPECT_EQ(expectedDeadline, compositeDeadline);

    // Re-enabling frame timestamps should get the latest values.
    disableFrameTimestamps();
    enableFrameTimestamps();

    // A "now" over 2 intervals before the deadline snaps properly.
    mSurface->setNow(
            mFrames[2].mRefreshes[1].kCompositorTiming.deadline -
            mFrames[2].mRefreshes[1].kCompositorTiming.interval * 2 - 1);
    result = native_window_get_compositor_timing(mWindow.get(),
        &compositeDeadline, &compositeInterval, &compositeToPresentLatency);
    EXPECT_EQ(NO_ERROR, result);
    expectedDeadline =
            mFrames[2].mRefreshes[1].kCompositorTiming.deadline -
            mFrames[2].mRefreshes[1].kCompositorTiming.interval * 2;
    EXPECT_EQ(expectedDeadline, compositeDeadline);
}

// This verifies the timestamps recorded in the consumer's
// FrameTimestampsHistory are properly retrieved by the producer for the
// correct frames.
TEST_F(GetFrameTimestampsTest, TimestampsAssociatedWithCorrectFrame) {
    enableFrameTimestamps();

    const uint64_t fId1 = getNextFrameId();
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    const uint64_t fId2 = getNextFrameId();
    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(true, NO_FRAME_INDEX, 0);
    mFrames[0].signalRefreshFences();
    addFrameEvents(true, 0, 1);
    mFrames[0].signalReleaseFences();
    mFrames[1].signalRefreshFences();

    // Verify timestamps are correct for frame 1.
    resetTimestamps();
    int result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kGpuCompositionDoneTime,
            outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(mFrames[0].kReleaseTime, outReleaseTime);

    // Verify timestamps are correct for frame 2.
    resetTimestamps();
    result = getAllFrameTimestamps(fId2);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[1].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[1].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[1].mRefreshes[1].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kGpuCompositionDoneTime,
            outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outDequeueReadyTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outReleaseTime);
}

// This test verifies the acquire fence recorded by the consumer is not sent
// back to the producer and the producer saves its own fence.
TEST_F(GetFrameTimestampsTest, QueueTimestampsNoSync) {
    enableFrameTimestamps();

    // Dequeue and queue frame 1.
    const uint64_t fId1 = getNextFrameId();
    dequeueAndQueue(0);

    // Verify queue-related timestamps for f1 are available immediately in the
    // producer without asking the consumer again, even before signaling the
    // acquire fence.
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), fId1,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outAcquireTime);

    // Signal acquire fences. Verify a sync call still isn't necessary.
    mFrames[0].signalQueueFences();

    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), fId1,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);

    // Dequeue and queue frame 2.
    const uint64_t fId2 = getNextFrameId();
    dequeueAndQueue(1);

    // Verify queue-related timestamps for f2 are available immediately in the
    // producer without asking the consumer again, even before signaling the
    // acquire fence.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), fId2,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outAcquireTime);

    // Signal acquire fences. Verify a sync call still isn't necessary.
    mFrames[1].signalQueueFences();

    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = native_window_get_frame_timestamps(mWindow.get(), fId2,
            &outRequestedPresentTime, &outAcquireTime, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[1].kProducerAcquireTime, outAcquireTime);
}

TEST_F(GetFrameTimestampsTest, ZeroRequestedTimestampsNoSync) {
    enableFrameTimestamps();

    // Dequeue and queue frame 1.
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    // Dequeue and queue frame 2.
    const uint64_t fId2 = getNextFrameId();
    dequeueAndQueue(1);
    mFrames[1].signalQueueFences();

    addFrameEvents(true, NO_FRAME_INDEX, 0);
    mFrames[0].signalRefreshFences();
    addFrameEvents(true, 0, 1);
    mFrames[0].signalReleaseFences();
    mFrames[1].signalRefreshFences();

    // Verify a request for no timestamps doesn't result in a sync call.
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), fId2,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
}

// This test verifies that fences can signal and update timestamps producer
// side without an additional sync call to the consumer.
TEST_F(GetFrameTimestampsTest, FencesInProducerNoSync) {
    enableFrameTimestamps();

    // Dequeue and queue frame 1.
    const uint64_t fId1 = getNextFrameId();
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
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(oldCount + 1, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outGpuCompositionDoneTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outReleaseTime);

    // Verify available timestamps are correct for frame 1 again, before any
    // fence has been signaled.
    // This time a sync call should not be necessary.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outGpuCompositionDoneTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outReleaseTime);

    // Signal the fences for frame 1.
    mFrames[0].signalRefreshFences();
    mFrames[0].signalReleaseFences();

    // Verify all timestamps are available without a sync call.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kGpuCompositionDoneTime,
            outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(mFrames[0].kReleaseTime, outReleaseTime);
}

// This test verifies that if the frame wasn't GPU composited but has a refresh
// event a sync call isn't made to get the GPU composite done time since it will
// never exist.
TEST_F(GetFrameTimestampsTest, NoGpuNoSync) {
    enableFrameTimestamps();

    // Dequeue and queue frame 1.
    const uint64_t fId1 = getNextFrameId();
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
    int result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(oldCount + 1, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_INVALID, outGpuCompositionDoneTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outReleaseTime);

    // Signal the fences for frame 1.
    mFrames[0].signalRefreshFences();
    mFrames[0].signalReleaseFences();

    // Verify all timestamps, except GPU composition, are available without a
    // sync call.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_INVALID, outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(mFrames[0].kReleaseTime, outReleaseTime);
}

// This test verifies that if the certain timestamps can't possibly exist for
// the most recent frame, then a sync call is not done.
TEST_F(GetFrameTimestampsTest, NoReleaseNoSync) {
    enableFrameTimestamps();

    // Dequeue and queue frame 1.
    const uint64_t fId1 = getNextFrameId();
    dequeueAndQueue(0);
    mFrames[0].signalQueueFences();

    // Dequeue and queue frame 2.
    const uint64_t fId2 = getNextFrameId();
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
    int result = getAllFrameTimestamps(fId1);
    EXPECT_EQ(oldCount + 1, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[0].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[0].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[0].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[0].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[0].mRefreshes[2].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_INVALID, outGpuCompositionDoneTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outDisplayPresentTime);
    EXPECT_EQ(mFrames[0].kDequeueReadyTime, outDequeueReadyTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outReleaseTime);

    mFrames[0].signalRefreshFences();
    mFrames[0].signalReleaseFences();
    mFrames[1].signalRefreshFences();

    // Verify querying for all timestmaps of f2 does not do a sync call. Even
    // though the lastRefresh, dequeueReady, and release times aren't
    // available, a sync call should not occur because it's not possible for f2
    // to encounter the final value for those events until another frame is
    // queued.
    resetTimestamps();
    oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    result = getAllFrameTimestamps(fId2);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(NO_ERROR, result);
    EXPECT_EQ(mFrames[1].kRequestedPresentTime, outRequestedPresentTime);
    EXPECT_EQ(mFrames[1].kProducerAcquireTime, outAcquireTime);
    EXPECT_EQ(mFrames[1].kLatchTime, outLatchTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kStartTime, outFirstRefreshStartTime);
    EXPECT_EQ(mFrames[1].mRefreshes[1].kStartTime, outLastRefreshStartTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_INVALID, outGpuCompositionDoneTime);
    EXPECT_EQ(mFrames[1].mRefreshes[0].kPresentTime, outDisplayPresentTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outDequeueReadyTime);
    EXPECT_EQ(NATIVE_WINDOW_TIMESTAMP_PENDING, outReleaseTime);
}

// This test verifies there are no sync calls for present times
// when they aren't supported and that an error is returned.

TEST_F(GetFrameTimestampsTest, PresentUnsupportedNoSync) {
    enableFrameTimestamps();
    mSurface->mFakeSurfaceComposer->setSupportsPresent(false);
    mSurface->mFakeSurfaceComposerAIDL->setSupportsPresent(false);

    // Dequeue and queue frame 1.
    const uint64_t fId1 = getNextFrameId();
    dequeueAndQueue(0);

    // Verify a query for the Present times do not trigger a sync call if they
    // are not supported.
    resetTimestamps();
    int oldCount = mFakeConsumer->mGetFrameTimestampsCount;
    int result = native_window_get_frame_timestamps(mWindow.get(), fId1,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            &outDisplayPresentTime, nullptr, nullptr);
    EXPECT_EQ(oldCount, mFakeConsumer->mGetFrameTimestampsCount);
    EXPECT_EQ(BAD_VALUE, result);
    EXPECT_EQ(-1, outDisplayPresentTime);
}

TEST_F(SurfaceTest, DequeueWithConsumerDrivenSize) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);
    consumer->setDefaultBufferSize(10, 10);

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);
    ASSERT_EQ(NO_ERROR, native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU));
    ASSERT_EQ(NO_ERROR, native_window_set_buffers_dimensions(window.get(), 0, 0));
    ASSERT_EQ(NO_ERROR, native_window_set_usage(window.get(), TEST_PRODUCER_USAGE_BITS));

    int fence;
    ANativeWindowBuffer* buffer;

    // Buffer size is driven by the consumer
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(10, buffer->width);
    EXPECT_EQ(10, buffer->height);
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));

    // Buffer size is driven by the consumer
    consumer->setDefaultBufferSize(10, 20);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(10, buffer->width);
    EXPECT_EQ(20, buffer->height);
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));

    // Transform hint isn't synced to producer before queueBuffer or connect
    consumer->setTransformHint(NATIVE_WINDOW_TRANSFORM_ROT_270);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(10, buffer->width);
    EXPECT_EQ(20, buffer->height);
    ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, fence));

    // Transform hint is synced to producer but no auto prerotation
    consumer->setTransformHint(NATIVE_WINDOW_TRANSFORM_ROT_270);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(10, buffer->width);
    EXPECT_EQ(20, buffer->height);
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));

    // Prerotation is driven by the consumer with the transform hint used by producer
    native_window_set_auto_prerotation(window.get(), true);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(20, buffer->width);
    EXPECT_EQ(10, buffer->height);
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));

    // Turn off auto prerotaton
    native_window_set_auto_prerotation(window.get(), false);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(10, buffer->width);
    EXPECT_EQ(20, buffer->height);
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));

    // Test auto prerotation bit is disabled after disconnect
    native_window_set_auto_prerotation(window.get(), true);
    native_window_api_disconnect(window.get(), NATIVE_WINDOW_API_CPU);
    native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU);
    consumer->setTransformHint(NATIVE_WINDOW_TRANSFORM_ROT_270);
    native_window_set_buffers_dimensions(window.get(), 0, 0);
    native_window_set_usage(window.get(), TEST_PRODUCER_USAGE_BITS);
    ASSERT_EQ(NO_ERROR, window->dequeueBuffer(window.get(), &buffer, &fence));
    EXPECT_EQ(10, buffer->width);
    EXPECT_EQ(20, buffer->height);
    ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));
}

TEST_F(SurfaceTest, DefaultMaxBufferCountSetAndUpdated) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<MockConsumer> mockConsumer(new MockConsumer);
    consumer->consumerConnect(mockConsumer, false);

    sp<Surface> surface = new Surface(producer);
    sp<ANativeWindow> window(surface);

    int count = -1;
    ASSERT_EQ(NO_ERROR, window->query(window.get(), NATIVE_WINDOW_MAX_BUFFER_COUNT, &count));
    EXPECT_EQ(BufferQueueDefs::NUM_BUFFER_SLOTS, count);

    consumer->setMaxBufferCount(10);
    ASSERT_EQ(NO_ERROR, native_window_api_connect(window.get(), NATIVE_WINDOW_API_CPU));
    EXPECT_EQ(NO_ERROR, window->query(window.get(), NATIVE_WINDOW_MAX_BUFFER_COUNT, &count));
    EXPECT_EQ(10, count);

    ASSERT_EQ(NO_ERROR, native_window_api_disconnect(window.get(), NATIVE_WINDOW_API_CPU));
    ASSERT_EQ(NO_ERROR, window->query(window.get(), NATIVE_WINDOW_MAX_BUFFER_COUNT, &count));
    EXPECT_EQ(BufferQueueDefs::NUM_BUFFER_SLOTS, count);
}

TEST_F(SurfaceTest, BatchOperations) {
    const int BUFFER_COUNT = 16;
    const int BATCH_SIZE = 8;

    auto [cpuConsumer, surface] = CpuConsumer::create(1);
    sp<ANativeWindow> window(surface);
    sp<StubSurfaceListener> listener = new StubSurfaceListener();

    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, /*listener*/listener,
            /*reportBufferRemoval*/false));

    ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(window.get(), BUFFER_COUNT));

    std::vector<Surface::BatchBuffer> buffers(BATCH_SIZE);

    // Batch dequeued buffers can be queued individually
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffers(&buffers));
    for (size_t i = 0; i < BATCH_SIZE; i++) {
        ANativeWindowBuffer* buffer = buffers[i].buffer;
        int fence = buffers[i].fenceFd;
        ASSERT_EQ(NO_ERROR, window->queueBuffer(window.get(), buffer, fence));
    }

    // Batch dequeued buffers can be canceled individually
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffers(&buffers));
    for (size_t i = 0; i < BATCH_SIZE; i++) {
        ANativeWindowBuffer* buffer = buffers[i].buffer;
        int fence = buffers[i].fenceFd;
        ASSERT_EQ(NO_ERROR, window->cancelBuffer(window.get(), buffer, fence));
    }

    // Batch dequeued buffers can be batch cancelled
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffers(&buffers));
    ASSERT_EQ(NO_ERROR, surface->cancelBuffers(buffers));

    // Batch dequeued buffers can be batch queued
    ASSERT_EQ(NO_ERROR, surface->dequeueBuffers(&buffers));
    std::vector<Surface::BatchQueuedBuffer> queuedBuffers(BATCH_SIZE);
    for (size_t i = 0; i < BATCH_SIZE; i++) {
        queuedBuffers[i].buffer = buffers[i].buffer;
        queuedBuffers[i].fenceFd = buffers[i].fenceFd;
        queuedBuffers[i].timestamp = NATIVE_WINDOW_TIMESTAMP_AUTO;
    }
    ASSERT_EQ(NO_ERROR, surface->queueBuffers(queuedBuffers));

    ASSERT_EQ(NO_ERROR, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

TEST_F(SurfaceTest, BatchIllegalOperations) {
    const int BUFFER_COUNT = 16;
    const int BATCH_SIZE = 8;

    auto [cpuConsumer, surface] = CpuConsumer::create(1);
    sp<ANativeWindow> window(surface);
    sp<StubSurfaceListener> listener = new StubSurfaceListener();

    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, /*listener*/listener,
            /*reportBufferRemoval*/false));

    ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(window.get(), BUFFER_COUNT));

    std::vector<Surface::BatchBuffer> buffers(BATCH_SIZE);
    std::vector<Surface::BatchQueuedBuffer> queuedBuffers(BATCH_SIZE);

    // Batch operations are invalid in shared buffer mode
    surface->setSharedBufferMode(true);
    ASSERT_EQ(INVALID_OPERATION, surface->dequeueBuffers(&buffers));
    ASSERT_EQ(INVALID_OPERATION, surface->cancelBuffers(buffers));
    ASSERT_EQ(INVALID_OPERATION, surface->queueBuffers(queuedBuffers));
    surface->setSharedBufferMode(false);

    ASSERT_EQ(NO_ERROR, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

TEST_F(SurfaceTest, PlatformBufferMethods) {
    sp<CpuConsumer> cpuConsumer = sp<CpuConsumer>::make(1);
    sp<Surface> surface = cpuConsumer->getSurface();
    sp<StubSurfaceListener> listener = sp<StubSurfaceListener>::make();
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;

    EXPECT_EQ(OK,
              surface->connect(NATIVE_WINDOW_API_CPU, listener, /* reportBufferRemoval */ false));

    //
    // Verify nullptrs are handled safely:
    //

    EXPECT_EQ(BAD_VALUE, surface->dequeueBuffer((sp<GraphicBuffer>*)nullptr, &fence));
    EXPECT_EQ(BAD_VALUE, surface->queueBuffer(nullptr, nullptr));
    EXPECT_EQ(BAD_VALUE, surface->detachBuffer(nullptr));

    //
    // Verify dequeue/queue:
    //

    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_NE(nullptr, buffer);
    EXPECT_EQ(OK, surface->queueBuffer(buffer, fence));

    //
    // Verify dequeue/detach:
    //

    wp<GraphicBuffer> weakBuffer;
    {
        EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));

        EXPECT_EQ(OK, surface->detachBuffer(buffer));

        weakBuffer = buffer;
        buffer = nullptr;
    }
    EXPECT_EQ(nullptr, weakBuffer.promote()) << "Weak buffer still held by Surface.";

    //
    // Verify detach without borrowing the buffer does not work:
    //

    sp<GraphicBuffer> heldTooLongBuffer;
    EXPECT_EQ(OK, surface->dequeueBuffer(&heldTooLongBuffer, &fence));
    EXPECT_EQ(OK, surface->queueBuffer(heldTooLongBuffer));
    EXPECT_EQ(BAD_VALUE, surface->detachBuffer(heldTooLongBuffer));
}

TEST_F(SurfaceTest, AllowAllocation) {
    // controlledByApp must be true to disable blocking
    sp<CpuConsumer> cpuConsumer = sp<CpuConsumer>::make(1, /*controlledByApp*/ true);
    sp<Surface> surface = cpuConsumer->getSurface();
    sp<StubSurfaceListener> listener = sp<StubSurfaceListener>::make();
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;

    EXPECT_EQ(OK,
              surface->connect(NATIVE_WINDOW_API_CPU, listener, /* reportBufferRemoval */ false));
    EXPECT_EQ(OK, surface->allowAllocation(false));

    EXPECT_EQ(OK, surface->setDequeueTimeout(-1));
    EXPECT_EQ(WOULD_BLOCK, surface->dequeueBuffer(&buffer, &fence));

    EXPECT_EQ(OK, surface->setDequeueTimeout(10));
    EXPECT_EQ(TIMED_OUT, surface->dequeueBuffer(&buffer, &fence));

    EXPECT_EQ(OK, surface->allowAllocation(true));
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
}

TEST_F(SurfaceTest, QueueAcquireReleaseDequeue_CalledInStack_DoesNotDeadlock) {
    class DequeuingSurfaceListener : public SurfaceListener {
    public:
        DequeuingSurfaceListener(const wp<Surface>& surface) : mSurface(surface) {}

        virtual void onBufferReleased() override {
            sp<Surface> surface = mSurface.promote();
            ASSERT_NE(nullptr, surface);
            EXPECT_EQ(OK, surface->dequeueBuffer(&mBuffer, &mFence));
        }

        virtual bool needsReleaseNotify() override { return true; }
        virtual void onBuffersDiscarded(const std::vector<sp<GraphicBuffer>>&) override {}
        virtual void onBufferDetached(uint64_t) override {}

        sp<GraphicBuffer> mBuffer;
        sp<Fence> mFence;

    private:
        wp<Surface> mSurface;
    };

    class ImmediateReleaseConsumerListener : public BufferItemConsumer::FrameAvailableListener {
    public:
        ImmediateReleaseConsumerListener(const wp<BufferItemConsumer>& consumer)
              : mConsumer(consumer) {}

        virtual void onFrameAvailable(const BufferItem&) override {
            sp<BufferItemConsumer> consumer = mConsumer.promote();
            ASSERT_NE(nullptr, consumer);

            mCalls += 1;

            BufferItem buffer;
            EXPECT_EQ(OK, consumer->acquireBuffer(&buffer, 0));
            EXPECT_EQ(OK, consumer->releaseBuffer(buffer));
        }

        size_t mCalls = 0;

    private:
        wp<BufferItemConsumer> mConsumer;
    };

    sp<IGraphicBufferProducer> bqProducer;
    sp<IGraphicBufferConsumer> bqConsumer;
    BufferQueue::createBufferQueue(&bqProducer, &bqConsumer);

    auto [consumer, surface] = BufferItemConsumer::create(3);
    sp<ImmediateReleaseConsumerListener> consumerListener =
            sp<ImmediateReleaseConsumerListener>::make(consumer);
    consumer->setFrameAvailableListener(consumerListener);

    sp<DequeuingSurfaceListener> surfaceListener = sp<DequeuingSurfaceListener>::make(surface);
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener, false));

    EXPECT_EQ(OK, surface->setMaxDequeuedBufferCount(2));

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(OK, surface->queueBuffer(buffer, fence));

    EXPECT_EQ(1u, consumerListener->mCalls);
    EXPECT_NE(nullptr, surfaceListener->mBuffer);

    EXPECT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

// See: b/414442592
TEST_F(SurfaceTest, DequeueBuffer_WithDeadConsumer_DoesNotCrash) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);

    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener, false));

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(OK, surface->queueBuffer(buffer, fence));

    consumer->abandon();

    auto beforeBuffer = buffer;
    auto beforeFence = fence;

    EXPECT_NE(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(buffer, beforeBuffer);
    EXPECT_EQ(fence, beforeFence);
}

TEST_F(SurfaceTest, ViewSurface_toString) {
    view::Surface surface{};
    EXPECT_EQ("", surface.toString());

    surface.name = String16("name");
    EXPECT_EQ("name", surface.toString());
}

TEST_F(SurfaceTest, TestRemoteSurfaceDied_CallbackCalled) {
    sp<TestServerClient> testServer = TestServerClient::Create();
    sp<IGraphicBufferProducer> producer = testServer->CreateProducer();
    EXPECT_NE(nullptr, producer);

    sp<Surface> surface = sp<Surface>::make(producer);
    sp<DeathWatcherListener> deathWatcher = sp<DeathWatcherListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, deathWatcher));

    auto diedFuture = deathWatcher->getDiedFuture();
    EXPECT_EQ(OK, testServer->Kill());

    diedFuture.wait();
    EXPECT_TRUE(diedFuture.get());
}

TEST_F(SurfaceTest, TestRemoteSurfaceDied_Disconnect_CallbackNotCalled) {
    sp<TestServerClient> testServer = TestServerClient::Create();
    sp<IGraphicBufferProducer> producer = testServer->CreateProducer();
    EXPECT_NE(nullptr, producer);

    sp<Surface> surface = sp<Surface>::make(producer);
    sp<DeathWatcherListener> deathWatcher = sp<DeathWatcherListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, deathWatcher));
    EXPECT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));

    auto watcherDiedFuture = deathWatcher->getDiedFuture();
    EXPECT_EQ(OK, testServer->Kill());

    std::future_status status = watcherDiedFuture.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(std::future_status::timeout, status);
}

TEST_F(SurfaceTest, QueueBufferOutput_TracksReplacements) {
    sp<BufferItemConsumer> consumer = sp<BufferItemConsumer>::make(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, consumer->setMaxBufferCount(3));
    ASSERT_EQ(OK, consumer->setMaxAcquiredBufferCount(1));

    sp<Surface> surface = consumer->getSurface();
    sp<StubSurfaceListener> listener = sp<StubSurfaceListener>::make();

    // Async mode sets up an extra buffer so the surface can queue it without waiting.
    ASSERT_EQ(OK, surface->setMaxDequeuedBufferCount(1));
    ASSERT_EQ(OK, surface->setAsyncMode(true));
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, listener));

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    SurfaceQueueBufferOutput output;
    BufferItem item;

    // We can queue directly, without an output arg.
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(OK, surface->queueBuffer(buffer, fence));
    EXPECT_EQ(OK, consumer->acquireBuffer(&item, 0));
    EXPECT_EQ(OK, consumer->releaseBuffer(item));

    // We can queue with an output arg, and that we don't expect to see a replacement.
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(OK, surface->queueBuffer(buffer, fence, &output));
    EXPECT_FALSE(output.bufferReplaced);

    // We expect see a replacement when we queue a second buffer in async mode, and the consumer
    // hasn't acquired the first one yet.
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(OK, surface->queueBuffer(buffer, fence, &output));
    EXPECT_TRUE(output.bufferReplaced);
}

TEST_F(SurfaceTest, QueueBufferOutput_TracksReplacements_Plural) {
    sp<BufferItemConsumer> consumer = sp<BufferItemConsumer>::make(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, consumer->setMaxBufferCount(4));
    ASSERT_EQ(OK, consumer->setMaxAcquiredBufferCount(1));

    sp<Surface> surface = consumer->getSurface();
    consumer->setName(String8("TRPTest"));
    sp<StubSurfaceListener> listener = sp<StubSurfaceListener>::make();

    // Async mode sets up an extra buffer so the surface can queue it without waiting.
    ASSERT_EQ(OK, surface->setMaxDequeuedBufferCount(2));
    ASSERT_EQ(OK, surface->setAsyncMode(true));
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, listener));

    // dequeueBuffers requires a vector of a certain size:
    std::vector<Surface::BatchBuffer> buffers(2);
    std::vector<Surface::BatchQueuedBuffer> queuedBuffers;
    std::vector<SurfaceQueueBufferOutput> outputs;
    BufferItem item;

    auto moveBuffersToQueuedBuffers = [&]() {
        EXPECT_EQ(2u, buffers.size());
        EXPECT_NE(nullptr, buffers[0].buffer);
        EXPECT_NE(nullptr, buffers[1].buffer);

        queuedBuffers.clear();
        for (auto& buffer : buffers) {
            auto& queuedBuffer = queuedBuffers.emplace_back();
            queuedBuffer.buffer = buffer.buffer;
            queuedBuffer.fenceFd = buffer.fenceFd;
            queuedBuffer.timestamp = NATIVE_WINDOW_TIMESTAMP_AUTO;
        }
        buffers = {{}, {}};
    };

    // We can queue directly, without an output arg.
    EXPECT_EQ(OK, surface->dequeueBuffers(&buffers));
    moveBuffersToQueuedBuffers();
    EXPECT_EQ(OK, surface->queueBuffers(queuedBuffers));
    EXPECT_EQ(OK, consumer->acquireBuffer(&item, 0));
    EXPECT_EQ(OK, consumer->releaseBuffer(item));

    // We can queue with an output arg. Only the second one should be replaced.
    EXPECT_EQ(OK, surface->dequeueBuffers(&buffers));
    moveBuffersToQueuedBuffers();
    EXPECT_EQ(OK, surface->queueBuffers(queuedBuffers, &outputs));
    EXPECT_EQ(2u, outputs.size());
    EXPECT_FALSE(outputs[0].bufferReplaced);
    EXPECT_TRUE(outputs[1].bufferReplaced);

    // Since we haven't acquired anything, both queued buffers will replace the original one.
    EXPECT_EQ(OK, surface->dequeueBuffers(&buffers));
    moveBuffersToQueuedBuffers();
    EXPECT_EQ(OK, surface->queueBuffers(queuedBuffers, &outputs));
    EXPECT_EQ(2u, outputs.size());
    EXPECT_TRUE(outputs[0].bufferReplaced);
    EXPECT_TRUE(outputs[1].bufferReplaced);
}

TEST_F(SurfaceTest, QueueBufferInputOutput) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, consumer->setDefaultBufferSize(20, 20));
    surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false);

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));

    SurfaceQueueBufferInput input;
    input.fence = fence;
    input.crop = Rect(0, 0, 10, 10);
    input.transform = NATIVE_WINDOW_TRANSFORM_ROT_90;
    input.timestamp = 12345;

    SurfaceQueueBufferOutput output;
    ASSERT_EQ(OK, surface->queueBuffer(buffer, input, &output));

    EXPECT_GE(output.nextFrameNumber, 1u);
}

TEST_F(SurfaceTest, CancelBuffer_GraphicBuffer_Fence) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false);

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));

    ASSERT_EQ(OK, surface->cancelBuffer(buffer, fence));
}

TEST_F(SurfaceTest, AttachBuffer_GraphicBuffer) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false);

    // We need a detached buffer.
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(OK, surface->detachBuffer(buffer));

    ASSERT_EQ(OK, surface->attachBuffer(buffer));
    // Can cancel/queue after attach
    ASSERT_EQ(OK, surface->cancelBuffer(buffer, fence));
}

TEST_F(SurfaceTest, UnlimitedSlots_FailsOnIncompatibleConsumer) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<IConsumerListener> consumerListener = sp<FakeConsumer>::make();

    EXPECT_EQ(OK, consumer->allowUnlimitedSlots(false));
    EXPECT_EQ(OK, consumer->consumerConnect(consumerListener, /* consumerListener */ true));

    sp<Surface> surface = sp<Surface>::make(producer);
    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    EXPECT_NE(OK, surface->setMaxDequeuedBufferCount(128))
            << "We shouldn't be able to set high max buffer counts if the consumer doesn't allow "
               "it";
}

TEST_F(SurfaceTest, UnlimitedSlots_CanDequeueAndQueueMoreThanOldMaximum) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<IConsumerListener> consumerListener = sp<FakeConsumer>::make();

    EXPECT_EQ(OK, consumer->allowUnlimitedSlots(true));
    EXPECT_EQ(OK, consumer->consumerConnect(consumerListener, /* consumerListener */ true));
    EXPECT_EQ(OK, consumer->setDefaultBufferFormat(PIXEL_FORMAT_RGBA_8888));
    EXPECT_EQ(OK, consumer->setConsumerUsageBits(AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN));

    sp<Surface> surface = sp<Surface>::make(producer);
    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    EXPECT_EQ(OK, surface->setMaxDequeuedBufferCount(128))
            << "If unlimited slots are allowed, we should be able increase the max dequeued buffer "
               "count arbitrarily";

    std::vector<std::tuple<sp<GraphicBuffer>, sp<Fence>, int>> buffers;
    for (int i = 0; i < 128; i++) {
        sp<GraphicBuffer> buffer;
        sp<Fence> fence;
        ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence)) << "Unable to dequeue buffer #" << i;
        buffers.push_back({buffer, fence, i});
    }

    for (auto& [buffer, fence, idx] : buffers) {
        ASSERT_EQ(OK, surface->queueBuffer(buffer, fence)) << "Unable to queue buffer #" << idx;
    }
}

TEST_F(SurfaceTest, UnlimitedSlots_CanDequeueAndDetachMoreThanOldMaximum) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<IConsumerListener> consumerListener = sp<FakeConsumer>::make();

    EXPECT_EQ(OK, consumer->allowUnlimitedSlots(true));
    EXPECT_EQ(OK, consumer->consumerConnect(consumerListener, /* consumerListener */ true));
    EXPECT_EQ(OK, consumer->setDefaultBufferFormat(PIXEL_FORMAT_RGBA_8888));
    EXPECT_EQ(OK, consumer->setConsumerUsageBits(AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN));

    sp<Surface> surface = sp<Surface>::make(producer);
    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    EXPECT_EQ(OK, surface->setMaxDequeuedBufferCount(128))
            << "If unlimited slots are allowed, we should be able increase the max dequeued buffer "
               "count arbitrarily";

    std::vector<std::tuple<sp<GraphicBuffer>, sp<Fence>, int>> buffers;
    for (int i = 0; i < 128; i++) {
        sp<GraphicBuffer> buffer;
        sp<Fence> fence;
        ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence)) << "Unable to dequeue buffer #" << i;
        buffers.push_back({buffer, fence, i});
    }

    for (auto& [buffer, _, idx] : buffers) {
        ASSERT_EQ(OK, surface->detachBuffer(buffer)) << "Unable to detach buffer #" << idx;
    }
}

TEST_F(SurfaceTest, UnlimitedSlots_BatchOperations) {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);

    sp<IConsumerListener> consumerListener = sp<FakeConsumer>::make();

    EXPECT_EQ(OK, consumer->allowUnlimitedSlots(true));
    EXPECT_EQ(OK, consumer->consumerConnect(consumerListener, /* consumerListener */ true));
    EXPECT_EQ(OK, consumer->setDefaultBufferFormat(PIXEL_FORMAT_RGBA_8888));
    EXPECT_EQ(OK, consumer->setConsumerUsageBits(AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN));

    sp<Surface> surface = sp<Surface>::make(producer);
    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    EXPECT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    EXPECT_EQ(OK, surface->setMaxDequeuedBufferCount(128))
            << "If unlimited slots are allowed, we should be able increase the max dequeued buffer "
               "count arbitrarily";

    std::vector<Surface::BatchBuffer> buffers(128);
    EXPECT_EQ(OK, surface->dequeueBuffers(&buffers));
    EXPECT_EQ(128u, buffers.size());

    std::vector<Surface::BatchQueuedBuffer> queuedBuffers;
    std::transform(buffers.begin(), buffers.end(), std::back_inserter(queuedBuffers),
                   [](Surface::BatchBuffer& buffer) {
                       Surface::BatchQueuedBuffer out;
                       out.buffer = buffer.buffer;
                       out.fenceFd = buffer.fenceFd;
                       return out;
                   });

    std::vector<SurfaceQueueBufferOutput> outputs;
    EXPECT_EQ(OK, surface->queueBuffers(queuedBuffers, &outputs));
    EXPECT_EQ(128u, outputs.size());
}

TEST_F(SurfaceTest, UnlimitedSlots_SetMaxDequeuedBufferCount_EdgeCase) {
    auto [consumer, surface] = BufferItemConsumer::create(TEST_PRODUCER_USAGE_BITS);

    sp<SurfaceListener> listener = sp<StubSurfaceListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, listener));

    // We carefully configure the BufferQueue so that it's bigger than the old max of 64, but the
    // max dequeued count is smaller than it. Previously, this would lead to us not extending the BQ
    // before setting the max.
    const int kDequeableBufferCount = 60;
    const int kAcquireableBufferCount = 10;
    ASSERT_EQ(OK, consumer->setMaxAcquiredBufferCount(kAcquireableBufferCount));
    ASSERT_EQ(OK, surface->setMaxDequeuedBufferCount(kDequeableBufferCount));

    // Do a single round of operations so that the BQ will actually check max dequeued:
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    BufferItem item;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));
    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
    ASSERT_EQ(OK, consumer->releaseBuffer(item));

    // Verify that we can actually dequeue all kDequeableBufferCount at once:
    for (int i = 0; i < kDequeableBufferCount; i++) {
        ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence)) << "Failed to dequeue buffer #" << i;
    }
}

TEST_F(SurfaceTest, UnlimitedSlots_SecondSurface_UnderstandsExtraSlots) {
    auto [consumer, surface] = BufferItemConsumer::create(TEST_PRODUCER_USAGE_BITS);
    ASSERT_NE(nullptr, surface.get());

    // We can set the max dequeued count before connecting.
    ASSERT_EQ(NO_ERROR, surface->setMaxDequeuedBufferCount(32));

    // 100 is more than the default 64
    ASSERT_EQ(NO_ERROR, surface->setMaxDequeuedBufferCount(100));

    sp<Surface> surface2 = sp<Surface>::make(surface->getIGraphicBufferProducer());
    ASSERT_EQ(NO_ERROR, surface2->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make()));

    sp<GraphicBuffer> buffers[100];
    for (int i = 0; i < 100; i++) {
        sp<Fence> fence;
        ASSERT_EQ(NO_ERROR, surface2->dequeueBuffer(&buffers[i], &fence));
    }

    for (int i = 0; i < 100; i++) {
        ASSERT_EQ(NO_ERROR, surface2->cancelBuffer(buffers[i], Fence::NO_FENCE));
    }

    ASSERT_EQ(NO_ERROR, surface2->disconnect(NATIVE_WINDOW_API_CPU));
}

TEST_F(SurfaceTest, isBufferOwned) {
    const int TEST_USAGE_FLAGS = GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER;
    auto [bufferItemConsumer, surface] = BufferItemConsumer::create(TEST_USAGE_FLAGS);

    sp<SurfaceListener> listener = sp<StubSurfaceListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, listener));

    sp<GraphicBuffer> surfaceAttachableBuffer =
            sp<GraphicBuffer>::make(10, 10, PIXEL_FORMAT_RGBA_8888, 1, TEST_USAGE_FLAGS);

    //
    // Attaching a buffer makes it owned.
    //

    bool isOwned;
    EXPECT_EQ(OK, surface->isBufferOwned(surfaceAttachableBuffer, &isOwned));
    EXPECT_FALSE(isOwned);

    EXPECT_EQ(OK, surface->attachBuffer(surfaceAttachableBuffer.get()));
    EXPECT_EQ(OK, surface->isBufferOwned(surfaceAttachableBuffer, &isOwned));
    EXPECT_TRUE(isOwned);

    //
    // A dequeued buffer is always owned.
    //

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    EXPECT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    EXPECT_EQ(OK, surface->isBufferOwned(buffer, &isOwned));
    EXPECT_TRUE(isOwned);

    //
    // A detached buffer is no longer owned.
    //

    EXPECT_EQ(OK, surface->detachBuffer(buffer));
    EXPECT_EQ(OK, surface->isBufferOwned(buffer, &isOwned));
    EXPECT_FALSE(isOwned);

    //
    // It's not currently possible to verify whether or not a consumer has attached a buffer until
    // it shows up on the Surface.
    //

    sp<GraphicBuffer> consumerAttachableBuffer =
            sp<GraphicBuffer>::make(10, 10, PIXEL_FORMAT_RGBA_8888, 1, TEST_USAGE_FLAGS);

    ASSERT_EQ(OK, bufferItemConsumer->attachBuffer(consumerAttachableBuffer));
    EXPECT_EQ(OK, surface->isBufferOwned(consumerAttachableBuffer, &isOwned));
    EXPECT_FALSE(isOwned);
}

TEST_F(SurfaceTest, isBufferOwned_SameBufferBufferWithDifferentHandles) {
    //
    // Surface setup:
    //
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));

    //
    // Buffer setup:
    //
    sp<GraphicBuffer> originalBuffer =
            sp<GraphicBuffer>::make(10, 10, PIXEL_FORMAT_RGBA_8888, 1, GRALLOC_USAGE_SW_READ_OFTEN);
    sp<GraphicBuffer> copiedBuffer = sp<GraphicBuffer>::make();

    // Copy all the data from one buffer to the other. At time of writing, this will clone and
    // duplicate the native handle, making them different, while the rest of the aspects of the
    // buffers remain the same.
    std::vector<uint8_t> bufferData(originalBuffer->getFlattenedSize());
    std::vector<int> fdCount(originalBuffer->getFdCount());

    void* data = bufferData.data();
    size_t size = bufferData.size();
    int* fds = fdCount.data();
    size_t count = fdCount.size();
    ASSERT_EQ(OK, originalBuffer->flatten(data, size, fds, count));

    void const* inData = bufferData.data();
    size = bufferData.size();
    int const* inFds = fdCount.data();
    count = fdCount.size();
    ASSERT_EQ(OK, copiedBuffer->unflatten(inData, size, inFds, count));

    // Double check our expectations about a flattened/unflattened buffer:
    ASSERT_NE(originalBuffer, copiedBuffer);
    ASSERT_EQ(originalBuffer->getId(), copiedBuffer->getId());

    ASSERT_EQ(originalBuffer->handle->numFds, copiedBuffer->handle->numFds);
    for (int i = 0; i < originalBuffer->handle->numFds; i++) {
        ASSERT_NE(originalBuffer->handle->data[i], copiedBuffer->handle->data[i]);
    }

    //
    // Test:
    //
    EXPECT_EQ(OK, surface->attachBuffer(originalBuffer->getNativeBuffer()));

    bool isOwned;
    ASSERT_EQ(OK, surface->isBufferOwned(originalBuffer, &isOwned));
    EXPECT_TRUE(isOwned);

    ASSERT_EQ(OK, surface->isBufferOwned(copiedBuffer, &isOwned));
    EXPECT_TRUE(isOwned);
}

TEST_F(SurfaceTest, DisconnectWhileDequeued_HoldsDequeuedBuffersOnDisconnect) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));

    // Dequeue a raw buffer. According to ANativeWindow::dequeueBuffer, the client can generally
    // expect a reference to be held by the Surface.
    ANativeWindow* anw = static_cast<ANativeWindow*>(surface.get());
    ANativeWindowBuffer* buffer;
    int fence;
    ASSERT_EQ(OK, anw->dequeueBuffer(anw, &buffer, &fence));

    wp<GraphicBuffer> wpBuffer = GraphicBuffer::from(buffer);
    ASSERT_NE(nullptr, wpBuffer.promote());

    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
    ASSERT_NE(nullptr, wpBuffer.promote())
            << "A dequeued buffer should not go out of scope just because of a disconnect.";

    anw->cancelBuffer(anw, buffer, fence);
    ASSERT_EQ(nullptr, wpBuffer.promote())
            << "A dequeued buffer should go out of scope if it was cancelled, even if it was "
               "dequeued from a disconnected buffer.";
}

TEST_F(SurfaceTest, DisconnectWhileDequeued_QueueLeakedBufferAfterDisconnect) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));

    ANativeWindow* anw = static_cast<ANativeWindow*>(surface.get());
    ANativeWindowBuffer* buffer;
    int fence;
    ASSERT_EQ(OK, anw->dequeueBuffer(anw, &buffer, &fence));

    wp<GraphicBuffer> wpBuffer = GraphicBuffer::from(buffer);
    ASSERT_NE(nullptr, wpBuffer.promote());

    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
    ASSERT_NE(nullptr, wpBuffer.promote());

    ASSERT_EQ(OK, anw->queueBuffer(anw, buffer, fence));
    ASSERT_EQ(nullptr, wpBuffer.promote());
}

TEST_F(SurfaceTest, DisconnectWhileDequeued_BatchCancelLeakedBuffers) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));
    ANativeWindow* anw = static_cast<ANativeWindow*>(surface.get());
    ASSERT_EQ(OK, native_window_set_buffer_count(anw, 4));

    ANativeWindowBuffer* buffers[3];
    wp<GraphicBuffer> wpBuffers[3];
    int fences[3];

    for (int i = 0; i < 3; ++i) {
        ASSERT_EQ(OK, anw->dequeueBuffer(anw, &buffers[i], &fences[i]));
        wpBuffers[i] = GraphicBuffer::from(buffers[i]);
        ASSERT_NE(nullptr, wpBuffers[i].promote());
    }

    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));

    for (int i = 0; i < 3; ++i) {
        ASSERT_NE(nullptr, wpBuffers[i].promote());
    }

    // The batch cancel should release all leaked buffers.
    std::vector<Surface::BatchBuffer> batch;
    for (int i = 0; i < 3; ++i) {
        batch.push_back({buffers[i], fences[i]});
    }
    ASSERT_EQ(OK, surface->cancelBuffers(batch));

    for (int i = 0; i < 3; ++i) {
        ASSERT_EQ(nullptr, wpBuffers[i].promote());
    }
}

TEST_F(SurfaceTest, DisconnectWhileDequeued_ReconnectDoesNotAffectLeakedBuffers) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ANativeWindow* anw = static_cast<ANativeWindow*>(surface.get());

    // Client A connects and dequeues a buffer.
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));
    ANativeWindowBuffer* bufferA;
    int fenceA;
    ASSERT_EQ(OK, anw->dequeueBuffer(anw, &bufferA, &fenceA));
    wp<GraphicBuffer> wpBufferA = GraphicBuffer::from(bufferA);
    ANativeWindowBuffer* bufferB;
    int fenceB;
    ASSERT_EQ(OK, anw->dequeueBuffer(anw, &bufferB, &fenceB));
    wp<GraphicBuffer> wpBufferB = GraphicBuffer::from(bufferB);

    // Client A disconnects, leaking bufferA.
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
    ASSERT_NE(nullptr, wpBufferA.promote());

    // Client B connects and performs some operations.
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));
    ANativeWindowBuffer* bufferC;
    int fenceC;
    ASSERT_EQ(OK, anw->dequeueBuffer(anw, &bufferC, &fenceC));

    // Even though they likely use the same slot, the new buffer should be really new.
    ASSERT_NE(bufferA, bufferC);

    ASSERT_EQ(OK, anw->cancelBuffer(anw, bufferC, fenceC));

    // Cancelling will remove the previously dequeued buffer from the leaked set, but should fail
    // since it's an invalid operation on the reconnected BQ.
    ASSERT_NE(OK, anw->cancelBuffer(anw, bufferB, fenceB));
    ASSERT_EQ(nullptr, wpBufferB.promote());

    // Leaked bufferA should not be affected.
    ASSERT_NE(nullptr, wpBufferA.promote());

    // Client B disconnects.
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));

    ASSERT_EQ(OK, anw->cancelBuffer(anw, bufferA, fenceA));
    ASSERT_EQ(nullptr, wpBufferA.promote());
}

TEST_F(SurfaceTest, Detach_BufferIsNotLeaked) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);

    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, sp<StubSurfaceListener>::make(), false));
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));

    wp<GraphicBuffer> weakBuffer = buffer;
    buffer = nullptr;
    ASSERT_EQ(OK, surface->detachBuffer(weakBuffer.promote()));
    ASSERT_EQ(nullptr, weakBuffer.promote());
}

TEST_F(SurfaceTest, DiscardDetach_DoesNotDeadlock) {
    constexpr size_t kLotsOfBuffers = 512;
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);

    consumer->setName(String8("DetachDeadlockTest"));

    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    //
    // Set up a large number of buffers to increase the likelihood that a deadlock might get caught:
    //
    ASSERT_EQ(OK, surface->setMaxDequeuedBufferCount(kLotsOfBuffers));

    std::vector<std::tuple<sp<GraphicBuffer>, sp<Fence>>> buffers(kLotsOfBuffers);
    for (size_t i = 0; i < kLotsOfBuffers; i++) {
        auto& [buffer, fence] = buffers[i];
        ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    }

    BufferItem item;
    for (auto& [buffer, fence] : buffers) {
        ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));
        ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
        ASSERT_EQ(OK, consumer->releaseBuffer(item));
    }

    //
    // Do work in two threads simultaneously (as simultaneously as humanly possible). The cv helps
    // thread us not get caught in synchronous thread creation.
    //
    std::condition_variable cv;
    auto surfaceThread = std::jthread([&] {
        std::mutex m;
        std::unique_lock l(m);
        cv.wait(l);
        sp<GraphicBuffer> buffer;
        sp<Fence> fence;
        status_t ret = surface->detachNextBuffer(&buffer, &fence);
        ASSERT_TRUE(ret == OK || ret == NO_MEMORY);
    });
    auto consumerThread = std::jthread([&] {
        std::mutex m;
        std::unique_lock l(m);
        cv.wait(l);
        ASSERT_EQ(OK, consumer->discardFreeBuffers());
    });

    std::this_thread::sleep_for(2s);
    cv.notify_all();
}

TEST_F(SurfaceTest, DisconnectDetach_DoesNotDeadlock) {
    constexpr size_t kLotsOfBuffers = 512;
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);

    consumer->setName(String8("DisconnectDeadlockTest"));

    sp<SurfaceListener> surfaceListener = sp<StubSurfaceListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    //
    // Set up a large number of buffers to increase the likelihood that a deadlock might get caught:
    //
    ASSERT_EQ(OK, surface->setMaxDequeuedBufferCount(kLotsOfBuffers));

    std::vector<std::tuple<sp<GraphicBuffer>, sp<Fence>>> buffers(kLotsOfBuffers);
    for (size_t i = 0; i < kLotsOfBuffers; i++) {
        auto& [buffer, fence] = buffers[i];
        ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    }

    BufferItem item;
    for (auto& [buffer, fence] : buffers) {
        ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));
        ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
        ASSERT_EQ(OK, consumer->releaseBuffer(item));
    }

    //
    // Do work in two threads simultaneously (as simultaneously as humanly possible). The cv helps
    // thread us not get caught in synchronous thread creation.
    //
    std::condition_variable cv;
    auto surfaceThread = std::jthread([&] {
        std::mutex m;
        std::unique_lock l(m);
        cv.wait(l);
        sp<GraphicBuffer> buffer;
        sp<Fence> fence;
        ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
    });
    auto consumerThread = std::jthread([&] {
        std::mutex m;
        std::unique_lock l(m);
        cv.wait(l);
        ASSERT_EQ(OK, consumer->discardFreeBuffers());
    });

    // Give some time for the threads to be ready.
    std::this_thread::sleep_for(2s);
    cv.notify_all();
}

TEST_F(SurfaceTest, DisconnectWithBadApi) {
    const android_dataspace kDataspace = HAL_DATASPACE_V0_SRGB_LINEAR;
    const int kFormat = PIXEL_FORMAT_RGB_565;

    // This test ensures that the internal surface state isn't disrupted in the weird case that the
    // wrong api is set--the underlying IGBP will still be connected with no state changes within
    // itself.
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    ANativeWindow* anw = static_cast<ANativeWindow*>(surface.get());

    consumer->setName(String8("DisconnectWithBadApi"));

    struct NotifyingListener : public StubSurfaceListener {
        virtual bool needsReleaseNotify() override { return true; }
        virtual void onBufferReleased() override { mReleasedCount++; }

        uint32_t mReleasedCount = 0;
    };

    sp<NotifyingListener> surfaceListener = sp<NotifyingListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, surfaceListener));

    //
    // Prepare two buffers, one we'll acquire and one we won't.
    //
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));

    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));

    //
    // Set some values that should be cleared by a correct disconnect
    //
    ASSERT_EQ(NO_ERROR, native_window_set_buffers_data_space(anw, kDataspace));
    ASSERT_EQ(NO_ERROR, native_window_set_buffers_format(anw, kFormat));

    //
    // This disconnect will fail, leaving everything the same and functional.
    //
    ASSERT_EQ(BAD_VALUE, surface->disconnect(NATIVE_WINDOW_API_CAMERA));

    int value;
    ASSERT_EQ(NO_ERROR, anw->query(anw, NATIVE_WINDOW_DATASPACE, &value));
    EXPECT_EQ(kDataspace, value);
    ASSERT_EQ(NO_ERROR, anw->query(anw, NATIVE_WINDOW_FORMAT, &value));
    EXPECT_EQ(kFormat, value);

    BufferItem item;
    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
    ASSERT_EQ(OK, consumer->releaseBuffer(item));

    ASSERT_EQ(1u, surfaceListener->mReleasedCount);

    //
    // This disconnect will succeed, cleaning up the state.
    //
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
    ASSERT_EQ(NO_ERROR, anw->query(anw, NATIVE_WINDOW_DATASPACE, &value));
    EXPECT_NE(kDataspace, value);
    ASSERT_EQ(NO_ERROR, anw->query(anw, NATIVE_WINDOW_FORMAT, &value));
    EXPECT_NE(kFormat, value);

    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
    ASSERT_EQ(IGraphicBufferConsumer::STALE_BUFFER_SLOT, consumer->releaseBuffer(item));
    ASSERT_EQ(1u, surfaceListener->mReleasedCount);
}

enum class LegacyBufferDropMode : uint8_t {
    Disabled = 0,
    Enabled = 1,
};

void CheckLegacyBufferDropMode(sp<BufferItemConsumer> consumer, sp<Surface> surface,
                               LegacyBufferDropMode mode) {
    // Clear all the buffers for a fresh queue.
    for (;;) {
        BufferItem item;
        status_t ret = consumer->acquireBuffer(&item, 0);
        if (ret == BufferItemConsumer::NO_BUFFER_AVAILABLE) {
            break;
        }
        EXPECT_EQ(OK, consumer->releaseBuffer(item));
    }

    sp<GraphicBuffer> bufferA, bufferB, bufferC, bufferD;
    sp<Fence> fenceA, fenceB, fenceC, fenceD;
    EXPECT_EQ(OK, surface->dequeueBuffer(&bufferA, &fenceA));
    EXPECT_EQ(OK, surface->queueBuffer(bufferA, fenceA));
    EXPECT_EQ(OK, surface->dequeueBuffer(&bufferB, &fenceB));
    EXPECT_EQ(OK, surface->queueBuffer(bufferB, fenceB));
    EXPECT_EQ(OK, surface->dequeueBuffer(&bufferC, &fenceC));
    EXPECT_EQ(OK, surface->queueBuffer(bufferC, fenceC));
    EXPECT_EQ(OK, surface->dequeueBuffer(&bufferD, &fenceD));
    EXPECT_EQ(OK, surface->queueBuffer(bufferD, fenceD));

    switch (mode) {
        case LegacyBufferDropMode::Enabled: {
            // The queue will replace the last buffer.
            EXPECT_NE(bufferA, bufferB);
            EXPECT_EQ(bufferA, bufferC);
            EXPECT_EQ(bufferB, bufferD);
            break;
        }
        case LegacyBufferDropMode::Disabled: {
            EXPECT_NE(bufferA, bufferB);
            EXPECT_NE(bufferA, bufferC);
            EXPECT_NE(bufferA, bufferD);
            EXPECT_NE(bufferB, bufferC);
            EXPECT_NE(bufferB, bufferD);
            EXPECT_NE(bufferC, bufferD);
            break;
        }
        default: {
            FAIL() << "Unknown LegacyBufferDropMode: " << static_cast<uint8_t>(mode);
            break;
        }
    }
}

TEST_F(SurfaceTest, LegacyBufferDrop_AppOwned) {
    auto [consumer, surface] =
            BufferItemConsumer::create(TEST_PRODUCER_USAGE_BITS, 10, /* controlledByApp */ true);

    sp<SurfaceListener> listener = sp<StubSurfaceListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, listener));

    // Legacy buffer drop starts out true.
    CheckLegacyBufferDropMode(consumer, surface, LegacyBufferDropMode::Enabled);

    ASSERT_EQ(OK, surface->setLegacyBufferDrop(false));

    CheckLegacyBufferDropMode(consumer, surface, LegacyBufferDropMode::Disabled);
}

TEST_F(SurfaceTest, LegacyBufferDrop_PresentMode) {
    auto [consumer, surface] =
            BufferItemConsumer::create(TEST_PRODUCER_USAGE_BITS, 10, /* controlledByApp */ true);
    sp<ANativeWindow> window(surface);

    sp<SurfaceListener> listener = sp<StubSurfaceListener>::make();
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, listener));

    // In default mode, legacy buffer mode should be enabled
    ASSERT_EQ(NO_ERROR,
              native_window_set_present_mode(window.get(), ANATIVEWINDOW_PRESENT_DEFAULT));
    CheckLegacyBufferDropMode(consumer, surface, LegacyBufferDropMode::Enabled);

    // With fifo latest ready, legacy buffer mode should be disabled
    ASSERT_EQ(NO_ERROR,
              native_window_set_present_mode(window.get(),
                                             ANATIVEWINDOW_PRESENT_FIFO_LATEST_READY));
    CheckLegacyBufferDropMode(consumer, surface, LegacyBufferDropMode::Disabled);
}

// Test for native_window_get_last_replaced_frame_id, which is used by Vulkan's
// vkWaitForPresent2KHR to know when a frame has been replaced in the queue.
TEST_F(SurfaceTest, PresentWaitANWGetLastReplacedFrameIdIsCorrect) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    sp<ANativeWindow> window(surface);

    // Async mode is required for buffers to be dropped.
    ASSERT_EQ(OK, surface->setAsyncMode(true));

    // We don't need a listener for this test.
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false));

    uint64_t lastReplacedFrameId = 0;
    // Before any buffers are queued, the last replaced frame ID should be NOT_ENOUGH_DATA
    ASSERT_EQ(NOT_ENOUGH_DATA,
              native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(0u, lastReplacedFrameId);

    sp<GraphicBuffer> buffer1;
    sp<Fence> fence1;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer1, &fence1));
    ASSERT_EQ(OK, surface->queueBuffer(buffer1, fence1)); // frame 1

    ASSERT_EQ(NOT_ENOUGH_DATA,
              native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(0u, lastReplacedFrameId);

    sp<GraphicBuffer> buffer2;
    sp<Fence> fence2;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer2, &fence2));
    ASSERT_EQ(OK, surface->queueBuffer(buffer2, fence2)); // frame 2, replaces frame 1

    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(1u, lastReplacedFrameId);

    sp<GraphicBuffer> buffer3;
    sp<Fence> fence3;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer3, &fence3));
    ASSERT_EQ(OK, surface->queueBuffer(buffer3, fence3)); // frame 3, replaces frame 2

    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(2u, lastReplacedFrameId);

    // Acquire the buffer to make sure the queue is not empty.
    BufferItem item;
    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
    // The acquired buffer should be buffer3, with frame number 3.
    ASSERT_EQ(item.mFrameNumber, 3u);

    // The last replaced frame ID should not change after acquiring a buffer.
    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(2u, lastReplacedFrameId);

    ASSERT_EQ(OK, consumer->releaseBuffer(item));
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

TEST_F(SurfaceTest, FrameNumberIsResetAfterReconnect) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    sp<ANativeWindow> window(surface);

    // Async mode is required for buffers to be dropped.
    ASSERT_EQ(OK, surface->setAsyncMode(true));

    // We don't need a listener for this test.
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false));

    uint64_t lastReplacedFrameId = 0;
    // Before any buffers are queued, the last replaced frame ID should be 0.
    ASSERT_EQ(NOT_ENOUGH_DATA,
              native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(0u, lastReplacedFrameId);

    sp<GraphicBuffer> buffer1;
    sp<Fence> fence1;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer1, &fence1));
    ASSERT_EQ(OK, surface->queueBuffer(buffer1, fence1)); // frame 1

    ASSERT_EQ(NOT_ENOUGH_DATA,
              native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(0u, lastReplacedFrameId);

    sp<GraphicBuffer> buffer2;
    sp<Fence> fence2;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer2, &fence2));
    ASSERT_EQ(OK, surface->queueBuffer(buffer2, fence2)); // frame 2, replaces frame 1

    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(1u, lastReplacedFrameId);

    // Disconnect and reconnect
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false));

    // Check value resets
    ASSERT_EQ(NOT_ENOUGH_DATA,
              native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(1u, lastReplacedFrameId);
}

// Test for native_window_get_last_replaced_frame_id, which is used by Vulkan's
// vkWaitForPresent2KHR to know when a frame has been replaced in the queue.
TEST_F(SurfaceTest, PresentWaitANWGetLastReplacedFrameIdIsCorrect_Plural) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    sp<ANativeWindow> window(surface);

    // Async mode is required for buffers to be dropped.
    ASSERT_EQ(OK, surface->setAsyncMode(true));

    // We don't need a listener for this test.
    ASSERT_EQ(OK, surface->connect(NATIVE_WINDOW_API_CPU, nullptr, false));
    ASSERT_EQ(OK, surface->setMaxDequeuedBufferCount(2));

    uint64_t lastReplacedFrameId = 0;
    // Before any buffers are queued, the last replaced frame ID should be NOT_ENOUGH_DATA
    ASSERT_EQ(NOT_ENOUGH_DATA,
              native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(0u, lastReplacedFrameId);

    std::vector<Surface::BatchBuffer> buffers(2);
    std::vector<Surface::BatchQueuedBuffer> queuedBuffers;

    ASSERT_EQ(OK, surface->dequeueBuffers(&buffers));
    for (const auto& b : buffers) {
        queuedBuffers.push_back({b.buffer, b.fenceFd, NATIVE_WINDOW_TIMESTAMP_AUTO});
    }
    ASSERT_EQ(OK, surface->queueBuffers(queuedBuffers)); // frames 1 and 2. frame 2 replaces 1.

    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(1u, lastReplacedFrameId);

    queuedBuffers.clear();
    ASSERT_EQ(OK, surface->dequeueBuffers(&buffers));
    for (const auto& b : buffers) {
        queuedBuffers.push_back({b.buffer, b.fenceFd, NATIVE_WINDOW_TIMESTAMP_AUTO});
    }
    // frames 3 and 4. frame 3 replaces 2, frame 4 replaces 3.
    ASSERT_EQ(OK, surface->queueBuffers(queuedBuffers));

    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(3u, lastReplacedFrameId);

    // Acquire the buffer to make sure the queue is not empty.
    BufferItem item;
    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
    // The acquired buffer should be buffer with frame number 4.
    ASSERT_EQ(4u, item.mFrameNumber);

    // The last replaced frame ID should not change after acquiring a buffer.
    ASSERT_EQ(OK, native_window_get_last_replaced_frame_id(window.get(), &lastReplacedFrameId));
    ASSERT_EQ(3u, lastReplacedFrameId);

    ASSERT_EQ(OK, consumer->releaseBuffer(item));
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

namespace {

struct OnAcquiredCallbackState {
    std::mutex mutex;
    std::condition_variable cv;
    bool called = false;
    uint64_t bufferId = 0;
    uint64_t frameId = 0;
};

void onAcquiredCallback(uint64_t bufferId, uint64_t frameId, void* data) {
    OnAcquiredCallbackState* state = static_cast<OnAcquiredCallbackState*>(data);
    std::unique_lock<std::mutex> lock(state->mutex);
    state->called = true;
    state->bufferId = bufferId;
    state->frameId = frameId;
    state->cv.notify_one();
}

} // namespace

class OnAcquiredListener : public StubSurfaceListener {};

//  Test for ANativeWindow_OnAcquiredCallback, which is used by Vulkan's
//  vkWaitForPresent2KHR to know when a frame has been presented.
TEST_F(SurfaceTest, PresentWaitANWOnBufferAcquiredCallbackIsCalled) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    sp<ANativeWindow> window(surface);

    sp<OnAcquiredListener> listener = sp<OnAcquiredListener>::make();
    native_window_api_connect_with_listener(window.get(), NATIVE_WINDOW_API_CPU, false, true, true);

    OnAcquiredCallbackState state;
    native_window_set_on_acquired_callback(window.get(), onAcquiredCallback, &state);

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));

    BufferItem item;
    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));

    // Wait for callback
    {
        using namespace std::chrono_literals;
        std::unique_lock<std::mutex> lock(state.mutex);
        ASSERT_TRUE(state.cv.wait_for(lock, 1s, [&state] { return state.called; }));
        ASSERT_TRUE(state.called);
        ASSERT_EQ(state.bufferId, buffer->getId());
        // frame number should be 1 for the first buffer
        ASSERT_EQ(state.frameId, 1u);
    }

    ASSERT_EQ(OK, consumer->releaseBuffer(item));
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

namespace {

struct OnDroppedCallbackState {
    std::mutex mutex;
    std::condition_variable cv;
    bool called = false;
    uint64_t bufferId = 0;
    uint64_t frameId = 0;
};

void onDroppedCallback(uint64_t bufferId, uint64_t frameId, void* data) {
    OnDroppedCallbackState* state = static_cast<OnDroppedCallbackState*>(data);
    std::unique_lock<std::mutex> lock(state->mutex);
    state->called = true;
    state->bufferId = bufferId;
    state->frameId = frameId;
    state->cv.notify_one();
}

} // namespace

class OnDroppedListener : public StubSurfaceListener {};

// Test for ANativeWindow_OnDroppedCallback, which is used by Vulkan's
// vkWaitForPresent2KHR to know when a frame has been dropped.
TEST_F(SurfaceTest, PresentWaitANWOnBufferDroppedCallbackIsCalled) {
    auto [consumer, surface] = BufferItemConsumer::create(GRALLOC_USAGE_SW_READ_OFTEN);
    sp<ANativeWindow> window(surface);

    sp<OnDroppedListener> listener = sp<OnDroppedListener>::make();
    native_window_api_connect_with_listener(window.get(), NATIVE_WINDOW_API_CPU, false, true, true);

    OnDroppedCallbackState state;
    native_window_set_on_dropped_callback(window.get(), onDroppedCallback, &state);
    native_window_set_present_mode(window.get(), ANATIVEWINDOW_PRESENT_FIFO_LATEST_READY);
    sp<GraphicBuffer> bufferToDrop;
    sp<Fence> fenceToDrop;
    ASSERT_EQ(OK, surface->dequeueBuffer(&bufferToDrop, &fenceToDrop));
    ASSERT_EQ(OK, surface->queueBuffer(bufferToDrop, fenceToDrop));

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    ASSERT_EQ(OK, surface->dequeueBuffer(&buffer, &fence));
    ASSERT_EQ(OK, surface->queueBuffer(buffer, fence));

    BufferItem item;
    // The dropped buffer is gone, so acquire should get the second buffer.
    ASSERT_EQ(OK, consumer->acquireBuffer(&item, 0));
    ASSERT_EQ(item.mGraphicBuffer->getId(), buffer->getId());

    // Wait for callback
    {
        using namespace std::chrono_literals;
        std::unique_lock<std::mutex> lock(state.mutex);
        ASSERT_TRUE(state.cv.wait_for(lock, 1s, [&state] { return state.called; }));
        ASSERT_TRUE(state.called);
        ASSERT_EQ(state.bufferId, bufferToDrop->getId());
        // frame number should be 1 for the first buffer
        ASSERT_EQ(state.frameId, 1u);
    }

    ASSERT_EQ(OK, consumer->releaseBuffer(item));
    ASSERT_EQ(OK, surface->disconnect(NATIVE_WINDOW_API_CPU));
}

} // namespace android
