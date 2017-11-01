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

#include <android/native_window.h>

#include <gui/ISurfaceComposer.h>
#include <gui/LayerState.h>

#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>

#include <utils/String8.h>
#include <ui/DisplayInfo.h>

#include <math.h>
#include <math/vec3.h>

#include <functional>

namespace android {

using Transaction = SurfaceComposerClient::Transaction;

// Fill an RGBA_8888 formatted surface with a single color.
static void fillSurfaceRGBA8(const sp<SurfaceControl>& sc,
        uint8_t r, uint8_t g, uint8_t b, bool unlock=true) {
    ANativeWindow_Buffer outBuffer;
    sp<Surface> s = sc->getSurface();
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(NO_ERROR, s->lock(&outBuffer, NULL));
    uint8_t* img = reinterpret_cast<uint8_t*>(outBuffer.bits);
    for (int y = 0; y < outBuffer.height; y++) {
        for (int x = 0; x < outBuffer.width; x++) {
            uint8_t* pixel = img + (4 * (y*outBuffer.stride + x));
            pixel[0] = r;
            pixel[1] = g;
            pixel[2] = b;
            pixel[3] = 255;
        }
    }
    if (unlock) {
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
    }
}

// A ScreenCapture is a screenshot from SurfaceFlinger that can be used to check
// individual pixel values for testing purposes.
class ScreenCapture : public RefBase {
public:
    static void captureScreen(sp<ScreenCapture>* sc) {
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);
        sp<CpuConsumer> cpuConsumer = new CpuConsumer(consumer, 1);
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        sp<IBinder> display(sf->getBuiltInDisplay(
                ISurfaceComposer::eDisplayIdMain));
        SurfaceComposerClient::Transaction().apply(true);

        ASSERT_EQ(NO_ERROR, sf->captureScreen(display, producer, Rect(), 0, 0,
                0, INT_MAX, false));
        *sc = new ScreenCapture(cpuConsumer);
    }

    void checkPixel(uint32_t x, uint32_t y, uint8_t r, uint8_t g, uint8_t b) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mBuf.format);
        const uint8_t* img = static_cast<const uint8_t*>(mBuf.data);
        const uint8_t* pixel = img + (4 * (y * mBuf.stride + x));
        if (r != pixel[0] || g != pixel[1] || b != pixel[2]) {
            String8 err(String8::format("pixel @ (%3d, %3d): "
                    "expected [%3d, %3d, %3d], got [%3d, %3d, %3d]",
                    x, y, r, g, b, pixel[0], pixel[1], pixel[2]));
            EXPECT_EQ(String8(), err) << err.string();
        }
    }

    void expectFGColor(uint32_t x, uint32_t y) {
        checkPixel(x, y, 195, 63, 63);
    }

    void expectBGColor(uint32_t x, uint32_t y) {
        checkPixel(x, y, 63, 63, 195);
    }

    void expectChildColor(uint32_t x, uint32_t y) {
        checkPixel(x, y, 200, 200, 200);
    }

private:
    ScreenCapture(const sp<CpuConsumer>& cc) :
        mCC(cc) {
        EXPECT_EQ(NO_ERROR, mCC->lockNextBuffer(&mBuf));
    }

    ~ScreenCapture() {
        mCC->unlockBuffer(mBuf);
    }

    sp<CpuConsumer> mCC;
    CpuConsumer::LockedBuffer mBuf;
};

class CaptureLayer {
public:
    static void captureScreen(std::unique_ptr<CaptureLayer>* sc, sp<IBinder>& parentHandle) {
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);
        sp<CpuConsumer> cpuConsumer = new CpuConsumer(consumer, 1);
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        sp<IBinder> display(sf->getBuiltInDisplay(
            ISurfaceComposer::eDisplayIdMain));
        SurfaceComposerClient::Transaction().apply(true);
        ASSERT_EQ(NO_ERROR, sf->captureLayers(parentHandle, producer));
        *sc = std::make_unique<CaptureLayer>(cpuConsumer);
    }

    void checkPixel(uint32_t x, uint32_t y, uint8_t r, uint8_t g, uint8_t b) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mBuffer.format);
        const uint8_t* img = static_cast<const uint8_t*>(mBuffer.data);
        const uint8_t* pixel = img + (4 * (y * mBuffer.stride + x));
        if (r != pixel[0] || g != pixel[1] || b != pixel[2]) {
            String8 err(String8::format("pixel @ (%3d, %3d): "
                                            "expected [%3d, %3d, %3d], got [%3d, %3d, %3d]",
                                        x, y, r, g, b, pixel[0], pixel[1], pixel[2]));
            EXPECT_EQ(String8(), err) << err.string();
        }
    }

    void expectFGColor(uint32_t x, uint32_t y) {
        checkPixel(x, y, 195, 63, 63);
    }

    void expectBGColor(uint32_t x, uint32_t y) {
        checkPixel(x, y, 63, 63, 195);
    }

    void expectChildColor(uint32_t x, uint32_t y) {
        checkPixel(x, y, 200, 200, 200);
    }

    CaptureLayer(const sp<CpuConsumer>& cc) :
        mCC(cc) {
        EXPECT_EQ(NO_ERROR, mCC->lockNextBuffer(&mBuffer));
    }

    ~CaptureLayer() {
        mCC->unlockBuffer(mBuffer);
    }

private:
    sp<CpuConsumer> mCC;
    CpuConsumer::LockedBuffer mBuffer;
};


class LayerUpdateTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

        sp<IBinder> display(SurfaceComposerClient::getBuiltInDisplay(
                ISurfaceComposer::eDisplayIdMain));
        DisplayInfo info;
        SurfaceComposerClient::getDisplayInfo(display, &info);

        ssize_t displayWidth = info.w;
        ssize_t displayHeight = info.h;

        // Background surface
        mBGSurfaceControl = mComposerClient->createSurface(
                String8("BG Test Surface"), displayWidth, displayHeight,
                PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(mBGSurfaceControl != NULL);
        ASSERT_TRUE(mBGSurfaceControl->isValid());
        fillSurfaceRGBA8(mBGSurfaceControl, 63, 63, 195);

        // Foreground surface
        mFGSurfaceControl = mComposerClient->createSurface(
                String8("FG Test Surface"), 64, 64, PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(mFGSurfaceControl != NULL);
        ASSERT_TRUE(mFGSurfaceControl->isValid());

        fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);

        // Synchronization surface
        mSyncSurfaceControl = mComposerClient->createSurface(
                String8("Sync Test Surface"), 1, 1, PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(mSyncSurfaceControl != NULL);
        ASSERT_TRUE(mSyncSurfaceControl->isValid());

        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);

        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, 0);

            t.setLayer(mBGSurfaceControl, INT32_MAX-2)
                .show(mBGSurfaceControl);

            t.setLayer(mFGSurfaceControl, INT32_MAX-1)
                .setPosition(mFGSurfaceControl, 64, 64)
                .show(mFGSurfaceControl);

            t.setLayer(mSyncSurfaceControl, INT32_MAX-1)
                .setPosition(mSyncSurfaceControl, displayWidth-2,
                        displayHeight-2)
                .show(mSyncSurfaceControl);
        });
    }

    virtual void TearDown() {
        mComposerClient->dispose();
        mBGSurfaceControl = 0;
        mFGSurfaceControl = 0;
        mSyncSurfaceControl = 0;
        mComposerClient = 0;
    }

    void waitForPostedBuffers() {
        // Since the sync surface is in synchronous mode (i.e. double buffered)
        // posting three buffers to it should ensure that at least two
        // SurfaceFlinger::handlePageFlip calls have been made, which should
        // guaranteed that a buffer posted to another Surface has been retired.
        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
    }

    void asTransaction(const std::function<void(Transaction&)>& exec) {
        Transaction t;
        exec(t);
        t.apply(true);
    }

    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mFGSurfaceControl;

    // This surface is used to ensure that the buffers posted to
    // mFGSurfaceControl have been picked up by SurfaceFlinger.
    sp<SurfaceControl> mSyncSurfaceControl;
};

TEST_F(LayerUpdateTest, LayerMoveWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before move");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(0, 12);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.setPosition(mFGSurfaceControl, 128, 128);
    });

    {
        // This should reflect the new position, but not the new color.
        SCOPED_TRACE("after move, before redraw");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectFGColor(145, 145);
    }

    fillSurfaceRGBA8(mFGSurfaceControl, 63, 195, 63);
    waitForPostedBuffers();
    {
        // This should reflect the new position and the new color.
        SCOPED_TRACE("after redraw");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->checkPixel(145, 145, 63, 195, 63);
    }
}

TEST_F(LayerUpdateTest, LayerResizeWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before resize");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(0, 12);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    ALOGD("resizing");
    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
    });
    ALOGD("resized");
    {
        // This should not reflect the new size or color because SurfaceFlinger
        // has not yet received a buffer of the correct size.
        SCOPED_TRACE("after resize, before redraw");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(0, 12);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    ALOGD("drawing");
    fillSurfaceRGBA8(mFGSurfaceControl, 63, 195, 63);
    waitForPostedBuffers();
    ALOGD("drawn");
    {
        // This should reflect the new size and the new color.
        SCOPED_TRACE("after redraw");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->checkPixel(75, 75, 63, 195, 63);
        sc->checkPixel(145, 145, 63, 195, 63);
    }
}

TEST_F(LayerUpdateTest, LayerCropWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before crop");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        Rect cropRect(16, 16, 32, 32);
        t.setCrop(mFGSurfaceControl, cropRect);
    });
    {
        // This should crop the foreground surface.
        SCOPED_TRACE("after crop");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectFGColor(95, 80);
        sc->expectFGColor(80, 95);
        sc->expectBGColor(96, 96);
    }
}

TEST_F(LayerUpdateTest, LayerFinalCropWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before crop");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }
    asTransaction([&](Transaction& t) {
        Rect cropRect(16, 16, 32, 32);
        t.setFinalCrop(mFGSurfaceControl, cropRect);
    });
    {
        // This should crop the foreground surface.
        SCOPED_TRACE("after crop");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectBGColor(95, 80);
        sc->expectBGColor(80, 95);
        sc->expectBGColor(96, 96);
    }
}

TEST_F(LayerUpdateTest, LayerSetLayerWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setLayer");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.setLayer(mFGSurfaceControl, INT_MAX - 3);
    });

    {
        // This should hide the foreground surface beneath the background.
        SCOPED_TRACE("after setLayer");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectBGColor(145, 145);
    }
}

TEST_F(LayerUpdateTest, LayerShowHideWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before hide");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.hide(mFGSurfaceControl);
    });

    {
        // This should hide the foreground surface.
        SCOPED_TRACE("after hide, before show");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.show(mFGSurfaceControl);
    });

    {
        // This should show the foreground surface.
        SCOPED_TRACE("after show");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }
}

TEST_F(LayerUpdateTest, LayerSetAlphaWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setAlpha");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.setAlpha(mFGSurfaceControl, 0.75f);
    });

    {
        // This should set foreground to be 75% opaque.
        SCOPED_TRACE("after setAlpha");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->checkPixel(75, 75, 162, 63, 96);
        sc->expectBGColor(145, 145);
    }
}

TEST_F(LayerUpdateTest, LayerSetLayerStackWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setLayerStack");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.setLayerStack(mFGSurfaceControl, 1);
    });
    {
        // This should hide the foreground surface since it goes to a different
        // layer stack.
        SCOPED_TRACE("after setLayerStack");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectBGColor(145, 145);
    }
}

TEST_F(LayerUpdateTest, LayerSetFlagsWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setFlags");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
          t.setFlags(mFGSurfaceControl,
                layer_state_t::eLayerHidden, layer_state_t::eLayerHidden);
    });
    {
        // This should hide the foreground surface
        SCOPED_TRACE("after setFlags");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectBGColor(75, 75);
        sc->expectBGColor(145, 145);
    }
}

TEST_F(LayerUpdateTest, LayerSetMatrixWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setMatrix");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(91, 96);
        sc->expectFGColor(96, 101);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.setMatrix(mFGSurfaceControl,
                M_SQRT1_2, M_SQRT1_2,
                -M_SQRT1_2, M_SQRT1_2);
    });
    {
        SCOPED_TRACE("after setMatrix");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(91, 96);
        sc->expectBGColor(96, 91);
        sc->expectBGColor(145, 145);
    }
}

class GeometryLatchingTest : public LayerUpdateTest {
protected:
    void EXPECT_INITIAL_STATE(const char * trace) {
        SCOPED_TRACE(trace);
        ScreenCapture::captureScreen(&sc);
        // We find the leading edge of the FG surface.
        sc->expectFGColor(127, 127);
        sc->expectBGColor(128, 128);
    }

    void lockAndFillFGBuffer() {
        fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63, false);
    }

    void unlockFGBuffer() {
        sp<Surface> s = mFGSurfaceControl->getSurface();
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
        waitForPostedBuffers();
    }

    void completeFGResize() {
        fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);
        waitForPostedBuffers();
    }
    void restoreInitialState() {
        asTransaction([&](Transaction& t) {
            t.setSize(mFGSurfaceControl, 64, 64);
            t.setPosition(mFGSurfaceControl, 64, 64);
            t.setCrop(mFGSurfaceControl, Rect(0, 0, 64, 64));
            t.setFinalCrop(mFGSurfaceControl, Rect(0, 0, -1, -1));
        });

        EXPECT_INITIAL_STATE("After restoring initial state");
    }
    sp<ScreenCapture> sc;
};

TEST_F(GeometryLatchingTest, SurfacePositionLatching) {
    EXPECT_INITIAL_STATE("before anything");

    // By default position can be updated even while
    // a resize is pending.
    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 32, 32);
        t.setPosition(mFGSurfaceControl, 100, 100);
    });

    {
        SCOPED_TRACE("After moving surface");
        ScreenCapture::captureScreen(&sc);
        // If we moved, the FG Surface should cover up what was previously BG
        // however if we didn't move the FG wouldn't be large enough now.
        sc->expectFGColor(163, 163);
    }

    restoreInitialState();

    // Now we repeat with setGeometryAppliesWithResize
    // and verify the position DOESN'T latch.
    asTransaction([&](Transaction& t) {
        t.setGeometryAppliesWithResize(mFGSurfaceControl);
        t.setSize(mFGSurfaceControl, 32, 32);
        t.setPosition(mFGSurfaceControl, 100, 100);
    });

    {
        SCOPED_TRACE("While resize is pending");
        ScreenCapture::captureScreen(&sc);
        // This time we shouldn't have moved, so the BG color
        // should still be visible.
        sc->expectBGColor(128, 128);
    }

    completeFGResize();

    {
        SCOPED_TRACE("After the resize");
        ScreenCapture::captureScreen(&sc);
        // But after the resize completes, we should move
        // and the FG should be visible here.
        sc->expectFGColor(128, 128);
    }
}

class CropLatchingTest : public GeometryLatchingTest {
protected:
    void EXPECT_CROPPED_STATE(const char* trace) {
        SCOPED_TRACE(trace);
        ScreenCapture::captureScreen(&sc);
        // The edge should be moved back one pixel by our crop.
        sc->expectFGColor(126, 126);
        sc->expectBGColor(127, 127);
        sc->expectBGColor(128, 128);
    }

    void EXPECT_RESIZE_STATE(const char* trace) {
        SCOPED_TRACE(trace);
        ScreenCapture::captureScreen(&sc);
        // The FG is now resized too 128,128 at 64,64
        sc->expectFGColor(64, 64);
        sc->expectFGColor(191, 191);
        sc->expectBGColor(192, 192);
    }
};

TEST_F(CropLatchingTest, CropLatching) {
    EXPECT_INITIAL_STATE("before anything");
    // Normally the crop applies immediately even while a resize is pending.
    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setCrop(mFGSurfaceControl, Rect(0, 0, 63, 63));
    });

    EXPECT_CROPPED_STATE("after setting crop (without geometryAppliesWithResize)");

    restoreInitialState();

    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setGeometryAppliesWithResize(mFGSurfaceControl);
        t.setCrop(mFGSurfaceControl, Rect(0, 0, 63, 63));
    });

    EXPECT_INITIAL_STATE("after setting crop (with geometryAppliesWithResize)");

    completeFGResize();

    EXPECT_CROPPED_STATE("after the resize finishes");
}

TEST_F(CropLatchingTest, FinalCropLatching) {
    EXPECT_INITIAL_STATE("before anything");
    // Normally the crop applies immediately even while a resize is pending.
    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setFinalCrop(mFGSurfaceControl, Rect(64, 64, 127, 127));
    });

    EXPECT_CROPPED_STATE("after setting crop (without geometryAppliesWithResize)");

    restoreInitialState();

    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setGeometryAppliesWithResize(mFGSurfaceControl);
        t.setFinalCrop(mFGSurfaceControl, Rect(64, 64, 127, 127));
    });

    EXPECT_INITIAL_STATE("after setting crop (with geometryAppliesWithResize)");

    completeFGResize();

    EXPECT_CROPPED_STATE("after the resize finishes");
}

// In this test we ensure that setGeometryAppliesWithResize actually demands
// a buffer of the new size, and not just any size.
TEST_F(CropLatchingTest, FinalCropLatchingBufferOldSize) {
    EXPECT_INITIAL_STATE("before anything");
    // Normally the crop applies immediately even while a resize is pending.
    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setFinalCrop(mFGSurfaceControl, Rect(64, 64, 127, 127));
    });

    EXPECT_CROPPED_STATE("after setting crop (without geometryAppliesWithResize)");

    restoreInitialState();

    // In order to prepare to submit a buffer at the wrong size, we acquire it prior to
    // initiating the resize.
    lockAndFillFGBuffer();

    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setGeometryAppliesWithResize(mFGSurfaceControl);
        t.setFinalCrop(mFGSurfaceControl, Rect(64, 64, 127, 127));
    });

    EXPECT_INITIAL_STATE("after setting crop (with geometryAppliesWithResize)");

    // We now submit our old buffer, at the old size, and ensure it doesn't
    // trigger geometry latching.
    unlockFGBuffer();

    EXPECT_INITIAL_STATE("after unlocking FG buffer (with geometryAppliesWithResize)");

    completeFGResize();

    EXPECT_CROPPED_STATE("after the resize finishes");
}

TEST_F(CropLatchingTest, FinalCropLatchingRegressionForb37531386) {
    EXPECT_INITIAL_STATE("before anything");
    // In this scenario, we attempt to set the final crop a second time while the resize
    // is still pending, and ensure we are successful. Success meaning the second crop
    // is the one which eventually latches and not the first.
    asTransaction([&](Transaction& t) {
        t.setSize(mFGSurfaceControl, 128, 128);
        t.setGeometryAppliesWithResize(mFGSurfaceControl);
        t.setFinalCrop(mFGSurfaceControl, Rect(64, 64, 127, 127));
    });

    EXPECT_INITIAL_STATE("after setting crops with geometryAppliesWithResize");

    asTransaction([&](Transaction& t) {
        t.setFinalCrop(mFGSurfaceControl, Rect(0, 0, -1, -1));
    });

    EXPECT_INITIAL_STATE("after setting another crop");

    completeFGResize();

    EXPECT_RESIZE_STATE("after the resize finishes");
}

TEST_F(LayerUpdateTest, DeferredTransactionTest) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before anything");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->expectFGColor(96, 96);
        sc->expectBGColor(160, 160);
    }

    // set up two deferred transactions on different frames
    asTransaction([&](Transaction& t) {
        t.setAlpha(mFGSurfaceControl, 0.75);
        t.deferTransactionUntil(mFGSurfaceControl, mSyncSurfaceControl->getHandle(),
                mSyncSurfaceControl->getSurface()->getNextFrameNumber());
    });

    asTransaction([&](Transaction& t) {
        t.setPosition(mFGSurfaceControl, 128,128);
        t.deferTransactionUntil(mFGSurfaceControl, mSyncSurfaceControl->getHandle(),
                mSyncSurfaceControl->getSurface()->getNextFrameNumber() + 1);
    });

    {
        SCOPED_TRACE("before any trigger");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->expectFGColor(96, 96);
        sc->expectBGColor(160, 160);
    }

    // should trigger the first deferred transaction, but not the second one
    fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
    {
        SCOPED_TRACE("after first trigger");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->checkPixel(96, 96, 162, 63, 96);
        sc->expectBGColor(160, 160);
    }

    // should show up immediately since it's not deferred
    asTransaction([&](Transaction& t) {
        t.setAlpha(mFGSurfaceControl, 1.0);
    });

    // trigger the second deferred transaction
    fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
    {
        SCOPED_TRACE("after second trigger");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->expectBGColor(96, 96);
        sc->expectFGColor(160, 160);
    }
}

TEST_F(LayerUpdateTest, LayerSetRelativeLayerWorks) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before adding relative surface");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(24, 24);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    auto relativeSurfaceControl = mComposerClient->createSurface(
            String8("Test Surface"), 64, 64, PIXEL_FORMAT_RGBA_8888, 0);
    fillSurfaceRGBA8(relativeSurfaceControl, 255, 177, 177);
    waitForPostedBuffers();

    // Now we stack the surface above the foreground surface and make sure it is visible.
    asTransaction([&](Transaction& t) {
        t.setPosition(relativeSurfaceControl, 64, 64);
        t.show(relativeSurfaceControl);
        t.setRelativeLayer(relativeSurfaceControl, mFGSurfaceControl->getHandle(), 1);
    });

    {
        SCOPED_TRACE("after adding relative surface");
        ScreenCapture::captureScreen(&sc);
        // our relative surface should be visible now.
        sc->checkPixel(75, 75, 255, 177, 177);
    }

    // A call to setLayer will override a call to setRelativeLayer
    asTransaction([&](Transaction& t) {
        t.setLayer(relativeSurfaceControl, 0);
    });

    {
        SCOPED_TRACE("after set layer");
        ScreenCapture::captureScreen(&sc);
        // now the FG surface should be visible again.
        sc->expectFGColor(75, 75);
    }
}

TEST_F(LayerUpdateTest, LayerWithNoBuffersResizesImmediately) {
    sp<ScreenCapture> sc;

    sp<SurfaceControl> childNoBuffer =
        mComposerClient->createSurface(String8("Bufferless child"),
                10, 10, PIXEL_FORMAT_RGBA_8888,
                0, mFGSurfaceControl.get());
    sp<SurfaceControl> childBuffer = mComposerClient->createSurface(
            String8("Buffered child"), 20, 20,
            PIXEL_FORMAT_RGBA_8888, 0, childNoBuffer.get());
    fillSurfaceRGBA8(childBuffer, 200, 200, 200);

    SurfaceComposerClient::Transaction{}
            .show(childNoBuffer)
            .show(childBuffer)
            .apply(true);

    {
        ScreenCapture::captureScreen(&sc);
        sc->expectChildColor(73, 73);
        sc->expectFGColor(74, 74);
    }

    SurfaceComposerClient::Transaction{}
            .setSize(childNoBuffer, 20, 20)
            .apply(true);

    {
        ScreenCapture::captureScreen(&sc);
        sc->expectChildColor(73, 73);
        sc->expectChildColor(74, 74);
    }
}

TEST_F(LayerUpdateTest, MergingTransactions) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before move");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(0, 12);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    Transaction t1, t2;
    t1.setPosition(mFGSurfaceControl, 128, 128);
    t2.setPosition(mFGSurfaceControl, 0, 0);
    // We expect that the position update from t2 now
    // overwrites the position update from t1.
    t1.merge(std::move(t2));
    t1.apply();

    {
        ScreenCapture::captureScreen(&sc);
        sc->expectFGColor(1, 1);
    }
}

class ChildLayerTest : public LayerUpdateTest {
protected:
    void SetUp() override {
        LayerUpdateTest::SetUp();
        mChild = mComposerClient->createSurface(
                String8("Child surface"),
                10, 10, PIXEL_FORMAT_RGBA_8888,
                0, mFGSurfaceControl.get());
        fillSurfaceRGBA8(mChild, 200, 200, 200);

        {
            SCOPED_TRACE("before anything");
            ScreenCapture::captureScreen(&mCapture);
            mCapture->expectChildColor(64, 64);
        }
    }
    void TearDown() override {
        LayerUpdateTest::TearDown();
        mChild = 0;
    }

    sp<SurfaceControl> mChild;
    sp<ScreenCapture> mCapture;
};

TEST_F(ChildLayerTest, ChildLayerPositioning) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) {
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground should now be at 0, 0
        mCapture->expectFGColor(0, 0);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(10, 10);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(20, 20);
    }
}

TEST_F(ChildLayerTest, ChildLayerCropping) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
        t.setCrop(mFGSurfaceControl, Rect(0, 0, 5, 5));
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectChildColor(0, 0);
        mCapture->expectChildColor(4, 4);
        mCapture->expectBGColor(5, 5);
    }
}

TEST_F(ChildLayerTest, ChildLayerFinalCropping) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
        t.setFinalCrop(mFGSurfaceControl, Rect(0, 0, 5, 5));
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectChildColor(0, 0);
        mCapture->expectChildColor(4, 4);
        mCapture->expectBGColor(5, 5);
    }
}

TEST_F(ChildLayerTest, ChildLayerConstraints) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mFGSurfaceControl, 0, 0);
        t.setPosition(mChild, 63, 63);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectFGColor(0, 0);
        // Last pixel in foreground should now be the child.
        mCapture->expectChildColor(63, 63);
        // But the child should be constrained and the next pixel
        // must be the background
        mCapture->expectBGColor(64, 64);
    }
}

TEST_F(ChildLayerTest, ChildLayerScaling) {
    asTransaction([&](Transaction& t) {
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    // Find the boundary between the parent and child
    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectChildColor(9, 9);
        mCapture->expectFGColor(10, 10);
    }

    asTransaction([&](Transaction& t) {
        t.setMatrix(mFGSurfaceControl, 2.0, 0, 0, 2.0);
    });

    // The boundary should be twice as far from the origin now.
    // The pixels from the last test should all be child now
    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectChildColor(9, 9);
        mCapture->expectChildColor(10, 10);
        mCapture->expectChildColor(19, 19);
        mCapture->expectFGColor(20, 20);
    }
}

TEST_F(ChildLayerTest, ChildLayerAlpha) {
    fillSurfaceRGBA8(mBGSurfaceControl, 0, 0, 254);
    fillSurfaceRGBA8(mFGSurfaceControl, 254, 0, 0);
    fillSurfaceRGBA8(mChild, 0, 254, 0);
    waitForPostedBuffers();

    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Unblended child color
        mCapture->checkPixel(0, 0, 0, 254, 0);
    }

    asTransaction([&](Transaction& t) {
        t.setAlpha(mChild, 0.5);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Child and BG blended.
        mCapture->checkPixel(0, 0, 127, 127, 0);
    }

    asTransaction([&](Transaction& t) {
        t.setAlpha(mFGSurfaceControl, 0.5);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Child and BG blended.
        mCapture->checkPixel(0, 0, 95, 64, 95);
    }
}

TEST_F(ChildLayerTest, ReparentChildren) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) {
        t.reparentChildren(mFGSurfaceControl, mBGSurfaceControl->getHandle());
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectFGColor(64, 64);
        // In reparenting we should have exposed the entire foreground surface.
        mCapture->expectFGColor(74, 74);
        // And the child layer should now begin at 10, 10 (since the BG
        // layer is at (0, 0)).
        mCapture->expectBGColor(9, 9);
        mCapture->expectChildColor(10, 10);
    }
}

TEST_F(ChildLayerTest, DetachChildrenSameClient) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) {
        t.detachChildren(mFGSurfaceControl);
    });

    asTransaction([&](Transaction& t) {
        t.hide(mChild);
    });

    // Since the child has the same client as the parent, it will not get
    // detached and will be hidden.
    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectFGColor(64, 64);
        mCapture->expectFGColor(74, 74);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, DetachChildrenDifferentClient) {
    sp<SurfaceComposerClient> mNewComposerClient = new SurfaceComposerClient;
    sp<SurfaceControl> mChildNewClient = mNewComposerClient->createSurface(
        String8("New Child Test Surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
        0, mFGSurfaceControl.get());

    ASSERT_TRUE(mChildNewClient != NULL);
    ASSERT_TRUE(mChildNewClient->isValid());

    fillSurfaceRGBA8(mChildNewClient, 200, 200, 200);

    asTransaction([&](Transaction& t) {
        t.hide(mChild);
        t.show(mChildNewClient);
        t.setPosition(mChildNewClient, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) {
        t.detachChildren(mFGSurfaceControl);
    });

    asTransaction([&](Transaction& t) {
        t.hide(mChildNewClient);
    });

    // Nothing should have changed.
    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectFGColor(64, 64);
        mCapture->expectChildColor(74, 74);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, ChildrenInheritNonTransformScalingFromParent) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // We've positioned the child in the top left.
        mCapture->expectChildColor(0, 0);
        // But it's only 10x10.
        mCapture->expectFGColor(10, 10);
    }

    asTransaction([&](Transaction& t) {
        t.setOverrideScalingMode(mFGSurfaceControl, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW);
        // We cause scaling by 2.
        t.setSize(mFGSurfaceControl, 128, 128);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // We've positioned the child in the top left.
        mCapture->expectChildColor(0, 0);
        mCapture->expectChildColor(10, 10);
        mCapture->expectChildColor(19, 19);
        // And now it should be scaled all the way to 20x20
        mCapture->expectFGColor(20, 20);
    }
}

// Regression test for b/37673612
TEST_F(ChildLayerTest, ChildrenWithParentBufferTransform) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // We've positioned the child in the top left.
        mCapture->expectChildColor(0, 0);
        // But it's only 10x10.
        mCapture->expectFGColor(10, 10);
    }
    // We set things up as in b/37673612 so that there is a mismatch between the buffer size and
    // the WM specified state size.
    asTransaction([&](Transaction& t) {
         t.setSize(mFGSurfaceControl, 128, 64);
    });
    sp<Surface> s = mFGSurfaceControl->getSurface();
    auto anw = static_cast<ANativeWindow*>(s.get());
    native_window_set_buffers_transform(anw, NATIVE_WINDOW_TRANSFORM_ROT_90);
    native_window_set_buffers_dimensions(anw, 64, 128);
    fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);
    waitForPostedBuffers();

    {
        // The child should still be in the same place and not have any strange scaling as in
        // b/37673612.
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectChildColor(0, 0);
        mCapture->expectFGColor(10, 10);
    }
}

TEST_F(ChildLayerTest, Bug36858924) {
    // Destroy the child layer
    mChild.clear();

    // Now recreate it as hidden
    mChild = mComposerClient->createSurface(String8("Child surface"), 10, 10,
                                            PIXEL_FORMAT_RGBA_8888, ISurfaceComposerClient::eHidden,
                                            mFGSurfaceControl.get());

    // Show the child layer in a deferred transaction
    asTransaction([&](Transaction& t) {
        t.deferTransactionUntil(mChild, mFGSurfaceControl->getHandle(),
                mFGSurfaceControl->getSurface()->getNextFrameNumber());
        t.show(mChild);
    });

    // Render the foreground surface a few times
    //
    // Prior to the bugfix for b/36858924, this would usually hang while trying to fill the third
    // frame because SurfaceFlinger would never process the deferred transaction and would therefore
    // never acquire/release the first buffer
    ALOGI("Filling 1");
    fillSurfaceRGBA8(mFGSurfaceControl, 0, 255, 0);
    ALOGI("Filling 2");
    fillSurfaceRGBA8(mFGSurfaceControl, 0, 0, 255);
    ALOGI("Filling 3");
    fillSurfaceRGBA8(mFGSurfaceControl, 255, 0, 0);
    ALOGI("Filling 4");
    fillSurfaceRGBA8(mFGSurfaceControl, 0, 255, 0);
}

TEST_F(ChildLayerTest, Reparent) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) {
        t.reparent(mChild, mBGSurfaceControl->getHandle());
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectFGColor(64, 64);
        // In reparenting we should have exposed the entire foreground surface.
        mCapture->expectFGColor(74, 74);
        // And the child layer should now begin at 10, 10 (since the BG
        // layer is at (0, 0)).
        mCapture->expectBGColor(9, 9);
        mCapture->expectChildColor(10, 10);
    }
}

TEST_F(ChildLayerTest, ReparentToNoParent) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }
    asTransaction([&](Transaction& t) {
        t.reparent(mChild, nullptr);
    });
    {
        ScreenCapture::captureScreen(&mCapture);
        // Nothing should have changed.
        mCapture->expectFGColor(64, 64);
        mCapture->expectChildColor(74, 74);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, ReparentFromNoParent) {
    sp<SurfaceControl> newSurface = mComposerClient->createSurface(
        String8("New Surface"), 10, 10, PIXEL_FORMAT_RGBA_8888, 0);
    ASSERT_TRUE(newSurface != NULL);
    ASSERT_TRUE(newSurface->isValid());

    fillSurfaceRGBA8(newSurface, 63, 195, 63);
    asTransaction([&](Transaction& t) {
        t.hide(mChild);
        t.show(newSurface);
        t.setPosition(newSurface, 10, 10);
        t.setLayer(newSurface, INT32_MAX-2);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // At 10, 10 we should see the new surface
        mCapture->checkPixel(10, 10, 63, 195, 63);
    }

    asTransaction([&](Transaction& t) {
        t.reparent(newSurface, mFGSurfaceControl->getHandle());
    });

    {
        ScreenCapture::captureScreen(&mCapture);
        // newSurface will now be a child of mFGSurface so it will be 10, 10 offset from
        // mFGSurface, putting it at 74, 74.
        mCapture->expectFGColor(64, 64);
        mCapture->checkPixel(74, 74, 63, 195, 63);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, NestedChildren) {
    sp<SurfaceControl> grandchild = mComposerClient->createSurface(
        String8("Grandchild surface"),
        10, 10, PIXEL_FORMAT_RGBA_8888,
        0, mChild.get());
    fillSurfaceRGBA8(grandchild, 50, 50, 50);

    {
        ScreenCapture::captureScreen(&mCapture);
        // Expect the grandchild to begin at 64, 64 because it's a child of mChild layer
        // which begins at 64, 64
        mCapture->checkPixel(64, 64, 50, 50, 50);
    }
}

class LayerColorTest : public LayerUpdateTest {
 protected:
    void SetUp() override {
        LayerUpdateTest::SetUp();

        mLayerColorControl = mComposerClient->createSurface(
            String8("Layer color surface"),
            128, 128, PIXEL_FORMAT_RGBA_8888,
            ISurfaceComposerClient::eFXSurfaceColor);

        ASSERT_TRUE(mLayerColorControl != NULL);
        ASSERT_TRUE(mLayerColorControl->isValid());

        asTransaction([&](Transaction& t) {
            t.setLayer(mLayerColorControl, INT32_MAX-1);
            t.setPosition(mLayerColorControl, 140, 140);
            t.hide(mLayerColorControl);
            t.hide(mFGSurfaceControl);
        });
    }

    void TearDown() override {
        LayerUpdateTest::TearDown();
        mLayerColorControl = 0;
    }

    sp<SurfaceControl> mLayerColorControl;
};

TEST_F(LayerColorTest, ColorLayerNoAlpha) {
    sp<ScreenCapture> sc;

    {
        SCOPED_TRACE("before setColor");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        half3 color(43.0f/255.0f, 207.0f/255.0f, 131.0f/255.0f);
        t.setColor(mLayerColorControl, color);
        t.show(mLayerColorControl);
    });

    {
        // There should now be a color
        SCOPED_TRACE("after setColor");

        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(145, 145, 43, 207, 131);
    }
}

TEST_F(LayerColorTest, ColorLayerWithAlpha) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setColor");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        half3 color(43.0f/255.0f, 207.0f/255.0f, 131.0f/255.0f);
        t.setColor(mLayerColorControl, color);
        t.setAlpha(mLayerColorControl, .75f);
        t.show(mLayerColorControl);
    });

    {
        // There should now be a color with .75 alpha
        SCOPED_TRACE("after setColor");
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(145, 145, 48, 171, 147);
    }
}

TEST_F(LayerColorTest, ColorLayerWithNoColor) {
    sp<ScreenCapture> sc;
    {
        SCOPED_TRACE("before setColor");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(145, 145);
    }

    asTransaction([&](Transaction& t) {
        t.show(mLayerColorControl);
    });

    {
        // There should now be set to 0,0,0 (black) as default.
        SCOPED_TRACE("after setColor");
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(145, 145, 0, 0, 0);
    }
}

class ScreenCaptureTest : public LayerUpdateTest {
protected:
    std::unique_ptr<CaptureLayer> mCapture;
};

TEST_F(ScreenCaptureTest, CaptureSingleLayer) {
    auto bgHandle = mBGSurfaceControl->getHandle();
    CaptureLayer::captureScreen(&mCapture, bgHandle);
    mCapture->expectBGColor(0, 0);
    // Doesn't capture FG layer which is at 64, 64
    mCapture->expectBGColor(64, 64);
}

TEST_F(ScreenCaptureTest, CaptureLayerWithChild) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child = mComposerClient->createSurface(
        String8("Child surface"),
        10, 10, PIXEL_FORMAT_RGBA_8888,
        0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction()
        .show(child)
        .apply(true);

    // Captures mFGSurfaceControl layer and its child.
    CaptureLayer::captureScreen(&mCapture, fgHandle);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureLayerWithGrandchild) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child = mComposerClient->createSurface(
        String8("Child surface"),
        10, 10, PIXEL_FORMAT_RGBA_8888,
        0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);

    sp<SurfaceControl> grandchild = mComposerClient->createSurface(
        String8("Grandchild surface"), 5, 5,
        PIXEL_FORMAT_RGBA_8888, 0, child.get());

    fillSurfaceRGBA8(grandchild, 50, 50, 50);
    SurfaceComposerClient::Transaction()
        .show(child)
        .setPosition(grandchild, 5, 5)
        .show(grandchild)
        .apply(true);

    // Captures mFGSurfaceControl, its child, and the grandchild.
    CaptureLayer::captureScreen(&mCapture, fgHandle);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
    mCapture->checkPixel(5, 5, 50, 50, 50);
}

TEST_F(ScreenCaptureTest, CaptureChildOnly) {
    sp<SurfaceControl> child = mComposerClient->createSurface(
        String8("Child surface"),
        10, 10, PIXEL_FORMAT_RGBA_8888,
        0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);
    auto childHandle = child->getHandle();

    SurfaceComposerClient::Transaction()
        .setPosition(child, 5, 5)
        .show(child)
        .apply(true);

    // Captures only the child layer, and not the parent.
    CaptureLayer::captureScreen(&mCapture, childHandle);
    mCapture->expectChildColor(0, 0);
    mCapture->expectChildColor(9, 9);
}

TEST_F(ScreenCaptureTest, CaptureGrandchildOnly) {
    sp<SurfaceControl> child = mComposerClient->createSurface(
        String8("Child surface"),
        10, 10, PIXEL_FORMAT_RGBA_8888,
        0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);
    auto childHandle = child->getHandle();

    sp<SurfaceControl> grandchild = mComposerClient->createSurface(
        String8("Grandchild surface"), 5, 5,
        PIXEL_FORMAT_RGBA_8888, 0, child.get());
    fillSurfaceRGBA8(grandchild, 50, 50, 50);

    SurfaceComposerClient::Transaction()
        .show(child)
        .setPosition(grandchild, 5, 5)
        .show(grandchild)
        .apply(true);

    auto grandchildHandle = grandchild->getHandle();

    // Captures only the grandchild.
    CaptureLayer::captureScreen(&mCapture, grandchildHandle);
    mCapture->checkPixel(0, 0, 50, 50, 50);
    mCapture->checkPixel(4, 4, 50, 50, 50);
}

}
