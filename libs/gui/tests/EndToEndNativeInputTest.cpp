/*
 * Copyright 2018 The Android Open Source Project
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
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdio.h>
#include <poll.h>

#include <memory>

#include <android/native_window.h>

#include <binder/Binder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>

#include <gui/ISurfaceComposer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>

#include <android/os/IInputFlinger.h>
#include <input/Input.h>
#include <input/InputTransport.h>
#include <input/InputWindow.h>

#include <ui/DisplayMode.h>
#include <ui/Rect.h>
#include <ui/Region.h>

using android::os::IInputFlinger;

namespace android::test {

using Transaction = SurfaceComposerClient::Transaction;

sp<IInputFlinger> getInputFlinger() {
   sp<IBinder> input(defaultServiceManager()->getService(
            String16("inputflinger")));
    if (input == nullptr) {
        ALOGE("Failed to link to input service");
    } else { ALOGE("Linked to input"); }
    return interface_cast<IInputFlinger>(input);
}

// We use the top 10 layers as a way to haphazardly place ourselves above anything else.
static const int LAYER_BASE = INT32_MAX - 10;
static constexpr std::chrono::nanoseconds DISPATCHING_TIMEOUT = 5s;

class InputSurface {
public:
    InputSurface(const sp<SurfaceControl> &sc, int width, int height) {
        mSurfaceControl = sc;

        mInputFlinger = getInputFlinger();
        mClientChannel = std::make_shared<InputChannel>();
        mInputFlinger->createInputChannel("testchannels", mClientChannel.get());

        populateInputInfo(width, height);

        mInputConsumer = new InputConsumer(mClientChannel);
    }

    static std::unique_ptr<InputSurface> makeColorInputSurface(const sp<SurfaceComposerClient> &scc,
                                                               int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Surface"), 0 /* bufHeight */, 0 /* bufWidth */,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceEffect);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeBufferInputSurface(
            const sp<SurfaceComposerClient> &scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Buffer Surface"), width, height,
                                   PIXEL_FORMAT_RGBA_8888, 0 /* flags */);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeBlastInputSurface(const sp<SurfaceComposerClient> &scc,
                                                               int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Buffer Surface"), width, height,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceBufferState);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeContainerInputSurface(
            const sp<SurfaceComposerClient> &scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Container Surface"), 0 /* bufHeight */,
                                   0 /* bufWidth */, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceContainer);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeCursorInputSurface(
            const sp<SurfaceComposerClient> &scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Cursor Surface"), 0 /* bufHeight */,
                                   0 /* bufWidth */, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eCursorWindow);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    InputEvent* consumeEvent() {
        waitForEventAvailable();

        InputEvent *ev;
        uint32_t seqId;
        status_t consumed = mInputConsumer->consume(&mInputEventFactory, true, -1, &seqId, &ev);
        if (consumed != OK) {
            return nullptr;
        }
        status_t status = mInputConsumer->sendFinishedSignal(seqId, true);
        EXPECT_EQ(OK, status) << "Could not send finished signal";
        return ev;
    }

    void assertFocusChange(bool hasFocus) {
        InputEvent *ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(AINPUT_EVENT_TYPE_FOCUS, ev->getType());
        FocusEvent *focusEvent = static_cast<FocusEvent *>(ev);
        EXPECT_EQ(hasFocus, focusEvent->getHasFocus());
    }

    void expectTap(int x, int y) {
        InputEvent* ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, ev->getType());
        MotionEvent* mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, mev->getAction());
        EXPECT_EQ(x, mev->getX(0));
        EXPECT_EQ(y, mev->getY(0));
        EXPECT_EQ(0, mev->getFlags() & VERIFIED_MOTION_EVENT_FLAGS);

        ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, ev->getType());
        mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_UP, mev->getAction());
        EXPECT_EQ(0, mev->getFlags() & VERIFIED_MOTION_EVENT_FLAGS);
    }

    void expectTapWithFlag(int x, int y, int32_t flags) {
        InputEvent *ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, ev->getType());
        MotionEvent *mev = static_cast<MotionEvent *>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, mev->getAction());
        EXPECT_EQ(x, mev->getX(0));
        EXPECT_EQ(y, mev->getY(0));
        EXPECT_EQ(flags, mev->getFlags() & flags);

        ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, ev->getType());
        mev = static_cast<MotionEvent *>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_UP, mev->getAction());
        EXPECT_EQ(flags, mev->getFlags() & flags);
    }

    ~InputSurface() { mInputFlinger->removeInputChannel(mClientChannel->getConnectionToken()); }

    void doTransaction(std::function<void(SurfaceComposerClient::Transaction&,
                    const sp<SurfaceControl>&)> transactionBody) {
        SurfaceComposerClient::Transaction t;
        transactionBody(t, mSurfaceControl);
        t.apply(true);
    }

    void showAt(int x, int y, Rect crop = Rect(0, 0, 100, 100)) {
        SurfaceComposerClient::Transaction t;
        t.show(mSurfaceControl);
        t.setInputWindowInfo(mSurfaceControl, mInputInfo);
        t.setLayer(mSurfaceControl, LAYER_BASE);
        t.setPosition(mSurfaceControl, x, y);
        t.setCrop(mSurfaceControl, crop);
        t.setAlpha(mSurfaceControl, 1);
        t.apply(true);
    }

    void requestFocus() {
        SurfaceComposerClient::Transaction t;
        FocusRequest request;
        request.token = mInputInfo.token;
        request.windowName = mInputInfo.name;
        request.focusedToken = nullptr;
        request.focusedWindowName = "";
        request.timestamp = systemTime(SYSTEM_TIME_MONOTONIC);
        request.displayId = 0;
        t.setFocusedWindow(request);
        t.apply(true);
    }

private:
    void waitForEventAvailable() {
        struct pollfd fd;

        fd.fd = mClientChannel->getFd();
        fd.events = POLLIN;
        poll(&fd, 1, 3000);
    }

    void populateInputInfo(int width, int height) {
        mInputInfo.token = mClientChannel->getConnectionToken();
        mInputInfo.name = "Test info";
        mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCH_MODAL;
        mInputInfo.type = InputWindowInfo::Type::BASE_APPLICATION;
        mInputInfo.dispatchingTimeout = 5s;
        mInputInfo.globalScaleFactor = 1.0;
        mInputInfo.focusable = true;
        mInputInfo.hasWallpaper = false;
        mInputInfo.paused = false;

        mInputInfo.touchableRegion.orSelf(Rect(0, 0, width, height));

        // TODO: Fill in from SF?
        mInputInfo.ownerPid = 11111;
        mInputInfo.ownerUid = 11111;
        mInputInfo.displayId = 0;

        InputApplicationInfo aInfo;
        aInfo.token = new BBinder();
        aInfo.name = "Test app info";
        aInfo.dispatchingTimeoutMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(DISPATCHING_TIMEOUT).count();

        mInputInfo.applicationInfo = aInfo;
    }
public:
    sp<SurfaceControl> mSurfaceControl;
    std::shared_ptr<InputChannel> mClientChannel;
    sp<IInputFlinger> mInputFlinger;

    InputWindowInfo mInputInfo;

    PreallocatedInputEventFactory mInputEventFactory;
    InputConsumer* mInputConsumer;
};

class InputSurfacesTest : public ::testing::Test {
public:
    InputSurfacesTest() {
        ProcessState::self()->startThreadPool();
    }

    void SetUp() {
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

        const auto display = mComposerClient->getInternalDisplayToken();
        ASSERT_NE(display, nullptr);

        ui::DisplayMode mode;
        ASSERT_EQ(NO_ERROR, mComposerClient->getActiveDisplayMode(display, &mode));

        // After a new buffer is queued, SurfaceFlinger is notified and will
        // latch the new buffer on next vsync.  Let's heuristically wait for 3
        // vsyncs.
        mBufferPostDelay = static_cast<int32_t>(1e6 / mode.refreshRate) * 3;
    }

    void TearDown() {
        mComposerClient->dispose();
    }

    std::unique_ptr<InputSurface> makeSurface(int width, int height) {
        return InputSurface::makeColorInputSurface(mComposerClient, width, height);
    }

    void postBuffer(const sp<SurfaceControl> &layer) {
        // wait for previous transactions (such as setSize) to complete
        Transaction().apply(true);
        ANativeWindow_Buffer buffer = {};
        EXPECT_EQ(NO_ERROR, layer->getSurface()->lock(&buffer, nullptr));
        ASSERT_EQ(NO_ERROR, layer->getSurface()->unlockAndPost());
        // Request an empty transaction to get applied synchronously to ensure the buffer is
        // latched.
        Transaction().apply(true);
        usleep(mBufferPostDelay);
    }

    sp<SurfaceComposerClient> mComposerClient;
    int32_t mBufferPostDelay;
};

void injectTap(int x, int y) {
    char *buf1, *buf2;
    asprintf(&buf1, "%d", x);
    asprintf(&buf2, "%d", y);
    if (fork() == 0) {
        execlp("input", "input", "tap", buf1, buf2, NULL);
    }
}

TEST_F(InputSurfacesTest, can_receive_input) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);

    injectTap(101, 101);

    EXPECT_NE(surface->consumeEvent(), nullptr);
}

/**
 * Set up two surfaces side-by-side. Tap each surface.
 * Next, swap the positions of the two surfaces. Inject tap into the two
 * original locations. Ensure that the tap is received by the surfaces in the
 * reverse order.
 */
TEST_F(InputSurfacesTest, input_respects_positioning) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);

    std::unique_ptr<InputSurface> surface2 = makeSurface(100, 100);
    surface2->showAt(200, 200);

    injectTap(201, 201);
    surface2->expectTap(1, 1);

    injectTap(101, 101);
    surface->expectTap(1, 1);

    surface2->doTransaction([](auto &t, auto &sc) {
         t.setPosition(sc, 100, 100);
    });
    surface->doTransaction([](auto &t, auto &sc) {
         t.setPosition(sc, 200, 200);
    });

    injectTap(101, 101);
    surface2->expectTap(1, 1);

    injectTap(201, 201);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_respects_layering) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> surface2 = makeSurface(100, 100);

    surface->showAt(10, 10);
    surface2->showAt(10, 10);

    surface->doTransaction([](auto &t, auto &sc) {
         t.setLayer(sc, LAYER_BASE + 1);
    });

    injectTap(11, 11);
    surface->expectTap(1, 1);

    surface2->doTransaction([](auto &t, auto &sc) {
         t.setLayer(sc, LAYER_BASE + 1);
    });

    injectTap(11, 11);
    surface2->expectTap(1, 1);

    surface2->doTransaction([](auto &t, auto &sc) {
         t.hide(sc);
    });

    injectTap(11, 11);
    surface->expectTap(1, 1);
}

// Surface Insets are set to offset the client content and draw a border around the client surface
// (such as shadows in dialogs). Inputs sent to the client are offset such that 0,0 is the start
// of the client content.
TEST_F(InputSurfacesTest, input_respects_surface_insets) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    bgSurface->showAt(100, 100);

    fgSurface->mInputInfo.surfaceInset = 5;
    fgSurface->showAt(100, 100);

    injectTap(106, 106);
    fgSurface->expectTap(1, 1);

    injectTap(101, 101);
    bgSurface->expectTap(1, 1);
}

// Ensure a surface whose insets are cropped, handles the touch offset correctly. ref:b/120413463
TEST_F(InputSurfacesTest, input_respects_cropped_surface_insets) {
    std::unique_ptr<InputSurface> parentSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> childSurface = makeSurface(100, 100);
    parentSurface->showAt(100, 100);

    childSurface->mInputInfo.surfaceInset = 10;
    childSurface->showAt(100, 100);

    childSurface->doTransaction([&](auto &t, auto &sc) {
        t.setPosition(sc, -5, -5);
        t.reparent(sc, parentSurface->mSurfaceControl);
    });

    injectTap(106, 106);
    childSurface->expectTap(1, 1);

    injectTap(101, 101);
    parentSurface->expectTap(1, 1);
}

// Ensure a surface whose insets are scaled, handles the touch offset correctly.
TEST_F(InputSurfacesTest, input_respects_scaled_surface_insets) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    bgSurface->showAt(100, 100);

    fgSurface->mInputInfo.surfaceInset = 5;
    fgSurface->showAt(100, 100);

    fgSurface->doTransaction([&](auto &t, auto &sc) { t.setMatrix(sc, 2.0, 0, 0, 4.0); });

    // expect = touch / scale - inset
    injectTap(112, 124);
    fgSurface->expectTap(1, 1);

    injectTap(101, 101);
    bgSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_respects_scaled_surface_insets_overflow) {
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    // In case we pass the very big inset without any checking.
    fgSurface->mInputInfo.surfaceInset = INT32_MAX;
    fgSurface->showAt(100, 100);

    fgSurface->doTransaction([&](auto &t, auto &sc) { t.setMatrix(sc, 2.0, 0, 0, 2.0); });

    // expect no crash for overflow, and inset size to be clamped to surface size
    injectTap(202, 202);
    fgSurface->expectTap(1, 1);
}

// Ensure we ignore transparent region when getting screen bounds when positioning input frame.
TEST_F(InputSurfacesTest, input_ignores_transparent_region) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([](auto &t, auto &sc) {
        Region transparentRegion(Rect(0, 0, 10, 10));
        t.setTransparentRegionHint(sc, transparentRegion);
    });
    surface->showAt(100, 100);
    injectTap(101, 101);
    surface->expectTap(1, 1);
}

// TODO(b/139494112) update tests once we define expected behavior
// Ensure we still send input to the surface regardless of surface visibility changes due to the
// first buffer being submitted or alpha changes.
// Original bug ref: b/120839715
TEST_F(InputSurfacesTest, input_ignores_buffer_layer_buffer) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> bufferSurface =
            InputSurface::makeBufferInputSurface(mComposerClient, 100, 100);

    bgSurface->showAt(10, 10);
    bufferSurface->showAt(10, 10);

    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);

    postBuffer(bufferSurface->mSurfaceControl);
    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_ignores_buffer_layer_alpha) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> bufferSurface =
            InputSurface::makeBufferInputSurface(mComposerClient, 100, 100);
    postBuffer(bufferSurface->mSurfaceControl);

    bgSurface->showAt(10, 10);
    bufferSurface->showAt(10, 10);

    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);

    bufferSurface->doTransaction([](auto &t, auto &sc) { t.setAlpha(sc, 0.0); });

    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_ignores_color_layer_alpha) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);

    bgSurface->showAt(10, 10);
    fgSurface->showAt(10, 10);

    injectTap(11, 11);
    fgSurface->expectTap(1, 1);

    fgSurface->doTransaction([](auto &t, auto &sc) { t.setAlpha(sc, 0.0); });

    injectTap(11, 11);
    fgSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_respects_container_layer_visiblity) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> containerSurface =
            InputSurface::makeContainerInputSurface(mComposerClient, 100, 100);

    bgSurface->showAt(10, 10);
    containerSurface->showAt(10, 10);

    injectTap(11, 11);
    containerSurface->expectTap(1, 1);

    containerSurface->doTransaction([](auto &t, auto &sc) { t.hide(sc); });

    injectTap(11, 11);
    bgSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_respects_outscreen) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(-1, -1);

    injectTap(0, 0);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_ignores_cursor_layer) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> cursorSurface =
            InputSurface::makeCursorInputSurface(mComposerClient, 10, 10);

    surface->showAt(10, 10);
    cursorSurface->showAt(10, 10);

    injectTap(11, 11);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, can_be_focused) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);
    surface->requestFocus();

    surface->assertFocusChange(true);
}

TEST_F(InputSurfacesTest, rotate_surface) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(10, 10);
    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, 0, 1, -1, 0); // 90 degrees
    });
    injectTap(8, 11);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, -1, 0, 0, -1); // 180 degrees
    });
    injectTap(9, 8);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, 0, -1, 1, 0); // 270 degrees
    });
    injectTap(12, 9);
    surface->expectTap(1, 2);
}

TEST_F(InputSurfacesTest, rotate_surface_with_scale) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(10, 10);
    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, 0, 2, -4, 0); // 90 degrees
    });
    injectTap(2, 12);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, -2, 0, 0, -4); // 180 degrees
    });
    injectTap(8, 2);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, 0, -2, 4, 0); // 270 degrees
    });
    injectTap(18, 8);
    surface->expectTap(1, 2);
}

TEST_F(InputSurfacesTest, rotate_surface_with_scale_and_insets) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->mInputInfo.surfaceInset = 5;
    surface->showAt(100, 100);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, 0, 2, -4, 0); // 90 degrees
    });
    injectTap(40, 120);
    surface->expectTap(5, 10);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, -2, 0, 0, -4); // 180 degrees
    });
    injectTap(80, 40);
    surface->expectTap(5, 10);

    surface->doTransaction([](auto &t, auto &sc) {
        t.setMatrix(sc, 0, -2, 4, 0); // 270 degrees
    });
    injectTap(160, 80);
    surface->expectTap(5, 10);
}

TEST_F(InputSurfacesTest, touch_flag_obscured) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);

    // Add non touchable window to fully cover touchable window. Window behind gets touch, but
    // with flag AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED
    std::unique_ptr<InputSurface> nonTouchableSurface = makeSurface(100, 100);
    nonTouchableSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    nonTouchableSurface->mInputInfo.ownerUid = 22222;
    // Overriding occlusion mode otherwise the touch would be discarded at InputDispatcher by
    // the default obscured/untrusted touch filter introduced in S.
    nonTouchableSurface->mInputInfo.touchOcclusionMode = TouchOcclusionMode::ALLOW;
    nonTouchableSurface->showAt(100, 100);

    injectTap(190, 199);
    surface->expectTapWithFlag(90, 99, AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED);
}

TEST_F(InputSurfacesTest, touch_flag_partially_obscured_with_crop) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);

    // Add non touchable window to cover touchable window, but parent is cropped to not cover area
    // that will be tapped. Window behind gets touch, but with flag
    // AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED
    std::unique_ptr<InputSurface> parentSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> nonTouchableSurface = makeSurface(100, 100);
    nonTouchableSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    parentSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    nonTouchableSurface->mInputInfo.ownerUid = 22222;
    parentSurface->mInputInfo.ownerUid = 22222;
    nonTouchableSurface->showAt(0, 0);
    parentSurface->showAt(100, 100);

    nonTouchableSurface->doTransaction([&](auto &t, auto &sc) {
        t.setCrop(parentSurface->mSurfaceControl, Rect(0, 0, 50, 50));
        t.reparent(sc, parentSurface->mSurfaceControl);
    });

    injectTap(190, 199);
    surface->expectTapWithFlag(90, 99, AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED);
}

TEST_F(InputSurfacesTest, touch_not_obscured_with_crop) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);

    // Add non touchable window to cover touchable window, but parent is cropped to avoid covering
    // the touchable window. Window behind gets touch with no obscured flags.
    std::unique_ptr<InputSurface> parentSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> nonTouchableSurface = makeSurface(100, 100);
    nonTouchableSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    parentSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    nonTouchableSurface->mInputInfo.ownerUid = 22222;
    parentSurface->mInputInfo.ownerUid = 22222;
    nonTouchableSurface->showAt(0, 0);
    parentSurface->showAt(50, 50);

    nonTouchableSurface->doTransaction([&](auto &t, auto &sc) {
        t.setCrop(parentSurface->mSurfaceControl, Rect(0, 0, 50, 50));
        t.reparent(sc, parentSurface->mSurfaceControl);
    });

    injectTap(101, 110);
    surface->expectTap(1, 10);
}

TEST_F(InputSurfacesTest, touch_not_obscured_with_zero_sized_bql) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);

    std::unique_ptr<InputSurface> bufferSurface =
            InputSurface::makeBufferInputSurface(mComposerClient, 0, 0);
    bufferSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    bufferSurface->mInputInfo.ownerUid = 22222;

    surface->showAt(10, 10);
    bufferSurface->showAt(50, 50, Rect::EMPTY_RECT);

    injectTap(11, 11);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, touch_not_obscured_with_zero_sized_blast) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);

    std::unique_ptr<InputSurface> bufferSurface =
            InputSurface::makeBlastInputSurface(mComposerClient, 0, 0);
    bufferSurface->mInputInfo.flags = InputWindowInfo::Flag::NOT_TOUCHABLE;
    bufferSurface->mInputInfo.ownerUid = 22222;

    surface->showAt(10, 10);
    bufferSurface->showAt(50, 50, Rect::EMPTY_RECT);

    injectTap(11, 11);
    surface->expectTap(1, 1);
}

} // namespace android::test
