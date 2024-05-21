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

#include <android-base/thread_annotations.h>
#include <android/gui/BnWindowInfosReportedListener.h>
#include <android/keycodes.h>
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
#include <gui/WindowInfo.h>
#include <input/Input.h>
#include <input/InputConsumer.h>
#include <input/InputTransport.h>

#include <ui/DisplayMode.h>
#include <ui/Rect.h>
#include <ui/Region.h>

#include <private/android_filesystem_config.h>

using android::os::IInputFlinger;

using android::hardware::graphics::common::V1_1::BufferUsage;

using android::gui::FocusRequest;
using android::gui::InputApplicationInfo;
using android::gui::TouchOcclusionMode;
using android::gui::WindowInfo;

namespace android {
namespace {
ui::LogicalDisplayId toDisplayId(ui::LayerStack layerStack) {
    return ui::LogicalDisplayId{static_cast<int32_t>(layerStack.id)};
}
} // namespace
namespace test {

using Transaction = SurfaceComposerClient::Transaction;

sp<IInputFlinger> getInputFlinger() {
    sp<IBinder> input(defaultServiceManager()->waitForService(String16("inputflinger")));
    if (input == nullptr) {
        ALOGE("Failed to link to input service");
    } else {
        ALOGE("Linked to input");
    }
    return interface_cast<IInputFlinger>(input);
}

// We use the top 10 layers as a way to haphazardly place ourselves above anything else.
static const int LAYER_BASE = INT32_MAX - 10;
static constexpr std::chrono::nanoseconds DISPATCHING_TIMEOUT = 5s;

class SynchronousWindowInfosReportedListener : public gui::BnWindowInfosReportedListener {
public:
    binder::Status onWindowInfosReported() override {
        std::scoped_lock lock{mLock};
        mWindowInfosReported = true;
        mConditionVariable.notify_one();
        return binder::Status::ok();
    }

    void wait() {
        std::unique_lock lock{mLock};
        android::base::ScopedLockAssertion assumeLocked(mLock);
        mConditionVariable.wait(lock, [&]() REQUIRES(mLock) { return mWindowInfosReported; });
    }

private:
    std::mutex mLock;
    std::condition_variable mConditionVariable;
    bool mWindowInfosReported GUARDED_BY(mLock){false};
};

class InputSurface {
public:
    InputSurface(const sp<SurfaceControl>& sc, int width, int height, bool noInputChannel = false) {
        mSurfaceControl = sc;

        mInputFlinger = getInputFlinger();
        if (noInputChannel) {
            mInputInfo.setInputConfig(WindowInfo::InputConfig::NO_INPUT_CHANNEL, true);
        } else {
            android::os::InputChannelCore tempChannel;
            android::binder::Status result =
                    mInputFlinger->createInputChannel("testchannels", &tempChannel);
            if (!result.isOk()) {
                ADD_FAILURE() << "binder call to createInputChannel failed";
            }
            mClientChannel = InputChannel::create(std::move(tempChannel));
            mInputInfo.token = mClientChannel->getConnectionToken();
            mInputConsumer = new InputConsumer(mClientChannel);
        }

        mInputInfo.name = "Test info";
        mInputInfo.dispatchingTimeout = 5s;
        mInputInfo.globalScaleFactor = 1.0;
        mInputInfo.touchableRegion.orSelf(Rect(0, 0, width, height));

        InputApplicationInfo aInfo;
        aInfo.token = new BBinder();
        aInfo.name = "Test app info";
        aInfo.dispatchingTimeoutMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(DISPATCHING_TIMEOUT).count();
        mInputInfo.applicationInfo = aInfo;
    }

    static std::unique_ptr<InputSurface> makeColorInputSurface(const sp<SurfaceComposerClient>& scc,
                                                               int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Surface"), 0 /* bufHeight */, 0 /* bufWidth */,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceEffect);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeBufferInputSurface(
            const sp<SurfaceComposerClient>& scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Buffer Surface"), width, height,
                                   PIXEL_FORMAT_RGBA_8888, 0 /* flags */);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeContainerInputSurface(
            const sp<SurfaceComposerClient>& scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Container Surface"), 0 /* bufHeight */,
                                   0 /* bufWidth */, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceContainer);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    static std::unique_ptr<InputSurface> makeContainerInputSurfaceNoInputChannel(
            const sp<SurfaceComposerClient>& scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Container Surface"), 100 /* height */,
                                   100 /* width */, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceContainer);
        return std::make_unique<InputSurface>(surfaceControl, width, height,
                                              true /* noInputChannel */);
    }

    static std::unique_ptr<InputSurface> makeCursorInputSurface(
            const sp<SurfaceComposerClient>& scc, int width, int height) {
        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Cursor Surface"), 0 /* bufHeight */,
                                   0 /* bufWidth */, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eCursorWindow);
        return std::make_unique<InputSurface>(surfaceControl, width, height);
    }

    InputEvent* consumeEvent(std::chrono::milliseconds timeout = 3000ms) {
        mClientChannel->waitForMessage(timeout);

        InputEvent* ev;
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
        InputEvent* ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::FOCUS, ev->getType());
        FocusEvent* focusEvent = static_cast<FocusEvent*>(ev);
        EXPECT_EQ(hasFocus, focusEvent->getHasFocus());
    }

    void expectTap(float x, float y) {
        InputEvent* ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::MOTION, ev->getType());
        MotionEvent* mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, mev->getAction());
        EXPECT_EQ(x, mev->getX(0));
        EXPECT_EQ(y, mev->getY(0));
        EXPECT_EQ(0, mev->getFlags() & VERIFIED_MOTION_EVENT_FLAGS);

        ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::MOTION, ev->getType());
        mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_UP, mev->getAction());
        EXPECT_EQ(0, mev->getFlags() & VERIFIED_MOTION_EVENT_FLAGS);
    }

    void expectTapWithFlag(int x, int y, int32_t flags) {
        InputEvent* ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::MOTION, ev->getType());
        MotionEvent* mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, mev->getAction());
        EXPECT_EQ(x, mev->getX(0));
        EXPECT_EQ(y, mev->getY(0));
        EXPECT_EQ(flags, mev->getFlags() & flags);

        ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::MOTION, ev->getType());
        mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_UP, mev->getAction());
        EXPECT_EQ(flags, mev->getFlags() & flags);
    }

    void expectTapInDisplayCoordinates(int displayX, int displayY) {
        InputEvent* ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::MOTION, ev->getType());
        MotionEvent* mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, mev->getAction());
        const PointerCoords& coords = *mev->getRawPointerCoords(0 /*pointerIndex*/);
        EXPECT_EQ(displayX, coords.getX());
        EXPECT_EQ(displayY, coords.getY());
        EXPECT_EQ(0, mev->getFlags() & VERIFIED_MOTION_EVENT_FLAGS);

        ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::MOTION, ev->getType());
        mev = static_cast<MotionEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_UP, mev->getAction());
        EXPECT_EQ(0, mev->getFlags() & VERIFIED_MOTION_EVENT_FLAGS);
    }

    void expectKey(int32_t keycode) {
        InputEvent* ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::KEY, ev->getType());
        KeyEvent* keyEvent = static_cast<KeyEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, keyEvent->getAction());
        EXPECT_EQ(keycode, keyEvent->getKeyCode());
        EXPECT_EQ(0, keyEvent->getFlags() & VERIFIED_KEY_EVENT_FLAGS);

        ev = consumeEvent();
        ASSERT_NE(ev, nullptr);
        ASSERT_EQ(InputEventType::KEY, ev->getType());
        keyEvent = static_cast<KeyEvent*>(ev);
        EXPECT_EQ(AMOTION_EVENT_ACTION_UP, keyEvent->getAction());
        EXPECT_EQ(keycode, keyEvent->getKeyCode());
        EXPECT_EQ(0, keyEvent->getFlags() & VERIFIED_KEY_EVENT_FLAGS);
    }

    void assertNoEvent() {
        InputEvent* event = consumeEvent(/*timeout=*/100ms);
        ASSERT_EQ(event, nullptr) << "Expected no event, but got " << *event;
    }

    virtual ~InputSurface() {
        if (mClientChannel) {
            mInputFlinger->removeInputChannel(mClientChannel->getConnectionToken());
        }
    }

    virtual void doTransaction(
            std::function<void(SurfaceComposerClient::Transaction&, const sp<SurfaceControl>&)>
                    transactionBody) {
        SurfaceComposerClient::Transaction t;
        transactionBody(t, mSurfaceControl);
        t.apply(true);
    }

    virtual void showAt(int x, int y, Rect crop = Rect(0, 0, 100, 100)) {
        SurfaceComposerClient::Transaction t;
        t.show(mSurfaceControl);
        t.setInputWindowInfo(mSurfaceControl, mInputInfo);
        t.setLayer(mSurfaceControl, LAYER_BASE);
        t.setPosition(mSurfaceControl, x, y);
        t.setCrop(mSurfaceControl, crop);
        t.setAlpha(mSurfaceControl, 1);
        auto reportedListener = sp<SynchronousWindowInfosReportedListener>::make();
        t.addWindowInfosReportedListener(reportedListener);
        t.apply();
        reportedListener->wait();
    }

    void requestFocus(ui::LogicalDisplayId displayId = ui::LogicalDisplayId::DEFAULT) {
        SurfaceComposerClient::Transaction t;
        FocusRequest request;
        request.token = mInputInfo.token;
        request.windowName = mInputInfo.name;
        request.timestamp = systemTime(SYSTEM_TIME_MONOTONIC);
        request.displayId = displayId.val();
        t.setFocusedWindow(request);
        t.apply(true);
    }

public:
    sp<SurfaceControl> mSurfaceControl;
    std::shared_ptr<InputChannel> mClientChannel;
    sp<IInputFlinger> mInputFlinger;

    WindowInfo mInputInfo;

    PreallocatedInputEventFactory mInputEventFactory;
    InputConsumer* mInputConsumer;
};

class BlastInputSurface : public InputSurface {
public:
    BlastInputSurface(const sp<SurfaceControl>& sc, const sp<SurfaceControl>& parentSc, int width,
                      int height)
          : InputSurface(sc, width, height) {
        mParentSurfaceControl = parentSc;
    }

    ~BlastInputSurface() = default;

    static std::unique_ptr<BlastInputSurface> makeBlastInputSurface(
            const sp<SurfaceComposerClient>& scc, int width, int height) {
        sp<SurfaceControl> parentSc =
                scc->createSurface(String8("Test Parent Surface"), 0 /* bufHeight */,
                                   0 /* bufWidth */, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceContainer);

        sp<SurfaceControl> surfaceControl =
                scc->createSurface(String8("Test Buffer Surface"), width, height,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceBufferState,
                                   parentSc->getHandle());
        return std::make_unique<BlastInputSurface>(surfaceControl, parentSc, width, height);
    }

    void doTransaction(
            std::function<void(SurfaceComposerClient::Transaction&, const sp<SurfaceControl>&)>
                    transactionBody) override {
        SurfaceComposerClient::Transaction t;
        transactionBody(t, mParentSurfaceControl);
        t.apply(true);
    }

    void showAt(int x, int y, Rect crop = Rect(0, 0, 100, 100)) override {
        SurfaceComposerClient::Transaction t;
        t.show(mParentSurfaceControl);
        t.setLayer(mParentSurfaceControl, LAYER_BASE);
        t.setPosition(mParentSurfaceControl, x, y);
        t.setCrop(mParentSurfaceControl, crop);

        t.show(mSurfaceControl);
        t.setInputWindowInfo(mSurfaceControl, mInputInfo);
        t.setCrop(mSurfaceControl, crop);
        t.setAlpha(mSurfaceControl, 1);
        t.apply(true);
    }

private:
    sp<SurfaceControl> mParentSurfaceControl;
};

class InputSurfacesTest : public ::testing::Test {
public:
    InputSurfacesTest() { ProcessState::self()->startThreadPool(); }

    void SetUp() {
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());
        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        ASSERT_FALSE(ids.empty());
        // display 0 is picked for now, can extend to support all displays if needed
        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
        ASSERT_NE(display, nullptr);

        ui::DisplayMode mode;
        ASSERT_EQ(NO_ERROR, mComposerClient->getActiveDisplayMode(display, &mode));

        // After a new buffer is queued, SurfaceFlinger is notified and will
        // latch the new buffer on next vsync.  Let's heuristically wait for 3
        // vsyncs.
        mBufferPostDelay = static_cast<int32_t>(1e6 / mode.peakRefreshRate) * 3;
    }

    void TearDown() { mComposerClient->dispose(); }

    std::unique_ptr<InputSurface> makeSurface(int width, int height) {
        return InputSurface::makeColorInputSurface(mComposerClient, width, height);
    }

    void postBuffer(const sp<SurfaceControl>& layer, int32_t w, int32_t h) {
        int64_t usageFlags = BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                BufferUsage::COMPOSER_OVERLAY | BufferUsage::GPU_TEXTURE;
        sp<GraphicBuffer> buffer =
                new GraphicBuffer(w, h, PIXEL_FORMAT_RGBA_8888, 1, usageFlags, "test");
        Transaction().setBuffer(layer, buffer).apply(true);
        usleep(mBufferPostDelay);
    }

    sp<SurfaceComposerClient> mComposerClient;
    int32_t mBufferPostDelay;
};

void injectTapOnDisplay(int x, int y, ui::LogicalDisplayId displayId) {
    char *buf1, *buf2, *bufDisplayId;
    asprintf(&buf1, "%d", x);
    asprintf(&buf2, "%d", y);
    asprintf(&bufDisplayId, "%d", displayId.val());
    if (fork() == 0) {
        execlp("input", "input", "-d", bufDisplayId, "tap", buf1, buf2, NULL);
    }
}

void injectTap(int x, int y) {
    injectTapOnDisplay(x, y, ui::LogicalDisplayId::DEFAULT);
}

void injectKeyOnDisplay(uint32_t keycode, ui::LogicalDisplayId displayId) {
    char *buf1, *bufDisplayId;
    asprintf(&buf1, "%d", keycode);
    asprintf(&bufDisplayId, "%d", displayId.val());
    if (fork() == 0) {
        execlp("input", "input", "-d", bufDisplayId, "keyevent", buf1, NULL);
    }
}

void injectKey(uint32_t keycode) {
    injectKeyOnDisplay(keycode, ui::LogicalDisplayId::INVALID);
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

    surface2->doTransaction([](auto& t, auto& sc) { t.setPosition(sc, 100, 100); });
    surface->doTransaction([](auto& t, auto& sc) { t.setPosition(sc, 200, 200); });

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

    surface->doTransaction([](auto& t, auto& sc) { t.setLayer(sc, LAYER_BASE + 1); });

    injectTap(11, 11);
    surface->expectTap(1, 1);

    surface2->doTransaction([](auto& t, auto& sc) { t.setLayer(sc, LAYER_BASE + 1); });

    injectTap(11, 11);
    surface2->expectTap(1, 1);

    surface2->doTransaction([](auto& t, auto& sc) { t.hide(sc); });

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

TEST_F(InputSurfacesTest, input_respects_surface_insets_with_replaceTouchableRegionWithCrop) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    bgSurface->showAt(100, 100);

    fgSurface->mInputInfo.surfaceInset = 5;
    fgSurface->mInputInfo.replaceTouchableRegionWithCrop = true;
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

    childSurface->doTransaction([&](auto& t, auto& sc) {
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

    fgSurface->doTransaction([&](auto& t, auto& sc) { t.setMatrix(sc, 2.0, 0, 0, 4.0); });

    // expect = touch / scale - inset
    injectTap(112, 124);
    fgSurface->expectTap(1, 1);

    injectTap(101, 101);
    bgSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_respects_scaled_surface_insets_overflow) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    bgSurface->showAt(100, 100);

    // In case we pass the very big inset without any checking.
    fgSurface->mInputInfo.surfaceInset = INT32_MAX;
    fgSurface->showAt(100, 100);

    fgSurface->doTransaction([&](auto& t, auto& sc) { t.setMatrix(sc, 2.0, 0, 0, 2.0); });

    // expect no crash for overflow, and inset size to be clamped to surface size
    injectTap(112, 124);
    bgSurface->expectTap(12, 24);
}

TEST_F(InputSurfacesTest, touchable_region) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);

    surface->mInputInfo.touchableRegion.set(Rect{19, 29, 21, 31});

    surface->showAt(11, 22);

    // A tap within the surface but outside the touchable region should not be sent to the surface.
    injectTap(20, 30);
    EXPECT_EQ(surface->consumeEvent(/*timeout=*/200ms), nullptr);

    injectTap(31, 52);
    surface->expectTap(20, 30);
}

TEST_F(InputSurfacesTest, input_respects_touchable_region_offset_overflow) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    bgSurface->showAt(100, 100);

    // Set the touchable region to the values at the limit of its corresponding type.
    // Since the surface is offset from the origin, the touchable region will be transformed into
    // display space, which would trigger an overflow or an underflow. Ensure that we are protected
    // against such a situation.
    fgSurface->mInputInfo.touchableRegion.orSelf(Rect{INT32_MIN, INT32_MIN, INT32_MAX, INT32_MAX});

    fgSurface->showAt(100, 100);

    // Expect no crash for overflow. The overflowed touchable region is ignored, so the background
    // surface receives touch.
    injectTap(112, 124);
    bgSurface->expectTap(12, 24);
}

TEST_F(InputSurfacesTest, input_respects_scaled_touchable_region_overflow) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);
    bgSurface->showAt(0, 0);

    fgSurface->mInputInfo.touchableRegion.orSelf(Rect{INT32_MIN, INT32_MIN, INT32_MAX, INT32_MAX});
    fgSurface->showAt(0, 0);

    fgSurface->doTransaction([&](auto& t, auto& sc) { t.setMatrix(sc, 2.0, 0, 0, 2.0); });

    // Expect no crash for overflow.
    injectTap(12, 24);
    bgSurface->expectTap(12, 24);
}

// Ensure we ignore transparent region when getting screen bounds when positioning input frame.
TEST_F(InputSurfacesTest, input_ignores_transparent_region) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([](auto& t, auto& sc) {
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
    std::unique_ptr<BlastInputSurface> bufferSurface =
            BlastInputSurface::makeBlastInputSurface(mComposerClient, 100, 100);

    bgSurface->showAt(10, 10);
    bufferSurface->showAt(10, 10);

    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);

    postBuffer(bufferSurface->mSurfaceControl, 100, 100);
    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_respects_buffer_layer_alpha) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<BlastInputSurface> bufferSurface =
            BlastInputSurface::makeBlastInputSurface(mComposerClient, 100, 100);
    postBuffer(bufferSurface->mSurfaceControl, 100, 100);

    bgSurface->showAt(10, 10);
    bufferSurface->showAt(10, 10);

    injectTap(11, 11);
    bufferSurface->expectTap(1, 1);

    bufferSurface->doTransaction([](auto& t, auto& sc) { t.setAlpha(sc, 0.0); });

    injectTap(11, 11);
    bgSurface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, input_ignores_color_layer_alpha) {
    std::unique_ptr<InputSurface> bgSurface = makeSurface(100, 100);
    std::unique_ptr<InputSurface> fgSurface = makeSurface(100, 100);

    bgSurface->showAt(10, 10);
    fgSurface->showAt(10, 10);

    injectTap(11, 11);
    fgSurface->expectTap(1, 1);

    fgSurface->doTransaction([](auto& t, auto& sc) { t.setAlpha(sc, 0.0); });

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

    containerSurface->doTransaction([](auto& t, auto& sc) { t.hide(sc); });

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

    injectKey(AKEYCODE_V);
    surface->expectKey(AKEYCODE_V);
}

TEST_F(InputSurfacesTest, rotate_surface) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(10, 10);
    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, 0, 1, -1, 0); // 90 degrees
    });
    injectTap(8, 11);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, -1, 0, 0, -1); // 180 degrees
    });
    injectTap(9, 8);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, 0, -1, 1, 0); // 270 degrees
    });
    injectTap(12, 9);
    surface->expectTap(1, 2);
}

TEST_F(InputSurfacesTest, rotate_surface_with_scale) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(10, 10);
    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, 0, 2, -4, 0); // 90 degrees
    });
    injectTap(2, 12);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, -2, 0, 0, -4); // 180 degrees
    });
    injectTap(8, 2);
    surface->expectTap(1, 2);

    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, 0, -2, 4, 0); // 270 degrees
    });
    injectTap(18, 8);
    surface->expectTap(1, 2);
}

TEST_F(InputSurfacesTest, rotate_surface_with_scale_and_insets) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->mInputInfo.surfaceInset = 5;
    surface->showAt(100, 100);

    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, 0, 2, -4, 0); // 90 degrees
    });
    injectTap(40, 120);
    surface->expectTap(5, 10);

    surface->doTransaction([](auto& t, auto& sc) {
        t.setMatrix(sc, -2, 0, 0, -4); // 180 degrees
    });
    injectTap(80, 40);
    surface->expectTap(5, 10);

    surface->doTransaction([](auto& t, auto& sc) {
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
    nonTouchableSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    nonTouchableSurface->mInputInfo.ownerUid = gui::Uid{22222};
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
    nonTouchableSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    parentSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    nonTouchableSurface->mInputInfo.ownerUid = gui::Uid{22222};
    parentSurface->mInputInfo.ownerUid = gui::Uid{22222};
    nonTouchableSurface->showAt(0, 0);
    parentSurface->showAt(100, 100);

    nonTouchableSurface->doTransaction([&](auto& t, auto& sc) {
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
    nonTouchableSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    parentSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    nonTouchableSurface->mInputInfo.ownerUid = gui::Uid{22222};
    parentSurface->mInputInfo.ownerUid = gui::Uid{22222};
    nonTouchableSurface->showAt(0, 0);
    parentSurface->showAt(50, 50);

    nonTouchableSurface->doTransaction([&](auto& t, auto& sc) {
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
    bufferSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    bufferSurface->mInputInfo.ownerUid = gui::Uid{22222};

    surface->showAt(10, 10);
    bufferSurface->showAt(50, 50, Rect::EMPTY_RECT);

    injectTap(11, 11);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, touch_not_obscured_with_zero_sized_blast) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);

    std::unique_ptr<BlastInputSurface> bufferSurface =
            BlastInputSurface::makeBlastInputSurface(mComposerClient, 0, 0);
    bufferSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    bufferSurface->mInputInfo.ownerUid = gui::Uid{22222};

    surface->showAt(10, 10);
    bufferSurface->showAt(50, 50, Rect::EMPTY_RECT);

    injectTap(11, 11);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, strict_unobscured_input_unobscured_window) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction(
            [&](auto& t, auto& sc) { t.setDropInputMode(sc, gui::DropInputMode::OBSCURED); });
    surface->showAt(100, 100);

    injectTap(101, 101);
    surface->expectTap(1, 1);

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->expectKey(AKEYCODE_V);
}

TEST_F(InputSurfacesTest, strict_unobscured_input_scaled_without_crop_window) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) {
        t.setDropInputMode(sc, gui::DropInputMode::OBSCURED);
        t.setMatrix(sc, 2.0, 0, 0, 2.0);
    });
    surface->showAt(100, 100);

    injectTap(101, 101);
    surface->expectTap(.5, .5);

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->expectKey(AKEYCODE_V);
}

TEST_F(InputSurfacesTest, strict_unobscured_input_obscured_window) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->mInputInfo.ownerUid = gui::Uid{11111};
    surface->doTransaction(
            [&](auto& t, auto& sc) { t.setDropInputMode(sc, gui::DropInputMode::OBSCURED); });
    surface->showAt(100, 100);
    std::unique_ptr<InputSurface> obscuringSurface = makeSurface(100, 100);
    obscuringSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    obscuringSurface->mInputInfo.ownerUid = gui::Uid{22222};
    obscuringSurface->showAt(100, 100);
    injectTap(101, 101);
    surface->assertNoEvent();

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->assertNoEvent();
}

TEST_F(InputSurfacesTest, strict_unobscured_input_partially_obscured_window) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->mInputInfo.ownerUid = gui::Uid{11111};
    surface->doTransaction(
            [&](auto& t, auto& sc) { t.setDropInputMode(sc, gui::DropInputMode::OBSCURED); });
    surface->showAt(100, 100);
    std::unique_ptr<InputSurface> obscuringSurface = makeSurface(100, 100);
    obscuringSurface->mInputInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, true);
    obscuringSurface->mInputInfo.ownerUid = gui::Uid{22222};
    obscuringSurface->showAt(190, 190);

    injectTap(101, 101);

    surface->assertNoEvent();

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->assertNoEvent();
}

TEST_F(InputSurfacesTest, strict_unobscured_input_alpha_window) {
    std::unique_ptr<InputSurface> parentSurface = makeSurface(300, 300);
    parentSurface->showAt(0, 0, Rect(0, 0, 300, 300));

    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->showAt(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) {
        t.setDropInputMode(sc, gui::DropInputMode::OBSCURED);
        t.reparent(sc, parentSurface->mSurfaceControl);
        t.setAlpha(parentSurface->mSurfaceControl, 0.9f);
    });

    injectTap(101, 101);

    surface->assertNoEvent();

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->assertNoEvent();
}

TEST_F(InputSurfacesTest, strict_unobscured_input_cropped_window) {
    std::unique_ptr<InputSurface> parentSurface = makeSurface(300, 300);
    parentSurface->showAt(0, 0, Rect(0, 0, 300, 300));

    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) {
        t.setDropInputMode(sc, gui::DropInputMode::OBSCURED);
        t.reparent(sc, parentSurface->mSurfaceControl);
        t.setCrop(parentSurface->mSurfaceControl, Rect(10, 10, 100, 100));
    });
    surface->showAt(100, 100);

    injectTap(111, 111);

    surface->assertNoEvent();

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->assertNoEvent();
}

TEST_F(InputSurfacesTest, ignore_touch_region_with_zero_sized_blast) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);

    std::unique_ptr<BlastInputSurface> bufferSurface =
            BlastInputSurface::makeBlastInputSurface(mComposerClient, 0, 0);

    surface->showAt(100, 100);
    bufferSurface->mInputInfo.touchableRegion.orSelf(Rect(0, 0, 200, 200));
    bufferSurface->showAt(100, 100, Rect::EMPTY_RECT);

    injectTap(101, 101);
    surface->expectTap(1, 1);
}

TEST_F(InputSurfacesTest, drop_input_policy) {
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction(
            [&](auto& t, auto& sc) { t.setDropInputMode(sc, gui::DropInputMode::ALL); });
    surface->showAt(100, 100);

    injectTap(101, 101);
    surface->assertNoEvent();

    surface->requestFocus();
    surface->assertFocusChange(true);
    injectKey(AKEYCODE_V);
    surface->assertNoEvent();
}

TEST_F(InputSurfacesTest, layer_with_valid_crop_can_be_focused) {
    std::unique_ptr<InputSurface> bufferSurface =
            InputSurface::makeBufferInputSurface(mComposerClient, 100, 100);

    bufferSurface->showAt(50, 50, Rect{0, 0, 100, 100});

    bufferSurface->requestFocus();
    bufferSurface->assertFocusChange(true);
}

/**
 * If a cropped layer's touchable region is replaced with a null crop, it should receive input in
 * its own crop.
 */
TEST_F(InputSurfacesTest, cropped_container_replaces_touchable_region_with_null_crop) {
    std::unique_ptr<InputSurface> parentContainer =
            InputSurface::makeContainerInputSurface(mComposerClient, 0, 0);
    std::unique_ptr<InputSurface> containerSurface =
            InputSurface::makeContainerInputSurface(mComposerClient, 100, 100);
    containerSurface->doTransaction(
            [&](auto& t, auto& sc) { t.reparent(sc, parentContainer->mSurfaceControl); });
    containerSurface->mInputInfo.replaceTouchableRegionWithCrop = true;
    containerSurface->mInputInfo.touchableRegionCropHandle = nullptr;
    parentContainer->showAt(10, 10, Rect(0, 0, 20, 20));
    containerSurface->showAt(10, 10, Rect(0, 0, 5, 5));

    // Receives events inside its own crop
    injectTap(21, 21);
    containerSurface->expectTap(1, 1); // Event is in layer space

    // Does not receive events outside its crop
    injectTap(26, 26);
    containerSurface->assertNoEvent();
}

/**
 * If an un-cropped layer's touchable region is replaced with a null crop, it should receive input
 * in its parent's touchable region. The input events should be in the layer's coordinate space.
 */
TEST_F(InputSurfacesTest, uncropped_container_replaces_touchable_region_with_null_crop) {
    std::unique_ptr<InputSurface> parentContainer =
            InputSurface::makeContainerInputSurface(mComposerClient, 0, 0);
    std::unique_ptr<InputSurface> containerSurface =
            InputSurface::makeContainerInputSurface(mComposerClient, 100, 100);
    containerSurface->doTransaction(
            [&](auto& t, auto& sc) { t.reparent(sc, parentContainer->mSurfaceControl); });
    containerSurface->mInputInfo.replaceTouchableRegionWithCrop = true;
    containerSurface->mInputInfo.touchableRegionCropHandle = nullptr;
    parentContainer->showAt(10, 10, Rect(0, 0, 20, 20));
    containerSurface->showAt(10, 10, Rect::INVALID_RECT);

    // Receives events inside parent bounds
    injectTap(21, 21);
    containerSurface->expectTap(1, 1); // Event is in layer space

    // Does not receive events outside parent bounds
    injectTap(31, 31);
    containerSurface->assertNoEvent();
}

/**
 * If a layer's touchable region is replaced with a layer crop, it should receive input in the crop
 * layer's bounds. The input events should be in the layer's coordinate space.
 */
TEST_F(InputSurfacesTest, replace_touchable_region_with_crop) {
    std::unique_ptr<InputSurface> cropLayer =
            InputSurface::makeContainerInputSurface(mComposerClient, 0, 0);
    cropLayer->showAt(50, 50, Rect(0, 0, 20, 20));

    std::unique_ptr<InputSurface> containerSurface =
            InputSurface::makeContainerInputSurface(mComposerClient, 100, 100);
    containerSurface->mInputInfo.replaceTouchableRegionWithCrop = true;
    containerSurface->mInputInfo.touchableRegionCropHandle =
            cropLayer->mSurfaceControl->getHandle();
    containerSurface->showAt(10, 10, Rect::INVALID_RECT);

    // Receives events inside crop layer bounds
    injectTap(51, 51);
    containerSurface->expectTap(41, 41); // Event is in layer space

    // Does not receive events outside crop layer bounds
    injectTap(21, 21);
    injectTap(71, 71);
    containerSurface->assertNoEvent();
}

TEST_F(InputSurfacesTest, child_container_with_no_input_channel_blocks_parent) {
    std::unique_ptr<InputSurface> parent = makeSurface(100, 100);

    parent->showAt(100, 100);
    injectTap(101, 101);
    parent->expectTap(1, 1);

    std::unique_ptr<InputSurface> childContainerSurface =
            InputSurface::makeContainerInputSurfaceNoInputChannel(mComposerClient, 100, 100);
    childContainerSurface->showAt(0, 0);
    childContainerSurface->doTransaction(
            [&](auto& t, auto& sc) { t.reparent(sc, parent->mSurfaceControl); });
    injectTap(101, 101);

    parent->assertNoEvent();
}

class MultiDisplayTests : public InputSurfacesTest {
public:
    MultiDisplayTests() : InputSurfacesTest() { ProcessState::self()->startThreadPool(); }

    void TearDown() override {
        std::for_each(mVirtualDisplays.begin(), mVirtualDisplays.end(),
                      SurfaceComposerClient::destroyVirtualDisplay);
        InputSurfacesTest::TearDown();
    }

    void createDisplay(int32_t width, int32_t height, bool isSecure, ui::LayerStack layerStack,
                       bool receivesInput = true, int32_t offsetX = 0, int32_t offsetY = 0) {
        sp<IGraphicBufferConsumer> consumer;
        sp<IGraphicBufferProducer> producer;
        BufferQueue::createBufferQueue(&producer, &consumer);
        consumer->setConsumerName(String8("Virtual disp consumer"));
        consumer->setDefaultBufferSize(width, height);
        mProducers.push_back(producer);

        std::string name = "VirtualDisplay";
        name += std::to_string(mVirtualDisplays.size());
        sp<IBinder> token = SurfaceComposerClient::createVirtualDisplay(name, isSecure);
        SurfaceComposerClient::Transaction t;
        t.setDisplaySurface(token, producer);
        t.setDisplayFlags(token, receivesInput ? 0x01 /* DisplayDevice::eReceivesInput */ : 0);
        t.setDisplayLayerStack(token, layerStack);
        t.setDisplayProjection(token, ui::ROTATION_0, {0, 0, width, height},
                               {offsetX, offsetY, offsetX + width, offsetY + height});
        t.apply(true);

        mVirtualDisplays.push_back(token);
    }

    std::vector<sp<IBinder>> mVirtualDisplays;
    std::vector<sp<IGraphicBufferProducer>> mProducers;
};

TEST_F(MultiDisplayTests, drop_touch_if_layer_on_invalid_display) {
    ui::LayerStack layerStack = ui::LayerStack::fromValue(42);
    // Do not create a display associated with the LayerStack.
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) { t.setLayerStack(sc, layerStack); });
    surface->showAt(100, 100);

    // Touches should be dropped if the layer is on an invalid display.
    injectTapOnDisplay(101, 101, toDisplayId(layerStack));
    surface->assertNoEvent();

    // However, we still let the window be focused and receive keys.
    surface->requestFocus(toDisplayId(layerStack));
    surface->assertFocusChange(true);

    injectKeyOnDisplay(AKEYCODE_V, toDisplayId(layerStack));
    surface->expectKey(AKEYCODE_V);
}

TEST_F(MultiDisplayTests, virtual_display_receives_input) {
    ui::LayerStack layerStack = ui::LayerStack::fromValue(42);
    createDisplay(1000, 1000, false /*isSecure*/, layerStack);
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) { t.setLayerStack(sc, layerStack); });
    surface->showAt(100, 100);

    injectTapOnDisplay(101, 101, toDisplayId(layerStack));
    surface->expectTap(1, 1);

    surface->requestFocus(toDisplayId(layerStack));
    surface->assertFocusChange(true);
    injectKeyOnDisplay(AKEYCODE_V, toDisplayId(layerStack));
    surface->expectKey(AKEYCODE_V);
}

TEST_F(MultiDisplayTests, drop_input_for_secure_layer_on_nonsecure_display) {
    ui::LayerStack layerStack = ui::LayerStack::fromValue(42);
    createDisplay(1000, 1000, false /*isSecure*/, layerStack);
    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) {
        t.setFlags(sc, layer_state_t::eLayerSecure, layer_state_t::eLayerSecure);
        t.setLayerStack(sc, layerStack);
    });
    surface->showAt(100, 100);

    injectTapOnDisplay(101, 101, toDisplayId(layerStack));

    surface->assertNoEvent();

    surface->requestFocus(toDisplayId(layerStack));
    surface->assertFocusChange(true);
    injectKeyOnDisplay(AKEYCODE_V, toDisplayId(layerStack));
    surface->assertNoEvent();
}

TEST_F(MultiDisplayTests, dont_drop_input_for_secure_layer_on_secure_display) {
    ui::LayerStack layerStack = ui::LayerStack::fromValue(42);

    // Create the secure display as system, because only certain users can create secure displays.
    seteuid(AID_SYSTEM);
    createDisplay(1000, 1000, true /*isSecure*/, layerStack);
    // Change the uid back to root.
    seteuid(AID_ROOT);

    std::unique_ptr<InputSurface> surface = makeSurface(100, 100);
    surface->doTransaction([&](auto& t, auto& sc) {
        t.setFlags(sc, layer_state_t::eLayerSecure, layer_state_t::eLayerSecure);
        t.setLayerStack(sc, layerStack);
    });
    surface->showAt(100, 100);

    injectTapOnDisplay(101, 101, toDisplayId(layerStack));
    surface->expectTap(1, 1);

    surface->requestFocus(toDisplayId(layerStack));
    surface->assertFocusChange(true);
    injectKeyOnDisplay(AKEYCODE_V, toDisplayId(layerStack));

    surface->expectKey(AKEYCODE_V);
}

} // namespace test
} // namespace android
