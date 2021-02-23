/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "DisplayTransactionTestHelpers.h"

namespace android {

using testing::AnyNumber;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

using android::hardware::graphics::composer::hal::HWDisplayId;

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

DisplayTransactionTest::DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    // Default to no wide color display support configured
    mFlinger.mutableHasWideColorDisplay() = false;
    mFlinger.mutableUseColorManagement() = false;
    mFlinger.mutableDisplayColorSetting() = DisplayColorSetting::kUnmanaged;

    // Default to using HWC virtual displays
    mFlinger.mutableUseHwcVirtualDisplays() = true;

    mFlinger.setCreateBufferQueueFunction([](auto, auto, auto) {
        ADD_FAILURE() << "Unexpected request to create a buffer queue.";
    });

    mFlinger.setCreateNativeWindowSurface([](auto) {
        ADD_FAILURE() << "Unexpected request to create a native window surface.";
        return nullptr;
    });

    injectMockScheduler();
    mFlinger.mutableEventQueue().reset(mMessageQueue);
    mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    mFlinger.mutableInterceptor() = mSurfaceInterceptor;

    injectMockComposer(0);
}

DisplayTransactionTest::~DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

void DisplayTransactionTest::injectMockScheduler() {
    EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*mEventThread, createEventConnection(_, _))
            .WillOnce(Return(
                    new EventThreadConnection(mEventThread, /*callingUid=*/0, ResyncCallback())));

    EXPECT_CALL(*mSFEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*mSFEventThread, createEventConnection(_, _))
            .WillOnce(Return(
                    new EventThreadConnection(mSFEventThread, /*callingUid=*/0, ResyncCallback())));

    mFlinger.setupScheduler(std::unique_ptr<scheduler::VsyncController>(mVsyncController),
                            std::unique_ptr<scheduler::VSyncTracker>(mVSyncTracker),
                            std::unique_ptr<EventThread>(mEventThread),
                            std::unique_ptr<EventThread>(mSFEventThread), &mSchedulerCallback);
}

void DisplayTransactionTest::injectMockComposer(int virtualDisplayCount) {
    mComposer = new Hwc2::mock::Composer();
    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    Mock::VerifyAndClear(mComposer);
}

void DisplayTransactionTest::injectFakeBufferQueueFactory() {
    // This setup is only expected once per test.
    ASSERT_TRUE(mConsumer == nullptr && mProducer == nullptr);

    mConsumer = new mock::GraphicBufferConsumer();
    mProducer = new mock::GraphicBufferProducer();

    mFlinger.setCreateBufferQueueFunction([this](auto outProducer, auto outConsumer, bool) {
        *outProducer = mProducer;
        *outConsumer = mConsumer;
    });
}

void DisplayTransactionTest::injectFakeNativeWindowSurfaceFactory() {
    // This setup is only expected once per test.
    ASSERT_TRUE(mNativeWindowSurface == nullptr);

    mNativeWindowSurface = new surfaceflinger::mock::NativeWindowSurface();

    mFlinger.setCreateNativeWindowSurface([this](auto) {
        return std::unique_ptr<surfaceflinger::NativeWindowSurface>(mNativeWindowSurface);
    });
}

sp<DisplayDevice> DisplayTransactionTest::injectDefaultInternalDisplay(
        std::function<void(FakeDisplayDeviceInjector&)> injectExtra) {
    constexpr PhysicalDisplayId DEFAULT_DISPLAY_ID(777);
    constexpr int DEFAULT_DISPLAY_WIDTH = 1080;
    constexpr int DEFAULT_DISPLAY_HEIGHT = 1920;
    constexpr HWDisplayId DEFAULT_DISPLAY_HWC_DISPLAY_ID = 0;

    // The DisplayDevice is required to have a framebuffer (behind the
    // ANativeWindow interface) which uses the actual hardware display
    // size.
    EXPECT_CALL(*mNativeWindow, query(NATIVE_WINDOW_WIDTH, _))
            .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_WIDTH), Return(0)));
    EXPECT_CALL(*mNativeWindow, query(NATIVE_WINDOW_HEIGHT, _))
            .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_HEIGHT), Return(0)));
    EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_SET_BUFFERS_FORMAT));
    EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_API_CONNECT));
    EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_SET_USAGE64));
    EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_API_DISCONNECT)).Times(AnyNumber());

    auto compositionDisplay = compositionengine::impl::
            createDisplay(mFlinger.getCompositionEngine(),
                          compositionengine::DisplayCreationArgsBuilder()
                                  .setPhysical(
                                          {DEFAULT_DISPLAY_ID, ui::DisplayConnectionType::Internal})
                                  .setPixels({DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT})
                                  .setPowerAdvisor(&mPowerAdvisor)
                                  .build());

    auto injector = FakeDisplayDeviceInjector(mFlinger, compositionDisplay,
                                              ui::DisplayConnectionType::Internal,
                                              DEFAULT_DISPLAY_HWC_DISPLAY_ID, true /* isPrimary */);

    injector.setNativeWindow(mNativeWindow);
    if (injectExtra) {
        injectExtra(injector);
    }

    auto displayDevice = injector.inject();

    Mock::VerifyAndClear(mNativeWindow.get());

    return displayDevice;
}

bool DisplayTransactionTest::hasPhysicalHwcDisplay(HWDisplayId hwcDisplayId) {
    return mFlinger.mutableHwcPhysicalDisplayIdMap().count(hwcDisplayId) == 1;
}

bool DisplayTransactionTest::hasTransactionFlagSet(int flag) {
    return mFlinger.mutableTransactionFlags() & flag;
}

bool DisplayTransactionTest::hasDisplayDevice(sp<IBinder> displayToken) {
    return mFlinger.mutableDisplays().count(displayToken) == 1;
}

sp<DisplayDevice> DisplayTransactionTest::getDisplayDevice(sp<IBinder> displayToken) {
    return mFlinger.mutableDisplays()[displayToken];
}

bool DisplayTransactionTest::hasCurrentDisplayState(sp<IBinder> displayToken) {
    return mFlinger.mutableCurrentState().displays.indexOfKey(displayToken) >= 0;
}

const DisplayDeviceState& DisplayTransactionTest::getCurrentDisplayState(sp<IBinder> displayToken) {
    return mFlinger.mutableCurrentState().displays.valueFor(displayToken);
}

bool DisplayTransactionTest::hasDrawingDisplayState(sp<IBinder> displayToken) {
    return mFlinger.mutableDrawingState().displays.indexOfKey(displayToken) >= 0;
}

const DisplayDeviceState& DisplayTransactionTest::getDrawingDisplayState(sp<IBinder> displayToken) {
    return mFlinger.mutableDrawingState().displays.valueFor(displayToken);
}

} // namespace android
