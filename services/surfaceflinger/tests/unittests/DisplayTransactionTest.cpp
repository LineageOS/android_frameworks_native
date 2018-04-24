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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <log/log.h>

#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockDisplaySurface.h"
#include "mock/MockEventControlThread.h"
#include "mock/MockEventThread.h"
#include "mock/MockMessageQueue.h"
#include "mock/MockNativeWindowSurface.h"
#include "mock/MockSurfaceInterceptor.h"
#include "mock/RenderEngine/MockRenderEngine.h"
#include "mock/gui/MockGraphicBufferConsumer.h"
#include "mock/gui/MockGraphicBufferProducer.h"
#include "mock/system/window/MockNativeWindow.h"

namespace android {
namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

using android::hardware::graphics::common::V1_0::Hdr;
using android::hardware::graphics::common::V1_1::ColorMode;
using android::Hwc2::Error;
using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

using HWC2Display = TestableSurfaceFlinger::HWC2Display;
using HotplugEvent = TestableSurfaceFlinger::HotplugEvent;

constexpr int32_t DEFAULT_REFRESH_RATE = 1666666666;
constexpr int32_t DEFAULT_DPI = 320;

constexpr int DEFAULT_CONFIG_ID = 0;

class DisplayTransactionTest : public testing::Test {
protected:
    DisplayTransactionTest();
    ~DisplayTransactionTest() override;

    // --------------------------------------------------------------------
    // Precondition helpers

    void setupComposer(int virtualDisplayCount);
    void setupFakeHwcDisplay(hwc2_display_t displayId, DisplayDevice::DisplayType type, int width,
                             int height);

    struct FakeDisplayDeviceFactory {
    public:
        FakeDisplayDeviceFactory(TestableSurfaceFlinger& flinger, sp<BBinder>& displayToken,
                                 DisplayDevice::DisplayType type, int hwcId)
              : mFlinger(flinger), mDisplayToken(displayToken), mType(type), mHwcId(hwcId) {}

        sp<DisplayDevice> build() {
            return new DisplayDevice(mFlinger.mFlinger.get(), mType, mHwcId, false, mDisplayToken,
                                     mNativeWindow, mDisplaySurface, std::move(mRenderSurface), 0,
                                     0, false, {}, 0, HWC_POWER_MODE_NORMAL);
        }

        FakeDisplayDeviceFactory& setNativeWindow(const sp<ANativeWindow>& nativeWindow) {
            mNativeWindow = nativeWindow;
            return *this;
        }

        FakeDisplayDeviceFactory& setDisplaySurface(const sp<DisplaySurface>& displaySurface) {
            mDisplaySurface = displaySurface;
            return *this;
        }

        FakeDisplayDeviceFactory& setRenderSurface(std::unique_ptr<RE::Surface> renderSurface) {
            mRenderSurface = std::move(renderSurface);
            return *this;
        }

        TestableSurfaceFlinger& mFlinger;
        sp<BBinder>& mDisplayToken;
        DisplayDevice::DisplayType mType;
        int mHwcId;
        sp<ANativeWindow> mNativeWindow;
        sp<DisplaySurface> mDisplaySurface;
        std::unique_ptr<RE::Surface> mRenderSurface;
    };

    sp<BBinder> setupFakeExistingPhysicalDisplay(hwc2_display_t displayId,
                                                 DisplayDevice::DisplayType type);

    void setupFakeBufferQueueFactory();
    void setupFakeNativeWindowSurfaceFactory(int displayWidth, int displayHeight, bool critical,
                                             bool async);
    void expectFramebufferUsageSet(int width, int height, int grallocUsage);
    void expectHwcHotplugCalls(hwc2_display_t displayId, int displayWidth, int displayHeight);

    // --------------------------------------------------------------------
    // Call expectation helpers

    void expectRESurfaceCreationCalls();
    void expectPhysicalDisplayDeviceCreationCalls(hwc2_display_t displayId, int displayWidth,
                                                  int displayHeight, bool critical, bool async);

    // --------------------------------------------------------------------
    // Postcondition helpers

    bool hasTransactionFlagSet(int flag);
    bool hasDisplayDevice(sp<IBinder> displayToken);
    sp<DisplayDevice> getDisplayDevice(sp<IBinder> displayToken);
    bool hasCurrentDisplayState(sp<IBinder> displayToken);
    const DisplayDeviceState& getCurrentDisplayState(sp<IBinder> displayToken);
    bool hasDrawingDisplayState(sp<IBinder> displayToken);
    const DisplayDeviceState& getDrawingDisplayState(sp<IBinder> displayToken);

    // --------------------------------------------------------------------
    // Test instances

    std::unordered_set<HWC2::Capability> mCapabilities;

    TestableSurfaceFlinger mFlinger;
    mock::EventThread* mEventThread = new mock::EventThread();
    mock::EventControlThread* mEventControlThread = new mock::EventControlThread();

    // These mocks are created by the test, but are destroyed by SurfaceFlinger
    // by virtue of being stored into a std::unique_ptr. However we still need
    // to keep a reference to them for use in setting up call expectations.
    RE::mock::RenderEngine* mRenderEngine = new RE::mock::RenderEngine();
    Hwc2::mock::Composer* mComposer = new Hwc2::mock::Composer();
    mock::MessageQueue* mMessageQueue = new mock::MessageQueue();
    mock::SurfaceInterceptor* mSurfaceInterceptor = new mock::SurfaceInterceptor();

    // These mocks are created only when expected to be created via a factory.
    sp<mock::GraphicBufferConsumer> mConsumer;
    sp<mock::GraphicBufferProducer> mProducer;
    mock::NativeWindowSurface* mNativeWindowSurface = nullptr;
    sp<mock::NativeWindow> mNativeWindow;
    RE::mock::Surface* mRenderSurface = nullptr;
    std::vector<std::unique_ptr<HWC2Display>> mFakeHwcDisplays;
};

DisplayTransactionTest::DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    mFlinger.setCreateBufferQueueFunction([](auto, auto, auto) {
        ADD_FAILURE() << "Unexpected request to create a buffer queue.";
    });

    mFlinger.setCreateNativeWindowSurface([](auto) {
        ADD_FAILURE() << "Unexpected request to create a native window surface.";
        return nullptr;
    });

    mFlinger.mutableEventControlThread().reset(mEventControlThread);
    mFlinger.mutableEventThread().reset(mEventThread);
    mFlinger.mutableEventQueue().reset(mMessageQueue);
    mFlinger.setupRenderEngine(std::unique_ptr<RE::RenderEngine>(mRenderEngine));
    mFlinger.mutableInterceptor().reset(mSurfaceInterceptor);

    setupComposer(0);
}

DisplayTransactionTest::~DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

void DisplayTransactionTest::setupComposer(int virtualDisplayCount) {
    EXPECT_CALL(*mComposer, getCapabilities())
            .WillOnce(Return(std::vector<IComposer::Capability>()));
    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    Mock::VerifyAndClear(mComposer);
}

void DisplayTransactionTest::setupFakeHwcDisplay(hwc2_display_t displayId,
                                                 DisplayDevice::DisplayType type, int width,
                                                 int height) {
    auto display = std::make_unique<HWC2Display>(*mComposer, mCapabilities, displayId,
                                                 HWC2::DisplayType::Physical);
    display->mutableIsConnected() = true;
    display->mutableConfigs().emplace(DEFAULT_CONFIG_ID,
                                      HWC2::Display::Config::Builder(*display, DEFAULT_CONFIG_ID)
                                              .setWidth(width)
                                              .setHeight(height)
                                              .setVsyncPeriod(DEFAULT_REFRESH_RATE)
                                              .setDpiX(DEFAULT_DPI)
                                              .setDpiY(DEFAULT_DPI)
                                              .build());

    mFlinger.mutableHwcDisplayData()[type].reset();
    mFlinger.mutableHwcDisplayData()[type].hwcDisplay = display.get();
    mFlinger.mutableHwcDisplaySlots().emplace(displayId, type);

    mFakeHwcDisplays.push_back(std::move(display));
}

sp<BBinder> DisplayTransactionTest::setupFakeExistingPhysicalDisplay(
        hwc2_display_t displayId, DisplayDevice::DisplayType type) {
    setupFakeHwcDisplay(displayId, type, 0, 0);

    sp<BBinder> displayToken = new BBinder();
    mFlinger.mutableBuiltinDisplays()[type] = displayToken;
    mFlinger.mutableDisplays()
            .add(displayToken,
                 FakeDisplayDeviceFactory(mFlinger, displayToken, type, type).build());

    DisplayDeviceState state(type, true);
    mFlinger.mutableCurrentState().displays.add(displayToken, state);
    mFlinger.mutableDrawingState().displays.add(displayToken, state);

    return displayToken;
}

void DisplayTransactionTest::setupFakeBufferQueueFactory() {
    // This setup is only expected once per test.
    ASSERT_TRUE(mConsumer == nullptr && mProducer == nullptr);

    mConsumer = new mock::GraphicBufferConsumer();
    mProducer = new mock::GraphicBufferProducer();

    mFlinger.setCreateBufferQueueFunction([this](auto outProducer, auto outConsumer, bool) {
        *outProducer = mProducer;
        *outConsumer = mConsumer;
    });
}

void DisplayTransactionTest::setupFakeNativeWindowSurfaceFactory(int displayWidth,
                                                                 int displayHeight, bool critical,
                                                                 bool async) {
    // This setup is only expected once per test.
    ASSERT_TRUE(mNativeWindowSurface == nullptr);

    mNativeWindowSurface = new mock::NativeWindowSurface();
    mNativeWindow = new mock::NativeWindow();

    mFlinger.setCreateNativeWindowSurface(
            [this](auto) { return std::unique_ptr<NativeWindowSurface>(mNativeWindowSurface); });

    EXPECT_CALL(*mNativeWindowSurface, getNativeWindow()).WillOnce(Return(mNativeWindow));

    EXPECT_CALL(*mNativeWindow, perform(19)).Times(1);

    EXPECT_CALL(*mRenderSurface, setAsync(async)).Times(1);
    EXPECT_CALL(*mRenderSurface, setCritical(critical)).Times(1);
    EXPECT_CALL(*mRenderSurface, setNativeWindow(mNativeWindow.get())).Times(1);
    EXPECT_CALL(*mRenderSurface, queryWidth()).WillOnce(Return(displayWidth));
    EXPECT_CALL(*mRenderSurface, queryHeight()).WillOnce(Return(displayHeight));
}

void DisplayTransactionTest::expectFramebufferUsageSet(int width, int height, int grallocUsage) {
    EXPECT_CALL(*mConsumer, consumerConnect(_, false)).WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mConsumer, setConsumerName(_)).WillRepeatedly(Return(NO_ERROR));
    EXPECT_CALL(*mConsumer, setConsumerUsageBits(grallocUsage)).WillRepeatedly(Return(NO_ERROR));
    EXPECT_CALL(*mConsumer, setDefaultBufferSize(width, height)).WillRepeatedly(Return(NO_ERROR));
    EXPECT_CALL(*mConsumer, setMaxAcquiredBufferCount(_)).WillRepeatedly(Return(NO_ERROR));

    EXPECT_CALL(*mProducer, allocateBuffers(0, 0, 0, 0)).WillRepeatedly(Return());
}

void DisplayTransactionTest::expectHwcHotplugCalls(hwc2_display_t displayId, int displayWidth,
                                                   int displayHeight) {
    EXPECT_CALL(*mComposer, getDisplayType(displayId, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayType::PHYSICAL),
                            Return(Error::NONE)));
    EXPECT_CALL(*mComposer, setClientTargetSlotCount(_)).WillOnce(Return(Error::NONE));
    EXPECT_CALL(*mComposer, getDisplayConfigs(_, _))
            .WillOnce(DoAll(SetArgPointee<1>(std::vector<unsigned>{0}), Return(Error::NONE)));
    EXPECT_CALL(*mComposer, getDisplayAttribute(displayId, 0, IComposerClient::Attribute::WIDTH, _))
            .WillOnce(DoAll(SetArgPointee<3>(displayWidth), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(displayId, 0, IComposerClient::Attribute::HEIGHT, _))
            .WillOnce(DoAll(SetArgPointee<3>(displayHeight), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(displayId, 0, IComposerClient::Attribute::VSYNC_PERIOD, _))
            .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_REFRESH_RATE), Return(Error::NONE)));
    EXPECT_CALL(*mComposer, getDisplayAttribute(displayId, 0, IComposerClient::Attribute::DPI_X, _))
            .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_DPI), Return(Error::NONE)));
    EXPECT_CALL(*mComposer, getDisplayAttribute(displayId, 0, IComposerClient::Attribute::DPI_Y, _))
            .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_DPI), Return(Error::NONE)));
}

void DisplayTransactionTest::expectRESurfaceCreationCalls() {
    // This setup is only expected once per test.
    ASSERT_TRUE(mRenderSurface == nullptr);

    mRenderSurface = new RE::mock::Surface();
    EXPECT_CALL(*mRenderEngine, createSurface())
            .WillOnce(Return(ByMove(std::unique_ptr<RE::Surface>(mRenderSurface))));
}

void DisplayTransactionTest::expectPhysicalDisplayDeviceCreationCalls(hwc2_display_t displayId,
                                                                      int displayWidth,
                                                                      int displayHeight,
                                                                      bool critical, bool async) {
    EXPECT_CALL(*mComposer, getActiveConfig(displayId, _))
            .WillOnce(DoAll(SetArgPointee<1>(DEFAULT_CONFIG_ID), Return(Error::NONE)));
    EXPECT_CALL(*mComposer, getColorModes(displayId, _)).Times(0);
    EXPECT_CALL(*mComposer, getHdrCapabilities(displayId, _, _, _, _))
            .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hdr>()), Return(Error::NONE)));

    setupFakeBufferQueueFactory();
    expectFramebufferUsageSet(displayWidth, displayHeight,
                              GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_COMPOSER |
                                      GRALLOC_USAGE_HW_FB);

    setupFakeNativeWindowSurfaceFactory(displayWidth, displayHeight, critical, async);
}

bool DisplayTransactionTest::hasTransactionFlagSet(int flag) {
    return mFlinger.mutableTransactionFlags() & flag;
}

bool DisplayTransactionTest::hasDisplayDevice(sp<IBinder> displayToken) {
    return mFlinger.mutableDisplays().indexOfKey(displayToken) >= 0;
}

sp<DisplayDevice> DisplayTransactionTest::getDisplayDevice(sp<IBinder> displayToken) {
    return mFlinger.mutableDisplays().valueFor(displayToken);
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

/* ------------------------------------------------------------------------
 * SurfaceFlinger::handleTransactionLocked(eDisplayTransactionNeeded)
 */

TEST_F(DisplayTransactionTest, handleTransactionLockedProcessesHotplugConnectPrimary) {
    constexpr hwc2_display_t externalDisplayId = 102;
    constexpr hwc2_display_t displayId = 123;
    constexpr int displayWidth = 1920;
    constexpr int displayHeight = 1080;

    // --------------------------------------------------------------------
    // Preconditions

    // An external display may already be set up
    setupFakeHwcDisplay(externalDisplayId, DisplayDevice::DISPLAY_EXTERNAL, 3840, 2160);

    // A hotplug connect comes in for a new display
    mFlinger.mutablePendingHotplugEvents().emplace_back(
            HotplugEvent{displayId, HWC2::Connection::Connected});

    // --------------------------------------------------------------------
    // Call Expectations

    EXPECT_CALL(*mComposer, isUsingVrComposer()).WillOnce(Return(false));
    expectHwcHotplugCalls(displayId, displayWidth, displayHeight);
    expectRESurfaceCreationCalls();
    expectPhysicalDisplayDeviceCreationCalls(displayId, displayWidth, displayHeight, true, false);

    EXPECT_CALL(*mSurfaceInterceptor, saveDisplayCreation(_)).Times(1);

    EXPECT_CALL(*mEventThread, onHotplugReceived(DisplayDevice::DISPLAY_PRIMARY, true)).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.handleTransactionLocked(eDisplayTransactionNeeded);

    // --------------------------------------------------------------------
    // Postconditions

    // HWComposer should have an entry for the display
    EXPECT_TRUE(mFlinger.mutableHwcDisplaySlots().count(displayId) == 1);

    // The display should have set up as a primary built-in display.
    auto displayToken = mFlinger.mutableBuiltinDisplays()[DisplayDevice::DISPLAY_PRIMARY];
    ASSERT_TRUE(displayToken != nullptr);

    // The display device should have been set up in the list of displays.
    ASSERT_TRUE(hasDisplayDevice(displayToken));
    const auto& device = getDisplayDevice(displayToken);
    EXPECT_TRUE(device->isSecure());
    EXPECT_TRUE(device->isPrimary());

    // The display should have been set up in the current display state
    ASSERT_TRUE(hasCurrentDisplayState(displayToken));
    const auto& current = getCurrentDisplayState(displayToken);
    EXPECT_EQ(DisplayDevice::DISPLAY_PRIMARY, current.type);

    // The display should have been set up in the drawing display state
    ASSERT_TRUE(hasDrawingDisplayState(displayToken));
    const auto& draw = getDrawingDisplayState(displayToken);
    EXPECT_EQ(DisplayDevice::DISPLAY_PRIMARY, draw.type);

    // --------------------------------------------------------------------
    // Cleanup conditions

    EXPECT_CALL(*mComposer, setVsyncEnabled(displayId, IComposerClient::Vsync::DISABLE))
            .WillOnce(Return(Error::NONE));
    EXPECT_CALL(*mConsumer, consumerDisconnect()).WillOnce(Return(NO_ERROR));
}

} // namespace
} // namespace android
