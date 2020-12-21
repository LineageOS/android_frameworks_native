/*
 * Copyright 2020 The Android Open Source Project
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

#pragma once

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <type_traits>
#include "DisplayIdentificationTest.h"

#include <binder/IPCThreadState.h>
#include <compositionengine/Display.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/mock/Display.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/DisplaySurface.h>
#include <compositionengine/mock/RenderSurface.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/mock/GraphicBufferConsumer.h>
#include <gui/mock/GraphicBufferProducer.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <renderengine/mock/RenderEngine.h>
#include <ui/DebugUtils.h>

#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockPowerAdvisor.h"
#include "mock/MockEventThread.h"
#include "mock/MockMessageQueue.h"
#include "mock/MockNativeWindowSurface.h"
#include "mock/MockSchedulerCallback.h"
#include "mock/MockSurfaceInterceptor.h"
#include "mock/MockVsyncController.h"
#include "mock/system/window/MockNativeWindow.h"

namespace android {

// TODO: Do not polute the android namespace
namespace hal = android::hardware::graphics::composer::hal;

using testing::_;
using testing::AnyNumber;
using testing::DoAll;
using testing::Mock;
using testing::ResultOf;
using testing::Return;
using testing::SetArgPointee;

using hal::ColorMode;
using hal::Connection;
using hal::DisplayCapability;
using hal::DisplayType;
using hal::Error;
using hal::Hdr;
using hal::HWDisplayId;
using hal::IComposer;
using hal::IComposerClient;
using hal::PerFrameMetadataKey;
using hal::PowerMode;

class DisplayTransactionTest : public testing::Test {
public:
    ~DisplayTransactionTest() override;

    // --------------------------------------------------------------------
    // Mock/Fake injection

    void injectMockScheduler();
    void injectMockComposer(int virtualDisplayCount);
    void injectFakeBufferQueueFactory();
    void injectFakeNativeWindowSurfaceFactory();
    sp<DisplayDevice> injectDefaultInternalDisplay(
            std::function<void(TestableSurfaceFlinger::FakeDisplayDeviceInjector&)>);

    // --------------------------------------------------------------------
    // Postcondition helpers

    bool hasPhysicalHwcDisplay(hal::HWDisplayId hwcDisplayId);
    bool hasTransactionFlagSet(int flag);
    bool hasDisplayDevice(sp<IBinder> displayToken);
    sp<DisplayDevice> getDisplayDevice(sp<IBinder> displayToken);
    bool hasCurrentDisplayState(sp<IBinder> displayToken);
    const DisplayDeviceState& getCurrentDisplayState(sp<IBinder> displayToken);
    bool hasDrawingDisplayState(sp<IBinder> displayToken);
    const DisplayDeviceState& getDrawingDisplayState(sp<IBinder> displayToken);

    // --------------------------------------------------------------------
    // Test instances

    TestableSurfaceFlinger mFlinger;
    sp<mock::NativeWindow> mNativeWindow = new mock::NativeWindow();
    sp<GraphicBuffer> mBuffer = new GraphicBuffer();
    Hwc2::mock::PowerAdvisor mPowerAdvisor;

    // These mocks are created by the test, but are destroyed by SurfaceFlinger
    // by virtue of being stored into a std::unique_ptr. However we still need
    // to keep a reference to them for use in setting up call expectations.
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();
    Hwc2::mock::Composer* mComposer = nullptr;
    mock::MessageQueue* mMessageQueue = new mock::MessageQueue();
    sp<mock::SurfaceInterceptor> mSurfaceInterceptor = new mock::SurfaceInterceptor;

    mock::VsyncController* mVsyncController = new mock::VsyncController;
    mock::VSyncTracker* mVSyncTracker = new mock::VSyncTracker;
    mock::SchedulerCallback mSchedulerCallback;
    mock::EventThread* mEventThread = new mock::EventThread;
    mock::EventThread* mSFEventThread = new mock::EventThread;

    // These mocks are created only when expected to be created via a factory.
    sp<mock::GraphicBufferConsumer> mConsumer;
    sp<mock::GraphicBufferProducer> mProducer;
    surfaceflinger::mock::NativeWindowSurface* mNativeWindowSurface = nullptr;

protected:
    DisplayTransactionTest();
};

constexpr int32_t DEFAULT_REFRESH_RATE = 16'666'667;
constexpr int32_t DEFAULT_DPI = 320;
constexpr int DEFAULT_VIRTUAL_DISPLAY_SURFACE_FORMAT = HAL_PIXEL_FORMAT_RGB_565;

constexpr int POWER_MODE_LEET = 1337; // An out of range power mode value

/* ------------------------------------------------------------------------
 * Boolean avoidance
 *
 * To make calls and template instantiations more readable, we define some
 * local enums along with an implicit bool conversion.
 */

#define BOOL_SUBSTITUTE(TYPENAME) enum class TYPENAME : bool { FALSE = false, TRUE = true };

BOOL_SUBSTITUTE(Async);
BOOL_SUBSTITUTE(Critical);
BOOL_SUBSTITUTE(Primary);
BOOL_SUBSTITUTE(Secure);
BOOL_SUBSTITUTE(Virtual);

template <typename PhysicalDisplay>
struct PhysicalDisplayIdType {};

template <uint64_t displayId>
using HalVirtualDisplayIdType = std::integral_constant<uint64_t, displayId>;

struct GpuVirtualDisplayIdType {};

template <typename>
struct IsPhysicalDisplayId : std::bool_constant<false> {};

template <typename PhysicalDisplay>
struct IsPhysicalDisplayId<PhysicalDisplayIdType<PhysicalDisplay>> : std::bool_constant<true> {};

template <typename>
struct DisplayIdGetter;

template <typename PhysicalDisplay>
struct DisplayIdGetter<PhysicalDisplayIdType<PhysicalDisplay>> {
    static PhysicalDisplayId get() {
        if (!PhysicalDisplay::HAS_IDENTIFICATION_DATA) {
            return PhysicalDisplayId::fromPort(static_cast<bool>(PhysicalDisplay::PRIMARY)
                                                       ? LEGACY_DISPLAY_TYPE_PRIMARY
                                                       : LEGACY_DISPLAY_TYPE_EXTERNAL);
        }

        const auto info =
                parseDisplayIdentificationData(PhysicalDisplay::PORT,
                                               PhysicalDisplay::GET_IDENTIFICATION_DATA());
        return info ? info->id : PhysicalDisplayId::fromPort(PhysicalDisplay::PORT);
    }
};

template <uint64_t displayId>
struct DisplayIdGetter<HalVirtualDisplayIdType<displayId>> {
    static HalVirtualDisplayId get() { return HalVirtualDisplayId(displayId); }
};

template <>
struct DisplayIdGetter<GpuVirtualDisplayIdType> {
    static GpuVirtualDisplayId get() { return GpuVirtualDisplayId(0); }
};

template <typename>
struct DisplayConnectionTypeGetter {
    static constexpr std::optional<DisplayConnectionType> value;
};

template <typename PhysicalDisplay>
struct DisplayConnectionTypeGetter<PhysicalDisplayIdType<PhysicalDisplay>> {
    static constexpr std::optional<DisplayConnectionType> value = PhysicalDisplay::CONNECTION_TYPE;
};

template <typename>
struct HwcDisplayIdGetter {
    static constexpr std::optional<HWDisplayId> value;
};

constexpr HWDisplayId HWC_VIRTUAL_DISPLAY_HWC_DISPLAY_ID = 1010;

template <uint64_t displayId>
struct HwcDisplayIdGetter<HalVirtualDisplayIdType<displayId>> {
    static constexpr std::optional<HWDisplayId> value = HWC_VIRTUAL_DISPLAY_HWC_DISPLAY_ID;
};

template <typename PhysicalDisplay>
struct HwcDisplayIdGetter<PhysicalDisplayIdType<PhysicalDisplay>> {
    static constexpr std::optional<HWDisplayId> value = PhysicalDisplay::HWC_DISPLAY_ID;
};

// DisplayIdType can be:
//     1) PhysicalDisplayIdType<...> for generated ID of physical display backed by HWC.
//     2) HalVirtualDisplayIdType<...> for hard-coded ID of virtual display backed by HWC.
//     3) GpuVirtualDisplayIdType for virtual display without HWC backing.
template <typename DisplayIdType, int width, int height, Critical critical, Async async,
          Secure secure, Primary primary, int grallocUsage>
struct DisplayVariant {
    using DISPLAY_ID = DisplayIdGetter<DisplayIdType>;
    using CONNECTION_TYPE = DisplayConnectionTypeGetter<DisplayIdType>;
    using HWC_DISPLAY_ID_OPT = HwcDisplayIdGetter<DisplayIdType>;

    // The display width and height
    static constexpr int WIDTH = width;
    static constexpr int HEIGHT = height;

    static constexpr int GRALLOC_USAGE = grallocUsage;

    // Whether the display is virtual or physical
    static constexpr Virtual VIRTUAL =
            IsPhysicalDisplayId<DisplayIdType>{} ? Virtual::FALSE : Virtual::TRUE;

    // When creating native window surfaces for the framebuffer, whether those should be critical
    static constexpr Critical CRITICAL = critical;

    // When creating native window surfaces for the framebuffer, whether those should be async
    static constexpr Async ASYNC = async;

    // Whether the display should be treated as secure
    static constexpr Secure SECURE = secure;

    // Whether the display is primary
    static constexpr Primary PRIMARY = primary;

    static auto makeFakeExistingDisplayInjector(DisplayTransactionTest* test) {
        auto ceDisplayArgs = compositionengine::DisplayCreationArgsBuilder();
        if (auto displayId = PhysicalDisplayId::tryCast(DISPLAY_ID::get())) {
            ceDisplayArgs.setPhysical({*displayId, DisplayConnectionType::Internal});
        } else {
            // We turn off the use of HwcVirtualDisplays, to prevent Composition Engine
            // from calling into HWComposer. This way all virtual displays will get
            // a GpuVirtualDisplayId, even if we are in the HwcVirtualDisplayVariant.
            // In this case we later override it by calling display.setDisplayIdForTesting().
            ceDisplayArgs.setUseHwcVirtualDisplays(false);

            GpuVirtualDisplayId desiredDisplayId = GpuVirtualDisplayId::tryCast(DISPLAY_ID::get())
                                                           .value_or(GpuVirtualDisplayId(0));

            ON_CALL(test->mFlinger.gpuVirtualDisplayIdGenerator(), nextId())
                    .WillByDefault(Return(desiredDisplayId));

            auto& generator = test->mFlinger.gpuVirtualDisplayIdGenerator();
            ceDisplayArgs.setGpuVirtualDisplayIdGenerator(generator);
        }
        ceDisplayArgs.setPixels({WIDTH, HEIGHT}).setPowerAdvisor(&test->mPowerAdvisor);

        auto compositionDisplay =
                compositionengine::impl::createDisplay(test->mFlinger.getCompositionEngine(),
                                                       ceDisplayArgs.build());

        if (HalVirtualDisplayId::tryCast(DISPLAY_ID::get())) {
            // CompositionEngine has assigned a placeholder GpuVirtualDisplayId and we need to
            // override it with the correct HalVirtualDisplayId.
            compositionDisplay->setDisplayIdForTesting(DISPLAY_ID::get());
        }

        auto injector =
                TestableSurfaceFlinger::FakeDisplayDeviceInjector(test->mFlinger,
                                                                  compositionDisplay,
                                                                  CONNECTION_TYPE::value,
                                                                  HWC_DISPLAY_ID_OPT::value,
                                                                  static_cast<bool>(PRIMARY));

        injector.setSecure(static_cast<bool>(SECURE));
        injector.setNativeWindow(test->mNativeWindow);

        // Creating a DisplayDevice requires getting default dimensions from the
        // native window along with some other initial setup.
        EXPECT_CALL(*test->mNativeWindow, query(NATIVE_WINDOW_WIDTH, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(WIDTH), Return(0)));
        EXPECT_CALL(*test->mNativeWindow, query(NATIVE_WINDOW_HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(HEIGHT), Return(0)));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_BUFFERS_FORMAT))
                .WillRepeatedly(Return(0));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_API_CONNECT))
                .WillRepeatedly(Return(0));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_USAGE64))
                .WillRepeatedly(Return(0));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_API_DISCONNECT))
                .WillRepeatedly(Return(0));

        return injector;
    }

    // Called by tests to set up any native window creation call expectations.
    static void setupNativeWindowSurfaceCreationCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mNativeWindowSurface, getNativeWindow())
                .WillOnce(Return(test->mNativeWindow));

        EXPECT_CALL(*test->mNativeWindow, query(NATIVE_WINDOW_WIDTH, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(WIDTH), Return(0)));
        EXPECT_CALL(*test->mNativeWindow, query(NATIVE_WINDOW_HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(HEIGHT), Return(0)));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_BUFFERS_FORMAT))
                .WillRepeatedly(Return(0));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_API_CONNECT))
                .WillRepeatedly(Return(0));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_USAGE64))
                .WillRepeatedly(Return(0));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_API_DISCONNECT))
                .WillRepeatedly(Return(0));
    }

    static void setupFramebufferConsumerBufferQueueCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mConsumer, consumerConnect(_, false)).WillOnce(Return(NO_ERROR));
        EXPECT_CALL(*test->mConsumer, setConsumerName(_)).WillRepeatedly(Return(NO_ERROR));
        EXPECT_CALL(*test->mConsumer, setConsumerUsageBits(GRALLOC_USAGE))
                .WillRepeatedly(Return(NO_ERROR));
        EXPECT_CALL(*test->mConsumer, setDefaultBufferSize(WIDTH, HEIGHT))
                .WillRepeatedly(Return(NO_ERROR));
        EXPECT_CALL(*test->mConsumer, setMaxAcquiredBufferCount(_))
                .WillRepeatedly(Return(NO_ERROR));
    }

    static void setupFramebufferProducerBufferQueueCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mProducer, allocateBuffers(0, 0, 0, 0)).WillRepeatedly(Return());
    }
};

template <HWDisplayId hwcDisplayId, DisplayType hwcDisplayType, typename DisplayVariant,
          typename PhysicalDisplay = void>
struct HwcDisplayVariant {
    // The display id supplied by the HWC
    static constexpr HWDisplayId HWC_DISPLAY_ID = hwcDisplayId;

    // The HWC display type
    static constexpr DisplayType HWC_DISPLAY_TYPE = hwcDisplayType;

    // The HWC active configuration id
    static constexpr int HWC_ACTIVE_CONFIG_ID = 2001;
    static constexpr PowerMode INIT_POWER_MODE = hal::PowerMode::ON;

    static void injectPendingHotplugEvent(DisplayTransactionTest* test, Connection connection) {
        test->mFlinger.mutablePendingHotplugEvents().emplace_back(
                TestableSurfaceFlinger::HotplugEvent{HWC_DISPLAY_ID, connection});
    }

    // Called by tests to inject a HWC display setup
    static void injectHwcDisplayWithNoDefaultCapabilities(DisplayTransactionTest* test) {
        const auto displayId = DisplayVariant::DISPLAY_ID::get();
        ASSERT_FALSE(GpuVirtualDisplayId::tryCast(displayId));
        TestableSurfaceFlinger::FakeHwcDisplayInjector(displayId, HWC_DISPLAY_TYPE,
                                                       static_cast<bool>(DisplayVariant::PRIMARY))
                .setHwcDisplayId(HWC_DISPLAY_ID)
                .setWidth(DisplayVariant::WIDTH)
                .setHeight(DisplayVariant::HEIGHT)
                .setActiveConfig(HWC_ACTIVE_CONFIG_ID)
                .setPowerMode(INIT_POWER_MODE)
                .inject(&test->mFlinger, test->mComposer);
    }

    // Called by tests to inject a HWC display setup
    static void injectHwcDisplay(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getDisplayCapabilities(HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<DisplayCapability>({})),
                                Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer, setPowerMode(HWC_DISPLAY_ID, INIT_POWER_MODE))
                .WillOnce(Return(Error::NONE));
        injectHwcDisplayWithNoDefaultCapabilities(test);
    }

    static std::shared_ptr<compositionengine::Display> injectCompositionDisplay(
            DisplayTransactionTest* test) {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();

        auto ceDisplayArgs = compositionengine::DisplayCreationArgsBuilder()
                                     .setPhysical({DisplayVariant::DISPLAY_ID::get(),
                                                   PhysicalDisplay::CONNECTION_TYPE})
                                     .setPixels({DisplayVariant::WIDTH, DisplayVariant::HEIGHT})
                                     .setIsSecure(static_cast<bool>(DisplayVariant::SECURE))
                                     .setPowerAdvisor(&test->mPowerAdvisor)
                                     .setName(std::string("Injected display for ") +
                                              test_info->test_case_name() + "." + test_info->name())
                                     .build();

        return compositionengine::impl::createDisplay(test->mFlinger.getCompositionEngine(),
                                                      ceDisplayArgs);
    }

    static void setupHwcHotplugCallExpectations(DisplayTransactionTest* test) {
        constexpr auto CONNECTION_TYPE =
                PhysicalDisplay::CONNECTION_TYPE == DisplayConnectionType::Internal
                ? IComposerClient::DisplayConnectionType::INTERNAL
                : IComposerClient::DisplayConnectionType::EXTERNAL;

        EXPECT_CALL(*test->mComposer, getDisplayConnectionType(HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(CONNECTION_TYPE), Return(hal::V2_4::Error::NONE)));

        EXPECT_CALL(*test->mComposer, setClientTargetSlotCount(_))
                .WillOnce(Return(hal::Error::NONE));
        EXPECT_CALL(*test->mComposer, getDisplayConfigs(HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<unsigned>{HWC_ACTIVE_CONFIG_ID}),
                                Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getDisplayAttribute(HWC_DISPLAY_ID, HWC_ACTIVE_CONFIG_ID,
                                        IComposerClient::Attribute::WIDTH, _))
                .WillOnce(DoAll(SetArgPointee<3>(DisplayVariant::WIDTH), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getDisplayAttribute(HWC_DISPLAY_ID, HWC_ACTIVE_CONFIG_ID,
                                        IComposerClient::Attribute::HEIGHT, _))
                .WillOnce(DoAll(SetArgPointee<3>(DisplayVariant::HEIGHT), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getDisplayAttribute(HWC_DISPLAY_ID, HWC_ACTIVE_CONFIG_ID,
                                        IComposerClient::Attribute::VSYNC_PERIOD, _))
                .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_REFRESH_RATE), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getDisplayAttribute(HWC_DISPLAY_ID, HWC_ACTIVE_CONFIG_ID,
                                        IComposerClient::Attribute::DPI_X, _))
                .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_DPI), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getDisplayAttribute(HWC_DISPLAY_ID, HWC_ACTIVE_CONFIG_ID,
                                        IComposerClient::Attribute::DPI_Y, _))
                .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_DPI), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getDisplayAttribute(HWC_DISPLAY_ID, HWC_ACTIVE_CONFIG_ID,
                                        IComposerClient::Attribute::CONFIG_GROUP, _))
                .WillOnce(DoAll(SetArgPointee<3>(-1), Return(Error::NONE)));

        if (PhysicalDisplay::HAS_IDENTIFICATION_DATA) {
            EXPECT_CALL(*test->mComposer, getDisplayIdentificationData(HWC_DISPLAY_ID, _, _))
                    .WillOnce(DoAll(SetArgPointee<1>(PhysicalDisplay::PORT),
                                    SetArgPointee<2>(PhysicalDisplay::GET_IDENTIFICATION_DATA()),
                                    Return(Error::NONE)));
        } else {
            EXPECT_CALL(*test->mComposer, getDisplayIdentificationData(HWC_DISPLAY_ID, _, _))
                    .WillOnce(Return(Error::UNSUPPORTED));
        }
    }

    // Called by tests to set up HWC call expectations
    static void setupHwcGetActiveConfigCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getActiveConfig(HWC_DISPLAY_ID, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(HWC_ACTIVE_CONFIG_ID), Return(Error::NONE)));
    }
};

// Physical displays are expected to be synchronous, secure, and have a HWC display for output.
constexpr uint32_t GRALLOC_USAGE_PHYSICAL_DISPLAY =
        GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_FB;

template <typename PhysicalDisplay, int width, int height, Critical critical>
struct PhysicalDisplayVariant
      : DisplayVariant<PhysicalDisplayIdType<PhysicalDisplay>, width, height, critical,
                       Async::FALSE, Secure::TRUE, PhysicalDisplay::PRIMARY,
                       GRALLOC_USAGE_PHYSICAL_DISPLAY>,
        HwcDisplayVariant<PhysicalDisplay::HWC_DISPLAY_ID, DisplayType::PHYSICAL,
                          DisplayVariant<PhysicalDisplayIdType<PhysicalDisplay>, width, height,
                                         critical, Async::FALSE, Secure::TRUE,
                                         PhysicalDisplay::PRIMARY, GRALLOC_USAGE_PHYSICAL_DISPLAY>,
                          PhysicalDisplay> {};

template <bool hasIdentificationData>
struct PrimaryDisplay {
    static constexpr auto CONNECTION_TYPE = DisplayConnectionType::Internal;
    static constexpr Primary PRIMARY = Primary::TRUE;
    static constexpr uint8_t PORT = 255;
    static constexpr HWDisplayId HWC_DISPLAY_ID = 1001;
    static constexpr bool HAS_IDENTIFICATION_DATA = hasIdentificationData;
    static constexpr auto GET_IDENTIFICATION_DATA = getInternalEdid;
};

template <bool hasIdentificationData>
struct ExternalDisplay {
    static constexpr auto CONNECTION_TYPE = DisplayConnectionType::External;
    static constexpr Primary PRIMARY = Primary::FALSE;
    static constexpr uint8_t PORT = 254;
    static constexpr HWDisplayId HWC_DISPLAY_ID = 1002;
    static constexpr bool HAS_IDENTIFICATION_DATA = hasIdentificationData;
    static constexpr auto GET_IDENTIFICATION_DATA = getExternalEdid;
};

struct TertiaryDisplay {
    static constexpr Primary PRIMARY = Primary::FALSE;
    static constexpr uint8_t PORT = 253;
    static constexpr HWDisplayId HWC_DISPLAY_ID = 1003;
    static constexpr auto GET_IDENTIFICATION_DATA = getExternalEdid;
};

// A primary display is a physical display that is critical
using PrimaryDisplayVariant =
        PhysicalDisplayVariant<PrimaryDisplay<false>, 3840, 2160, Critical::TRUE>;

// An external display is physical display that is not critical.
using ExternalDisplayVariant =
        PhysicalDisplayVariant<ExternalDisplay<false>, 1920, 1280, Critical::FALSE>;

using TertiaryDisplayVariant = PhysicalDisplayVariant<TertiaryDisplay, 1600, 1200, Critical::FALSE>;

// A virtual display not supported by the HWC.
constexpr uint32_t GRALLOC_USAGE_NONHWC_VIRTUAL_DISPLAY = 0;

template <int width, int height, Secure secure>
struct NonHwcVirtualDisplayVariant
      : DisplayVariant<GpuVirtualDisplayIdType, width, height, Critical::FALSE, Async::TRUE, secure,
                       Primary::FALSE, GRALLOC_USAGE_NONHWC_VIRTUAL_DISPLAY> {
    using Base =
            DisplayVariant<GpuVirtualDisplayIdType, width, height, Critical::FALSE, Async::TRUE,
                           secure, Primary::FALSE, GRALLOC_USAGE_NONHWC_VIRTUAL_DISPLAY>;

    static void injectHwcDisplay(DisplayTransactionTest*) {}

    static std::shared_ptr<compositionengine::Display> injectCompositionDisplay(
            DisplayTransactionTest* test) {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();

        ON_CALL(test->mFlinger.gpuVirtualDisplayIdGenerator(), nextId())
                .WillByDefault(Return(Base::DISPLAY_ID::get()));

        auto ceDisplayArgs = compositionengine::DisplayCreationArgsBuilder()
                                     .setPixels({Base::WIDTH, Base::HEIGHT})
                                     .setIsSecure(static_cast<bool>(Base::SECURE))
                                     .setPowerAdvisor(&test->mPowerAdvisor)
                                     .setName(std::string("Injected display for ") +
                                              test_info->test_case_name() + "." + test_info->name())
                                     .setGpuVirtualDisplayIdGenerator(
                                             test->mFlinger.gpuVirtualDisplayIdGenerator())
                                     .build();

        return compositionengine::impl::createDisplay(test->mFlinger.getCompositionEngine(),
                                                      ceDisplayArgs);
    }

    static void setupHwcGetActiveConfigCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getActiveConfig(_, _)).Times(0);
    }

    static void setupNativeWindowSurfaceCreationCallExpectations(DisplayTransactionTest* test) {
        Base::setupNativeWindowSurfaceCreationCallExpectations(test);
        EXPECT_CALL(*test->mNativeWindow, setSwapInterval(0)).Times(1);
    }
};

// A virtual display supported by the HWC.
constexpr uint32_t GRALLOC_USAGE_HWC_VIRTUAL_DISPLAY = GRALLOC_USAGE_HW_COMPOSER;

template <int width, int height, Secure secure>
struct HwcVirtualDisplayVariant
      : DisplayVariant<HalVirtualDisplayIdType<42>, width, height, Critical::FALSE, Async::TRUE,
                       secure, Primary::FALSE, GRALLOC_USAGE_HWC_VIRTUAL_DISPLAY>,
        HwcDisplayVariant<HWC_VIRTUAL_DISPLAY_HWC_DISPLAY_ID, DisplayType::VIRTUAL,
                          DisplayVariant<HalVirtualDisplayIdType<42>, width, height,
                                         Critical::FALSE, Async::TRUE, secure, Primary::FALSE,
                                         GRALLOC_USAGE_HWC_VIRTUAL_DISPLAY>> {
    using Base = DisplayVariant<HalVirtualDisplayIdType<42>, width, height, Critical::FALSE,
                                Async::TRUE, secure, Primary::FALSE, GRALLOC_USAGE_HW_COMPOSER>;
    using Self = HwcVirtualDisplayVariant<width, height, secure>;

    static std::shared_ptr<compositionengine::Display> injectCompositionDisplay(
            DisplayTransactionTest* test) {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();

        // In order to prevent compostition engine calling into HWComposer, we
        // 1. turn off the use of HWC virtual displays,
        // 2. provide a GpuVirtualDisplayIdGenerator which always returns some fake ID
        // 3. override the ID by calling setDisplayIdForTesting()

        ON_CALL(test->mFlinger.gpuVirtualDisplayIdGenerator(), nextId())
                .WillByDefault(Return(GpuVirtualDisplayId(0)));

        auto ceDisplayArgs = compositionengine::DisplayCreationArgsBuilder()
                                     .setUseHwcVirtualDisplays(false)
                                     .setPixels({Base::WIDTH, Base::HEIGHT})
                                     .setIsSecure(static_cast<bool>(Base::SECURE))
                                     .setPowerAdvisor(&test->mPowerAdvisor)
                                     .setName(std::string("Injected display for ") +
                                              test_info->test_case_name() + "." + test_info->name())
                                     .setGpuVirtualDisplayIdGenerator(
                                             test->mFlinger.gpuVirtualDisplayIdGenerator())
                                     .build();

        auto compositionDisplay =
                compositionengine::impl::createDisplay(test->mFlinger.getCompositionEngine(),
                                                       ceDisplayArgs);
        compositionDisplay->setDisplayIdForTesting(Base::DISPLAY_ID::get());

        // Insert display data so that the HWC thinks it created the virtual display.
        if (const auto displayId = Base::DISPLAY_ID::get();
            HalVirtualDisplayId::tryCast(displayId)) {
            test->mFlinger.mutableHwcDisplayData().try_emplace(displayId);
        }

        return compositionDisplay;
    }

    static void setupNativeWindowSurfaceCreationCallExpectations(DisplayTransactionTest* test) {
        Base::setupNativeWindowSurfaceCreationCallExpectations(test);
        EXPECT_CALL(*test->mNativeWindow, setSwapInterval(0)).Times(1);
    }

    static void setupHwcVirtualDisplayCreationCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, createVirtualDisplay(Base::WIDTH, Base::HEIGHT, _, _))
                .WillOnce(DoAll(SetArgPointee<3>(Self::HWC_DISPLAY_ID), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer, setClientTargetSlotCount(_)).WillOnce(Return(Error::NONE));
    }
};

// For this variant, the display is not a HWC display, so no HDR support should
// be configured.
struct NonHwcDisplayHdrSupportVariant {
    static constexpr bool HDR10_PLUS_SUPPORTED = false;
    static constexpr bool HDR10_SUPPORTED = false;
    static constexpr bool HDR_HLG_SUPPORTED = false;
    static constexpr bool HDR_DOLBY_VISION_SUPPORTED = false;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getHdrCapabilities(_, _, _, _, _)).Times(0);
    }
};

// For this variant, the composer should respond with am empty list of HDR
// modes, so no HDR support should be configured.
template <typename Display>
struct HdrNotSupportedVariant {
    static constexpr bool HDR10_PLUS_SUPPORTED = false;
    static constexpr bool HDR10_SUPPORTED = false;
    static constexpr bool HDR_HLG_SUPPORTED = false;
    static constexpr bool HDR_DOLBY_VISION_SUPPORTED = false;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getHdrCapabilities(Display::HWC_DISPLAY_ID, _, _, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hdr>()), Return(Error::NONE)));
    }
};

struct NonHwcPerFrameMetadataSupportVariant {
    static constexpr int PER_FRAME_METADATA_KEYS = 0;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getPerFrameMetadataKeys(_)).Times(0);
    }
};

template <typename Display>
struct NoPerFrameMetadataSupportVariant {
    static constexpr int PER_FRAME_METADATA_KEYS = 0;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getPerFrameMetadataKeys(Display::HWC_DISPLAY_ID))
                .WillOnce(Return(std::vector<PerFrameMetadataKey>()));
    }
};

// For this variant, SurfaceFlinger should configure itself with wide display
// support, but the display should respond with an empty list of supported color
// modes. Wide-color support for the display should not be configured.
template <typename Display>
struct WideColorNotSupportedVariant {
    static constexpr bool WIDE_COLOR_SUPPORTED = false;

    static void injectConfigChange(DisplayTransactionTest* test) {
        test->mFlinger.mutableUseColorManagement() = true;
        test->mFlinger.mutableHasWideColorDisplay() = true;
    }

    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getColorModes(Display::HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<ColorMode>()), Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer, setColorMode(_, _, _)).Times(0);
    }
};

// For this variant, SurfaceFlinger should not configure itself with wide
// display support, so the display should not be configured for wide-color
// support.
struct WideColorSupportNotConfiguredVariant {
    static constexpr bool WIDE_COLOR_SUPPORTED = false;

    static void injectConfigChange(DisplayTransactionTest* test) {
        test->mFlinger.mutableHasWideColorDisplay() = false;
        test->mFlinger.mutableUseColorManagement() = false;
        test->mFlinger.mutableDisplayColorSetting() = DisplayColorSetting::kUnmanaged;
    }

    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getColorModes(_, _)).Times(0);
        EXPECT_CALL(*test->mComposer, getRenderIntents(_, _, _)).Times(0);
        EXPECT_CALL(*test->mComposer, setColorMode(_, _, _)).Times(0);
    }
};

/* ------------------------------------------------------------------------
 * Typical display configurations to test
 */

template <typename DisplayPolicy, typename WideColorSupportPolicy, typename HdrSupportPolicy,
          typename PerFrameMetadataSupportPolicy>
struct Case {
    using Display = DisplayPolicy;
    using WideColorSupport = WideColorSupportPolicy;
    using HdrSupport = HdrSupportPolicy;
    using PerFrameMetadataSupport = PerFrameMetadataSupportPolicy;
};

using SimplePrimaryDisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             HdrNotSupportedVariant<PrimaryDisplayVariant>,
             NoPerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using SimpleExternalDisplayCase =
        Case<ExternalDisplayVariant, WideColorNotSupportedVariant<ExternalDisplayVariant>,
             HdrNotSupportedVariant<ExternalDisplayVariant>,
             NoPerFrameMetadataSupportVariant<ExternalDisplayVariant>>;
using SimpleTertiaryDisplayCase =
        Case<TertiaryDisplayVariant, WideColorNotSupportedVariant<TertiaryDisplayVariant>,
             HdrNotSupportedVariant<TertiaryDisplayVariant>,
             NoPerFrameMetadataSupportVariant<TertiaryDisplayVariant>>;

using NonHwcVirtualDisplayCase =
        Case<NonHwcVirtualDisplayVariant<1024, 768, Secure::FALSE>,
             WideColorSupportNotConfiguredVariant, NonHwcDisplayHdrSupportVariant,
             NonHwcPerFrameMetadataSupportVariant>;
using SimpleHwcVirtualDisplayVariant = HwcVirtualDisplayVariant<1024, 768, Secure::TRUE>;
using HwcVirtualDisplayCase =
        Case<SimpleHwcVirtualDisplayVariant, WideColorSupportNotConfiguredVariant,
             HdrNotSupportedVariant<SimpleHwcVirtualDisplayVariant>,
             NoPerFrameMetadataSupportVariant<SimpleHwcVirtualDisplayVariant>>;

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
