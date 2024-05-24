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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <optional>
#include <vector>

// StrictMock<T> derives from T and is not marked final, so the destructor of T is expected to be
// virtual in case StrictMock<T> is used as a polymorphic base class. That is not the case here.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#include <gmock/gmock.h>
#pragma clang diagnostic pop

#include <common/FlagManager.h>
#include <gui/LayerMetadata.h>
#include <log/log.h>
#include <chrono>

#include <common/test/FlagUtils.h>
#include "DisplayHardware/DisplayMode.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/Hal.h"
#include "DisplayIdentificationTestHelpers.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockHWC2.h"

#include <com_android_graphics_surfaceflinger_flags.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

namespace android {

namespace V2_1 = hardware::graphics::composer::V2_1;
namespace V2_4 = hardware::graphics::composer::V2_4;
namespace aidl = aidl::android::hardware::graphics::composer3;
using namespace std::chrono_literals;

using Hwc2::Config;

using ::aidl::android::hardware::graphics::common::DisplayHotplugEvent;
using ::aidl::android::hardware::graphics::composer3::RefreshRateChangedDebugData;
using hal::IComposerClient;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

struct HWComposerTest : testing::Test {
    using HalError = hardware::graphics::composer::V2_1::Error;

    Hwc2::mock::Composer* const mHal = new StrictMock<Hwc2::mock::Composer>();
    impl::HWComposer mHwc{std::unique_ptr<Hwc2::Composer>(mHal)};

    void expectHotplugConnect(hal::HWDisplayId hwcDisplayId) {
        constexpr uint8_t kPort = 255;
        EXPECT_CALL(*mHal, getDisplayIdentificationData(hwcDisplayId, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(kPort),
                                SetArgPointee<2>(getExternalEdid()), Return(HalError::NONE)));

        EXPECT_CALL(*mHal, setClientTargetSlotCount(_));
        EXPECT_CALL(*mHal, setVsyncEnabled(hwcDisplayId, Hwc2::IComposerClient::Vsync::DISABLE));
        EXPECT_CALL(*mHal, onHotplugConnect(hwcDisplayId));
    }

    void setVrrTimeoutHint(bool status) { mHwc.mEnableVrrTimeout = status; }
};

TEST_F(HWComposerTest, isHeadless) {
    ASSERT_TRUE(mHwc.isHeadless());

    constexpr hal::HWDisplayId kHwcDisplayId = 1;
    expectHotplugConnect(kHwcDisplayId);

    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    ASSERT_FALSE(mHwc.isHeadless());

    mHwc.disconnectDisplay(info->id);
    ASSERT_TRUE(mHwc.isHeadless());
}

TEST_F(HWComposerTest, getDisplayConnectionType) {
    // Unknown display.
    EXPECT_EQ(mHwc.getDisplayConnectionType(PhysicalDisplayId::fromPort(0)),
              ui::DisplayConnectionType::Internal);

    constexpr hal::HWDisplayId kHwcDisplayId = 1;
    expectHotplugConnect(kHwcDisplayId);

    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    EXPECT_CALL(*mHal, getDisplayConnectionType(kHwcDisplayId, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayConnectionType::EXTERNAL),
                            Return(V2_4::Error::NONE)));

    // The first call caches the connection type.
    EXPECT_EQ(mHwc.getDisplayConnectionType(info->id), ui::DisplayConnectionType::External);

    // Subsequent calls return the cached connection type.
    EXPECT_EQ(mHwc.getDisplayConnectionType(info->id), ui::DisplayConnectionType::External);
    EXPECT_EQ(mHwc.getDisplayConnectionType(info->id), ui::DisplayConnectionType::External);
}

TEST_F(HWComposerTest, getActiveMode) {
    // Unknown display.
    EXPECT_EQ(mHwc.getActiveMode(PhysicalDisplayId::fromPort(0)), ftl::Unexpected(BAD_INDEX));

    constexpr hal::HWDisplayId kHwcDisplayId = 2;
    expectHotplugConnect(kHwcDisplayId);

    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    {
        // Display is known to SF but not HWC, e.g. the hotplug disconnect is pending.
        EXPECT_CALL(*mHal, getActiveConfig(kHwcDisplayId, _))
                .WillOnce(Return(HalError::BAD_DISPLAY));

        EXPECT_EQ(mHwc.getActiveMode(info->id), ftl::Unexpected(UNKNOWN_ERROR));
    }
    {
        EXPECT_CALL(*mHal, getActiveConfig(kHwcDisplayId, _))
                .WillOnce(Return(HalError::BAD_CONFIG));

        EXPECT_EQ(mHwc.getActiveMode(info->id), ftl::Unexpected(NO_INIT));
    }
    {
        constexpr hal::HWConfigId kConfigId = 42;
        EXPECT_CALL(*mHal, getActiveConfig(kHwcDisplayId, _))
                .WillOnce(DoAll(SetArgPointee<1>(kConfigId), Return(HalError::NONE)));

        EXPECT_EQ(mHwc.getActiveMode(info->id).value_opt(), kConfigId);
    }
}

TEST_F(HWComposerTest, getModesWithLegacyDisplayConfigs) {
    constexpr hal::HWDisplayId kHwcDisplayId = 2;
    constexpr hal::HWConfigId kConfigId = 42;
    constexpr int32_t kMaxFrameIntervalNs = 50000000; // 20Fps

    expectHotplugConnect(kHwcDisplayId);
    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    EXPECT_CALL(*mHal, isVrrSupported()).WillRepeatedly(Return(false));

    {
        EXPECT_CALL(*mHal, getDisplayConfigs(kHwcDisplayId, _))
                .WillOnce(Return(HalError::BAD_DISPLAY));
        EXPECT_TRUE(mHwc.getModes(info->id, kMaxFrameIntervalNs).empty());
    }
    {
        constexpr int32_t kWidth = 480;
        constexpr int32_t kHeight = 720;
        constexpr int32_t kConfigGroup = 1;
        constexpr int32_t kVsyncPeriod = 16666667;

        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::WIDTH,
                                        _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kWidth), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId,
                                        IComposerClient::Attribute::HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kHeight), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId,
                                        IComposerClient::Attribute::CONFIG_GROUP, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kConfigGroup), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId,
                                        IComposerClient::Attribute::VSYNC_PERIOD, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kVsyncPeriod), Return(HalError::NONE)));

        // Optional Parameters UNSUPPORTED
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_X,
                                        _))
                .WillOnce(Return(HalError::UNSUPPORTED));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_Y,
                                        _))
                .WillOnce(Return(HalError::UNSUPPORTED));

        EXPECT_CALL(*mHal, getDisplayConfigs(kHwcDisplayId, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(std::vector<hal::HWConfigId>{kConfigId}),
                                      Return(HalError::NONE)));

        auto modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.size(), size_t{1});
        EXPECT_EQ(modes.front().hwcId, kConfigId);
        EXPECT_EQ(modes.front().width, kWidth);
        EXPECT_EQ(modes.front().height, kHeight);
        EXPECT_EQ(modes.front().configGroup, kConfigGroup);
        EXPECT_EQ(modes.front().vsyncPeriod, kVsyncPeriod);
        EXPECT_EQ(modes.front().dpiX, -1);
        EXPECT_EQ(modes.front().dpiY, -1);

        // Optional parameters are supported
        constexpr int32_t kDpi = 320;
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_X,
                                        _))
                .WillOnce(DoAll(SetArgPointee<3>(kDpi), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_Y,
                                        _))
                .WillOnce(DoAll(SetArgPointee<3>(kDpi), Return(HalError::NONE)));

        modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.size(), size_t{1});
        EXPECT_EQ(modes.front().hwcId, kConfigId);
        EXPECT_EQ(modes.front().width, kWidth);
        EXPECT_EQ(modes.front().height, kHeight);
        EXPECT_EQ(modes.front().configGroup, kConfigGroup);
        EXPECT_EQ(modes.front().vsyncPeriod, kVsyncPeriod);
        // DPI values are scaled by 1000 in the legacy implementation.
        EXPECT_EQ(modes.front().dpiX, kDpi / 1000.f);
        EXPECT_EQ(modes.front().dpiY, kDpi / 1000.f);
    }
}

TEST_F(HWComposerTest, getModesWithDisplayConfigurations_VRR_OFF) {
    // if vrr_config is off, getDisplayConfigurationsSupported() is off as well
    // then getModesWithLegacyDisplayConfigs should be called instead
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::vrr_config, false);
    ASSERT_FALSE(FlagManager::getInstance().vrr_config());

    constexpr hal::HWDisplayId kHwcDisplayId = 2;
    constexpr hal::HWConfigId kConfigId = 42;
    constexpr int32_t kMaxFrameIntervalNs = 50000000; // 20Fps

    expectHotplugConnect(kHwcDisplayId);
    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    EXPECT_CALL(*mHal, isVrrSupported()).WillRepeatedly(Return(false));

    {
        EXPECT_CALL(*mHal, getDisplayConfigs(kHwcDisplayId, _))
                .WillOnce(Return(HalError::BAD_DISPLAY));
        EXPECT_TRUE(mHwc.getModes(info->id, kMaxFrameIntervalNs).empty());
    }
    {
        constexpr int32_t kWidth = 480;
        constexpr int32_t kHeight = 720;
        constexpr int32_t kConfigGroup = 1;
        constexpr int32_t kVsyncPeriod = 16666667;

        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::WIDTH,
                                        _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kWidth), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId,
                                        IComposerClient::Attribute::HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kHeight), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId,
                                        IComposerClient::Attribute::CONFIG_GROUP, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kConfigGroup), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId,
                                        IComposerClient::Attribute::VSYNC_PERIOD, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(kVsyncPeriod), Return(HalError::NONE)));

        // Optional Parameters UNSUPPORTED
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_X,
                                        _))
                .WillOnce(Return(HalError::UNSUPPORTED));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_Y,
                                        _))
                .WillOnce(Return(HalError::UNSUPPORTED));

        EXPECT_CALL(*mHal, getDisplayConfigs(kHwcDisplayId, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(std::vector<hal::HWConfigId>{kConfigId}),
                                      Return(HalError::NONE)));

        auto modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.size(), size_t{1});
        EXPECT_EQ(modes.front().hwcId, kConfigId);
        EXPECT_EQ(modes.front().width, kWidth);
        EXPECT_EQ(modes.front().height, kHeight);
        EXPECT_EQ(modes.front().configGroup, kConfigGroup);
        EXPECT_EQ(modes.front().vsyncPeriod, kVsyncPeriod);
        EXPECT_EQ(modes.front().dpiX, -1);
        EXPECT_EQ(modes.front().dpiY, -1);

        // Optional parameters are supported
        constexpr int32_t kDpi = 320;
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_X,
                                        _))
                .WillOnce(DoAll(SetArgPointee<3>(kDpi), Return(HalError::NONE)));
        EXPECT_CALL(*mHal,
                    getDisplayAttribute(kHwcDisplayId, kConfigId, IComposerClient::Attribute::DPI_Y,
                                        _))
                .WillOnce(DoAll(SetArgPointee<3>(kDpi), Return(HalError::NONE)));

        modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.size(), size_t{1});
        EXPECT_EQ(modes.front().hwcId, kConfigId);
        EXPECT_EQ(modes.front().width, kWidth);
        EXPECT_EQ(modes.front().height, kHeight);
        EXPECT_EQ(modes.front().configGroup, kConfigGroup);
        EXPECT_EQ(modes.front().vsyncPeriod, kVsyncPeriod);
        // DPI values are scaled by 1000 in the legacy implementation.
        EXPECT_EQ(modes.front().dpiX, kDpi / 1000.f);
        EXPECT_EQ(modes.front().dpiY, kDpi / 1000.f);
    }
}

TEST_F(HWComposerTest, getModesWithDisplayConfigurations_VRR_ON) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::vrr_config, true);
    ASSERT_TRUE(FlagManager::getInstance().vrr_config());

    constexpr hal::HWDisplayId kHwcDisplayId = 2;
    constexpr hal::HWConfigId kConfigId = 42;
    constexpr int32_t kMaxFrameIntervalNs = 50000000; // 20Fps
    expectHotplugConnect(kHwcDisplayId);
    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    EXPECT_CALL(*mHal, isVrrSupported()).WillRepeatedly(Return(true));

    {
        EXPECT_CALL(*mHal, getDisplayConfigurations(kHwcDisplayId, _, _))
                .WillOnce(Return(HalError::BAD_DISPLAY));
        EXPECT_TRUE(mHwc.getModes(info->id, kMaxFrameIntervalNs).empty());
    }
    {
        setVrrTimeoutHint(true);
        constexpr int32_t kWidth = 480;
        constexpr int32_t kHeight = 720;
        constexpr int32_t kConfigGroup = 1;
        constexpr int32_t kVsyncPeriod = 16666667;
        const hal::VrrConfig vrrConfig =
                hal::VrrConfig{.minFrameIntervalNs = static_cast<Fps>(120_Hz).getPeriodNsecs(),
                               .notifyExpectedPresentConfig = hal::VrrConfig::
                                       NotifyExpectedPresentConfig{.headsUpNs = ms2ns(30),
                                                                   .timeoutNs = ms2ns(30)}};
        hal::DisplayConfiguration displayConfiguration{.configId = kConfigId,
                                                       .width = kWidth,
                                                       .height = kHeight,
                                                       .configGroup = kConfigGroup,
                                                       .vsyncPeriod = kVsyncPeriod,
                                                       .vrrConfig = vrrConfig};

        EXPECT_CALL(*mHal, getDisplayConfigurations(kHwcDisplayId, _, _))
                .WillOnce(DoAll(SetArgPointee<2>(std::vector<hal::DisplayConfiguration>{
                                        displayConfiguration}),
                                Return(HalError::NONE)));

        // Optional dpi not supported
        auto modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.size(), size_t{1});
        EXPECT_EQ(modes.front().hwcId, kConfigId);
        EXPECT_EQ(modes.front().width, kWidth);
        EXPECT_EQ(modes.front().height, kHeight);
        EXPECT_EQ(modes.front().configGroup, kConfigGroup);
        EXPECT_EQ(modes.front().vsyncPeriod, kVsyncPeriod);
        EXPECT_EQ(modes.front().vrrConfig, vrrConfig);
        EXPECT_EQ(modes.front().dpiX, -1);
        EXPECT_EQ(modes.front().dpiY, -1);

        // Supports optional dpi parameter
        constexpr int32_t kDpi = 320;
        displayConfiguration.dpi = {kDpi, kDpi};

        EXPECT_CALL(*mHal, getDisplayConfigurations(kHwcDisplayId, _, _))
                .WillRepeatedly(DoAll(SetArgPointee<2>(std::vector<hal::DisplayConfiguration>{
                                              displayConfiguration}),
                                      Return(HalError::NONE)));

        modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.size(), size_t{1});
        EXPECT_EQ(modes.front().hwcId, kConfigId);
        EXPECT_EQ(modes.front().width, kWidth);
        EXPECT_EQ(modes.front().height, kHeight);
        EXPECT_EQ(modes.front().configGroup, kConfigGroup);
        EXPECT_EQ(modes.front().vsyncPeriod, kVsyncPeriod);
        EXPECT_EQ(modes.front().vrrConfig, vrrConfig);
        EXPECT_EQ(modes.front().dpiX, kDpi);
        EXPECT_EQ(modes.front().dpiY, kDpi);

        setVrrTimeoutHint(false);
        modes = mHwc.getModes(info->id, kMaxFrameIntervalNs);
        EXPECT_EQ(modes.front().vrrConfig->notifyExpectedPresentConfig, std::nullopt);
    }
}

TEST_F(HWComposerTest, onVsync) {
    constexpr hal::HWDisplayId kHwcDisplayId = 1;
    expectHotplugConnect(kHwcDisplayId);

    const auto info = mHwc.onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
    ASSERT_TRUE(info);

    const auto physicalDisplayId = info->id;

    // Deliberately chosen not to match DisplayData.lastPresentTimestamp's
    // initial value.
    constexpr nsecs_t kTimestamp = 1;
    auto displayIdOpt = mHwc.onVsync(kHwcDisplayId, kTimestamp);
    ASSERT_TRUE(displayIdOpt);
    EXPECT_EQ(physicalDisplayId, displayIdOpt);

    // Attempt to send the same time stamp again.
    displayIdOpt = mHwc.onVsync(kHwcDisplayId, kTimestamp);
    EXPECT_FALSE(displayIdOpt);
}

TEST_F(HWComposerTest, onVsyncInvalid) {
    constexpr hal::HWDisplayId kInvalidHwcDisplayId = 2;
    constexpr nsecs_t kTimestamp = 1;
    const auto displayIdOpt = mHwc.onVsync(kInvalidHwcDisplayId, kTimestamp);
    EXPECT_FALSE(displayIdOpt);
}

struct MockHWC2ComposerCallback final : StrictMock<HWC2::ComposerCallback> {
    MOCK_METHOD(void, onComposerHalHotplugEvent, (hal::HWDisplayId, DisplayHotplugEvent),
                (override));
    MOCK_METHOD1(onComposerHalRefresh, void(hal::HWDisplayId));
    MOCK_METHOD3(onComposerHalVsync,
                 void(hal::HWDisplayId, int64_t timestamp, std::optional<hal::VsyncPeriodNanos>));
    MOCK_METHOD2(onComposerHalVsyncPeriodTimingChanged,
                 void(hal::HWDisplayId, const hal::VsyncPeriodChangeTimeline&));
    MOCK_METHOD1(onComposerHalSeamlessPossible, void(hal::HWDisplayId));
    MOCK_METHOD1(onComposerHalVsyncIdle, void(hal::HWDisplayId));
    MOCK_METHOD(void, onRefreshRateChangedDebug, (const RefreshRateChangedDebugData&), (override));
};

struct HWComposerSetCallbackTest : HWComposerTest {
    MockHWC2ComposerCallback mCallback;
};

TEST_F(HWComposerSetCallbackTest, loadsLayerMetadataSupport) {
    const std::string kMetadata1Name = "com.example.metadata.1";
    constexpr bool kMetadata1Mandatory = false;
    const std::string kMetadata2Name = "com.example.metadata.2";
    constexpr bool kMetadata2Mandatory = true;

    EXPECT_CALL(*mHal, getCapabilities()).WillOnce(Return(std::vector<aidl::Capability>{}));
    EXPECT_CALL(*mHal, getLayerGenericMetadataKeys(_))
            .WillOnce(DoAll(SetArgPointee<0>(std::vector<hal::LayerGenericMetadataKey>{
                                    {kMetadata1Name, kMetadata1Mandatory},
                                    {kMetadata2Name, kMetadata2Mandatory},
                            }),
                            Return(V2_4::Error::NONE)));
    EXPECT_CALL(*mHal, getOverlaySupport(_)).WillOnce(Return(HalError::NONE));
    EXPECT_CALL(*mHal, getHdrConversionCapabilities(_)).WillOnce(Return(HalError::NONE));

    EXPECT_CALL(*mHal, registerCallback(_));

    mHwc.setCallback(mCallback);

    const auto& supported = mHwc.getSupportedLayerGenericMetadata();
    EXPECT_EQ(2u, supported.size());
    EXPECT_EQ(1u, supported.count(kMetadata1Name));
    EXPECT_EQ(kMetadata1Mandatory, supported.find(kMetadata1Name)->second);
    EXPECT_EQ(1u, supported.count(kMetadata2Name));
    EXPECT_EQ(kMetadata2Mandatory, supported.find(kMetadata2Name)->second);
}

TEST_F(HWComposerSetCallbackTest, handlesUnsupportedCallToGetLayerGenericMetadataKeys) {
    EXPECT_CALL(*mHal, getCapabilities()).WillOnce(Return(std::vector<aidl::Capability>{}));
    EXPECT_CALL(*mHal, getLayerGenericMetadataKeys(_)).WillOnce(Return(V2_4::Error::UNSUPPORTED));
    EXPECT_CALL(*mHal, getOverlaySupport(_)).WillOnce(Return(HalError::UNSUPPORTED));
    EXPECT_CALL(*mHal, getHdrConversionCapabilities(_)).WillOnce(Return(HalError::UNSUPPORTED));
    EXPECT_CALL(*mHal, registerCallback(_));

    mHwc.setCallback(mCallback);

    const auto& supported = mHwc.getSupportedLayerGenericMetadata();
    EXPECT_TRUE(supported.empty());
}

struct HWComposerLayerTest : public testing::Test {
    static constexpr hal::HWDisplayId kDisplayId = static_cast<hal::HWDisplayId>(1001);
    static constexpr hal::HWLayerId kLayerId = static_cast<hal::HWLayerId>(1002);

    HWComposerLayerTest(const std::unordered_set<aidl::Capability>& capabilities)
          : mCapabilies(capabilities) {
        EXPECT_CALL(mDisplay, getId()).WillRepeatedly(Return(kDisplayId));
    }

    ~HWComposerLayerTest() override {
        EXPECT_CALL(mDisplay, onLayerDestroyed(kLayerId));
        EXPECT_CALL(*mHal, destroyLayer(kDisplayId, kLayerId));
    }

    std::unique_ptr<Hwc2::mock::Composer> mHal{new StrictMock<Hwc2::mock::Composer>()};
    const std::unordered_set<aidl::Capability> mCapabilies;
    StrictMock<HWC2::mock::Display> mDisplay;
    HWC2::impl::Layer mLayer{*mHal, mCapabilies, mDisplay, kLayerId};
};

struct HWComposerLayerGenericMetadataTest : public HWComposerLayerTest {
    static const std::string kLayerGenericMetadata1Name;
    static constexpr bool kLayerGenericMetadata1Mandatory = false;
    static const std::vector<uint8_t> kLayerGenericMetadata1Value;
    static const std::string kLayerGenericMetadata2Name;
    static constexpr bool kLayerGenericMetadata2Mandatory = true;
    static const std::vector<uint8_t> kLayerGenericMetadata2Value;

    HWComposerLayerGenericMetadataTest() : HWComposerLayerTest({}) {}
};

const std::string HWComposerLayerGenericMetadataTest::kLayerGenericMetadata1Name =
        "com.example.metadata.1";

const std::vector<uint8_t> HWComposerLayerGenericMetadataTest::kLayerGenericMetadata1Value = {1u,
                                                                                              2u,
                                                                                              3u};

const std::string HWComposerLayerGenericMetadataTest::kLayerGenericMetadata2Name =
        "com.example.metadata.2";

const std::vector<uint8_t> HWComposerLayerGenericMetadataTest::kLayerGenericMetadata2Value = {45u,
                                                                                              67u};

TEST_F(HWComposerLayerGenericMetadataTest, forwardsSupportedMetadata) {
    EXPECT_CALL(*mHal,
                setLayerGenericMetadata(kDisplayId, kLayerId, kLayerGenericMetadata1Name,
                                        kLayerGenericMetadata1Mandatory,
                                        kLayerGenericMetadata1Value))
            .WillOnce(Return(V2_4::Error::NONE));
    auto result = mLayer.setLayerGenericMetadata(kLayerGenericMetadata1Name,
                                                 kLayerGenericMetadata1Mandatory,
                                                 kLayerGenericMetadata1Value);
    EXPECT_EQ(hal::Error::NONE, result);

    EXPECT_CALL(*mHal,
                setLayerGenericMetadata(kDisplayId, kLayerId, kLayerGenericMetadata2Name,
                                        kLayerGenericMetadata2Mandatory,
                                        kLayerGenericMetadata2Value))
            .WillOnce(Return(V2_4::Error::UNSUPPORTED));
    result = mLayer.setLayerGenericMetadata(kLayerGenericMetadata2Name,
                                            kLayerGenericMetadata2Mandatory,
                                            kLayerGenericMetadata2Value);
    EXPECT_EQ(hal::Error::UNSUPPORTED, result);
}

} // namespace android
