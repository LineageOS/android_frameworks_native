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

#include <vector>

// StrictMock<T> derives from T and is not marked final, so the destructor of T is expected to be
// virtual in case StrictMock<T> is used as a polymorphic base class. That is not the case here.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#include <gmock/gmock.h>
#pragma clang diagnostic pop

#include <gui/LayerMetadata.h>
#include <log/log.h>

#include "DisplayHardware/HWComposer.h"
#include "mock/DisplayHardware/MockComposer.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

namespace android {
namespace {

namespace V2_1 = hardware::graphics::composer::V2_1;
namespace V2_4 = hardware::graphics::composer::V2_4;

using Hwc2::Config;

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

struct MockHWC2ComposerCallback final : StrictMock<HWC2::ComposerCallback> {
    MOCK_METHOD3(onHotplugReceived, void(int32_t sequenceId, hal::HWDisplayId, hal::Connection));
    MOCK_METHOD2(onRefreshReceived, void(int32_t sequenceId, hal::HWDisplayId));
    MOCK_METHOD4(onVsyncReceived,
                 void(int32_t sequenceId, hal::HWDisplayId, int64_t timestamp,
                      std::optional<hal::VsyncPeriodNanos>));
    MOCK_METHOD3(onVsyncPeriodTimingChangedReceived,
                 void(int32_t sequenceId, hal::HWDisplayId, const hal::VsyncPeriodChangeTimeline&));
    MOCK_METHOD2(onSeamlessPossible, void(int32_t sequenceId, hal::HWDisplayId));
};

struct HWComposerSetConfigurationTest : testing::Test {
    Hwc2::mock::Composer* mHal = new StrictMock<Hwc2::mock::Composer>();
    MockHWC2ComposerCallback mCallback;
};

TEST_F(HWComposerSetConfigurationTest, loadsLayerMetadataSupport) {
    const std::string kMetadata1Name = "com.example.metadata.1";
    constexpr bool kMetadata1Mandatory = false;
    const std::string kMetadata2Name = "com.example.metadata.2";
    constexpr bool kMetadata2Mandatory = true;

    EXPECT_CALL(*mHal, getMaxVirtualDisplayCount()).WillOnce(Return(0));
    EXPECT_CALL(*mHal, getCapabilities()).WillOnce(Return(std::vector<hal::Capability>{}));
    EXPECT_CALL(*mHal, getLayerGenericMetadataKeys(_))
            .WillOnce(DoAll(SetArgPointee<0>(std::vector<hal::LayerGenericMetadataKey>{
                                    {kMetadata1Name, kMetadata1Mandatory},
                                    {kMetadata2Name, kMetadata2Mandatory},
                            }),
                            Return(hardware::graphics::composer::V2_4::Error::NONE)));
    EXPECT_CALL(*mHal, registerCallback(_));
    EXPECT_CALL(*mHal, isVsyncPeriodSwitchSupported()).WillOnce(Return(false));

    impl::HWComposer hwc{std::unique_ptr<Hwc2::Composer>(mHal)};
    hwc.setConfiguration(&mCallback, 123);

    const auto& supported = hwc.getSupportedLayerGenericMetadata();
    EXPECT_EQ(2u, supported.size());
    EXPECT_EQ(1u, supported.count(kMetadata1Name));
    EXPECT_EQ(kMetadata1Mandatory, supported.find(kMetadata1Name)->second);
    EXPECT_EQ(1u, supported.count(kMetadata2Name));
    EXPECT_EQ(kMetadata2Mandatory, supported.find(kMetadata2Name)->second);
}

TEST_F(HWComposerSetConfigurationTest, handlesUnsupportedCallToGetLayerGenericMetadataKeys) {
    EXPECT_CALL(*mHal, getMaxVirtualDisplayCount()).WillOnce(Return(0));
    EXPECT_CALL(*mHal, getCapabilities()).WillOnce(Return(std::vector<hal::Capability>{}));
    EXPECT_CALL(*mHal, getLayerGenericMetadataKeys(_))
            .WillOnce(Return(hardware::graphics::composer::V2_4::Error::UNSUPPORTED));
    EXPECT_CALL(*mHal, registerCallback(_));
    EXPECT_CALL(*mHal, isVsyncPeriodSwitchSupported()).WillOnce(Return(false));

    impl::HWComposer hwc{std::unique_ptr<Hwc2::Composer>(mHal)};
    hwc.setConfiguration(&mCallback, 123);

    const auto& supported = hwc.getSupportedLayerGenericMetadata();
    EXPECT_EQ(0u, supported.size());
}

struct HWComposerLayerTest : public testing::Test {
    static constexpr hal::HWDisplayId kDisplayId = static_cast<hal::HWDisplayId>(1001);
    static constexpr hal::HWLayerId kLayerId = static_cast<hal::HWLayerId>(1002);

    HWComposerLayerTest(const std::unordered_set<hal::Capability>& capabilities)
          : mCapabilies(capabilities) {}

    ~HWComposerLayerTest() override { EXPECT_CALL(*mHal, destroyLayer(kDisplayId, kLayerId)); }

    std::unique_ptr<Hwc2::mock::Composer> mHal{new StrictMock<Hwc2::mock::Composer>()};
    const std::unordered_set<hal::Capability> mCapabilies;
    HWC2::impl::Layer mLayer{*mHal, mCapabilies, kDisplayId, kLayerId};
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
            .WillOnce(Return(hardware::graphics::composer::V2_4::Error::NONE));
    auto result = mLayer.setLayerGenericMetadata(kLayerGenericMetadata1Name,
                                                 kLayerGenericMetadata1Mandatory,
                                                 kLayerGenericMetadata1Value);
    EXPECT_EQ(hal::Error::NONE, result);

    EXPECT_CALL(*mHal,
                setLayerGenericMetadata(kDisplayId, kLayerId, kLayerGenericMetadata2Name,
                                        kLayerGenericMetadata2Mandatory,
                                        kLayerGenericMetadata2Value))
            .WillOnce(Return(hardware::graphics::composer::V2_4::Error::UNSUPPORTED));
    result = mLayer.setLayerGenericMetadata(kLayerGenericMetadata2Name,
                                            kLayerGenericMetadata2Mandatory,
                                            kLayerGenericMetadata2Value);
    EXPECT_EQ(hal::Error::UNSUPPORTED, result);
}

class HWComposerConfigsTest : public testing::Test {
public:
    Hwc2::mock::Composer* mHal = new StrictMock<Hwc2::mock::Composer>();
    MockHWC2ComposerCallback mCallback;

    void setActiveConfig(Config config) {
        EXPECT_CALL(*mHal, getActiveConfig(_, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(config), Return(V2_1::Error::NONE)));
    }

    void setDisplayConfigs(std::vector<Config> configs) {
        EXPECT_CALL(*mHal, getDisplayConfigs(_, _))
                .WillOnce(DoAll(SetArgPointee<1>(configs), Return(V2_1::Error::NONE)));
        EXPECT_CALL(*mHal, getDisplayAttribute(_, _, _, _))
                .WillRepeatedly(DoAll(SetArgPointee<3>(1), Return(V2_1::Error::NONE)));
    }

    void testSetActiveConfigWithConstraintsCommon(bool isVsyncPeriodSwitchSupported);
};

void HWComposerConfigsTest::testSetActiveConfigWithConstraintsCommon(
        bool isVsyncPeriodSwitchSupported) {
    EXPECT_CALL(*mHal, getMaxVirtualDisplayCount()).WillOnce(Return(0));
    EXPECT_CALL(*mHal, getCapabilities()).WillOnce(Return(std::vector<hal::Capability>{}));
    EXPECT_CALL(*mHal, getLayerGenericMetadataKeys(_)).WillOnce(Return(V2_4::Error::UNSUPPORTED));
    EXPECT_CALL(*mHal, registerCallback(_));
    EXPECT_CALL(*mHal, setVsyncEnabled(_, _)).WillRepeatedly(Return(V2_1::Error::NONE));
    EXPECT_CALL(*mHal, getDisplayIdentificationData(_, _, _))
            .WillRepeatedly(Return(V2_1::Error::UNSUPPORTED));
    EXPECT_CALL(*mHal, setClientTargetSlotCount(_)).WillRepeatedly(Return(V2_1::Error::NONE));

    EXPECT_CALL(*mHal, isVsyncPeriodSwitchSupported())
            .WillRepeatedly(Return(isVsyncPeriodSwitchSupported));

    if (isVsyncPeriodSwitchSupported) {
        EXPECT_CALL(*mHal, setActiveConfigWithConstraints(_, _, _, _))
                .WillRepeatedly(Return(V2_4::Error::NONE));
    } else {
        EXPECT_CALL(*mHal, setActiveConfig(_, _)).WillRepeatedly(Return(V2_1::Error::NONE));
    }

    impl::HWComposer hwc{std::unique_ptr<Hwc2::Composer>(mHal)};
    hwc.setConfiguration(&mCallback, 123);

    setDisplayConfigs({15});
    setActiveConfig(15);

    const auto physicalId = PhysicalDisplayId::fromPort(0);
    const hal::HWDisplayId hwcId = 0;
    hwc.allocatePhysicalDisplay(hwcId, physicalId);

    hal::VsyncPeriodChangeConstraints constraints;
    constraints.desiredTimeNanos = systemTime();
    constraints.seamlessRequired = false;

    hal::VsyncPeriodChangeTimeline timeline = {0, 0, 0};
    constexpr size_t kConfigIndex = 0;
    const auto status =
            hwc.setActiveConfigWithConstraints(physicalId, kConfigIndex, constraints, &timeline);
    EXPECT_EQ(NO_ERROR, status);

    const std::vector<Config> kConfigs{7, 8, 9, 10, 11};
    // Change the set of supported modes.
    setDisplayConfigs(kConfigs);
    setActiveConfig(11);
    hwc.onHotplug(hwcId, hal::Connection::CONNECTED);
    hwc.allocatePhysicalDisplay(hwcId, physicalId);

    for (size_t configIndex = 0; configIndex < kConfigs.size(); configIndex++) {
        const auto status =
                hwc.setActiveConfigWithConstraints(physicalId, configIndex, constraints, &timeline);
        EXPECT_EQ(NO_ERROR, status) << "Error when switching to config " << configIndex;
    }
}

TEST_F(HWComposerConfigsTest, setActiveConfigWithConstraintsWithVsyncSwitchingSupported) {
    testSetActiveConfigWithConstraintsCommon(/*supported=*/true);
}

TEST_F(HWComposerConfigsTest, setActiveConfigWithConstraintsWithVsyncSwitchingNotSupported) {
    testSetActiveConfigWithConstraintsCommon(/*supported=*/false);
}

} // namespace
} // namespace android