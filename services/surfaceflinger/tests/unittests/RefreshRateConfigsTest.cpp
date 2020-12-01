/*
 * Copyright 2019 The Android Open Source Project
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
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <log/log.h>
#include <thread>

#include "../../Scheduler/RefreshRateConfigs.h"
#include "DisplayHardware/HWC2.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "mock/DisplayHardware/MockDisplay.h"

using namespace std::chrono_literals;
using testing::_;

namespace android {
namespace scheduler {

namespace hal = android::hardware::graphics::composer::hal;

using RefreshRate = RefreshRateConfigs::RefreshRate;
using LayerVoteType = RefreshRateConfigs::LayerVoteType;
using LayerRequirement = RefreshRateConfigs::LayerRequirement;

class RefreshRateConfigsTest : public testing::Test {
protected:
    RefreshRateConfigsTest();
    ~RefreshRateConfigsTest();

    float findClosestKnownFrameRate(const RefreshRateConfigs& refreshRateConfigs, float frameRate) {
        return refreshRateConfigs.findClosestKnownFrameRate(frameRate);
    }

    std::vector<float> getKnownFrameRate(const RefreshRateConfigs& refreshRateConfigs) {
        return refreshRateConfigs.mKnownFrameRates;
    }

    // Test config IDs
    static inline const HwcConfigIndexType HWC_CONFIG_ID_60 = HwcConfigIndexType(0);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_90 = HwcConfigIndexType(1);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_72 = HwcConfigIndexType(2);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_120 = HwcConfigIndexType(3);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_30 = HwcConfigIndexType(4);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_25 = HwcConfigIndexType(5);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_50 = HwcConfigIndexType(6);

    // Test configs
    std::shared_ptr<const HWC2::Display::Config> mConfig60 =
            createConfig(HWC_CONFIG_ID_60, 0, static_cast<int64_t>(1e9f / 60));
    std::shared_ptr<const HWC2::Display::Config> mConfig90 =
            createConfig(HWC_CONFIG_ID_90, 0, static_cast<int64_t>(1e9f / 90));
    std::shared_ptr<const HWC2::Display::Config> mConfig90DifferentGroup =
            createConfig(HWC_CONFIG_ID_90, 1, static_cast<int64_t>(1e9f / 90));
    std::shared_ptr<const HWC2::Display::Config> mConfig90DifferentResolution =
            createConfig(HWC_CONFIG_ID_90, 0, static_cast<int64_t>(1e9f / 90), 111, 222);
    std::shared_ptr<const HWC2::Display::Config> mConfig72 =
            createConfig(HWC_CONFIG_ID_72, 0, static_cast<int64_t>(1e9f / 72));
    std::shared_ptr<const HWC2::Display::Config> mConfig72DifferentGroup =
            createConfig(HWC_CONFIG_ID_72, 1, static_cast<int64_t>(1e9f / 72));
    std::shared_ptr<const HWC2::Display::Config> mConfig120 =
            createConfig(HWC_CONFIG_ID_120, 0, static_cast<int64_t>(1e9f / 120));
    std::shared_ptr<const HWC2::Display::Config> mConfig120DifferentGroup =
            createConfig(HWC_CONFIG_ID_120, 1, static_cast<int64_t>(1e9f / 120));
    std::shared_ptr<const HWC2::Display::Config> mConfig30 =
            createConfig(HWC_CONFIG_ID_30, 0, static_cast<int64_t>(1e9f / 30));
    std::shared_ptr<const HWC2::Display::Config> mConfig30DifferentGroup =
            createConfig(HWC_CONFIG_ID_30, 1, static_cast<int64_t>(1e9f / 30));
    std::shared_ptr<const HWC2::Display::Config> mConfig25DifferentGroup =
            createConfig(HWC_CONFIG_ID_25, 1, static_cast<int64_t>(1e9f / 25));
    std::shared_ptr<const HWC2::Display::Config> mConfig50 =
            createConfig(HWC_CONFIG_ID_50, 0, static_cast<int64_t>(1e9f / 50));

    // Test device configurations
    // The positions of the configs in the arrays below MUST match their IDs. For example,
    // the first config should always be 60Hz, the second 90Hz etc.
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m60OnlyConfigDevice = {mConfig60};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m60_90Device = {mConfig60, mConfig90};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m60_90DeviceWithDifferentGroups =
            {mConfig60, mConfig90DifferentGroup};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m60_90DeviceWithDifferentResolutions =
            {mConfig60, mConfig90DifferentResolution};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m60_72_90Device = {mConfig60,
                                                                                 mConfig90,
                                                                                 mConfig72};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m60_90_72_120Device = {mConfig60,
                                                                                     mConfig90,
                                                                                     mConfig72,
                                                                                     mConfig120};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m30_60_72_90_120Device = {mConfig60,
                                                                                        mConfig90,
                                                                                        mConfig72,
                                                                                        mConfig120,
                                                                                        mConfig30};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m30_60Device =
            {mConfig60, mConfig90DifferentGroup, mConfig72DifferentGroup, mConfig120DifferentGroup,
             mConfig30};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m30_60_72_90Device =
            {mConfig60, mConfig90, mConfig72, mConfig120DifferentGroup, mConfig30};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m30_60_90Device =
            {mConfig60, mConfig90, mConfig72DifferentGroup, mConfig120DifferentGroup, mConfig30};
    std::vector<std::shared_ptr<const HWC2::Display::Config>> m25_30_50_60Device =
            {mConfig60,
             mConfig90,
             mConfig72DifferentGroup,
             mConfig120DifferentGroup,
             mConfig30DifferentGroup,
             mConfig25DifferentGroup,
             mConfig50};

    // Expected RefreshRate objects
    RefreshRate mExpected60Config = {HWC_CONFIG_ID_60, mConfig60, "60fps", 60,
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpectedAlmost60Config = {HWC_CONFIG_ID_60,
                                           createConfig(HWC_CONFIG_ID_60, 0, 16666665), "60fps", 60,
                                           RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected90Config = {HWC_CONFIG_ID_90, mConfig90, "90fps", 90,
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected90DifferentGroupConfig = {HWC_CONFIG_ID_90, mConfig90DifferentGroup,
                                                   "90fps", 90, RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected90DifferentResolutionConfig = {HWC_CONFIG_ID_90,
                                                        mConfig90DifferentResolution, "90fps", 90,
                                                        RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected72Config = {HWC_CONFIG_ID_72, mConfig72, "72fps", 72,
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected30Config = {HWC_CONFIG_ID_30, mConfig30, "30fps", 30,
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected120Config = {HWC_CONFIG_ID_120, mConfig120, "120fps", 120,
                                      RefreshRate::ConstructorTag(0)};

    Hwc2::mock::Display mDisplay;

private:
    std::shared_ptr<const HWC2::Display::Config> createConfig(HwcConfigIndexType configId,
                                                              int32_t configGroup,
                                                              int64_t vsyncPeriod,
                                                              int32_t hight = -1,
                                                              int32_t width = -1);
};

using Builder = HWC2::Display::Config::Builder;

RefreshRateConfigsTest::RefreshRateConfigsTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

RefreshRateConfigsTest::~RefreshRateConfigsTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

std::shared_ptr<const HWC2::Display::Config> RefreshRateConfigsTest::createConfig(
        HwcConfigIndexType configId, int32_t configGroup, int64_t vsyncPeriod, int32_t hight,
        int32_t width) {
    return HWC2::Display::Config::Builder(mDisplay, hal::HWConfigId(configId.value()))
            .setVsyncPeriod(int32_t(vsyncPeriod))
            .setConfigGroup(configGroup)
            .setHeight(hight)
            .setWidth(width)
            .build();
}

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(RefreshRateConfigsTest, oneDeviceConfig_SwitchingSupported) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60OnlyConfigDevice,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
}

TEST_F(RefreshRateConfigsTest, invalidPolicy) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60OnlyConfigDevice,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    ASSERT_LT(refreshRateConfigs->setDisplayManagerPolicy({HwcConfigIndexType(10), {60, 60}}), 0);
    ASSERT_LT(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {20, 40}}), 0);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto& minRate = refreshRateConfigs->getMinRefreshRate();
    const auto& performanceRate = refreshRateConfigs->getMaxRefreshRate();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected90Config, performanceRate);

    const auto& minRateByPolicy = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRateByPolicy = refreshRateConfigs->getMaxRefreshRateByPolicy();
    ASSERT_EQ(minRateByPolicy, minRate);
    ASSERT_EQ(performanceRateByPolicy, performanceRate);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap_differentGroups) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto& minRate = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRate = refreshRateConfigs->getMaxRefreshRate();
    const auto& minRate60 = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected60Config, minRate60);
    ASSERT_EQ(mExpected60Config, performanceRate60);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {60, 90}}), 0);
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);

    const auto& minRate90 = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRate90 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected90DifferentGroupConfig, performanceRate);
    ASSERT_EQ(mExpected90DifferentGroupConfig, minRate90);
    ASSERT_EQ(mExpected90DifferentGroupConfig, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap_differentResolutions) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentResolutions,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto& minRate = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRate = refreshRateConfigs->getMaxRefreshRate();
    const auto& minRate60 = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected60Config, minRate60);
    ASSERT_EQ(mExpected60Config, performanceRate60);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {60, 90}}), 0);
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);

    const auto& minRate90 = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto& performanceRate90 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected90DifferentResolutionConfig, performanceRate);
    ASSERT_EQ(mExpected90DifferentResolutionConfig, minRate90);
    ASSERT_EQ(mExpected90DifferentResolutionConfig, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_policyChange) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto& minRate = refreshRateConfigs->getMinRefreshRateByPolicy();
    auto& performanceRate = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected90Config, performanceRate);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {60, 60}}), 0);

    auto& minRate60 = refreshRateConfigs->getMinRefreshRateByPolicy();
    auto& performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();
    ASSERT_EQ(mExpected60Config, minRate60);
    ASSERT_EQ(mExpected60Config, performanceRate60);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getCurrentRefreshRate) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    {
        auto& current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.getConfigId(), HWC_CONFIG_ID_60);
    }

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    {
        auto& current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.getConfigId(), HWC_CONFIG_ID_90);
    }

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {90, 90}}), 0);
    {
        auto& current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.getConfigId(), HWC_CONFIG_ID_90);
    }
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getRefreshRateForContent) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto makeLayerRequirements = [](float refreshRate) -> std::vector<LayerRequirement> {
        return {{"testLayer", LayerVoteType::Heuristic, refreshRate, Seamlessness::OnlySeamless,
                 /*weight*/ 1.0f, /*focused*/ false}};
    };

    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(90.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(60.0f)));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(45.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(30.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(24.0f)));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {60, 60}}), 0);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(90.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(60.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(45.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(30.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(24.0f)));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {90, 90}}), 0);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(90.0f)));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(60.0f)));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(45.0f)));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(30.0f)));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(24.0f)));
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {0, 120}}), 0);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(90.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(60.0f)));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(45.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(30.0f)));
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getRefreshRateForContent(makeLayerRequirements(24.0f)));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_noLayers) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_72_90Device, /*currentConfigId=*/
                                                 HWC_CONFIG_ID_72);

    // If there are no layers we select the default frame rate, which is the max of the primary
    // range.
    auto layers = std::vector<LayerRequirement>{};
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {60, 60}}), 0);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_60_90) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.name = "";
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {60, 60}}), 0);

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {90, 90}}), 0);

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {0, 120}}), 0);
    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_60_72_90) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_72_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_72_90_120) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60.0f;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48.0f;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48.0f;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_90_120_DifferentTypes) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 60.0f;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60.0f;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60.0f;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = 24.0f;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_72_90) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 90.0f;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = 45.0f;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = 30.0f;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = 24.0f;
    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.name = "24Hz ExplicitExactOrMultiple";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_PriorityTest) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 24.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 15.0f;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 30.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 45.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_24FpsVideo) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = fps;
        const auto& refreshRate =
                refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false});
        EXPECT_EQ(mExpected60Config, refreshRate) << fps << "Hz chooses " << refreshRate.getName();
    }
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getRefreshRateForContent_Explicit) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 60.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 90.0f;
    EXPECT_EQ(mExpected90Config, refreshRateConfigs->getRefreshRateForContent(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected60Config, refreshRateConfigs->getRefreshRateForContent(layers));
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getBestRefreshRate_Explicit) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 60.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 90.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 90.0f;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60.0f;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, testInPolicy) {
    ASSERT_TRUE(mExpectedAlmost60Config.inPolicy(60.000004f, 60.000004f));
    ASSERT_TRUE(mExpectedAlmost60Config.inPolicy(59.0f, 60.1f));
    ASSERT_FALSE(mExpectedAlmost60Config.inPolicy(75.0f, 90.0f));
    ASSERT_FALSE(mExpectedAlmost60Config.inPolicy(60.0011f, 90.0f));
    ASSERT_FALSE(mExpectedAlmost60Config.inPolicy(50.0f, 59.998f));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_75HzContent) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 75.0f; fps < 100.0f; fps += 0.1f) {
        lr.desiredRefreshRate = fps;
        const auto& refreshRate =
                refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false});
        EXPECT_EQ(mExpected90Config, refreshRate) << fps << "Hz chooses " << refreshRate.getName();
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_Multiples) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90.0f;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 90.0f;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30.0f;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90.0f;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30.0f;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, scrollWhileWatching60fps_60_90) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    // The other layer starts to provide buffers
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90.0f;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, touchConsidered) {
    RefreshRateConfigs::GlobalSignals consideredSignals;
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    refreshRateConfigs->getBestRefreshRate({}, {.touch = false, .idle = false}, &consideredSignals);
    EXPECT_EQ(false, consideredSignals.touch);

    refreshRateConfigs->getBestRefreshRate({}, {.touch = true, .idle = false}, &consideredSignals);
    EXPECT_EQ(true, consideredSignals.touch);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 1.0f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60.0f;
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(true, consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60.0f;
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(false, consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60.0f;
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(true, consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 60.0f;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60.0f;
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(false, consideredSignals.touch);
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitDefault) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90_72_120Device, /*currentConfigId=*/
                                                 HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    // Prepare a table with the vote and the expected refresh rate
    const std::vector<std::pair<float, float>> testCases = {
            {130, 120}, {120, 120}, {119, 120}, {110, 120},

            {100, 90},  {90, 90},   {89, 90},

            {80, 72},   {73, 72},   {72, 72},   {71, 72},   {70, 72},

            {65, 60},   {60, 60},   {59, 60},   {58, 60},

            {55, 90},   {50, 90},   {45, 90},

            {42, 120},  {40, 120},  {39, 120},

            {37, 72},   {36, 72},   {35, 72},

            {30, 60},
    };

    for (const auto& test : testCases) {
        lr.vote = LayerVoteType::ExplicitDefault;
        lr.desiredRefreshRate = test.first;

        std::stringstream ss;
        ss << "ExplicitDefault " << test.first << " fps";
        lr.name = ss.str();

        const auto& refreshRate =
                refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false});
        EXPECT_FLOAT_EQ(refreshRate.getFps(), test.second)
                << "Expecting " << test.first << "fps => " << test.second << "Hz";
    }
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresTouchFlag) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_90);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_90, {90.f, 90.f}, {60.f, 90.f}}),
              0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    RefreshRateConfigs::GlobalSignals consideredSignals;
    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = true;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = true},
                                                     &consideredSignals));
    EXPECT_EQ(false, consideredSignals.touch);
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresIdleFlag) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {60.f, 60.f}, {60.f, 90.f}}),
              0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 90.0f;
    lr.name = "90Hz ExplicitDefault";
    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = true}));
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_onlySwitchesRatesForExplicitFocusedLayers) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_90);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_90, {90.f, 90.f}, {60.f, 90.f}}),
              0);

    RefreshRateConfigs::GlobalSignals consideredSignals;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate({}, {.touch = false, .idle = false},
                                                     &consideredSignals));
    EXPECT_EQ(false, consideredSignals.touch);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz ExplicitExactOrMultiple";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Heuristic;
    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz Heuristic";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz Max";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Min;
    lr.desiredRefreshRate = 60.0f;
    lr.name = "60Hz Min";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, groupSwitching) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90.0f;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;

    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    RefreshRateConfigs::Policy policy;
    policy.defaultConfig = refreshRateConfigs->getCurrentPolicy().defaultConfig;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);
    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    // Verify that we won't change the group if seamless switch is required.
    layer.seamlessness = Seamlessness::OnlySeamless;
    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    // Verify that we won't do a seamless switch if we request the same mode as the default
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    layer.desiredRefreshRate = 60.0f;
    layer.name = "60Hz ExplicitDefault";
    layer.seamlessness = Seamlessness::OnlySeamless;
    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    // Verify that if the current config is in another group and there are no layers with
    // seamlessness=SeamedAndSeamless we'll go back to the default group.
    layer.desiredRefreshRate = 60.0f;
    layer.name = "60Hz ExplicitDefault";
    layer.seamlessness = Seamlessness::Default;
    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    // If there's a layer with seamlessness=SeamedAndSeamless, another layer with
    // seamlessness=OnlySeamless can't change the config group.
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    layer.seamlessness = Seamlessness::OnlySeamless;

    layers.push_back(LayerRequirement{.weight = 0.5f});
    auto& layer2 = layers[layers.size() - 1];
    layer2.vote = LayerVoteType::ExplicitDefault;
    layer2.desiredRefreshRate = 90.0f;
    layer2.name = "90Hz ExplicitDefault";
    layer2.seamlessness = Seamlessness::SeamedAndSeamless;
    layer2.focused = false;

    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    // If there's a layer with seamlessness=SeamedAndSeamless, another layer with
    // seamlessness=Default can't change the config group.
    layers[0].seamlessness = Seamlessness::Default;
    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());
}

TEST_F(RefreshRateConfigsTest, nonSeamlessVotePrefersSeamlessSwitches) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultConfig = refreshRateConfigs->getCurrentPolicy().defaultConfig;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitExactOrMultiple;
    layer.desiredRefreshRate = 60.0f;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "60Hz ExplicitExactOrMultiple";
    layer.focused = true;

    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_120);
    ASSERT_EQ(HWC_CONFIG_ID_120,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());
}

TEST_F(RefreshRateConfigsTest, nonSeamlessExactAndSeamlessMultipleLayers) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m25_30_50_60Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultConfig = refreshRateConfigs->getCurrentPolicy().defaultConfig;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    auto layers = std::vector<
            LayerRequirement>{LayerRequirement{.name = "60Hz ExplicitDefault",
                                               .vote = LayerVoteType::ExplicitDefault,
                                               .desiredRefreshRate = 60.0f,
                                               .seamlessness = Seamlessness::SeamedAndSeamless,
                                               .weight = 0.5f,
                                               .focused = false},
                              LayerRequirement{.name = "25Hz ExplicitExactOrMultiple",
                                               .vote = LayerVoteType::ExplicitExactOrMultiple,
                                               .desiredRefreshRate = 25.0f,
                                               .seamlessness = Seamlessness::OnlySeamless,
                                               .weight = 1.0f,
                                               .focused = true}};
    auto& seamedLayer = layers[0];

    ASSERT_EQ(HWC_CONFIG_ID_50,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());

    seamedLayer.name = "30Hz ExplicitDefault", seamedLayer.desiredRefreshRate = 30.0f;
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_30);

    ASSERT_EQ(HWC_CONFIG_ID_25,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getConfigId());
}

TEST_F(RefreshRateConfigsTest, primaryVsAppRequestPolicy) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].name = "Test layer";

    // Return the config ID from calling getBestRefreshRate() for a single layer with the
    // given voteType and fps.
    auto getFrameRate = [&](LayerVoteType voteType, float fps, bool touchActive = false,
                            bool focused = true) -> HwcConfigIndexType {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = fps;
        layers[0].focused = focused;
        return refreshRateConfigs->getBestRefreshRate(layers, {.touch = touchActive, .idle = false})
                .getConfigId();
    };

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {30.f, 60.f}, {30.f, 90.f}}),
              0);
    EXPECT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate({}, {.touch = false, .idle = false})
                      .getConfigId());
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::NoVote, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_30, getFrameRate(LayerVoteType::Min, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Max, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Heuristic, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_90, getFrameRate(LayerVoteType::ExplicitDefault, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90.f));

    // Layers not focused are not allowed to override primary config
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getFrameRate(LayerVoteType::ExplicitDefault, 90.f, /*touch=*/false,
                           /*focused=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90.f, /*touch=*/false,
                           /*focused=*/false));

    // Touch boost should be restricted to the primary range.
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Max, 90.f, /*touch=*/true));
    // When we're higher than the primary range max due to a layer frame rate setting, touch boost
    // shouldn't drag us back down to the primary range max.
    EXPECT_EQ(HWC_CONFIG_ID_90, getFrameRate(LayerVoteType::ExplicitDefault, 90.f, /*touch=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90.f, /*touch=*/true));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {60.f, 60.f}, {60.f, 60.f}}),
              0);
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::NoVote, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Min, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Max, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Heuristic, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::ExplicitDefault, 90.f));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90.f));
}

TEST_F(RefreshRateConfigsTest, idle) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].name = "Test layer";

    const auto getIdleFrameRate = [&](LayerVoteType voteType,
                                      bool touchActive) -> HwcConfigIndexType {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = 90.f;
        RefreshRateConfigs::GlobalSignals consideredSignals;
        const auto configId =
                refreshRateConfigs
                        ->getBestRefreshRate(layers, {.touch = touchActive, .idle = true},
                                             &consideredSignals)
                        .getConfigId();
        // Refresh rate will be chosen by either touch state or idle state
        EXPECT_EQ(!touchActive, consideredSignals.idle);
        return configId;
    };

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {60.f, 90.f}, {60.f, 90.f}}),
              0);

    // Idle should be lower priority than touch boost.
    EXPECT_EQ(HWC_CONFIG_ID_90, getIdleFrameRate(LayerVoteType::NoVote, /*touchActive=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_90, getIdleFrameRate(LayerVoteType::Min, /*touchActive=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_90, getIdleFrameRate(LayerVoteType::Max, /*touchActive=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_90, getIdleFrameRate(LayerVoteType::Heuristic, /*touchActive=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_90,
              getIdleFrameRate(LayerVoteType::ExplicitDefault, /*touchActive=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_90,
              getIdleFrameRate(LayerVoteType::ExplicitExactOrMultiple, /*touchActive=*/true));

    // With no layers, idle should still be lower priority than touch boost.
    EXPECT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate({}, {.touch = true, .idle = true})
                      .getConfigId());

    // Idle should be higher precedence than other layer frame rate considerations.
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    EXPECT_EQ(HWC_CONFIG_ID_60, getIdleFrameRate(LayerVoteType::NoVote, /*touchActive=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60, getIdleFrameRate(LayerVoteType::Min, /*touchActive=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60, getIdleFrameRate(LayerVoteType::Max, /*touchActive=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60, getIdleFrameRate(LayerVoteType::Heuristic, /*touchActive=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getIdleFrameRate(LayerVoteType::ExplicitDefault, /*touchActive=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getIdleFrameRate(LayerVoteType::ExplicitExactOrMultiple, /*touchActive=*/false));

    // Idle should be applied rather than the current config when there are no layers.
    EXPECT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate({}, {.touch = false, .idle = true})
                      .getConfigId());
}

TEST_F(RefreshRateConfigsTest, findClosestKnownFrameRate) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    for (float fps = 1.0f; fps <= 120.0f; fps += 0.1f) {
        const auto knownFrameRate = findClosestKnownFrameRate(*refreshRateConfigs, fps);
        float expectedFrameRate;
        if (fps < 26.91f) {
            expectedFrameRate = 24.0f;
        } else if (fps < 37.51f) {
            expectedFrameRate = 30.0f;
        } else if (fps < 52.51f) {
            expectedFrameRate = 45.0f;
        } else if (fps < 66.01f) {
            expectedFrameRate = 60.0f;
        } else if (fps < 81.01f) {
            expectedFrameRate = 72.0f;
        } else {
            expectedFrameRate = 90.0f;
        }
        EXPECT_FLOAT_EQ(expectedFrameRate, knownFrameRate)
                << "findClosestKnownFrameRate(" << fps << ") = " << knownFrameRate;
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_KnownFrameRate) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    struct ExpectedRate {
        float rate;
        const RefreshRate& expected;
    };

    /* clang-format off */
    std::vector<ExpectedRate> knownFrameRatesExpectations = {
        {24.0f, mExpected60Config},
        {30.0f, mExpected60Config},
        {45.0f, mExpected90Config},
        {60.0f, mExpected60Config},
        {72.0f, mExpected90Config},
        {90.0f, mExpected90Config},
    };
    /* clang-format on */

    // Make sure the test tests all the known frame rate
    const auto knownFrameRateList = getKnownFrameRate(*refreshRateConfigs);
    const auto equal = std::equal(knownFrameRateList.begin(), knownFrameRateList.end(),
                                  knownFrameRatesExpectations.begin(),
                                  [](float a, const ExpectedRate& b) { return a == b.rate; });
    EXPECT_TRUE(equal);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::Heuristic;
    for (const auto& expectedRate : knownFrameRatesExpectations) {
        layer.desiredRefreshRate = expectedRate.rate;
        const auto& refreshRate =
                refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false});
        EXPECT_EQ(expectedRate.expected, refreshRate);
    }
}

TEST_F(RefreshRateConfigsTest, testComparisonOperator) {
    EXPECT_TRUE(mExpected60Config < mExpected90Config);
    EXPECT_FALSE(mExpected60Config < mExpected60Config);
    EXPECT_FALSE(mExpected90Config < mExpected90Config);
}

TEST_F(RefreshRateConfigsTest, testKernelIdleTimerAction) {
    using KernelIdleTimerAction = scheduler::RefreshRateConfigs::KernelIdleTimerAction;

    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_90);
    // SetPolicy(60, 90), current 90Hz => TurnOn.
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, refreshRateConfigs->getIdleTimerAction());

    // SetPolicy(60, 90), current 60Hz => TurnOn.
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {60, 90}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, refreshRateConfigs->getIdleTimerAction());

    // SetPolicy(60, 60), current 60Hz => NoChange, avoid extra calls.
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {60, 60}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::NoChange, refreshRateConfigs->getIdleTimerAction());

    // SetPolicy(90, 90), current 90Hz => TurnOff.
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {90, 90}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, refreshRateConfigs->getIdleTimerAction());
}

TEST_F(RefreshRateConfigsTest, RefreshRateDividerForUnknownUid) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_30);
    EXPECT_EQ(1, refreshRateConfigs->getRefreshRateDividerForUid(1234));
}

TEST_F(RefreshRateConfigsTest, RefreshRateDividerForUid) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_30);
    const uid_t uid = 1234;
    refreshRateConfigs->setPreferredRefreshRateForUid({uid, 30});
    EXPECT_EQ(1, refreshRateConfigs->getRefreshRateDividerForUid(uid));

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_60);
    EXPECT_EQ(2, refreshRateConfigs->getRefreshRateDividerForUid(uid));

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_72);
    EXPECT_EQ(1, refreshRateConfigs->getRefreshRateDividerForUid(uid));

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    EXPECT_EQ(3, refreshRateConfigs->getRefreshRateDividerForUid(uid));

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_120);
    EXPECT_EQ(4, refreshRateConfigs->getRefreshRateDividerForUid(uid));

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    refreshRateConfigs->setPreferredRefreshRateForUid({uid, 22.5});
    EXPECT_EQ(4, refreshRateConfigs->getRefreshRateDividerForUid(uid));
    refreshRateConfigs->setPreferredRefreshRateForUid({uid, 22.6f});
    EXPECT_EQ(4, refreshRateConfigs->getRefreshRateDividerForUid(uid));
}

} // namespace
} // namespace scheduler
} // namespace android
