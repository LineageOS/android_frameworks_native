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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <log/log.h>
#include <thread>

#include <ui/Size.h>

#include "../../Scheduler/RefreshRateConfigs.h"
#include "DisplayHardware/HWC2.h"
#include "Scheduler/RefreshRateConfigs.h"

using namespace std::chrono_literals;

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

    Fps findClosestKnownFrameRate(const RefreshRateConfigs& refreshRateConfigs, Fps frameRate) {
        return refreshRateConfigs.findClosestKnownFrameRate(frameRate);
    }

    std::vector<Fps> getKnownFrameRate(const RefreshRateConfigs& refreshRateConfigs) {
        return refreshRateConfigs.mKnownFrameRates;
    }

    RefreshRate getMinRefreshRateByPolicy(const RefreshRateConfigs& refreshRateConfigs) {
        std::lock_guard lock(refreshRateConfigs.mLock);
        return refreshRateConfigs.getMinRefreshRateByPolicyLocked();
    }

    RefreshRate getMinSupportedRefreshRate(const RefreshRateConfigs& refreshRateConfigs) {
        std::lock_guard lock(refreshRateConfigs.mLock);
        return *refreshRateConfigs.mMinSupportedRefreshRate;
    }

    RefreshRate getMaxSupportedRefreshRate(const RefreshRateConfigs& refreshRateConfigs) {
        std::lock_guard lock(refreshRateConfigs.mLock);
        return *refreshRateConfigs.mMaxSupportedRefreshRate;
    }

    // Test config IDs
    static inline const DisplayModeId HWC_CONFIG_ID_60 = DisplayModeId(0);
    static inline const DisplayModeId HWC_CONFIG_ID_90 = DisplayModeId(1);
    static inline const DisplayModeId HWC_CONFIG_ID_72 = DisplayModeId(2);
    static inline const DisplayModeId HWC_CONFIG_ID_120 = DisplayModeId(3);
    static inline const DisplayModeId HWC_CONFIG_ID_30 = DisplayModeId(4);
    static inline const DisplayModeId HWC_CONFIG_ID_25 = DisplayModeId(5);
    static inline const DisplayModeId HWC_CONFIG_ID_50 = DisplayModeId(6);

    // Test configs
    DisplayModePtr mConfig60 = createDisplayMode(HWC_CONFIG_ID_60, 0, Fps(60.0f).getPeriodNsecs());
    DisplayModePtr mConfig90 = createDisplayMode(HWC_CONFIG_ID_90, 0, Fps(90.0f).getPeriodNsecs());
    DisplayModePtr mConfig90DifferentGroup =
            createDisplayMode(HWC_CONFIG_ID_90, 1, Fps(90.0f).getPeriodNsecs());
    DisplayModePtr mConfig90DifferentResolution =
            createDisplayMode(HWC_CONFIG_ID_90, 0, Fps(90.0f).getPeriodNsecs(), ui::Size(111, 222));
    DisplayModePtr mConfig72 = createDisplayMode(HWC_CONFIG_ID_72, 0, Fps(72.0f).getPeriodNsecs());
    DisplayModePtr mConfig72DifferentGroup =
            createDisplayMode(HWC_CONFIG_ID_72, 1, Fps(72.0f).getPeriodNsecs());
    DisplayModePtr mConfig120 =
            createDisplayMode(HWC_CONFIG_ID_120, 0, Fps(120.0f).getPeriodNsecs());
    DisplayModePtr mConfig120DifferentGroup =
            createDisplayMode(HWC_CONFIG_ID_120, 1, Fps(120.0f).getPeriodNsecs());
    DisplayModePtr mConfig30 = createDisplayMode(HWC_CONFIG_ID_30, 0, Fps(30.0f).getPeriodNsecs());
    DisplayModePtr mConfig30DifferentGroup =
            createDisplayMode(HWC_CONFIG_ID_30, 1, Fps(30.0f).getPeriodNsecs());
    DisplayModePtr mConfig25DifferentGroup =
            createDisplayMode(HWC_CONFIG_ID_25, 1, Fps(25.0f).getPeriodNsecs());
    DisplayModePtr mConfig50 = createDisplayMode(HWC_CONFIG_ID_50, 0, Fps(50.0f).getPeriodNsecs());

    // Test device configurations
    // The positions of the configs in the arrays below MUST match their IDs. For example,
    // the first config should always be 60Hz, the second 90Hz etc.
    DisplayModes m60OnlyConfigDevice = {mConfig60};
    DisplayModes m60_90Device = {mConfig60, mConfig90};
    DisplayModes m60_90DeviceWithDifferentGroups = {mConfig60, mConfig90DifferentGroup};
    DisplayModes m60_90DeviceWithDifferentResolutions = {mConfig60, mConfig90DifferentResolution};
    DisplayModes m60_72_90Device = {mConfig60, mConfig90, mConfig72};
    DisplayModes m60_90_72_120Device = {mConfig60, mConfig90, mConfig72, mConfig120};
    DisplayModes m30_60_72_90_120Device = {mConfig60, mConfig90, mConfig72, mConfig120, mConfig30};
    DisplayModes m30_60Device = {mConfig60, mConfig90DifferentGroup, mConfig72DifferentGroup,
                                 mConfig120DifferentGroup, mConfig30};
    DisplayModes m30_60_72_90Device = {mConfig60, mConfig90, mConfig72, mConfig120DifferentGroup,
                                       mConfig30};
    DisplayModes m30_60_90Device = {mConfig60, mConfig90, mConfig72DifferentGroup,
                                    mConfig120DifferentGroup, mConfig30};
    DisplayModes m25_30_50_60Device = {mConfig60,
                                       mConfig90,
                                       mConfig72DifferentGroup,
                                       mConfig120DifferentGroup,
                                       mConfig30DifferentGroup,
                                       mConfig25DifferentGroup,
                                       mConfig50};

    // Expected RefreshRate objects
    RefreshRate mExpected60Config = {HWC_CONFIG_ID_60, mConfig60, Fps(60),
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpectedAlmost60Config = {HWC_CONFIG_ID_60,
                                           createDisplayMode(HWC_CONFIG_ID_60, 0, 16666665),
                                           Fps(60), RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected90Config = {HWC_CONFIG_ID_90, mConfig90, Fps(90),
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected90DifferentGroupConfig = {HWC_CONFIG_ID_90, mConfig90DifferentGroup,
                                                   Fps(90), RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected90DifferentResolutionConfig = {HWC_CONFIG_ID_90,
                                                        mConfig90DifferentResolution, Fps(90),
                                                        RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected72Config = {HWC_CONFIG_ID_72, mConfig72, Fps(72.0f),
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected30Config = {HWC_CONFIG_ID_30, mConfig30, Fps(30),
                                     RefreshRate::ConstructorTag(0)};
    RefreshRate mExpected120Config = {HWC_CONFIG_ID_120, mConfig120, Fps(120),
                                      RefreshRate::ConstructorTag(0)};
private:
    DisplayModePtr createDisplayMode(DisplayModeId modeId, int32_t group, int64_t vsyncPeriod,
                                     ui::Size resolution = ui::Size());
};

using Builder = DisplayMode::Builder;

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

DisplayModePtr RefreshRateConfigsTest::createDisplayMode(DisplayModeId modeId, int32_t group,
                                                         int64_t vsyncPeriod, ui::Size resolution) {
    return DisplayMode::Builder(hal::HWConfigId(modeId.value()))
            .setId(modeId)
            .setVsyncPeriod(int32_t(vsyncPeriod))
            .setGroup(group)
            .setHeight(resolution.height)
            .setWidth(resolution.width)
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
    ASSERT_LT(refreshRateConfigs->setDisplayManagerPolicy({DisplayModeId(10), {Fps(60), Fps(60)}}),
              0);
    ASSERT_LT(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {Fps(20), Fps(40)}}),
              0);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto& minRate = getMinSupportedRefreshRate(*refreshRateConfigs);
    const auto& performanceRate = getMaxSupportedRefreshRate(*refreshRateConfigs);

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected90Config, performanceRate);

    const auto& minRateByPolicy = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRateByPolicy = refreshRateConfigs->getMaxRefreshRateByPolicy();
    ASSERT_EQ(minRateByPolicy, minRate);
    ASSERT_EQ(performanceRateByPolicy, performanceRate);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap_differentGroups) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto& minRate = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRate = getMaxSupportedRefreshRate(*refreshRateConfigs);
    const auto& minRate60 = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected60Config, minRate60);
    ASSERT_EQ(mExpected60Config, performanceRate60);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {Fps(60), Fps(90)}}),
              0);
    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    const auto& minRate90 = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRate90 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected90DifferentGroupConfig, performanceRate);
    ASSERT_EQ(mExpected90DifferentGroupConfig, minRate90);
    ASSERT_EQ(mExpected90DifferentGroupConfig, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap_differentResolutions) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentResolutions,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    const auto& minRate = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRate = getMaxSupportedRefreshRate(*refreshRateConfigs);
    const auto& minRate60 = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected60Config, minRate60);
    ASSERT_EQ(mExpected60Config, performanceRate60);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {Fps(60), Fps(90)}}),
              0);
    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    const auto& minRate90 = getMinRefreshRateByPolicy(*refreshRateConfigs);
    const auto& performanceRate90 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected90DifferentResolutionConfig, performanceRate);
    ASSERT_EQ(mExpected90DifferentResolutionConfig, minRate90);
    ASSERT_EQ(mExpected90DifferentResolutionConfig, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_policyChange) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto minRate = getMinRefreshRateByPolicy(*refreshRateConfigs);
    auto performanceRate = refreshRateConfigs->getMaxRefreshRateByPolicy();

    ASSERT_EQ(mExpected60Config, minRate);
    ASSERT_EQ(mExpected90Config, performanceRate);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {Fps(60), Fps(60)}}),
              0);

    auto minRate60 = getMinRefreshRateByPolicy(*refreshRateConfigs);
    auto performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();
    ASSERT_EQ(mExpected60Config, minRate60);
    ASSERT_EQ(mExpected60Config, performanceRate60);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getCurrentRefreshRate) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    {
        auto current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.getModeId(), HWC_CONFIG_ID_60);
    }

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);
    {
        auto current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.getModeId(), HWC_CONFIG_ID_90);
    }

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {Fps(90), Fps(90)}}),
              0);
    {
        auto current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.getModeId(), HWC_CONFIG_ID_90);
    }
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

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {Fps(60), Fps(60)}}),
              0);
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

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.name = "";
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {Fps(60), Fps(60)}}),
              0);

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_90, {Fps(90.0f), Fps(90.0f)}}),
              0);

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {Fps(0.0f), Fps(120.0f)}}),
              0);
    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
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

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
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

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(48.0f);
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(48.0f);
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

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.desiredRefreshRate = Fps(24.0f);
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = Fps(90.0f);
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

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
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

    lr.desiredRefreshRate = Fps(90.0f);
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = Fps(45.0f);
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = Fps(30.0f);
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr.desiredRefreshRate = Fps(24.0f);
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
    lr2.desiredRefreshRate = Fps(24.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = Fps(24.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = Fps(15.0f);
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(45.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = Fps(30.0f);
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = Fps(45.0f);
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
        lr.desiredRefreshRate = Fps(fps);
        const auto& refreshRate =
                refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false});
        EXPECT_EQ(mExpected60Config, refreshRate) << fps << "Hz chooses " << refreshRate.getName();
    }
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
    lr1.desiredRefreshRate = Fps(60.0f);
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = Fps(90.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = Fps(90.0f);
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = Fps(60.0f);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, testInPolicy) {
    ASSERT_TRUE(mExpectedAlmost60Config.inPolicy(Fps(60.000004f), Fps(60.000004f)));
    ASSERT_TRUE(mExpectedAlmost60Config.inPolicy(Fps(59.0f), Fps(60.1f)));
    ASSERT_FALSE(mExpectedAlmost60Config.inPolicy(Fps(75.0f), Fps(90.0f)));
    ASSERT_FALSE(mExpectedAlmost60Config.inPolicy(Fps(60.0011f), Fps(90.0f)));
    ASSERT_FALSE(mExpectedAlmost60Config.inPolicy(Fps(50.0f), Fps(59.998f)));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_75HzContent) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 75.0f; fps < 100.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps(fps);
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
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(30.0f);
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(90.0f);
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(30.0f);
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
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    // The other layer starts to provide buffers
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(90.0f);
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
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(true, consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(false, consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(60.0f);
    lr2.name = "60Hz Heuristic";
    refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false},
                                           &consideredSignals);
    EXPECT_EQ(true, consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = Fps(60.0f);
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = Fps(60.0f);
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
        lr.desiredRefreshRate = Fps(test.first);

        std::stringstream ss;
        ss << "ExplicitDefault " << test.first << " fps";
        lr.name = ss.str();

        const auto& refreshRate =
                refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false});
        EXPECT_TRUE(refreshRate.getFps().equalsWithMargin(Fps(test.second)))
                << "Expecting " << test.first << "fps => " << test.second << "Hz";
    }
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresTouchFlag) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_90);

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_90, {Fps(90.f), Fps(90.f)}, {Fps(60.f), Fps(90.f)}}),
              0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    RefreshRateConfigs::GlobalSignals consideredSignals;
    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = Fps(60.0f);
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
                      {HWC_CONFIG_ID_60, {Fps(60.f), Fps(60.f)}, {Fps(60.f), Fps(90.f)}}),
              0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = Fps(90.0f);
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
                      {HWC_CONFIG_ID_90, {Fps(90.f), Fps(90.f)}, {Fps(60.f), Fps(90.f)}}),
              0);

    RefreshRateConfigs::GlobalSignals consideredSignals;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate({}, {.touch = false, .idle = false},
                                                     &consideredSignals));
    EXPECT_EQ(false, consideredSignals.touch);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz ExplicitExactOrMultiple";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz ExplicitDefault";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Heuristic;
    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz Heuristic";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Max;
    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz Max";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.vote = LayerVoteType::Min;
    lr.desiredRefreshRate = Fps(60.0f);
    lr.name = "60Hz Min";
    lr.focused = false;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    lr.focused = true;
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, groupSwitchingNotAllowed) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    // The default policy doesn't allow group switching. Verify that no
    // group switches are performed.
    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = Fps(90.0f);
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;

    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayer) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = Fps(90.0f);
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;
    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayerOnlySeamless) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    // Verify that we won't change the group if seamless switch is required.
    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = Fps(90.0f);
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;
    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayerOnlySeamlessDefaultFps) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    // Verify that we won't do a seamless switch if we request the same mode as the default
    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = Fps(60.0f);
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;
    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayerDefaultSeamlessness) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    // Verify that if the current config is in another group and there are no layers with
    // seamlessness=SeamedAndSeamless we'll go back to the default group.

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = Fps(60.0f);
    layer.seamlessness = Seamlessness::Default;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;

    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithTwoLayersOnlySeamlessAndSeamed) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    // If there's a layer with seamlessness=SeamedAndSeamless, another layer with
    // seamlessness=OnlySeamless can't change the mode group.
    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].desiredRefreshRate = Fps(60.0f);
    layers[0].seamlessness = Seamlessness::OnlySeamless;
    layers[0].name = "60Hz ExplicitDefault";
    layers[0].focused = true;

    layers.push_back(LayerRequirement{.weight = 0.5f});
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].seamlessness = Seamlessness::SeamedAndSeamless;
    layers[1].desiredRefreshRate = Fps(90.0f);
    layers[1].name = "90Hz ExplicitDefault";
    layers[1].focused = false;

    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithTwoLayersDefaultFocusedAndSeamed) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    // If there's a focused layer with seamlessness=SeamedAndSeamless, another layer with
    // seamlessness=Default can't change the mode group back to the group of the default
    // mode.
    // For example, this may happen when a video playback requests and gets a seamed switch,
    // but another layer (with default seamlessness) starts animating. The animating layer
    // should not cause a seamed switch.
    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].seamlessness = Seamlessness::Default;
    layers[0].desiredRefreshRate = Fps(60.0f);
    layers[0].focused = true;
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].name = "60Hz ExplicitDefault";

    layers.push_back(LayerRequirement{.weight = 0.1f});
    layers[1].seamlessness = Seamlessness::SeamedAndSeamless;
    layers[1].desiredRefreshRate = Fps(90.0f);
    layers[1].focused = true;
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].name = "90Hz ExplicitDefault";

    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithTwoLayersDefaultNotFocusedAndSeamed) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);

    // Layer with seamlessness=Default can change the mode group if there's a not
    // focused layer with seamlessness=SeamedAndSeamless. This happens for example,
    // when in split screen mode the user switches between the two visible applications.
    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].seamlessness = Seamlessness::Default;
    layers[0].desiredRefreshRate = Fps(60.0f);
    layers[0].focused = true;
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].name = "60Hz ExplicitDefault";

    layers.push_back(LayerRequirement{.weight = 0.7f});
    layers[1].seamlessness = Seamlessness::SeamedAndSeamless;
    layers[1].desiredRefreshRate = Fps(90.0f);
    layers[1].focused = false;
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].name = "90Hz ExplicitDefault";

    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, nonSeamlessVotePrefersSeamlessSwitches) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitExactOrMultiple;
    layer.desiredRefreshRate = Fps(60.0f);
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "60Hz ExplicitExactOrMultiple";
    layer.focused = true;

    ASSERT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_120);
    ASSERT_EQ(HWC_CONFIG_ID_120,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, nonSeamlessExactAndSeamlessMultipleLayers) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m25_30_50_60Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    auto layers = std::vector<
            LayerRequirement>{LayerRequirement{.name = "60Hz ExplicitDefault",
                                               .vote = LayerVoteType::ExplicitDefault,
                                               .desiredRefreshRate = Fps(60.0f),
                                               .seamlessness = Seamlessness::SeamedAndSeamless,
                                               .weight = 0.5f,
                                               .focused = false},
                              LayerRequirement{.name = "25Hz ExplicitExactOrMultiple",
                                               .vote = LayerVoteType::ExplicitExactOrMultiple,
                                               .desiredRefreshRate = Fps(25.0f),
                                               .seamlessness = Seamlessness::OnlySeamless,
                                               .weight = 1.0f,
                                               .focused = true}};

    ASSERT_EQ(HWC_CONFIG_ID_50,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());

    auto& seamedLayer = layers[0];
    seamedLayer.name = "30Hz ExplicitDefault", seamedLayer.desiredRefreshRate = Fps(30.0f);
    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_30);

    ASSERT_EQ(HWC_CONFIG_ID_25,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, minLayersDontTrigerSeamedSwitch) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90DeviceWithDifferentGroups,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_90);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = refreshRateConfigs->getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(policy), 0);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.name = "Min",
                                                                 .vote = LayerVoteType::Min,
                                                                 .weight = 1.f,
                                                                 .focused = true}};

    ASSERT_EQ(HWC_CONFIG_ID_90,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false})
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, primaryVsAppRequestPolicy) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].name = "Test layer";

    // Return the config ID from calling getBestRefreshRate() for a single layer with the
    // given voteType and fps.
    auto getFrameRate = [&](LayerVoteType voteType, Fps fps, bool touchActive = false,
                            bool focused = true) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = fps;
        layers[0].focused = focused;
        return refreshRateConfigs->getBestRefreshRate(layers, {.touch = touchActive, .idle = false})
                .getModeId();
    };

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {Fps(30.f), Fps(60.f)}, {Fps(30.f), Fps(90.f)}}),
              0);
    EXPECT_EQ(HWC_CONFIG_ID_60,
              refreshRateConfigs->getBestRefreshRate({}, {.touch = false, .idle = false})
                      .getModeId());
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::NoVote, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_30, getFrameRate(LayerVoteType::Min, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Max, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Heuristic, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_90, getFrameRate(LayerVoteType::ExplicitDefault, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, Fps(90.f)));

    // Layers not focused are not allowed to override primary config
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getFrameRate(LayerVoteType::ExplicitDefault, Fps(90.f), /*touch=*/false,
                           /*focused=*/false));
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getFrameRate(LayerVoteType::ExplicitExactOrMultiple, Fps(90.f), /*touch=*/false,
                           /*focused=*/false));

    // Touch boost should be restricted to the primary range.
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Max, Fps(90.f), /*touch=*/true));
    // When we're higher than the primary range max due to a layer frame rate setting, touch boost
    // shouldn't drag us back down to the primary range max.
    EXPECT_EQ(HWC_CONFIG_ID_90,
              getFrameRate(LayerVoteType::ExplicitDefault, Fps(90.f), /*touch=*/true));
    EXPECT_EQ(HWC_CONFIG_ID_60,
              getFrameRate(LayerVoteType::ExplicitExactOrMultiple, Fps(90.f), /*touch=*/true));

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {Fps(60.f), Fps(60.f)}, {Fps(60.f), Fps(60.f)}}),
              0);
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::NoVote, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Min, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Max, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::Heuristic, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::ExplicitDefault, Fps(90.f)));
    EXPECT_EQ(HWC_CONFIG_ID_60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, Fps(90.f)));
}

TEST_F(RefreshRateConfigsTest, idle) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].name = "Test layer";

    const auto getIdleFrameRate = [&](LayerVoteType voteType, bool touchActive) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = Fps(90.f);
        RefreshRateConfigs::GlobalSignals consideredSignals;
        const auto configId =
                refreshRateConfigs
                        ->getBestRefreshRate(layers, {.touch = touchActive, .idle = true},
                                             &consideredSignals)
                        .getModeId();
        // Refresh rate will be chosen by either touch state or idle state
        EXPECT_EQ(!touchActive, consideredSignals.idle);
        return configId;
    };

    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy(
                      {HWC_CONFIG_ID_60, {Fps(60.f), Fps(90.f)}, {Fps(60.f), Fps(90.f)}}),
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
                      .getModeId());

    // Idle should be higher precedence than other layer frame rate considerations.
    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);
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
                      .getModeId());
}

TEST_F(RefreshRateConfigsTest, findClosestKnownFrameRate) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    for (float fps = 1.0f; fps <= 120.0f; fps += 0.1f) {
        const auto knownFrameRate = findClosestKnownFrameRate(*refreshRateConfigs, Fps(fps));
        Fps expectedFrameRate;
        if (fps < 26.91f) {
            expectedFrameRate = Fps(24.0f);
        } else if (fps < 37.51f) {
            expectedFrameRate = Fps(30.0f);
        } else if (fps < 52.51f) {
            expectedFrameRate = Fps(45.0f);
        } else if (fps < 66.01f) {
            expectedFrameRate = Fps(60.0f);
        } else if (fps < 81.01f) {
            expectedFrameRate = Fps(72.0f);
        } else {
            expectedFrameRate = Fps(90.0f);
        }
        EXPECT_TRUE(expectedFrameRate.equalsWithMargin(knownFrameRate))
                << "findClosestKnownFrameRate(" << fps << ") = " << knownFrameRate;
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_KnownFrameRate) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m60_90Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    struct ExpectedRate {
        Fps rate;
        const RefreshRate& expected;
    };

    /* clang-format off */
    std::vector<ExpectedRate> knownFrameRatesExpectations = {
        {Fps(24.0f), mExpected60Config},
        {Fps(30.0f), mExpected60Config},
        {Fps(45.0f), mExpected90Config},
        {Fps(60.0f), mExpected60Config},
        {Fps(72.0f), mExpected90Config},
        {Fps(90.0f), mExpected90Config},
    };
    /* clang-format on */

    // Make sure the test tests all the known frame rate
    const auto knownFrameRateList = getKnownFrameRate(*refreshRateConfigs);
    const auto equal =
            std::equal(knownFrameRateList.begin(), knownFrameRateList.end(),
                       knownFrameRatesExpectations.begin(),
                       [](Fps a, const ExpectedRate& b) { return a.equalsWithMargin(b.rate); });
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

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitExact) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = Fps(60);

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = Fps(30);

    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected30Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    explicitExactOrMultipleLayer.desiredRefreshRate = Fps(120);
    explicitExactLayer.desiredRefreshRate = Fps(60);
    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    explicitExactLayer.desiredRefreshRate = Fps(72);
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    explicitExactLayer.desiredRefreshRate = Fps(90);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    explicitExactLayer.desiredRefreshRate = Fps(120);
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitExactEnableFrameRateOverride) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60,
                                                 /*enableFrameRateOverride=*/true);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f},
                                                LayerRequirement{.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = Fps(60);

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = Fps(30);

    EXPECT_EQ(mExpected60Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = true, .idle = false}));

    explicitExactOrMultipleLayer.desiredRefreshRate = Fps(120);
    explicitExactLayer.desiredRefreshRate = Fps(60);
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    explicitExactLayer.desiredRefreshRate = Fps(72);
    EXPECT_EQ(mExpected72Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    explicitExactLayer.desiredRefreshRate = Fps(90);
    EXPECT_EQ(mExpected90Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));

    explicitExactLayer.desiredRefreshRate = Fps(120);
    EXPECT_EQ(mExpected120Config,
              refreshRateConfigs->getBestRefreshRate(layers, {.touch = false, .idle = false}));
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
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {Fps(60), Fps(90)}}),
              0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, refreshRateConfigs->getIdleTimerAction());

    // SetPolicy(60, 60), current 60Hz => NoChange, avoid extra calls.
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_60, {Fps(60), Fps(60)}}),
              0);
    EXPECT_EQ(KernelIdleTimerAction::NoChange, refreshRateConfigs->getIdleTimerAction());

    // SetPolicy(90, 90), current 90Hz => TurnOff.
    ASSERT_GE(refreshRateConfigs->setDisplayManagerPolicy({HWC_CONFIG_ID_90, {Fps(90), Fps(90)}}),
              0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, refreshRateConfigs->getIdleTimerAction());
}

TEST_F(RefreshRateConfigsTest, getFrameRateDivider) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_30);

    const auto frameRate = Fps(30.f);
    Fps displayRefreshRate = refreshRateConfigs->getCurrentRefreshRate().getFps();
    EXPECT_EQ(1, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, frameRate));

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_60);
    displayRefreshRate = refreshRateConfigs->getCurrentRefreshRate().getFps();
    EXPECT_EQ(2, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, frameRate));

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_72);
    displayRefreshRate = refreshRateConfigs->getCurrentRefreshRate().getFps();
    EXPECT_EQ(0, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, frameRate));

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);
    displayRefreshRate = refreshRateConfigs->getCurrentRefreshRate().getFps();
    EXPECT_EQ(3, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, frameRate));

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_120);
    displayRefreshRate = refreshRateConfigs->getCurrentRefreshRate().getFps();
    EXPECT_EQ(4, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, frameRate));

    refreshRateConfigs->setCurrentModeId(HWC_CONFIG_ID_90);
    displayRefreshRate = refreshRateConfigs->getCurrentRefreshRate().getFps();
    EXPECT_EQ(4, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, Fps(22.5f)));
    EXPECT_EQ(4, RefreshRateConfigs::getFrameRateDivider(displayRefreshRate, Fps(22.6f)));
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_noLayers) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device, /*currentConfigId=*/
                                                 HWC_CONFIG_ID_120);

    auto layers = std::vector<LayerRequirement>{};
    ASSERT_TRUE(refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false)
                        .empty());
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_60on120) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device, /*currentConfigId=*/
                                                 HWC_CONFIG_ID_120,
                                                 /*enableFrameRateOverride=*/true);

    auto layers = std::vector<LayerRequirement>{LayerRequirement{.weight = 1.0f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = Fps(60.0f);
    layers[0].vote = LayerVoteType::ExplicitDefault;
    auto frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    layers[0].vote = LayerVoteType::NoVote;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Min;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Max;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Heuristic;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_twoUids) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device, /*currentConfigId=*/
                                                 HWC_CONFIG_ID_120,
                                                 /*enableFrameRateOverride=*/true);

    auto layers = std::vector<LayerRequirement>{
            LayerRequirement{.ownerUid = 1234, .weight = 1.0f},
            LayerRequirement{.ownerUid = 5678, .weight = 1.0f},
    };

    layers[0].name = "Test layer 1234";
    layers[0].desiredRefreshRate = Fps(60.0f);
    layers[0].vote = LayerVoteType::ExplicitDefault;

    layers[1].name = "Test layer 5678";
    layers[1].desiredRefreshRate = Fps(30.0f);
    layers[1].vote = LayerVoteType::ExplicitDefault;
    auto frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);

    ASSERT_EQ(2, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());
    ASSERT_EQ(1, frameRateOverrides.count(5678));
    ASSERT_EQ(30.0f, frameRateOverrides.at(5678).getValue());

    layers[1].vote = LayerVoteType::Heuristic;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    layers[1].ownerUid = 1234;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_touch) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device, /*currentConfigId=*/
                                                 HWC_CONFIG_ID_120,
                                                 /*enableFrameRateOverride=*/true);

    auto layers = std::vector<LayerRequirement>{
            LayerRequirement{.ownerUid = 1234, .weight = 1.0f},
    };

    layers[0].name = "Test layer";
    layers[0].desiredRefreshRate = Fps(60.0f);
    layers[0].vote = LayerVoteType::ExplicitDefault;

    auto frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/true);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    layers[0].vote = LayerVoteType::ExplicitExact;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/true);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/false);
    ASSERT_EQ(1, frameRateOverrides.size());
    ASSERT_EQ(1, frameRateOverrides.count(1234));
    ASSERT_EQ(60.0f, frameRateOverrides.at(1234).getValue());

    frameRateOverrides =
            refreshRateConfigs->getFrameRateOverrides(layers, Fps(120.0f), /*touch=*/true);
    ASSERT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateConfigsTest, updateDisplayModes) {
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(m30_60_72_90_120Device,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_30);
    refreshRateConfigs->setDisplayManagerPolicy({DisplayModeId(HWC_CONFIG_ID_30),
                                                 /* allowGroupSwitching */ false,
                                                 /* range */ {Fps(30.0f), Fps(30.0f)}});

    refreshRateConfigs->updateDisplayModes(m60_90Device, HWC_CONFIG_ID_60);

    const auto currentRefreshRate = refreshRateConfigs->getCurrentRefreshRate();
    EXPECT_TRUE(currentRefreshRate.getFps().equalsWithMargin(Fps(60.0)));
    EXPECT_EQ(currentRefreshRate.getModeId(), HWC_CONFIG_ID_60);

    EXPECT_TRUE(
            getMaxSupportedRefreshRate(*refreshRateConfigs).getFps().equalsWithMargin(Fps(90.0)));
    EXPECT_TRUE(
            getMinSupportedRefreshRate(*refreshRateConfigs).getFps().equalsWithMargin(Fps(60.0)));
}

} // namespace
} // namespace scheduler
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
