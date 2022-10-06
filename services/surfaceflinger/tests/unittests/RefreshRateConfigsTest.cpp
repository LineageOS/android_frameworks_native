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

#include <ftl/enum.h>
#include <gmock/gmock.h>
#include <log/log.h>
#include <ui/Size.h>

#include "DisplayHardware/HWC2.h"
#include "FpsOps.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "mock/DisplayHardware/MockDisplayMode.h"

using namespace std::chrono_literals;

namespace android::scheduler {

namespace hal = android::hardware::graphics::composer::hal;

using LayerVoteType = RefreshRateConfigs::LayerVoteType;
using LayerRequirement = RefreshRateConfigs::LayerRequirement;

using mock::createDisplayMode;

struct TestableRefreshRateConfigs : RefreshRateConfigs {
    using RefreshRateConfigs::RefreshRateConfigs;

    DisplayModePtr getMinSupportedRefreshRate() const {
        std::lock_guard lock(mLock);
        return mMinRefreshRateModeIt->second;
    }

    DisplayModePtr getMaxSupportedRefreshRate() const {
        std::lock_guard lock(mLock);
        return mMaxRefreshRateModeIt->second;
    }

    DisplayModePtr getMinRefreshRateByPolicy() const {
        std::lock_guard lock(mLock);
        return getMinRefreshRateByPolicyLocked();
    }

    const std::vector<Fps>& knownFrameRates() const { return mKnownFrameRates; }

    using RefreshRateConfigs::GetBestRefreshRateCache;
    auto& mutableGetBestRefreshRateCache() { return mGetBestRefreshRateCache; }

    auto getBestRefreshRateAndSignals(const std::vector<LayerRequirement>& layers,
                                      GlobalSignals signals) const {
        return RefreshRateConfigs::getBestRefreshRate(layers, signals);
    }

    DisplayModePtr getBestRefreshRate(const std::vector<LayerRequirement>& layers = {},
                                      GlobalSignals signals = {}) const {
        return getBestRefreshRateAndSignals(layers, signals).first;
    }
};

class RefreshRateConfigsTest : public testing::Test {
protected:
    RefreshRateConfigsTest();
    ~RefreshRateConfigsTest();

    static constexpr DisplayModeId kModeId60{0};
    static constexpr DisplayModeId kModeId90{1};
    static constexpr DisplayModeId kModeId72{2};
    static constexpr DisplayModeId kModeId120{3};
    static constexpr DisplayModeId kModeId30{4};
    static constexpr DisplayModeId kModeId25{5};
    static constexpr DisplayModeId kModeId50{6};
    static constexpr DisplayModeId kModeId24{7};
    static constexpr DisplayModeId kModeId24Frac{8};
    static constexpr DisplayModeId kModeId30Frac{9};
    static constexpr DisplayModeId kModeId60Frac{10};

    static inline const DisplayModePtr kMode60 = createDisplayMode(kModeId60, 60_Hz);
    static inline const DisplayModePtr kMode60Frac = createDisplayMode(kModeId60Frac, 59.94_Hz);
    static inline const DisplayModePtr kMode90 = createDisplayMode(kModeId90, 90_Hz);
    static inline const DisplayModePtr kMode90_G1 = createDisplayMode(kModeId90, 90_Hz, 1);
    static inline const DisplayModePtr kMode90_4K =
            createDisplayMode(kModeId90, 90_Hz, 0, {3840, 2160});
    static inline const DisplayModePtr kMode72 = createDisplayMode(kModeId72, 72_Hz);
    static inline const DisplayModePtr kMode72_G1 = createDisplayMode(kModeId72, 72_Hz, 1);
    static inline const DisplayModePtr kMode120 = createDisplayMode(kModeId120, 120_Hz);
    static inline const DisplayModePtr kMode120_G1 = createDisplayMode(kModeId120, 120_Hz, 1);
    static inline const DisplayModePtr kMode30 = createDisplayMode(kModeId30, 30_Hz);
    static inline const DisplayModePtr kMode30_G1 = createDisplayMode(kModeId30, 30_Hz, 1);
    static inline const DisplayModePtr kMode30Frac = createDisplayMode(kModeId30Frac, 29.97_Hz);
    static inline const DisplayModePtr kMode25 = createDisplayMode(kModeId25, 25_Hz);
    static inline const DisplayModePtr kMode25_G1 = createDisplayMode(kModeId25, 25_Hz, 1);
    static inline const DisplayModePtr kMode50 = createDisplayMode(kModeId50, 50_Hz);
    static inline const DisplayModePtr kMode24 = createDisplayMode(kModeId24, 24_Hz);
    static inline const DisplayModePtr kMode24Frac = createDisplayMode(kModeId24Frac, 23.976_Hz);

    // Test configurations.
    static inline const DisplayModes kModes_60 = makeModes(kMode60);
    static inline const DisplayModes kModes_60_90 = makeModes(kMode60, kMode90);
    static inline const DisplayModes kModes_60_90_G1 = makeModes(kMode60, kMode90_G1);
    static inline const DisplayModes kModes_60_90_4K = makeModes(kMode60, kMode90_4K);
    static inline const DisplayModes kModes_60_72_90 = makeModes(kMode60, kMode90, kMode72);
    static inline const DisplayModes kModes_60_90_72_120 =
            makeModes(kMode60, kMode90, kMode72, kMode120);
    static inline const DisplayModes kModes_30_60_72_90_120 =
            makeModes(kMode60, kMode90, kMode72, kMode120, kMode30);

    static inline const DisplayModes kModes_30_60 =
            makeModes(kMode60, kMode90_G1, kMode72_G1, kMode120_G1, kMode30);
    static inline const DisplayModes kModes_30_60_72_90 =
            makeModes(kMode60, kMode90, kMode72, kMode120_G1, kMode30);
    static inline const DisplayModes kModes_30_60_90 =
            makeModes(kMode60, kMode90, kMode72_G1, kMode120_G1, kMode30);
    static inline const DisplayModes kModes_25_30_50_60 =
            makeModes(kMode60, kMode90, kMode72_G1, kMode120_G1, kMode30_G1, kMode25_G1, kMode50);
    static inline const DisplayModes kModes_60_120 = makeModes(kMode60, kMode120);

    // This is a typical TV configuration.
    static inline const DisplayModes kModes_24_25_30_50_60_Frac =
            makeModes(kMode24, kMode24Frac, kMode25, kMode30, kMode30Frac, kMode50, kMode60,
                      kMode60Frac);
};

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

namespace {

TEST_F(RefreshRateConfigsTest, oneMode_canSwitch) {
    RefreshRateConfigs configs(kModes_60, kModeId60);
    EXPECT_FALSE(configs.canSwitch());
}

TEST_F(RefreshRateConfigsTest, invalidPolicy) {
    RefreshRateConfigs configs(kModes_60, kModeId60);
    EXPECT_LT(configs.setDisplayManagerPolicy({DisplayModeId(10), {60_Hz, 60_Hz}}), 0);
    EXPECT_LT(configs.setDisplayManagerPolicy({kModeId60, {20_Hz, 40_Hz}}), 0);
}

TEST_F(RefreshRateConfigsTest, twoModes_storesFullRefreshRateMap) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    const auto minRate = configs.getMinSupportedRefreshRate();
    const auto performanceRate = configs.getMaxSupportedRefreshRate();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode90, performanceRate);

    const auto minRateByPolicy = configs.getMinRefreshRateByPolicy();
    const auto performanceRateByPolicy = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(minRateByPolicy, minRate);
    EXPECT_EQ(performanceRateByPolicy, performanceRate);
}

TEST_F(RefreshRateConfigsTest, twoModes_storesFullRefreshRateMap_differentGroups) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    const auto minRate = configs.getMinRefreshRateByPolicy();
    const auto performanceRate = configs.getMaxSupportedRefreshRate();
    const auto minRate60 = configs.getMinRefreshRateByPolicy();
    const auto performanceRate60 = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}), 0);
    configs.setActiveModeId(kModeId90);

    const auto minRate90 = configs.getMinRefreshRateByPolicy();
    const auto performanceRate90 = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode90_G1, performanceRate);
    EXPECT_EQ(kMode90_G1, minRate90);
    EXPECT_EQ(kMode90_G1, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoModes_storesFullRefreshRateMap_differentResolutions) {
    TestableRefreshRateConfigs configs(kModes_60_90_4K, kModeId60);

    const auto minRate = configs.getMinRefreshRateByPolicy();
    const auto performanceRate = configs.getMaxSupportedRefreshRate();
    const auto minRate60 = configs.getMinRefreshRateByPolicy();
    const auto performanceRate60 = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}), 0);
    configs.setActiveModeId(kModeId90);

    const auto minRate90 = configs.getMinRefreshRateByPolicy();
    const auto performanceRate90 = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode90_4K, performanceRate);
    EXPECT_EQ(kMode90_4K, minRate90);
    EXPECT_EQ(kMode90_4K, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoModes_policyChange) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    const auto minRate = configs.getMinRefreshRateByPolicy();
    const auto performanceRate = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode90, performanceRate);

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}), 0);

    const auto minRate60 = configs.getMinRefreshRateByPolicy();
    const auto performanceRate60 = configs.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);
}

TEST_F(RefreshRateConfigsTest, twoModes_getActiveMode) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);
    {
        const auto mode = configs.getActiveMode();
        EXPECT_EQ(mode->getId(), kModeId60);
    }

    configs.setActiveModeId(kModeId90);
    {
        const auto mode = configs.getActiveMode();
        EXPECT_EQ(mode->getId(), kModeId90);
    }

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}), 0);
    {
        const auto mode = configs.getActiveMode();
        EXPECT_EQ(mode->getId(), kModeId90);
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_noLayers) {
    {
        TestableRefreshRateConfigs configs(kModes_60_72_90, kModeId72);

        // If there are no layers we select the default frame rate, which is the max of the primary
        // range.
        EXPECT_EQ(kMode90, configs.getBestRefreshRate());

        EXPECT_EQ(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}), NO_ERROR);
        EXPECT_EQ(kMode60, configs.getBestRefreshRate());
    }
    {
        // We select max even when this will cause a non-seamless switch.
        TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);
        constexpr bool kAllowGroupSwitching = true;
        EXPECT_EQ(configs.setDisplayManagerPolicy({kModeId90, kAllowGroupSwitching, {0_Hz, 90_Hz}}),
                  NO_ERROR);
        EXPECT_EQ(kMode90_G1, configs.getBestRefreshRate());
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_60_90) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.name = "";
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}), 0);

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}), 0);

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {0_Hz, 120_Hz}}), 0);
    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_multipleThreshold_60_90) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60, {.frameRateMultipleThreshold = 90});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_60_72_90) {
    TestableRefreshRateConfigs configs(kModes_60_72_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_72_90_120) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_90_120_DifferentTypes) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_90_120_DifferentTypes_multipleThreshold) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60,
                                       {.frameRateMultipleThreshold = 120});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];
    auto& lr3 = layers[2];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "120Hz ExplicitDefault";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::ExplicitExact;
    lr2.name = "120Hz ExplicitExact";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 10_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "120Hz ExplicitExact";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 30_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 30_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "30Hz ExplicitExactOrMultiple";
    lr3.vote = LayerVoteType::Heuristic;
    lr3.desiredRefreshRate = 120_Hz;
    lr3.name = "120Hz Heuristic";
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60) {
    TestableRefreshRateConfigs configs(kModes_30_60, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode30, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode30, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_30_60_72_90) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode30, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode30, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 24_Hz;
    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.name = "24Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_PriorityTest) {
    TestableRefreshRateConfigs configs(kModes_30_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 15_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 30_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_24FpsVideo) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = configs.getBestRefreshRate(layers);
        EXPECT_EQ(kMode60, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getFps());
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_24FpsVideo_multipleThreshold_60_120) {
    TestableRefreshRateConfigs configs(kModes_60_120, kModeId60,
                                       {.frameRateMultipleThreshold = 120});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = configs.getBestRefreshRate(layers);
        EXPECT_EQ(kMode60, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getFps());
    }
}

TEST_F(RefreshRateConfigsTest, twoModes_getBestRefreshRate_Explicit) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_75HzContent) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 75.0f; fps < 100.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = configs.getBestRefreshRate(layers, {});
        EXPECT_EQ(kMode90, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getFps());
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_Multiples) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, scrollWhileWatching60fps_60_90) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.touch = true}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    // The other layer starts to provide buffers
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, touchConsidered) {
    RefreshRateConfigs configs(kModes_60_90, kModeId60);

    auto [_, signals] = configs.getBestRefreshRate({}, {});
    EXPECT_FALSE(signals.touch);

    std::tie(std::ignore, signals) = configs.getBestRefreshRate({}, {.touch = true});
    EXPECT_TRUE(signals.touch);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = configs.getBestRefreshRate(layers, {.touch = true});
    EXPECT_TRUE(signals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = configs.getBestRefreshRate(layers, {.touch = true});
    EXPECT_FALSE(signals.touch);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = configs.getBestRefreshRate(layers, {.touch = true});
    EXPECT_TRUE(signals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = configs.getBestRefreshRate(layers, {.touch = true});
    EXPECT_FALSE(signals.touch);
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitDefault) {
    TestableRefreshRateConfigs configs(kModes_60_90_72_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Prepare a table with the vote and the expected refresh rate
    const std::initializer_list<std::pair<Fps, Fps>> testCases = {
            {130_Hz, 120_Hz}, {120_Hz, 120_Hz}, {119_Hz, 120_Hz}, {110_Hz, 120_Hz},

            {100_Hz, 90_Hz},  {90_Hz, 90_Hz},   {89_Hz, 90_Hz},

            {80_Hz, 72_Hz},   {73_Hz, 72_Hz},   {72_Hz, 72_Hz},   {71_Hz, 72_Hz},   {70_Hz, 72_Hz},

            {65_Hz, 60_Hz},   {60_Hz, 60_Hz},   {59_Hz, 60_Hz},   {58_Hz, 60_Hz},

            {55_Hz, 90_Hz},   {50_Hz, 90_Hz},   {45_Hz, 90_Hz},

            {42_Hz, 120_Hz},  {40_Hz, 120_Hz},  {39_Hz, 120_Hz},

            {37_Hz, 72_Hz},   {36_Hz, 72_Hz},   {35_Hz, 72_Hz},

            {30_Hz, 60_Hz},
    };

    for (auto [desired, expected] : testCases) {
        lr.vote = LayerVoteType::ExplicitDefault;
        lr.desiredRefreshRate = desired;

        std::stringstream ss;
        ss << "ExplicitDefault " << desired;
        lr.name = ss.str();

        EXPECT_EQ(expected, configs.getBestRefreshRate(layers)->getFps());
    }
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_ExplicitExactOrMultiple_WithFractionalRefreshRates) {
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Test that 23.976 will choose 24 if 23.976 is not supported
    {
        TestableRefreshRateConfigs configs(makeModes(kMode24, kMode25, kMode30, kMode30Frac,
                                                     kMode60, kMode60Frac),
                                           kModeId60);

        lr.vote = LayerVoteType::ExplicitExactOrMultiple;
        lr.desiredRefreshRate = 23.976_Hz;
        lr.name = "ExplicitExactOrMultiple 23.976 Hz";
        EXPECT_EQ(kModeId24, configs.getBestRefreshRate(layers)->getId());
    }

    // Test that 24 will choose 23.976 if 24 is not supported
    {
        TestableRefreshRateConfigs configs(makeModes(kMode24Frac, kMode25, kMode30, kMode30Frac,
                                                     kMode60, kMode60Frac),
                                           kModeId60);

        lr.desiredRefreshRate = 24_Hz;
        lr.name = "ExplicitExactOrMultiple 24 Hz";
        EXPECT_EQ(kModeId24Frac, configs.getBestRefreshRate(layers)->getId());
    }

    // Test that 29.97 will prefer 59.94 over 60 and 30
    {
        TestableRefreshRateConfigs configs(makeModes(kMode24, kMode24Frac, kMode25, kMode30,
                                                     kMode60, kMode60Frac),
                                           kModeId60);

        lr.desiredRefreshRate = 29.97_Hz;
        lr.name = "ExplicitExactOrMultiple 29.97 Hz";
        EXPECT_EQ(kModeId60Frac, configs.getBestRefreshRate(layers)->getId());
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitExact_WithFractionalRefreshRates) {
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Test that voting for supported refresh rate will select this refresh rate
    {
        TestableRefreshRateConfigs configs(kModes_24_25_30_50_60_Frac, kModeId60);

        for (auto desired : {23.976_Hz, 24_Hz, 25_Hz, 29.97_Hz, 30_Hz, 50_Hz, 59.94_Hz, 60_Hz}) {
            lr.vote = LayerVoteType::ExplicitExact;
            lr.desiredRefreshRate = desired;
            std::stringstream ss;
            ss << "ExplicitExact " << desired;
            lr.name = ss.str();

            EXPECT_EQ(lr.desiredRefreshRate, configs.getBestRefreshRate(layers)->getFps());
        }
    }

    // Test that 23.976 will choose 24 if 23.976 is not supported
    {
        TestableRefreshRateConfigs configs(makeModes(kMode24, kMode25, kMode30, kMode30Frac,
                                                     kMode60, kMode60Frac),
                                           kModeId60);

        lr.vote = LayerVoteType::ExplicitExact;
        lr.desiredRefreshRate = 23.976_Hz;
        lr.name = "ExplicitExact 23.976 Hz";
        EXPECT_EQ(kModeId24, configs.getBestRefreshRate(layers)->getId());
    }

    // Test that 24 will choose 23.976 if 24 is not supported
    {
        TestableRefreshRateConfigs configs(makeModes(kMode24Frac, kMode25, kMode30, kMode30Frac,
                                                     kMode60, kMode60Frac),
                                           kModeId60);

        lr.desiredRefreshRate = 24_Hz;
        lr.name = "ExplicitExact 24 Hz";
        EXPECT_EQ(kModeId24Frac, configs.getBestRefreshRate(layers)->getId());
    }
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresTouchFlag) {
    RefreshRateConfigs configs(kModes_60_90, kModeId90);

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}, {60_Hz, 90_Hz}}), 0);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = true;

    const auto [mode, signals] = configs.getBestRefreshRate(layers, {.touch = true, .idle = true});

    EXPECT_EQ(mode, kMode60);
    EXPECT_FALSE(signals.touch);
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresIdleFlag) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}, {60_Hz, 90_Hz}}), 0);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 90_Hz;
    lr.name = "90Hz ExplicitDefault";
    lr.focused = true;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers, {.idle = true}));
}

TEST_F(RefreshRateConfigsTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_onlySwitchesRatesForExplicitFocusedLayers) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId90);

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}, {60_Hz, 90_Hz}}), 0);

    const auto [mode, signals] = configs.getBestRefreshRateAndSignals({}, {});
    EXPECT_EQ(mode, kMode90);
    EXPECT_FALSE(signals.touch);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitExactOrMultiple";
    lr.focused = false;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = false;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Heuristic;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    lr.focused = false;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Max";
    lr.focused = false;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Min;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Min";
    lr.focused = false;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, groupSwitchingNotAllowed) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    // The default policy doesn't allow group switching. Verify that no
    // group switches are performed.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;

    EXPECT_EQ(kModeId60, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayer) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId90, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayerOnlySeamless) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    // Verify that we won't change the group if seamless switch is required.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId60, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayerOnlySeamlessDefaultFps) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    configs.setActiveModeId(kModeId90);

    // Verify that we won't do a seamless switch if we request the same mode as the default
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId90, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithOneLayerDefaultSeamlessness) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    configs.setActiveModeId(kModeId90);

    // Verify that if the current config is in another group and there are no layers with
    // seamlessness=SeamedAndSeamless we'll go back to the default group.

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::Default;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;

    EXPECT_EQ(kModeId60, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithTwoLayersOnlySeamlessAndSeamed) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    configs.setActiveModeId(kModeId90);

    // If there's a layer with seamlessness=SeamedAndSeamless, another layer with
    // seamlessness=OnlySeamless can't change the mode group.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].seamlessness = Seamlessness::OnlySeamless;
    layers[0].name = "60Hz ExplicitDefault";
    layers[0].focused = true;

    layers.push_back(LayerRequirement{.weight = 0.5f});
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].seamlessness = Seamlessness::SeamedAndSeamless;
    layers[1].desiredRefreshRate = 90_Hz;
    layers[1].name = "90Hz ExplicitDefault";
    layers[1].focused = false;

    EXPECT_EQ(kModeId90, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithTwoLayersDefaultFocusedAndSeamed) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    configs.setActiveModeId(kModeId90);

    // If there's a focused layer with seamlessness=SeamedAndSeamless, another layer with
    // seamlessness=Default can't change the mode group back to the group of the default
    // mode.
    // For example, this may happen when a video playback requests and gets a seamed switch,
    // but another layer (with default seamlessness) starts animating. The animating layer
    // should not cause a seamed switch.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].seamlessness = Seamlessness::Default;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].focused = true;
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].name = "60Hz ExplicitDefault";

    layers.push_back(LayerRequirement{.weight = 0.1f});
    layers[1].seamlessness = Seamlessness::SeamedAndSeamless;
    layers[1].desiredRefreshRate = 90_Hz;
    layers[1].focused = true;
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].name = "90Hz ExplicitDefault";

    EXPECT_EQ(kModeId90, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, groupSwitchingWithTwoLayersDefaultNotFocusedAndSeamed) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId60);

    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    configs.setActiveModeId(kModeId90);

    // Layer with seamlessness=Default can change the mode group if there's a not
    // focused layer with seamlessness=SeamedAndSeamless. This happens for example,
    // when in split screen mode the user switches between the two visible applications.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].seamlessness = Seamlessness::Default;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].focused = true;
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].name = "60Hz ExplicitDefault";

    layers.push_back(LayerRequirement{.weight = 0.7f});
    layers[1].seamlessness = Seamlessness::SeamedAndSeamless;
    layers[1].desiredRefreshRate = 90_Hz;
    layers[1].focused = false;
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].name = "90Hz ExplicitDefault";

    EXPECT_EQ(kModeId60, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, nonSeamlessVotePrefersSeamlessSwitches) {
    TestableRefreshRateConfigs configs(kModes_30_60, kModeId60);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitExactOrMultiple;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "60Hz ExplicitExactOrMultiple";
    layer.focused = true;

    EXPECT_EQ(kModeId60, configs.getBestRefreshRate(layers)->getId());

    configs.setActiveModeId(kModeId120);
    EXPECT_EQ(kModeId120, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, nonSeamlessExactAndSeamlessMultipleLayers) {
    TestableRefreshRateConfigs configs(kModes_25_30_50_60, kModeId60);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    std::vector<LayerRequirement> layers = {{.name = "60Hz ExplicitDefault",
                                             .vote = LayerVoteType::ExplicitDefault,
                                             .desiredRefreshRate = 60_Hz,
                                             .seamlessness = Seamlessness::SeamedAndSeamless,
                                             .weight = 0.5f,
                                             .focused = false},
                                            {.name = "25Hz ExplicitExactOrMultiple",
                                             .vote = LayerVoteType::ExplicitExactOrMultiple,
                                             .desiredRefreshRate = 25_Hz,
                                             .seamlessness = Seamlessness::OnlySeamless,
                                             .weight = 1.f,
                                             .focused = true}};

    EXPECT_EQ(kModeId50, configs.getBestRefreshRate(layers)->getId());

    auto& seamedLayer = layers[0];
    seamedLayer.desiredRefreshRate = 30_Hz;
    seamedLayer.name = "30Hz ExplicitDefault";
    configs.setActiveModeId(kModeId30);

    EXPECT_EQ(kModeId25, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, minLayersDontTrigerSeamedSwitch) {
    TestableRefreshRateConfigs configs(kModes_60_90_G1, kModeId90);

    // Allow group switching.
    RefreshRateConfigs::Policy policy;
    policy.defaultMode = configs.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_GE(configs.setDisplayManagerPolicy(policy), 0);

    std::vector<LayerRequirement> layers = {
            {.name = "Min", .vote = LayerVoteType::Min, .weight = 1.f, .focused = true}};

    EXPECT_EQ(kModeId90, configs.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateConfigsTest, primaryVsAppRequestPolicy) {
    TestableRefreshRateConfigs configs(kModes_30_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    struct Args {
        bool touch = false;
        bool focused = true;
    };

    // Return the config ID from calling getBestRefreshRate() for a single layer with the
    // given voteType and fps.
    auto getFrameRate = [&](LayerVoteType voteType, Fps fps, Args args = {}) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = fps;
        layers[0].focused = args.focused;
        return configs.getBestRefreshRate(layers, {.touch = args.touch})->getId();
    };

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {30_Hz, 60_Hz}, {30_Hz, 90_Hz}}), 0);

    EXPECT_EQ(kModeId60, configs.getBestRefreshRate()->getId());
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::NoVote, 90_Hz));
    EXPECT_EQ(kModeId30, getFrameRate(LayerVoteType::Min, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Max, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Heuristic, 90_Hz));
    EXPECT_EQ(kModeId90, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz));

    // Unfocused layers are not allowed to override primary config.
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz, {.focused = false}));
    EXPECT_EQ(kModeId60,
              getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz, {.focused = false}));

    // Touch boost should be restricted to the primary range.
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Max, 90_Hz, {.touch = true}));

    // When we're higher than the primary range max due to a layer frame rate setting, touch boost
    // shouldn't drag us back down to the primary range max.
    EXPECT_EQ(kModeId90, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz, {.touch = true}));
    EXPECT_EQ(kModeId60,
              getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz, {.touch = true}));

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}, {60_Hz, 60_Hz}}), 0);

    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::NoVote, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Min, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Max, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Heuristic, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz));
}

TEST_F(RefreshRateConfigsTest, idle) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    const auto getIdleFrameRate = [&](LayerVoteType voteType, bool touchActive) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = 90_Hz;

        const auto [refreshRate, signals] =
                configs.getBestRefreshRateAndSignals(layers, {.touch = touchActive, .idle = true});

        // Refresh rate will be chosen by either touch state or idle state.
        EXPECT_EQ(!touchActive, signals.idle);
        return refreshRate->getId();
    };

    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 90_Hz}, {60_Hz, 90_Hz}}), 0);

    // Idle should be lower priority than touch boost.
    {
        constexpr bool kTouchActive = true;
        EXPECT_EQ(kModeId90, getIdleFrameRate(LayerVoteType::NoVote, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleFrameRate(LayerVoteType::Min, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleFrameRate(LayerVoteType::Max, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleFrameRate(LayerVoteType::Heuristic, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleFrameRate(LayerVoteType::ExplicitDefault, kTouchActive));
        EXPECT_EQ(kModeId90,
                  getIdleFrameRate(LayerVoteType::ExplicitExactOrMultiple, kTouchActive));
    }

    // With no layers, idle should still be lower priority than touch boost.
    EXPECT_EQ(kModeId90, configs.getBestRefreshRate({}, {.touch = true, .idle = true})->getId());

    // Idle should be higher precedence than other layer frame rate considerations.
    configs.setActiveModeId(kModeId90);

    {
        constexpr bool kTouchActive = false;
        EXPECT_EQ(kModeId60, getIdleFrameRate(LayerVoteType::NoVote, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleFrameRate(LayerVoteType::Min, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleFrameRate(LayerVoteType::Max, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleFrameRate(LayerVoteType::Heuristic, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleFrameRate(LayerVoteType::ExplicitDefault, kTouchActive));
        EXPECT_EQ(kModeId60,
                  getIdleFrameRate(LayerVoteType::ExplicitExactOrMultiple, kTouchActive));
    }

    // Idle should be applied rather than the current config when there are no layers.
    EXPECT_EQ(kModeId60, configs.getBestRefreshRate({}, {.idle = true})->getId());
}

TEST_F(RefreshRateConfigsTest, findClosestKnownFrameRate) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    for (float fps = 1.0f; fps <= 120.0f; fps += 0.1f) {
        const auto knownFrameRate = configs.findClosestKnownFrameRate(Fps::fromValue(fps));
        const Fps expectedFrameRate = [fps] {
            if (fps < 26.91f) return 24_Hz;
            if (fps < 37.51f) return 30_Hz;
            if (fps < 52.51f) return 45_Hz;
            if (fps < 66.01f) return 60_Hz;
            if (fps < 81.01f) return 72_Hz;
            return 90_Hz;
        }();

        EXPECT_EQ(expectedFrameRate, knownFrameRate);
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_KnownFrameRate) {
    TestableRefreshRateConfigs configs(kModes_60_90, kModeId60);

    struct Expectation {
        Fps fps;
        DisplayModePtr mode;
    };

    const std::initializer_list<Expectation> knownFrameRatesExpectations = {
            {24_Hz, kMode60}, {30_Hz, kMode60}, {45_Hz, kMode90},
            {60_Hz, kMode60}, {72_Hz, kMode90}, {90_Hz, kMode90},
    };

    // Make sure the test tests all the known frame rate
    const auto& knownFrameRates = configs.knownFrameRates();
    const bool equal = std::equal(knownFrameRates.begin(), knownFrameRates.end(),
                                  knownFrameRatesExpectations.begin(),
                                  [](Fps fps, const Expectation& expected) {
                                      return isApproxEqual(fps, expected.fps);
                                  });
    EXPECT_TRUE(equal);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::Heuristic;

    for (const auto& [fps, mode] : knownFrameRatesExpectations) {
        layer.desiredRefreshRate = fps;
        EXPECT_EQ(mode, configs.getBestRefreshRate(layers));
    }
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitExact) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = 30_Hz;

    EXPECT_EQ(kMode30, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode30, configs.getBestRefreshRate(layers, {.touch = true}));

    explicitExactOrMultipleLayer.desiredRefreshRate = 120_Hz;
    explicitExactLayer.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 72_Hz;
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 120_Hz;
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitExactEnableFrameRateOverride) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60,
                                       {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = 30_Hz;

    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers, {.touch = true}));

    explicitExactOrMultipleLayer.desiredRefreshRate = 120_Hz;
    explicitExactLayer.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 72_Hz;
    EXPECT_EQ(kMode72, configs.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, configs.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 120_Hz;
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ReadsCache) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60);

    using GlobalSignals = RefreshRateConfigs::GlobalSignals;
    const auto args = std::make_pair(std::vector<LayerRequirement>{},
                                     GlobalSignals{.touch = true, .idle = true});
    const auto result = std::make_pair(kMode90, GlobalSignals{.touch = true});

    configs.mutableGetBestRefreshRateCache() = {args, result};

    EXPECT_EQ(result, configs.getBestRefreshRateAndSignals(args.first, args.second));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_WritesCache) {
    TestableRefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId60);

    EXPECT_FALSE(configs.mutableGetBestRefreshRateCache());

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    RefreshRateConfigs::GlobalSignals globalSignals{.touch = true, .idle = true};

    const auto result = configs.getBestRefreshRateAndSignals(layers, globalSignals);

    const auto& cache = configs.mutableGetBestRefreshRateCache();
    ASSERT_TRUE(cache);

    EXPECT_EQ(cache->arguments, std::make_pair(layers, globalSignals));
    EXPECT_EQ(cache->result, result);
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_ExplicitExactTouchBoost) {
    TestableRefreshRateConfigs configs(kModes_60_120, kModeId60, {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = 30_Hz;

    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode120, configs.getBestRefreshRate(layers, {.touch = true}));

    explicitExactOrMultipleLayer.vote = LayerVoteType::NoVote;

    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers, {.touch = true}));
}

TEST_F(RefreshRateConfigsTest, getBestRefreshRate_FractionalRefreshRates_ExactAndDefault) {
    TestableRefreshRateConfigs configs(kModes_24_25_30_50_60_Frac, kModeId60,
                                       {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.weight = 0.5f}, {.weight = 0.5f}};
    auto& explicitDefaultLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitDefaultLayer.vote = LayerVoteType::ExplicitDefault;
    explicitDefaultLayer.name = "ExplicitDefault";
    explicitDefaultLayer.desiredRefreshRate = 59.94_Hz;

    EXPECT_EQ(kMode60, configs.getBestRefreshRate(layers));
}

// b/190578904
TEST_F(RefreshRateConfigsTest, getBestRefreshRate_withCloseRefreshRates) {
    constexpr int kMinRefreshRate = 10;
    constexpr int kMaxRefreshRate = 240;

    DisplayModes displayModes;
    for (int fps = kMinRefreshRate; fps < kMaxRefreshRate; fps++) {
        const DisplayModeId modeId(fps);
        displayModes.try_emplace(modeId,
                                 createDisplayMode(modeId,
                                                   Fps::fromValue(static_cast<float>(fps))));
    }

    const TestableRefreshRateConfigs configs(std::move(displayModes),
                                             DisplayModeId(kMinRefreshRate));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    const auto testRefreshRate = [&](Fps fps, LayerVoteType vote) {
        layers[0].desiredRefreshRate = fps;
        layers[0].vote = vote;
        EXPECT_EQ(fps.getIntValue(), configs.getBestRefreshRate(layers)->getFps().getIntValue())
                << "Failed for " << ftl::enum_string(vote);
    };

    for (int fps = kMinRefreshRate; fps < kMaxRefreshRate; fps++) {
        const auto refreshRate = Fps::fromValue(static_cast<float>(fps));
        testRefreshRate(refreshRate, LayerVoteType::Heuristic);
        testRefreshRate(refreshRate, LayerVoteType::ExplicitDefault);
        testRefreshRate(refreshRate, LayerVoteType::ExplicitExactOrMultiple);
        testRefreshRate(refreshRate, LayerVoteType::ExplicitExact);
    }
}

// b/190578904
TEST_F(RefreshRateConfigsTest, getBestRefreshRate_conflictingVotes) {
    constexpr DisplayModeId kActiveModeId{0};
    DisplayModes displayModes = makeModes(createDisplayMode(kActiveModeId, 43_Hz),
                                          createDisplayMode(DisplayModeId(1), 53_Hz),
                                          createDisplayMode(DisplayModeId(2), 55_Hz),
                                          createDisplayMode(DisplayModeId(3), 60_Hz));

    const RefreshRateConfigs::GlobalSignals globalSignals = {.touch = false, .idle = false};
    const TestableRefreshRateConfigs configs(std::move(displayModes), kActiveModeId);

    const std::vector<LayerRequirement> layers = {
            {
                    .vote = LayerVoteType::ExplicitDefault,
                    .desiredRefreshRate = 43_Hz,
                    .seamlessness = Seamlessness::SeamedAndSeamless,
                    .weight = 0.41f,
            },
            {
                    .vote = LayerVoteType::ExplicitExactOrMultiple,
                    .desiredRefreshRate = 53_Hz,
                    .seamlessness = Seamlessness::SeamedAndSeamless,
                    .weight = 0.41f,
            },
    };

    EXPECT_EQ(53_Hz, configs.getBestRefreshRate(layers, globalSignals)->getFps());
}

TEST_F(RefreshRateConfigsTest, modeComparison) {
    EXPECT_LT(kMode60->getFps(), kMode90->getFps());
    EXPECT_GE(kMode60->getFps(), kMode60->getFps());
    EXPECT_GE(kMode90->getFps(), kMode90->getFps());
}

TEST_F(RefreshRateConfigsTest, testKernelIdleTimerAction) {
    using KernelIdleTimerAction = RefreshRateConfigs::KernelIdleTimerAction;

    RefreshRateConfigs configs(kModes_60_90, kModeId90);

    // SetPolicy(60, 90), current 90Hz => TurnOn.
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, configs.getIdleTimerAction());

    // SetPolicy(60, 90), current 60Hz => TurnOn.
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 90_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, configs.getIdleTimerAction());

    // SetPolicy(60, 60), current 60Hz => TurnOff
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, configs.getIdleTimerAction());

    // SetPolicy(90, 90), current 90Hz => TurnOff.
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, configs.getIdleTimerAction());
}

TEST_F(RefreshRateConfigsTest, testKernelIdleTimerActionFor120Hz) {
    using KernelIdleTimerAction = RefreshRateConfigs::KernelIdleTimerAction;

    RefreshRateConfigs configs(kModes_60_120, kModeId120);

    // SetPolicy(0, 60), current 60Hz => TurnOn.
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {0_Hz, 60_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, configs.getIdleTimerAction());

    // SetPolicy(60, 60), current 60Hz => TurnOff.
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, configs.getIdleTimerAction());

    // SetPolicy(60, 120), current 60Hz => TurnOn.
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId60, {60_Hz, 120_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, configs.getIdleTimerAction());

    // SetPolicy(120, 120), current 120Hz => TurnOff.
    EXPECT_GE(configs.setDisplayManagerPolicy({kModeId120, {120_Hz, 120_Hz}}), 0);
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, configs.getIdleTimerAction());
}

TEST_F(RefreshRateConfigsTest, getFrameRateDivisor) {
    RefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId30);

    const auto frameRate = 30_Hz;
    Fps displayRefreshRate = configs.getActiveMode()->getFps();
    EXPECT_EQ(1, RefreshRateConfigs::getFrameRateDivisor(displayRefreshRate, frameRate));

    configs.setActiveModeId(kModeId60);
    displayRefreshRate = configs.getActiveMode()->getFps();
    EXPECT_EQ(2, RefreshRateConfigs::getFrameRateDivisor(displayRefreshRate, frameRate));

    configs.setActiveModeId(kModeId72);
    displayRefreshRate = configs.getActiveMode()->getFps();
    EXPECT_EQ(0, RefreshRateConfigs::getFrameRateDivisor(displayRefreshRate, frameRate));

    configs.setActiveModeId(kModeId90);
    displayRefreshRate = configs.getActiveMode()->getFps();
    EXPECT_EQ(3, RefreshRateConfigs::getFrameRateDivisor(displayRefreshRate, frameRate));

    configs.setActiveModeId(kModeId120);
    displayRefreshRate = configs.getActiveMode()->getFps();
    EXPECT_EQ(4, RefreshRateConfigs::getFrameRateDivisor(displayRefreshRate, frameRate));

    configs.setActiveModeId(kModeId90);
    displayRefreshRate = configs.getActiveMode()->getFps();
    EXPECT_EQ(4, RefreshRateConfigs::getFrameRateDivisor(displayRefreshRate, 22.5_Hz));

    EXPECT_EQ(0, RefreshRateConfigs::getFrameRateDivisor(24_Hz, 25_Hz));
    EXPECT_EQ(0, RefreshRateConfigs::getFrameRateDivisor(24_Hz, 23.976_Hz));
    EXPECT_EQ(0, RefreshRateConfigs::getFrameRateDivisor(30_Hz, 29.97_Hz));
    EXPECT_EQ(0, RefreshRateConfigs::getFrameRateDivisor(60_Hz, 59.94_Hz));
}

TEST_F(RefreshRateConfigsTest, isFractionalPairOrMultiple) {
    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(23.976_Hz, 24_Hz));
    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(24_Hz, 23.976_Hz));

    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(29.97_Hz, 30_Hz));
    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(30_Hz, 29.97_Hz));

    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(59.94_Hz, 60_Hz));
    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(60_Hz, 59.94_Hz));

    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(29.97_Hz, 60_Hz));
    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(60_Hz, 29.97_Hz));

    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(59.94_Hz, 30_Hz));
    EXPECT_TRUE(RefreshRateConfigs::isFractionalPairOrMultiple(30_Hz, 59.94_Hz));

    const auto refreshRates = {23.976_Hz, 24_Hz, 25_Hz, 29.97_Hz, 30_Hz, 50_Hz, 59.94_Hz, 60_Hz};
    for (auto refreshRate : refreshRates) {
        EXPECT_FALSE(RefreshRateConfigs::isFractionalPairOrMultiple(refreshRate, refreshRate));
    }

    EXPECT_FALSE(RefreshRateConfigs::isFractionalPairOrMultiple(24_Hz, 25_Hz));
    EXPECT_FALSE(RefreshRateConfigs::isFractionalPairOrMultiple(23.978_Hz, 25_Hz));
    EXPECT_FALSE(RefreshRateConfigs::isFractionalPairOrMultiple(29.97_Hz, 59.94_Hz));
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_noLayers) {
    RefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId120);

    EXPECT_TRUE(configs.getFrameRateOverrides({}, 120_Hz, {}).empty());
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_60on120) {
    RefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId120,
                               {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    auto frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::NoVote;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Min;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Max;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Heuristic;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_twoUids) {
    RefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId120,
                               {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.ownerUid = 1234, .weight = 1.f},
                                            {.ownerUid = 5678, .weight = 1.f}};

    layers[0].name = "Test layer 1234";
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    layers[1].name = "Test layer 5678";
    layers[1].desiredRefreshRate = 30_Hz;
    layers[1].vote = LayerVoteType::ExplicitDefault;
    auto frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});

    EXPECT_EQ(2u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
    ASSERT_EQ(1u, frameRateOverrides.count(5678));
    EXPECT_EQ(30_Hz, frameRateOverrides.at(5678));

    layers[1].vote = LayerVoteType::Heuristic;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[1].ownerUid = 1234;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateConfigsTest, getFrameRateOverrides_touch) {
    RefreshRateConfigs configs(kModes_30_60_72_90_120, kModeId120,
                               {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.ownerUid = 1234, .weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    auto frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExact;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = configs.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());
}

} // namespace
} // namespace android::scheduler
