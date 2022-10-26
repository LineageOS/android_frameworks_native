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

#include <algorithm>
#include <array>

#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <log/log.h>
#include <ui/Size.h>

#include "DisplayHardware/HWC2.h"
#include "FpsOps.h"
#include "Scheduler/RefreshRateSelector.h"
#include "mock/DisplayHardware/MockDisplayMode.h"

using namespace std::chrono_literals;

namespace android::scheduler {

namespace hal = android::hardware::graphics::composer::hal;

using LayerRequirement = RefreshRateSelector::LayerRequirement;
using LayerVoteType = RefreshRateSelector::LayerVoteType;
using SetPolicyResult = RefreshRateSelector::SetPolicyResult;

using mock::createDisplayMode;

struct TestableRefreshRateSelector : RefreshRateSelector {
    using RefreshRateSelector::RefreshRateOrder;
    using RefreshRateSelector::RefreshRateRanking;

    using RefreshRateSelector::RefreshRateSelector;

    void setActiveModeId(DisplayModeId modeId) {
        ftl::FakeGuard guard(kMainThreadContext);
        return RefreshRateSelector::setActiveModeId(modeId);
    }

    const DisplayMode& getActiveMode() const {
        ftl::FakeGuard guard(kMainThreadContext);
        return RefreshRateSelector::getActiveMode();
    }

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

    DisplayModePtr getMaxRefreshRateByPolicy() const {
        std::lock_guard lock(mLock);
        return getMaxRefreshRateByPolicyLocked(getActiveModeItLocked()->second->getGroup());
    }

    RefreshRateRanking rankRefreshRates(std::optional<int> anchorGroupOpt,
                                        RefreshRateOrder refreshRateOrder) const {
        std::lock_guard lock(mLock);
        return RefreshRateSelector::rankRefreshRates(anchorGroupOpt, refreshRateOrder);
    }

    const std::vector<Fps>& knownFrameRates() const { return mKnownFrameRates; }

    using RefreshRateSelector::GetRankedRefreshRatesCache;
    auto& mutableGetRankedRefreshRatesCache() { return mGetRankedRefreshRatesCache; }

    auto getRankedRefreshRates(const std::vector<LayerRequirement>& layers,
                               GlobalSignals signals) const {
        const auto result = RefreshRateSelector::getRankedRefreshRates(layers, signals);

        EXPECT_TRUE(std::is_sorted(result.ranking.begin(), result.ranking.end(),
                                   ScoredRefreshRate::DescendingScore{}));

        return result;
    }

    auto getRankedRefreshRatesAsPair(const std::vector<LayerRequirement>& layers,
                                     GlobalSignals signals) const {
        const auto [ranking, consideredSignals] = getRankedRefreshRates(layers, signals);
        return std::make_pair(ranking, consideredSignals);
    }

    DisplayModePtr getBestRefreshRate(const std::vector<LayerRequirement>& layers = {},
                                      GlobalSignals signals = {}) const {
        return getRankedRefreshRates(layers, signals).ranking.front().modePtr;
    }

    SetPolicyResult setPolicy(const PolicyVariant& policy) {
        ftl::FakeGuard guard(kMainThreadContext);
        return RefreshRateSelector::setPolicy(policy);
    }

    SetPolicyResult setDisplayManagerPolicy(const DisplayManagerPolicy& policy) {
        return setPolicy(policy);
    }
};

class RefreshRateSelectorTest : public testing::Test {
protected:
    using RefreshRateOrder = TestableRefreshRateSelector::RefreshRateOrder;

    RefreshRateSelectorTest();
    ~RefreshRateSelectorTest();

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

RefreshRateSelectorTest::RefreshRateSelectorTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

RefreshRateSelectorTest::~RefreshRateSelectorTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

namespace {

TEST_F(RefreshRateSelectorTest, oneMode_canSwitch) {
    RefreshRateSelector selector(kModes_60, kModeId60);
    EXPECT_FALSE(selector.canSwitch());
}

TEST_F(RefreshRateSelectorTest, invalidPolicy) {
    TestableRefreshRateSelector selector(kModes_60, kModeId60);

    EXPECT_EQ(SetPolicyResult::Invalid,
              selector.setDisplayManagerPolicy({DisplayModeId(10), {60_Hz, 60_Hz}}));
    EXPECT_EQ(SetPolicyResult::Invalid,
              selector.setDisplayManagerPolicy({kModeId60, {20_Hz, 40_Hz}}));
}

TEST_F(RefreshRateSelectorTest, unchangedPolicy) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}));

    EXPECT_EQ(SetPolicyResult::Unchanged,
              selector.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}));

    // Override to the same policy.
    EXPECT_EQ(SetPolicyResult::Unchanged,
              selector.setPolicy(RefreshRateSelector::OverridePolicy{kModeId90, {60_Hz, 90_Hz}}));

    // Clear override to restore DisplayManagerPolicy.
    EXPECT_EQ(SetPolicyResult::Unchanged,
              selector.setPolicy(RefreshRateSelector::NoOverridePolicy{}));

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {30_Hz, 90_Hz}}));
}

TEST_F(RefreshRateSelectorTest, twoModes_storesFullRefreshRateMap) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    const auto minRate = selector.getMinSupportedRefreshRate();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode90, performanceRate);

    const auto minRateByPolicy = selector.getMinRefreshRateByPolicy();
    const auto performanceRateByPolicy = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(minRateByPolicy, minRate);
    EXPECT_EQ(performanceRateByPolicy, performanceRate);
}

TEST_F(RefreshRateSelectorTest, twoModes_storesFullRefreshRateMap_differentGroups) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    const auto minRate = selector.getMinRefreshRateByPolicy();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();
    const auto minRate60 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate60 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}));
    selector.setActiveModeId(kModeId90);

    const auto minRate90 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate90 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode90_G1, performanceRate);
    EXPECT_EQ(kMode90_G1, minRate90);
    EXPECT_EQ(kMode90_G1, performanceRate90);
}

TEST_F(RefreshRateSelectorTest, twoModes_storesFullRefreshRateMap_differentResolutions) {
    TestableRefreshRateSelector selector(kModes_60_90_4K, kModeId60);

    const auto minRate = selector.getMinRefreshRateByPolicy();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();
    const auto minRate60 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate60 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}));
    selector.setActiveModeId(kModeId90);

    const auto minRate90 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate90 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode90_4K, performanceRate);
    EXPECT_EQ(kMode90_4K, minRate90);
    EXPECT_EQ(kMode90_4K, performanceRate90);
}

TEST_F(RefreshRateSelectorTest, twoModes_policyChange) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    const auto minRate = selector.getMinRefreshRateByPolicy();
    const auto performanceRate = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode90, performanceRate);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));

    const auto minRate60 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate60 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);
}

TEST_F(RefreshRateSelectorTest, twoModes_getActiveMode) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);
    {
        const auto& mode = selector.getActiveMode();
        EXPECT_EQ(mode.getId(), kModeId60);
    }

    selector.setActiveModeId(kModeId90);
    {
        const auto& mode = selector.getActiveMode();
        EXPECT_EQ(mode.getId(), kModeId90);
    }

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}));
    {
        const auto& mode = selector.getActiveMode();
        EXPECT_EQ(mode.getId(), kModeId90);
    }
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_noLayers) {
    {
        TestableRefreshRateSelector selector(kModes_60_72_90, kModeId72);

        // If there are no layers we select the default frame rate, which is the max of the primary
        // range.
        EXPECT_EQ(kMode90, selector.getBestRefreshRate());

        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));
        EXPECT_EQ(kMode60, selector.getBestRefreshRate());
    }
    {
        // We select max even when this will cause a non-seamless switch.
        TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);
        constexpr bool kAllowGroupSwitching = true;
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId90, kAllowGroupSwitching, {0_Hz, 90_Hz}}));
        EXPECT_EQ(kMode90_G1, selector.getBestRefreshRate());
    }
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_exactDontChangeRefreshRateWhenNotInPolicy) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId72);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].vote = LayerVoteType::ExplicitExact;
    layers[0].desiredRefreshRate = 120_Hz;

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId72, {0_Hz, 90_Hz}}));
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_60_90) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.name = "";
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}));

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {0_Hz, 120_Hz}}));
    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_multipleThreshold_60_90) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60,
                                         {.frameRateMultipleThreshold = 90});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_60_72_90) {
    TestableRefreshRateSelector selector(kModes_60_72_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_30_60_72_90_120) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_30_60_90_120_DifferentTypes) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_30_60_90_120_DifferentTypes_multipleThreshold) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60,
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
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "120Hz ExplicitDefault";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::ExplicitExact;
    lr2.name = "120Hz ExplicitExact";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 10_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "120Hz ExplicitExact";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    lr1.desiredRefreshRate = 30_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 30_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "30Hz ExplicitExactOrMultiple";
    lr3.vote = LayerVoteType::Heuristic;
    lr3.desiredRefreshRate = 120_Hz;
    lr3.name = "120Hz Heuristic";
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_30_60) {
    TestableRefreshRateSelector selector(kModes_30_60, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode30, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode30, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_30_60_72_90) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode30, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode30, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));

    lr.desiredRefreshRate = 24_Hz;
    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.name = "24Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_PriorityTest) {
    TestableRefreshRateSelector selector(kModes_30_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 15_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 30_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_24FpsVideo) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = selector.getBestRefreshRate(layers);
        EXPECT_EQ(kMode60, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getFps());
    }
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_24FpsVideo_multipleThreshold_60_120) {
    TestableRefreshRateSelector selector(kModes_60_120, kModeId60,
                                         {.frameRateMultipleThreshold = 120});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = selector.getBestRefreshRate(layers);
        EXPECT_EQ(kMode60, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getFps());
    }
}

TEST_F(RefreshRateSelectorTest, twoModes_getBestRefreshRate_Explicit) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_75HzContent) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 75.0f; fps < 100.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = selector.getBestRefreshRate(layers, {});
        EXPECT_EQ(kMode90, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getFps());
    }
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_Multiples) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, scrollWhileWatching60fps_60_90) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.touch = true}));

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    // The other layer starts to provide buffers
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getMaxRefreshRatesByPolicy) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    TestableRefreshRateSelector selector(kModes_30_60_90, kModeId60);

    const auto refreshRates = selector.rankRefreshRates(selector.getActiveMode().getGroup(),
                                                        RefreshRateOrder::Descending);

    const std::array expectedRefreshRates = {kMode90, kMode60, kMode30};
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }
}

TEST_F(RefreshRateSelectorTest, getMinRefreshRatesByPolicy) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    TestableRefreshRateSelector selector(kModes_30_60_90, kModeId60);

    const auto refreshRates = selector.rankRefreshRates(selector.getActiveMode().getGroup(),
                                                        RefreshRateOrder::Ascending);

    const std::array expectedRefreshRates = {kMode30, kMode60, kMode90};
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }
}

TEST_F(RefreshRateSelectorTest, getMinRefreshRatesByPolicyOutsideTheGroup) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    TestableRefreshRateSelector selector(kModes_30_60_90, kModeId72);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {30_Hz, 90_Hz}, {30_Hz, 90_Hz}}));

    const auto refreshRates =
            selector.rankRefreshRates(/*anchorGroupOpt*/ std::nullopt, RefreshRateOrder::Ascending);

    const std::array expectedRefreshRates = {kMode30, kMode60, kMode90};
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }
}

TEST_F(RefreshRateSelectorTest, getMaxRefreshRatesByPolicyOutsideTheGroup) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    TestableRefreshRateSelector selector(kModes_30_60_90, kModeId72);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {30_Hz, 90_Hz}, {30_Hz, 90_Hz}}));

    const auto refreshRates = selector.rankRefreshRates(/*anchorGroupOpt*/ std::nullopt,
                                                        RefreshRateOrder::Descending);

    const std::array expectedRefreshRates = {kMode90, kMode60, kMode30};
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }
}

TEST_F(RefreshRateSelectorTest, powerOnImminentConsidered) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    auto [refreshRates, signals] = selector.getRankedRefreshRates({}, {});
    EXPECT_FALSE(signals.powerOnImminent);

    std::array expectedRefreshRates = {kMode90, kMode60};
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }

    std::tie(refreshRates, signals) =
            selector.getRankedRefreshRatesAsPair({}, {.powerOnImminent = true});
    EXPECT_TRUE(signals.powerOnImminent);

    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr1 = layers[0];
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";

    std::tie(refreshRates, signals) =
            selector.getRankedRefreshRatesAsPair(layers, {.powerOnImminent = true});
    EXPECT_TRUE(signals.powerOnImminent);

    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }

    std::tie(refreshRates, signals) =
            selector.getRankedRefreshRatesAsPair(layers, {.powerOnImminent = false});
    EXPECT_FALSE(signals.powerOnImminent);

    expectedRefreshRates = {kMode60, kMode90};
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].modePtr)
                << "Expected fps " << expectedRefreshRates[i]->getFps().getIntValue()
                << " Actual fps " << refreshRates[i].modePtr->getFps().getIntValue();
    }
}

TEST_F(RefreshRateSelectorTest, touchConsidered) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    auto [_, signals] = selector.getRankedRefreshRates({}, {});
    EXPECT_FALSE(signals.touch);

    std::tie(std::ignore, signals) = selector.getRankedRefreshRatesAsPair({}, {.touch = true});
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
    std::tie(std::ignore, signals) = selector.getRankedRefreshRatesAsPair(layers, {.touch = true});
    EXPECT_TRUE(signals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitDefault";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = selector.getRankedRefreshRatesAsPair(layers, {.touch = true});
    EXPECT_FALSE(signals.touch);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = selector.getRankedRefreshRatesAsPair(layers, {.touch = true});
    EXPECT_TRUE(signals.touch);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitDefault";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz Heuristic";
    std::tie(std::ignore, signals) = selector.getRankedRefreshRatesAsPair(layers, {.touch = true});
    EXPECT_FALSE(signals.touch);
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_ExplicitDefault) {
    TestableRefreshRateSelector selector(kModes_60_90_72_120, kModeId60);

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

        EXPECT_EQ(expected, selector.getBestRefreshRate(layers)->getFps());
    }
}

TEST_F(RefreshRateSelectorTest,
       getBestRefreshRate_ExplicitExactOrMultiple_WithFractionalRefreshRates) {
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Test that 23.976 will choose 24 if 23.976 is not supported
    {
        TestableRefreshRateSelector selector(makeModes(kMode24, kMode25, kMode30, kMode30Frac,
                                                       kMode60, kMode60Frac),
                                             kModeId60);

        lr.vote = LayerVoteType::ExplicitExactOrMultiple;
        lr.desiredRefreshRate = 23.976_Hz;
        lr.name = "ExplicitExactOrMultiple 23.976 Hz";
        EXPECT_EQ(kModeId24, selector.getBestRefreshRate(layers)->getId());
    }

    // Test that 24 will choose 23.976 if 24 is not supported
    {
        TestableRefreshRateSelector selector(makeModes(kMode24Frac, kMode25, kMode30, kMode30Frac,
                                                       kMode60, kMode60Frac),
                                             kModeId60);

        lr.desiredRefreshRate = 24_Hz;
        lr.name = "ExplicitExactOrMultiple 24 Hz";
        EXPECT_EQ(kModeId24Frac, selector.getBestRefreshRate(layers)->getId());
    }

    // Test that 29.97 will prefer 59.94 over 60 and 30
    {
        TestableRefreshRateSelector selector(makeModes(kMode24, kMode24Frac, kMode25, kMode30,
                                                       kMode60, kMode60Frac),
                                             kModeId60);

        lr.desiredRefreshRate = 29.97_Hz;
        lr.name = "ExplicitExactOrMultiple 29.97 Hz";
        EXPECT_EQ(kModeId60Frac, selector.getBestRefreshRate(layers)->getId());
    }
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_ExplicitExact_WithFractionalRefreshRates) {
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Test that voting for supported refresh rate will select this refresh rate
    {
        TestableRefreshRateSelector selector(kModes_24_25_30_50_60_Frac, kModeId60);

        for (auto desired : {23.976_Hz, 24_Hz, 25_Hz, 29.97_Hz, 30_Hz, 50_Hz, 59.94_Hz, 60_Hz}) {
            lr.vote = LayerVoteType::ExplicitExact;
            lr.desiredRefreshRate = desired;
            std::stringstream ss;
            ss << "ExplicitExact " << desired;
            lr.name = ss.str();

            EXPECT_EQ(lr.desiredRefreshRate, selector.getBestRefreshRate(layers)->getFps());
        }
    }
}

TEST_F(RefreshRateSelectorTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresTouchFlag) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId90);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}, {60_Hz, 90_Hz}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = true;

    const auto [mode, signals] =
            selector.getRankedRefreshRates(layers, {.touch = true, .idle = true});

    EXPECT_EQ(mode.begin()->modePtr, kMode60);
    EXPECT_FALSE(signals.touch);
}

TEST_F(RefreshRateSelectorTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_ignoresIdleFlag) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}, {60_Hz, 90_Hz}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 90_Hz;
    lr.name = "90Hz ExplicitDefault";
    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers, {.idle = true}));
}

TEST_F(RefreshRateSelectorTest, testDisplayModeOrdering) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f},
                                            {.weight = 1.f},
                                            {.weight = 1.f},
                                            {.weight = 1.f},
                                            {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];
    auto& lr3 = layers[2];
    auto& lr4 = layers[3];
    auto& lr5 = layers[4];

    lr1.desiredRefreshRate = 90_Hz;
    lr1.name = "90Hz";
    lr1.focused = true;

    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz";
    lr2.focused = true;

    lr3.desiredRefreshRate = 72_Hz;
    lr3.name = "72Hz";
    lr3.focused = true;

    lr4.desiredRefreshRate = 120_Hz;
    lr4.name = "120Hz";
    lr4.focused = true;

    lr5.desiredRefreshRate = 30_Hz;
    lr5.name = "30Hz";
    lr5.focused = true;

    std::array expectedRanking = {kMode120, kMode90, kMode72, kMode60, kMode30};
    auto actualRanking = selector.getRankedRefreshRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].modePtr)
                << "Expected fps " << expectedRanking[i]->getFps().getIntValue() << " Actual fps "
                << actualRanking[i].modePtr->getFps().getIntValue();
    }

    lr1.vote = LayerVoteType::Max;
    lr1.name = "Max";

    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz";

    lr3.desiredRefreshRate = 72_Hz;
    lr3.name = "72Hz";

    lr4.desiredRefreshRate = 90_Hz;
    lr4.name = "90Hz";

    lr5.desiredRefreshRate = 120_Hz;
    lr5.name = "120Hz";

    expectedRanking = {kMode120, kMode90, kMode72, kMode60, kMode30};
    actualRanking = selector.getRankedRefreshRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].modePtr)
                << "Expected fps " << expectedRanking[i]->getFps().getIntValue() << " Actual fps "
                << actualRanking[i].modePtr->getFps().getIntValue();
    }

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz";

    lr2.desiredRefreshRate = 120_Hz;
    lr2.name = "120Hz";

    lr3.desiredRefreshRate = 60_Hz;
    lr3.name = "60Hz";

    lr5.desiredRefreshRate = 72_Hz;
    lr5.name = "72Hz";

    expectedRanking = {kMode30, kMode60, kMode90, kMode120, kMode72};
    actualRanking = selector.getRankedRefreshRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].modePtr)
                << "Expected fps " << expectedRanking[i]->getFps().getIntValue() << " Actual fps "
                << actualRanking[i].modePtr->getFps().getIntValue();
    }

    lr1.desiredRefreshRate = 120_Hz;
    lr1.name = "120Hz";
    lr1.weight = 0.0f;

    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz";
    lr2.vote = LayerVoteType::NoVote;

    lr3.name = "60Hz-2";
    lr3.vote = LayerVoteType::Heuristic;

    lr4.vote = LayerVoteType::ExplicitExact;

    lr5.desiredRefreshRate = 120_Hz;
    lr5.name = "120Hz-2";

    expectedRanking = {kMode90, kMode60, kMode120, kMode72, kMode30};
    actualRanking = selector.getRankedRefreshRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].modePtr)
                << "Expected fps " << expectedRanking[i]->getFps().getIntValue() << " Actual fps "
                << actualRanking[i].modePtr->getFps().getIntValue();
    }
}

TEST_F(RefreshRateSelectorTest,
       getBestRefreshRate_withDisplayManagerRequestingSingleRate_onlySwitchesRatesForExplicitFocusedLayers) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId90);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}, {60_Hz, 90_Hz}}));

    const auto [ranking, signals] = selector.getRankedRefreshRates({}, {});
    EXPECT_EQ(ranking.front().modePtr, kMode90);
    EXPECT_FALSE(signals.touch);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitExactOrMultiple";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Heuristic;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Max;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Max";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.vote = LayerVoteType::Min;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Min";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, groupSwitchingNotAllowed) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    // The default policy doesn't allow group switching. Verify that no
    // group switches are performed.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;

    EXPECT_EQ(kModeId60, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithOneLayer) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId90, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithOneLayerOnlySeamless) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    // Verify that we won't change the group if seamless switch is required.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId60, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithOneLayerOnlySeamlessDefaultFps) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveModeId(kModeId90);

    // Verify that we won't do a seamless switch if we request the same mode as the default
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId90, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithOneLayerDefaultSeamlessness) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveModeId(kModeId90);

    // Verify that if the active mode is in another group and there are no layers with
    // Seamlessness::SeamedAndSeamless, we should switch back to the default group.

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::Default;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;

    EXPECT_EQ(kModeId60, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithTwoLayersOnlySeamlessAndSeamed) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveModeId(kModeId90);

    // If there's a layer with Seamlessness::SeamedAndSeamless, another layer with
    // Seamlessness::OnlySeamless can't change the mode group.
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

    EXPECT_EQ(kModeId90, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithTwoLayersDefaultFocusedAndSeamed) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveModeId(kModeId90);

    // If there's a focused layer with Seamlessness::SeamedAndSeamless, another layer with
    // Seamlessness::Default can't change the mode group back to the group of the default
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

    EXPECT_EQ(kModeId90, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, groupSwitchingWithTwoLayersDefaultNotFocusedAndSeamed) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveModeId(kModeId90);

    // Layer with Seamlessness::Default can change the mode group if there's an
    // unfocused layer with Seamlessness::SeamedAndSeamless. For example, this happens
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

    EXPECT_EQ(kModeId60, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, nonSeamlessVotePrefersSeamlessSwitches) {
    TestableRefreshRateSelector selector(kModes_30_60, kModeId60);

    // Allow group switching.
    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitExactOrMultiple;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "60Hz ExplicitExactOrMultiple";
    layer.focused = true;

    EXPECT_EQ(kModeId60, selector.getBestRefreshRate(layers)->getId());

    selector.setActiveModeId(kModeId120);
    EXPECT_EQ(kModeId120, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, nonSeamlessExactAndSeamlessMultipleLayers) {
    TestableRefreshRateSelector selector(kModes_25_30_50_60, kModeId60);

    // Allow group switching.
    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

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

    EXPECT_EQ(kModeId50, selector.getBestRefreshRate(layers)->getId());

    auto& seamedLayer = layers[0];
    seamedLayer.desiredRefreshRate = 30_Hz;
    seamedLayer.name = "30Hz ExplicitDefault";
    selector.setActiveModeId(kModeId30);

    EXPECT_EQ(kModeId25, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, minLayersDontTrigerSeamedSwitch) {
    TestableRefreshRateSelector selector(kModes_60_90_G1, kModeId90);

    // Allow group switching.
    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    std::vector<LayerRequirement> layers = {
            {.name = "Min", .vote = LayerVoteType::Min, .weight = 1.f, .focused = true}};

    EXPECT_EQ(kModeId90, selector.getBestRefreshRate(layers)->getId());
}

TEST_F(RefreshRateSelectorTest, primaryVsAppRequestPolicy) {
    TestableRefreshRateSelector selector(kModes_30_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    struct Args {
        bool touch = false;
        bool focused = true;
    };

    // Returns the mode selected by getBestRefreshRate for a single layer with the given arguments.
    const auto getFrameRate = [&](LayerVoteType voteType, Fps fps,
                                  Args args = {}) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = fps;
        layers[0].focused = args.focused;
        return selector.getBestRefreshRate(layers, {.touch = args.touch})->getId();
    };

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {30_Hz, 60_Hz}, {30_Hz, 90_Hz}}));

    EXPECT_EQ(kModeId60, selector.getBestRefreshRate()->getId());
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::NoVote, 90_Hz));
    EXPECT_EQ(kModeId30, getFrameRate(LayerVoteType::Min, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Max, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Heuristic, 90_Hz));
    EXPECT_EQ(kModeId90, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz));

    // Unfocused layers are not allowed to override primary range.
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

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}, {60_Hz, 60_Hz}}));

    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::NoVote, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Min, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Max, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Heuristic, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz));
}

TEST_F(RefreshRateSelectorTest, idle) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    const auto getIdleFrameRate = [&](LayerVoteType voteType, bool touchActive) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = 90_Hz;

        const auto [ranking, signals] =
                selector.getRankedRefreshRates(layers, {.touch = touchActive, .idle = true});

        // Refresh rate will be chosen by either touch state or idle state.
        EXPECT_EQ(!touchActive, signals.idle);
        return ranking.front().modePtr->getId();
    };

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 90_Hz}, {60_Hz, 90_Hz}}));

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
    EXPECT_EQ(kModeId90, selector.getBestRefreshRate({}, {.touch = true, .idle = true})->getId());

    // Idle should be higher precedence than other layer frame rate considerations.
    selector.setActiveModeId(kModeId90);

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

    // Idle should be applied rather than the active mode when there are no layers.
    EXPECT_EQ(kModeId60, selector.getBestRefreshRate({}, {.idle = true})->getId());
}

TEST_F(RefreshRateSelectorTest, findClosestKnownFrameRate) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    for (float fps = 1.0f; fps <= 120.0f; fps += 0.1f) {
        const auto knownFrameRate = selector.findClosestKnownFrameRate(Fps::fromValue(fps));
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

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_KnownFrameRate) {
    TestableRefreshRateSelector selector(kModes_60_90, kModeId60);

    struct Expectation {
        Fps fps;
        DisplayModePtr mode;
    };

    const std::initializer_list<Expectation> knownFrameRatesExpectations = {
            {24_Hz, kMode60}, {30_Hz, kMode60}, {45_Hz, kMode90},
            {60_Hz, kMode60}, {72_Hz, kMode90}, {90_Hz, kMode90},
    };

    // Make sure the test tests all the known frame rate
    const auto& knownFrameRates = selector.knownFrameRates();
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
        EXPECT_EQ(mode, selector.getBestRefreshRate(layers));
    }
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_ExplicitExact) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = 30_Hz;

    EXPECT_EQ(kMode30, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode30, selector.getBestRefreshRate(layers, {.touch = true}));

    explicitExactOrMultipleLayer.desiredRefreshRate = 120_Hz;
    explicitExactLayer.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 72_Hz;
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 120_Hz;
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_ExplicitExactEnableFrameRateOverride) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60,
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

    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers, {.touch = true}));

    explicitExactOrMultipleLayer.desiredRefreshRate = 120_Hz;
    explicitExactLayer.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 72_Hz;
    EXPECT_EQ(kMode72, selector.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, selector.getBestRefreshRate(layers));

    explicitExactLayer.desiredRefreshRate = 120_Hz;
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_ReadsCache) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60);

    using GlobalSignals = RefreshRateSelector::GlobalSignals;
    const auto args = std::make_pair(std::vector<LayerRequirement>{},
                                     GlobalSignals{.touch = true, .idle = true});

    const RefreshRateSelector::RankedRefreshRates result = {{RefreshRateSelector::ScoredRefreshRate{
                                                                    kMode90}},
                                                            {.touch = true}};

    selector.mutableGetRankedRefreshRatesCache() = {args, result};

    EXPECT_EQ(result, selector.getRankedRefreshRates(args.first, args.second));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_WritesCache) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId60);

    EXPECT_FALSE(selector.mutableGetRankedRefreshRatesCache());

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    RefreshRateSelector::GlobalSignals globalSignals{.touch = true, .idle = true};

    const auto result = selector.getRankedRefreshRates(layers, globalSignals);

    const auto& cache = selector.mutableGetRankedRefreshRatesCache();
    ASSERT_TRUE(cache);

    EXPECT_EQ(cache->arguments, std::make_pair(layers, globalSignals));
    EXPECT_EQ(cache->result, result);
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_ExplicitExactTouchBoost) {
    TestableRefreshRateSelector selector(kModes_60_120, kModeId60,
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

    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode120, selector.getBestRefreshRate(layers, {.touch = true}));

    explicitExactOrMultipleLayer.vote = LayerVoteType::NoVote;

    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers, {.touch = true}));
}

TEST_F(RefreshRateSelectorTest, getBestRefreshRate_FractionalRefreshRates_ExactAndDefault) {
    TestableRefreshRateSelector selector(kModes_24_25_30_50_60_Frac, kModeId60,
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

    EXPECT_EQ(kMode60, selector.getBestRefreshRate(layers));
}

// b/190578904
TEST_F(RefreshRateSelectorTest, getBestRefreshRate_withCloseRefreshRates) {
    constexpr int kMinRefreshRate = 10;
    constexpr int kMaxRefreshRate = 240;

    DisplayModes displayModes;
    for (int fps = kMinRefreshRate; fps < kMaxRefreshRate; fps++) {
        const DisplayModeId modeId(fps);
        displayModes.try_emplace(modeId,
                                 createDisplayMode(modeId,
                                                   Fps::fromValue(static_cast<float>(fps))));
    }

    const TestableRefreshRateSelector selector(std::move(displayModes),
                                               DisplayModeId(kMinRefreshRate));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    const auto testRefreshRate = [&](Fps fps, LayerVoteType vote) {
        layers[0].desiredRefreshRate = fps;
        layers[0].vote = vote;
        EXPECT_EQ(fps.getIntValue(), selector.getBestRefreshRate(layers)->getFps().getIntValue())
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
TEST_F(RefreshRateSelectorTest, getBestRefreshRate_conflictingVotes) {
    constexpr DisplayModeId kActiveModeId{0};
    DisplayModes displayModes = makeModes(createDisplayMode(kActiveModeId, 43_Hz),
                                          createDisplayMode(DisplayModeId(1), 53_Hz),
                                          createDisplayMode(DisplayModeId(2), 55_Hz),
                                          createDisplayMode(DisplayModeId(3), 60_Hz));

    const RefreshRateSelector::GlobalSignals globalSignals = {.touch = false, .idle = false};
    const TestableRefreshRateSelector selector(std::move(displayModes), kActiveModeId);

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

    EXPECT_EQ(53_Hz, selector.getBestRefreshRate(layers, globalSignals)->getFps());
}

TEST_F(RefreshRateSelectorTest, modeComparison) {
    EXPECT_LT(kMode60->getFps(), kMode90->getFps());
    EXPECT_GE(kMode60->getFps(), kMode60->getFps());
    EXPECT_GE(kMode90->getFps(), kMode90->getFps());
}

TEST_F(RefreshRateSelectorTest, testKernelIdleTimerAction) {
    using KernelIdleTimerAction = RefreshRateSelector::KernelIdleTimerAction;

    TestableRefreshRateSelector selector(kModes_60_90, kModeId90);

    EXPECT_EQ(KernelIdleTimerAction::TurnOn, selector.getIdleTimerAction());

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 90_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, selector.getIdleTimerAction());

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, selector.getIdleTimerAction());

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, selector.getIdleTimerAction());
}

TEST_F(RefreshRateSelectorTest, testKernelIdleTimerActionFor120Hz) {
    using KernelIdleTimerAction = RefreshRateSelector::KernelIdleTimerAction;

    TestableRefreshRateSelector selector(kModes_60_120, kModeId120);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {0_Hz, 60_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, selector.getIdleTimerAction());

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, selector.getIdleTimerAction());

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 120_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOn, selector.getIdleTimerAction());

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId120, {120_Hz, 120_Hz}}));
    EXPECT_EQ(KernelIdleTimerAction::TurnOff, selector.getIdleTimerAction());
}

TEST_F(RefreshRateSelectorTest, getFrameRateDivisor) {
    TestableRefreshRateSelector selector(kModes_30_60_72_90_120, kModeId30);

    const auto frameRate = 30_Hz;
    Fps displayRefreshRate = selector.getActiveMode().getFps();
    EXPECT_EQ(1, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveModeId(kModeId60);
    displayRefreshRate = selector.getActiveMode().getFps();
    EXPECT_EQ(2, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveModeId(kModeId72);
    displayRefreshRate = selector.getActiveMode().getFps();
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveModeId(kModeId90);
    displayRefreshRate = selector.getActiveMode().getFps();
    EXPECT_EQ(3, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveModeId(kModeId120);
    displayRefreshRate = selector.getActiveMode().getFps();
    EXPECT_EQ(4, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveModeId(kModeId90);
    displayRefreshRate = selector.getActiveMode().getFps();
    EXPECT_EQ(4, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, 22.5_Hz));

    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(24_Hz, 25_Hz));
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(24_Hz, 23.976_Hz));
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(30_Hz, 29.97_Hz));
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(60_Hz, 59.94_Hz));
}

TEST_F(RefreshRateSelectorTest, isFractionalPairOrMultiple) {
    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(23.976_Hz, 24_Hz));
    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(24_Hz, 23.976_Hz));

    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(29.97_Hz, 30_Hz));
    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(30_Hz, 29.97_Hz));

    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(59.94_Hz, 60_Hz));
    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(60_Hz, 59.94_Hz));

    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(29.97_Hz, 60_Hz));
    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(60_Hz, 29.97_Hz));

    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(59.94_Hz, 30_Hz));
    EXPECT_TRUE(RefreshRateSelector::isFractionalPairOrMultiple(30_Hz, 59.94_Hz));

    const auto refreshRates = {23.976_Hz, 24_Hz, 25_Hz, 29.97_Hz, 30_Hz, 50_Hz, 59.94_Hz, 60_Hz};
    for (auto refreshRate : refreshRates) {
        EXPECT_FALSE(RefreshRateSelector::isFractionalPairOrMultiple(refreshRate, refreshRate));
    }

    EXPECT_FALSE(RefreshRateSelector::isFractionalPairOrMultiple(24_Hz, 25_Hz));
    EXPECT_FALSE(RefreshRateSelector::isFractionalPairOrMultiple(23.978_Hz, 25_Hz));
    EXPECT_FALSE(RefreshRateSelector::isFractionalPairOrMultiple(29.97_Hz, 59.94_Hz));
}

TEST_F(RefreshRateSelectorTest, getFrameRateOverrides_noLayers) {
    RefreshRateSelector selector(kModes_30_60_72_90_120, kModeId120);

    EXPECT_TRUE(selector.getFrameRateOverrides({}, 120_Hz, {}).empty());
}

TEST_F(RefreshRateSelectorTest, getFrameRateOverrides_60on120) {
    RefreshRateSelector selector(kModes_30_60_72_90_120, kModeId120,
                                 {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    auto frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::NoVote;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Min;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Max;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());

    layers[0].vote = LayerVoteType::Heuristic;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateSelectorTest, getFrameRateOverrides_twoUids) {
    RefreshRateSelector selector(kModes_30_60_72_90_120, kModeId120,
                                 {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.ownerUid = 1234, .weight = 1.f},
                                            {.ownerUid = 5678, .weight = 1.f}};

    layers[0].name = "Test layer 1234";
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    layers[1].name = "Test layer 5678";
    layers[1].desiredRefreshRate = 30_Hz;
    layers[1].vote = LayerVoteType::ExplicitDefault;
    auto frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});

    EXPECT_EQ(2u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
    ASSERT_EQ(1u, frameRateOverrides.count(5678));
    EXPECT_EQ(30_Hz, frameRateOverrides.at(5678));

    layers[1].vote = LayerVoteType::Heuristic;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[1].ownerUid = 1234;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
}

TEST_F(RefreshRateSelectorTest, getFrameRateOverrides_touch) {
    RefreshRateSelector selector(kModes_30_60_72_90_120, kModeId120,
                                 {.enableFrameRateOverride = true});

    std::vector<LayerRequirement> layers = {{.ownerUid = 1234, .weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    auto frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExact;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());
}

} // namespace
} // namespace android::scheduler
