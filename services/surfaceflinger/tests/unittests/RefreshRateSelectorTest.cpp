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

#include <common/test/FlagUtils.h>
#include <scheduler/Fps.h>
#include <scheduler/FrameRateMode.h>
#include "DisplayHardware/HWC2.h"
#include "FpsOps.h"
#include "Scheduler/RefreshRateSelector.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockFrameRateMode.h"

#include "libsurfaceflinger_unittest_main.h"

#include <com_android_graphics_surfaceflinger_flags.h>

using namespace com::android::graphics::surfaceflinger;
using namespace std::chrono_literals;

namespace android::scheduler {

namespace hal = android::hardware::graphics::composer::hal;

using Config = RefreshRateSelector::Config;
using LayerRequirement = RefreshRateSelector::LayerRequirement;
using LayerVoteType = RefreshRateSelector::LayerVoteType;
using SetPolicyResult = RefreshRateSelector::SetPolicyResult;

using mock::createDisplayMode;
using mock::createVrrDisplayMode;

struct TestableRefreshRateSelector : RefreshRateSelector {
    using RefreshRateSelector::FrameRateRanking;
    using RefreshRateSelector::RefreshRateOrder;

    using RefreshRateSelector::RefreshRateSelector;

    void setActiveMode(DisplayModeId modeId, Fps renderFrameRate) {
        ftl::FakeGuard guard(kMainThreadContext);
        return RefreshRateSelector::setActiveMode(modeId, renderFrameRate);
    }

    const DisplayMode& getActiveMode() const {
        std::lock_guard lock(mLock);
        return *RefreshRateSelector::getActiveModeLocked().modePtr;
    }

    ftl::NonNull<DisplayModePtr> getMinSupportedRefreshRate() const {
        std::lock_guard lock(mLock);
        return ftl::as_non_null(mMinRefreshRateModeIt->second);
    }

    ftl::NonNull<DisplayModePtr> getMaxSupportedRefreshRate() const {
        std::lock_guard lock(mLock);
        return ftl::as_non_null(mMaxRefreshRateModeIt->second);
    }

    ftl::NonNull<DisplayModePtr> getMinRefreshRateByPolicy() const {
        std::lock_guard lock(mLock);
        return ftl::as_non_null(getMinRefreshRateByPolicyLocked());
    }

    ftl::NonNull<DisplayModePtr> getMaxRefreshRateByPolicy() const {
        std::lock_guard lock(mLock);
        return ftl::as_non_null(
                getMaxRefreshRateByPolicyLocked(getActiveModeLocked().modePtr->getGroup()));
    }

    FrameRateRanking rankRefreshRates(std::optional<int> anchorGroupOpt,
                                      RefreshRateOrder refreshRateOrder) const {
        std::lock_guard lock(mLock);
        return RefreshRateSelector::rankFrameRates(anchorGroupOpt, refreshRateOrder);
    }

    const std::vector<Fps>& knownFrameRates() const { return mKnownFrameRates; }

    using RefreshRateSelector::GetRankedFrameRatesCache;
    auto& mutableGetRankedRefreshRatesCache() { return mGetRankedFrameRatesCache; }

    auto getRankedFrameRates(const std::vector<LayerRequirement>& layers,
                             GlobalSignals signals = {}) const {
        const auto result = RefreshRateSelector::getRankedFrameRates(layers, signals);

        EXPECT_TRUE(std::is_sorted(result.ranking.begin(), result.ranking.end(),
                                   ScoredFrameRate::DescendingScore{}));

        return result;
    }

    auto getRankedRefreshRatesAsPair(const std::vector<LayerRequirement>& layers,
                                     GlobalSignals signals) const {
        const auto [ranking, consideredSignals] = getRankedFrameRates(layers, signals);
        return std::make_pair(ranking, consideredSignals);
    }

    FrameRateMode getBestFrameRateMode(const std::vector<LayerRequirement>& layers = {},
                                       GlobalSignals signals = {}) const {
        return getRankedFrameRates(layers, signals).ranking.front().frameRateMode;
    }

    ScoredFrameRate getBestScoredFrameRate(const std::vector<LayerRequirement>& layers = {},
                                           GlobalSignals signals = {}) const {
        return getRankedFrameRates(layers, signals).ranking.front();
    }

    SetPolicyResult setPolicy(const PolicyVariant& policy) {
        ftl::FakeGuard guard(kMainThreadContext);
        return RefreshRateSelector::setPolicy(policy);
    }

    SetPolicyResult setDisplayManagerPolicy(const DisplayManagerPolicy& policy) {
        return setPolicy(policy);
    }

    const auto& getPrimaryFrameRates() const { return mPrimaryFrameRates; }
};

class RefreshRateSelectorTest : public testing::TestWithParam<Config::FrameRateOverride> {
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
    static constexpr DisplayModeId kModeId35{11};
    static constexpr DisplayModeId kModeId1{12};
    static constexpr DisplayModeId kModeId5{13};
    static constexpr DisplayModeId kModeId10{14};

    static inline const ftl::NonNull<DisplayModePtr> kMode60 =
            ftl::as_non_null(createDisplayMode(kModeId60, 60_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode60Frac =
            ftl::as_non_null(createDisplayMode(kModeId60Frac, 59.94_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode90 =
            ftl::as_non_null(createDisplayMode(kModeId90, 90_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode90_G1 =
            ftl::as_non_null(createDisplayMode(kModeId90, 90_Hz, 1));
    static inline const ftl::NonNull<DisplayModePtr> kMode90_4K =
            ftl::as_non_null(createDisplayMode(kModeId90, 90_Hz, 0, {3840, 2160}));
    static inline const ftl::NonNull<DisplayModePtr> kMode72 =
            ftl::as_non_null(createDisplayMode(kModeId72, 72_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode72_G1 =
            ftl::as_non_null(createDisplayMode(kModeId72, 72_Hz, 1));
    static inline const ftl::NonNull<DisplayModePtr> kMode120 =
            ftl::as_non_null(createDisplayMode(kModeId120, 120_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode120_G1 =
            ftl::as_non_null(createDisplayMode(kModeId120, 120_Hz, 1));
    static inline const ftl::NonNull<DisplayModePtr> kMode30 =
            ftl::as_non_null(createDisplayMode(kModeId30, 30_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode30_G1 =
            ftl::as_non_null(createDisplayMode(kModeId30, 30_Hz, 1));
    static inline const ftl::NonNull<DisplayModePtr> kMode30Frac =
            ftl::as_non_null(createDisplayMode(kModeId30Frac, 29.97_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode25 =
            ftl::as_non_null(createDisplayMode(kModeId25, 25_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode25_G1 =
            ftl::as_non_null(createDisplayMode(kModeId25, 25_Hz, 1));
    static inline const ftl::NonNull<DisplayModePtr> kMode35 =
            ftl::as_non_null(createDisplayMode(kModeId35, 35_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode50 =
            ftl::as_non_null(createDisplayMode(kModeId50, 50_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode24 =
            ftl::as_non_null(createDisplayMode(kModeId24, 24_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode24Frac =
            ftl::as_non_null(createDisplayMode(kModeId24Frac, 23.976_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode1 =
            ftl::as_non_null(createDisplayMode(kModeId1, 1_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode5 =
            ftl::as_non_null(createDisplayMode(kModeId5, 5_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode10 =
            ftl::as_non_null(createDisplayMode(kModeId10, 10_Hz));

    // VRR modes
    static inline const ftl::NonNull<DisplayModePtr> kVrrMode120TE240 = ftl::as_non_null(
            createVrrDisplayMode(kModeId120, 240_Hz,
                                 hal::VrrConfig{
                                         .minFrameIntervalNs =
                                                 static_cast<Fps>(120_Hz).getPeriodNsecs()}));

    static inline const ftl::NonNull<DisplayModePtr> kVrrMode60TE120 = ftl::as_non_null(
            createVrrDisplayMode(kModeId60, 120_Hz,
                                 hal::VrrConfig{.minFrameIntervalNs =
                                                        static_cast<Fps>(60_Hz).getPeriodNsecs()},
                                 /*group=*/1));

    // Test configurations.
    static inline const DisplayModes kModes_60 = makeModes(kMode60);
    static inline const DisplayModes kModes_35_60_90 = makeModes(kMode35, kMode60, kMode90);
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
    static inline const DisplayModes kModes_1_5_10 = makeModes(kMode1, kMode5, kMode10);
    static inline const DisplayModes kModes_60_90_120 = makeModes(kMode60, kMode90, kMode120);

    // VRR display modes
    static inline const DisplayModes kVrrMode_120 = makeModes(kVrrMode120TE240);
    static inline const DisplayModes kVrrModes_60_120 =
            makeModes(kVrrMode60TE120, kVrrMode120TE240);

    // This is a typical TV configuration.
    static inline const DisplayModes kModes_24_25_30_50_60_Frac =
            makeModes(kMode24, kMode24Frac, kMode25, kMode30, kMode30Frac, kMode50, kMode60,
                      kMode60Frac);

    static TestableRefreshRateSelector createSelector(DisplayModes modes,
                                                      DisplayModeId activeModeId,
                                                      Config config = {}) {
        config.enableFrameRateOverride = GetParam();
        return TestableRefreshRateSelector(modes, activeModeId, config);
    }
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

INSTANTIATE_TEST_SUITE_P(PerOverrideConfig, RefreshRateSelectorTest,
                         testing::Values(Config::FrameRateOverride::Disabled,
                                         Config::FrameRateOverride::AppOverrideNativeRefreshRates,
                                         Config::FrameRateOverride::AppOverride,
                                         Config::FrameRateOverride::Enabled));

TEST_P(RefreshRateSelectorTest, oneMode_canSwitch) {
    auto selector = createSelector(kModes_60, kModeId60);
    if (GetParam() == Config::FrameRateOverride::Enabled) {
        EXPECT_TRUE(selector.canSwitch());
    } else {
        EXPECT_FALSE(selector.canSwitch());
    }
}

TEST_P(RefreshRateSelectorTest, invalidPolicy) {
    auto selector = createSelector(kModes_60, kModeId60);

    EXPECT_EQ(SetPolicyResult::Invalid,
              selector.setDisplayManagerPolicy({DisplayModeId(10), {60_Hz, 60_Hz}}));
    EXPECT_EQ(SetPolicyResult::Invalid,
              selector.setDisplayManagerPolicy({kModeId60, {20_Hz, 40_Hz}}));
}

TEST_P(RefreshRateSelectorTest, unchangedPolicy) {
    auto selector = createSelector(kModes_60_90, kModeId60);

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

TEST_P(RefreshRateSelectorTest, twoModes_storesFullRefreshRateMap) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    const auto minRate = selector.getMinSupportedRefreshRate();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode90, performanceRate);

    const auto minRateByPolicy = selector.getMinRefreshRateByPolicy();
    const auto performanceRateByPolicy = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(minRateByPolicy, minRate);
    EXPECT_EQ(performanceRateByPolicy, performanceRate);
}

TEST_P(RefreshRateSelectorTest, twoModes_storesFullRefreshRateMap_differentGroups) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    const auto minRate = selector.getMinRefreshRateByPolicy();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();
    const auto minRate60 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate60 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}));
    selector.setActiveMode(kModeId90, 90_Hz);

    const auto minRate90 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate90 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode90_G1, performanceRate);
    EXPECT_EQ(kMode90_G1, minRate90);
    EXPECT_EQ(kMode90_G1, performanceRate90);
}

TEST_P(RefreshRateSelectorTest, twoModes_storesFullRefreshRateMap_differentResolutions) {
    auto selector = createSelector(kModes_60_90_4K, kModeId60);

    const auto minRate = selector.getMinRefreshRateByPolicy();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();
    const auto minRate60 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate60 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode60, minRate);
    EXPECT_EQ(kMode60, minRate60);
    EXPECT_EQ(kMode60, performanceRate60);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {60_Hz, 90_Hz}}));
    selector.setActiveMode(kModeId90, 90_Hz);

    const auto minRate90 = selector.getMinRefreshRateByPolicy();
    const auto performanceRate90 = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kMode90_4K, performanceRate);
    EXPECT_EQ(kMode90_4K, minRate90);
    EXPECT_EQ(kMode90_4K, performanceRate90);
}

TEST_P(RefreshRateSelectorTest, twoModes_policyChange) {
    auto selector = createSelector(kModes_60_90, kModeId60);

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

TEST_P(RefreshRateSelectorTest, twoModes_getActiveMode) {
    auto selector = createSelector(kModes_60_90, kModeId60);
    {
        const auto& mode = selector.getActiveMode();
        EXPECT_EQ(mode.getId(), kModeId60);
    }

    selector.setActiveMode(kModeId90, 90_Hz);
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

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_noLayers) {
    {
        auto selector = createSelector(kModes_60_72_90, kModeId72);

        // If there are no layers we select the default frame rate, which is the max of the primary
        // range.
        EXPECT_EQ(kMode90, selector.getBestFrameRateMode().modePtr);

        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));
        EXPECT_EQ(kMode60, selector.getBestFrameRateMode().modePtr);
    }
    {
        // We select max even when this will cause a non-seamless switch.
        auto selector = createSelector(kModes_60_90_G1, kModeId60);
        constexpr bool kAllowGroupSwitching = true;
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId90, {0_Hz, 90_Hz}, kAllowGroupSwitching}));
        EXPECT_EQ(kMode90_G1, selector.getBestFrameRateMode().modePtr);
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_exactDontChangeRefreshRateWhenNotInPolicy) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId72);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].vote = LayerVoteType::ExplicitExact;
    layers[0].desiredRefreshRate = 120_Hz;

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId72, {0_Hz, 90_Hz}}));
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_60_90) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.name = "";
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {90_Hz, 90_Hz}}));

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {0_Hz, 120_Hz}}));
    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_multipleThreshold_60_90) {
    auto selector = createSelector(kModes_60_90, kModeId60, {.frameRateMultipleThreshold = 90});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_60_72_90) {
    auto selector = createSelector(kModes_60_72_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_30_60_72_90_120) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 48_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_30_60_90_120_DifferentTypes) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_30_60_90_120_DifferentTypes_multipleThreshold) {
    auto selector =
            createSelector(kModes_30_60_72_90_120, kModeId60, {.frameRateMultipleThreshold = 120});

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
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "60Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::Heuristic;
    lr1.name = "24Hz Heuristic";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.name = "24Hz ExplicitDefault";
    lr2.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.name = "120Hz ExplicitDefault";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 24_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "24Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::ExplicitExact;
    lr2.name = "120Hz ExplicitExact";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 10_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 120_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.name = "120Hz ExplicitExact";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.desiredRefreshRate = 30_Hz;
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.desiredRefreshRate = 30_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.name = "30Hz ExplicitExactOrMultiple";
    lr3.vote = LayerVoteType::Heuristic;
    lr3.desiredRefreshRate = 120_Hz;
    lr3.name = "120Hz Heuristic";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_30_60) {
    auto selector = createSelector(kModes_30_60, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    EXPECT_EQ(kMode30, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    EXPECT_EQ(kMode30, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_30_60_72_90) {
    auto selector = createSelector(kModes_30_60_72_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::Min;
    lr.name = "Min";
    EXPECT_EQ(kMode30, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    lr.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 90_Hz;
    lr.vote = LayerVoteType::Heuristic;
    lr.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);

    lr.desiredRefreshRate = 45_Hz;
    lr.name = "45Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);

    lr.desiredRefreshRate = 30_Hz;
    lr.name = "30Hz Heuristic";
    EXPECT_EQ(kMode30, selector.getBestFrameRateMode(layers).modePtr);
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    lr.name = "24Hz Heuristic";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);

    lr.desiredRefreshRate = 24_Hz;
    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.name = "24Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode72, selector.getBestFrameRateMode(layers).modePtr);
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_PriorityTest) {
    auto selector = createSelector(kModes_30_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Max;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Min;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 24_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Max;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 15_Hz;
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 30_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 45_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_24FpsVideo) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = selector.getBestFrameRateMode(layers).modePtr;
        EXPECT_EQ(kMode60, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getPeakFps()) << "("
                                 << to_string(mode->getVsyncRate()) << ")";
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_24FpsVideo_multipleThreshold_60_120) {
    auto selector = createSelector(kModes_60_120, kModeId60, {.frameRateMultipleThreshold = 120});

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 23.0f; fps < 25.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = selector.getBestFrameRateMode(layers).modePtr;
        EXPECT_EQ(kMode60, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getPeakFps()) << "("
                                 << to_string(mode->getVsyncRate()) << ")";
    }
}

TEST_P(RefreshRateSelectorTest, twoModes_getBestFrameRateMode_Explicit) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 60_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 90_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitDefault;
    lr1.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::Heuristic;
    lr1.desiredRefreshRate = 90_Hz;
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_75HzContent) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    for (float fps = 75.0f; fps < 100.0f; fps += 0.1f) {
        lr.desiredRefreshRate = Fps::fromValue(fps);
        const auto mode = selector.getBestFrameRateMode(layers, {}).modePtr;
        EXPECT_EQ(kMode90, mode) << lr.desiredRefreshRate << " chooses "
                                 << to_string(mode->getPeakFps()) << "("
                                 << to_string(mode->getVsyncRate()) << ")";
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_Multiples) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz ExplicitDefault";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 30_Hz;
    lr1.name = "30Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, scrollWhileWatching60fps_60_90) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);

    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Max;
    lr2.name = "Max";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    // The other layer starts to provide buffers
    lr1.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitExactOrMultiple";
    lr2.vote = LayerVoteType::Heuristic;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz Heuristic";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_ExplicitGte) {
    auto selector = createSelector(makeModes(kMode30, kMode60, kMode90, kMode120), kModeId120);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitGte";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 25_Hz;
    lr1.name = "25Hz ExplicitGte";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode30, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 91_Hz;
    lr1.name = "91Hz ExplicitGte";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitGte";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitDefault";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitGte";
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitGte";
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 60_Hz;
    lr2.name = "60Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitGte";
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 90_Hz;
    lr2.name = "90Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr1.vote = LayerVoteType::ExplicitGte;
    lr1.desiredRefreshRate = 60_Hz;
    lr1.name = "60Hz ExplicitGte";
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 120_Hz;
    lr2.name = "120Hz ExplicitExactOrMultiple";
    EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, getMaxRefreshRatesByPolicy) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    auto selector = createSelector(kModes_30_60_90, kModeId60);
    const auto refreshRates = selector.rankRefreshRates(selector.getActiveMode().getGroup(),
                                                        RefreshRateOrder::Descending);

    const auto expectedRefreshRates = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{90_Hz, kMode90}, {60_Hz, kMode60}, {30_Hz, kMode30}};
            case Config::FrameRateOverride::Enabled:
                return {{90_Hz, kMode90}, {60_Hz, kMode60}, {45_Hz, kMode90}, {30_Hz, kMode30}};
        }
    }();
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }
}

TEST_P(RefreshRateSelectorTest, getMinRefreshRatesByPolicy) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    auto selector = createSelector(kModes_30_60_90, kModeId60);

    const auto refreshRates = selector.rankRefreshRates(selector.getActiveMode().getGroup(),
                                                        RefreshRateOrder::Ascending);

    const auto expectedRefreshRates = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{30_Hz, kMode30}, {60_Hz, kMode60}, {90_Hz, kMode90}};
            case Config::FrameRateOverride::Enabled:
                return {{30_Hz, kMode30}, {60_Hz, kMode60}, {90_Hz, kMode90}};
        }
    }();
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }
}

TEST_P(RefreshRateSelectorTest, getMinRefreshRatesByPolicyOutsideTheGroup) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    auto selector = createSelector(kModes_30_60_90, kModeId72);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {30_Hz, 90_Hz}}));

    const auto refreshRates =
            selector.rankRefreshRates(/*anchorGroupOpt*/ std::nullopt, RefreshRateOrder::Ascending);

    const auto expectedRefreshRates = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{30_Hz, kMode30}, {60_Hz, kMode60}, {90_Hz, kMode90}};
            case Config::FrameRateOverride::Enabled:
                return {{30_Hz, kMode30}, {60_Hz, kMode60}, {90_Hz, kMode90}};
        }
    }();
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }
}

TEST_P(RefreshRateSelectorTest, getMaxRefreshRatesByPolicyOutsideTheGroup) {
    // The kModes_30_60_90 contains two kMode72_G1, kMode120_G1 which are from the
    // different group.
    auto selector = createSelector(kModes_30_60_90, kModeId72);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {30_Hz, 90_Hz}}));

    const auto refreshRates = selector.rankRefreshRates(/*anchorGroupOpt*/ std::nullopt,
                                                        RefreshRateOrder::Descending);

    const auto expectedRefreshRates = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{90_Hz, kMode90}, {60_Hz, kMode60}, {30_Hz, kMode30}};
            case Config::FrameRateOverride::Enabled:
                return {{90_Hz, kMode90}, {60_Hz, kMode60}, {45_Hz, kMode90}, {30_Hz, kMode30}};
        }
    }();
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }
}

TEST_P(RefreshRateSelectorTest, powerOnImminentConsidered) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    auto [refreshRates, signals] = selector.getRankedFrameRates({}, {});
    EXPECT_FALSE(signals.powerOnImminent);

    auto expectedRefreshRates = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{90_Hz, kMode90}, {60_Hz, kMode60}};
            case Config::FrameRateOverride::Enabled:
                return {{90_Hz, kMode90}, {60_Hz, kMode60},   {45_Hz, kMode90},
                        {30_Hz, kMode60}, {22.5_Hz, kMode90}, {20_Hz, kMode60}};
        }
    }();
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }

    std::tie(refreshRates, signals) =
            selector.getRankedRefreshRatesAsPair({}, {.powerOnImminent = true});
    EXPECT_TRUE(signals.powerOnImminent);

    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
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
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }

    std::tie(refreshRates, signals) =
            selector.getRankedRefreshRatesAsPair(layers, {.powerOnImminent = false});
    EXPECT_FALSE(signals.powerOnImminent);

    expectedRefreshRates = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{60_Hz, kMode60}, {90_Hz, kMode90}};
            case Config::FrameRateOverride::Enabled:
                return {{60_Hz, kMode60}, {90_Hz, kMode90},   {45_Hz, kMode90},
                        {30_Hz, kMode60}, {22.5_Hz, kMode90}, {20_Hz, kMode60}};
        }
    }();
    ASSERT_EQ(expectedRefreshRates.size(), refreshRates.size());

    for (size_t i = 0; i < expectedRefreshRates.size(); ++i) {
        EXPECT_EQ(expectedRefreshRates[i], refreshRates[i].frameRateMode)
                << "Expected " << expectedRefreshRates[i].fps.getIntValue() << " ("
                << expectedRefreshRates[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << refreshRates[i].frameRateMode.fps.getIntValue() << " ("
                << refreshRates[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }
}

TEST_P(RefreshRateSelectorTest, touchConsidered) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    auto [_, signals] = selector.getRankedFrameRates({}, {});
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

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_withFrameRateCategory_30_60_90_120) {
    auto selector = createSelector(makeModes(kMode30, kMode60, kMode90, kMode120), kModeId60);

    struct Case {
        // Params
        Fps desiredFrameRate = 0_Hz;
        FrameRateCategory frameRateCategory = FrameRateCategory::Default;

        // Expected result
        Fps expectedFrameRate = 0_Hz;
    };

    // Prepare a table with the vote and the expected refresh rate
    const std::initializer_list<Case> testCases = {
            // Cases that only have frame rate category requirements, but no desired frame rate.
            // When frame rates get an equal score, the lower is chosen, unless there are Max votes.
            {0_Hz, FrameRateCategory::High, 90_Hz},
            {0_Hz, FrameRateCategory::Normal, 60_Hz},
            {0_Hz, FrameRateCategory::Low, 30_Hz},
            {0_Hz, FrameRateCategory::NoPreference, 30_Hz},

            // Cases that have both desired frame rate and frame rate category requirements.
            {24_Hz, FrameRateCategory::High, 120_Hz},
            {30_Hz, FrameRateCategory::High, 90_Hz},
            {12_Hz, FrameRateCategory::Normal, 60_Hz},
            {30_Hz, FrameRateCategory::NoPreference, 30_Hz},

            // Cases that only have desired frame rate.
            {30_Hz, FrameRateCategory::Default, 30_Hz},
    };

    for (auto testCase : testCases) {
        std::vector<LayerRequirement> layers;
        ALOGI("**** %s: Testing desiredFrameRate=%s, frameRateCategory=%s", __func__,
              to_string(testCase.desiredFrameRate).c_str(),
              ftl::enum_string(testCase.frameRateCategory).c_str());

        if (testCase.desiredFrameRate.isValid()) {
            std::stringstream ss;
            ss << to_string(testCase.desiredFrameRate) << "ExplicitDefault";
            LayerRequirement layer = {.name = ss.str(),
                                      .vote = LayerVoteType::ExplicitDefault,
                                      .desiredRefreshRate = testCase.desiredFrameRate,
                                      .weight = 1.f};
            layers.push_back(layer);
        }

        if (testCase.frameRateCategory != FrameRateCategory::Default) {
            std::stringstream ss;
            ss << "ExplicitCategory (" << ftl::enum_string(testCase.frameRateCategory) << ")";
            LayerRequirement layer = {.name = ss.str(),
                                      .vote = LayerVoteType::ExplicitCategory,
                                      .frameRateCategory = testCase.frameRateCategory,
                                      .weight = 1.f};
            layers.push_back(layer);
        }

        EXPECT_EQ(testCase.expectedFrameRate,
                  selector.getBestFrameRateMode(layers).modePtr->getPeakFps())
                << "Did not get expected frame rate for frameRate="
                << to_string(testCase.desiredFrameRate)
                << " category=" << ftl::enum_string(testCase.frameRateCategory);
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_withFrameRateCategory_60_120) {
    auto selector = createSelector(makeModes(kMode60, kMode120), kModeId60);

    struct Case {
        // Params
        Fps desiredFrameRate = 0_Hz;
        FrameRateCategory frameRateCategory = FrameRateCategory::Default;

        // Expected result
        Fps expectedFrameRate = 0_Hz;
    };

    // Prepare a table with the vote and the expected refresh rate
    const std::initializer_list<Case> testCases = {
            // Cases that only have frame rate category requirements, but no desired frame rate.
            // When frame rates get an equal score, the lower is chosen, unless there are Max votes.
            {0_Hz, FrameRateCategory::High, 120_Hz},
            {0_Hz, FrameRateCategory::Normal, 60_Hz},
            {0_Hz, FrameRateCategory::Low, 60_Hz},
            {0_Hz, FrameRateCategory::NoPreference, 60_Hz},

            // Cases that have both desired frame rate and frame rate category requirements.
            {24_Hz, FrameRateCategory::High, 120_Hz},
            {30_Hz, FrameRateCategory::High, 120_Hz},
            {12_Hz, FrameRateCategory::Normal, 60_Hz},
            {30_Hz, FrameRateCategory::NoPreference, 60_Hz},

            // Cases that only have desired frame rate.
            {30_Hz, FrameRateCategory::Default, 60_Hz},
    };

    for (auto testCase : testCases) {
        std::vector<LayerRequirement> layers;
        ALOGI("**** %s: Testing desiredFrameRate=%s, frameRateCategory=%s", __func__,
              to_string(testCase.desiredFrameRate).c_str(),
              ftl::enum_string(testCase.frameRateCategory).c_str());

        if (testCase.desiredFrameRate.isValid()) {
            std::stringstream ss;
            ss << to_string(testCase.desiredFrameRate) << "ExplicitDefault";
            LayerRequirement layer = {.name = ss.str(),
                                      .vote = LayerVoteType::ExplicitDefault,
                                      .desiredRefreshRate = testCase.desiredFrameRate,
                                      .weight = 1.f};
            layers.push_back(layer);
        }

        if (testCase.frameRateCategory != FrameRateCategory::Default) {
            std::stringstream ss;
            ss << "ExplicitCategory (" << ftl::enum_string(testCase.frameRateCategory) << ")";
            LayerRequirement layer = {.name = ss.str(),
                                      .vote = LayerVoteType::ExplicitCategory,
                                      .frameRateCategory = testCase.frameRateCategory,
                                      .weight = 1.f};
            layers.push_back(layer);
        }

        EXPECT_EQ(testCase.expectedFrameRate,
                  selector.getBestFrameRateMode(layers).modePtr->getPeakFps())
                << "Did not get expected frame rate for frameRate="
                << to_string(testCase.desiredFrameRate)
                << " category=" << ftl::enum_string(testCase.frameRateCategory);
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_withFrameRateCategory_HighHint) {
    auto selector = createSelector(makeModes(kMode24, kMode30, kMode60, kMode120), kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 1.f}};
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    lr1.vote = LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = LayerVoteType::NoVote;
    lr2.name = "NoVote";
    auto actualRankedFrameRates = selector.getRankedFrameRates(layers);
    // Gets touch boost
    EXPECT_EQ(120_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
    EXPECT_EQ(kModeId120, actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
    EXPECT_TRUE(actualRankedFrameRates.consideredSignals.touch);

    // No touch boost, for example a game that uses setFrameRate(30, default compatibility).
    lr1.vote = LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitDefault";
    actualRankedFrameRates = selector.getRankedFrameRates(layers);
    EXPECT_EQ(30_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
    EXPECT_EQ(kModeId30, actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
    EXPECT_FALSE(actualRankedFrameRates.consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = LayerVoteType::ExplicitCategory;
    lr2.frameRateCategory = FrameRateCategory::HighHint;
    lr2.name = "ExplicitCategory HighHint#2";
    actualRankedFrameRates = selector.getRankedFrameRates(layers);
    // Gets touch boost
    EXPECT_EQ(120_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
    EXPECT_EQ(kModeId120, actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
    EXPECT_TRUE(actualRankedFrameRates.consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = LayerVoteType::ExplicitCategory;
    lr2.frameRateCategory = FrameRateCategory::Low;
    lr2.name = "ExplicitCategory Low";
    actualRankedFrameRates = selector.getRankedFrameRates(layers);
    // Gets touch boost
    EXPECT_EQ(120_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
    EXPECT_EQ(kModeId120, actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
    EXPECT_TRUE(actualRankedFrameRates.consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitExactOrMultiple";
    actualRankedFrameRates = selector.getRankedFrameRates(layers);
    // Gets touch boost
    EXPECT_EQ(120_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
    EXPECT_EQ(kModeId120, actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
    EXPECT_TRUE(actualRankedFrameRates.consideredSignals.touch);

    lr1.vote = LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = LayerVoteType::ExplicitExact;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitExact";
    actualRankedFrameRates = selector.getRankedFrameRates(layers);
    if (selector.supportsAppFrameRateOverrideByContent()) {
        // Gets touch boost
        EXPECT_EQ(120_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
        EXPECT_EQ(kModeId120,
                  actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
        EXPECT_TRUE(actualRankedFrameRates.consideredSignals.touch);
    } else {
        EXPECT_EQ(30_Hz, actualRankedFrameRates.ranking.front().frameRateMode.fps);
        EXPECT_EQ(kModeId30, actualRankedFrameRates.ranking.front().frameRateMode.modePtr->getId());
        EXPECT_FALSE(actualRankedFrameRates.consideredSignals.touch);
    }
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_withFrameRateCategory_smoothSwitchOnly_60_120_nonVrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, false);
    // VRR compatibility is determined by the presence of a vrr config in the DisplayMode.
    auto selector = createSelector(makeModes(kMode60, kMode120), kModeId120);

    struct Case {
        // Params
        FrameRateCategory frameRateCategory = FrameRateCategory::Default;
        bool smoothSwitchOnly = false;

        // Expected result
        Fps expectedFrameRate = 0_Hz;
        DisplayModeId expectedModeId = kModeId60;
    };

    const std::initializer_list<Case> testCases = {
            // These layers may switch modes because smoothSwitchOnly=false.
            {FrameRateCategory::Default, false, 120_Hz, kModeId120},
            // TODO(b/266481656): Once this bug is fixed, NoPreference should be a lower frame rate.
            {FrameRateCategory::NoPreference, false, 60_Hz, kModeId60},
            {FrameRateCategory::Low, false, 30_Hz, kModeId60},
            {FrameRateCategory::Normal, false, 60_Hz, kModeId60},
            {FrameRateCategory::High, false, 120_Hz, kModeId120},

            // These layers cannot change mode due to smoothSwitchOnly, and will definitely use
            // active mode (120Hz).
            {FrameRateCategory::NoPreference, true, 120_Hz, kModeId120},
            {FrameRateCategory::Low, true, 120_Hz, kModeId120},
            {FrameRateCategory::Normal, true, 40_Hz, kModeId120},
            {FrameRateCategory::High, true, 120_Hz, kModeId120},
    };

    for (auto testCase : testCases) {
        std::vector<LayerRequirement> layers;
        ALOGI("**** %s: Testing frameRateCategory=%s (smooth=%d)", __func__,
              ftl::enum_string(testCase.frameRateCategory).c_str(), testCase.smoothSwitchOnly);

        if (testCase.frameRateCategory != FrameRateCategory::Default) {
            std::stringstream ss;
            ss << "ExplicitCategory (" << ftl::enum_string(testCase.frameRateCategory)
               << " smooth:" << testCase.smoothSwitchOnly << ")";
            LayerRequirement layer = {.name = ss.str(),
                                      .vote = LayerVoteType::ExplicitCategory,
                                      .frameRateCategory = testCase.frameRateCategory,
                                      .frameRateCategorySmoothSwitchOnly =
                                              testCase.smoothSwitchOnly,
                                      .weight = 1.f};
            layers.push_back(layer);
        }

        auto actualFrameRateMode = selector.getBestFrameRateMode(layers);
        EXPECT_EQ(testCase.expectedFrameRate, actualFrameRateMode.fps)
                << "Did not get expected frame rate for category="
                << ftl::enum_string(testCase.frameRateCategory)
                << " (smooth=" << testCase.smoothSwitchOnly << ")";

        EXPECT_EQ(testCase.expectedModeId, actualFrameRateMode.modePtr->getId())
                << "Did not get expected mode for category="
                << ftl::enum_string(testCase.frameRateCategory)
                << " (smooth=" << testCase.smoothSwitchOnly << ")";
    }
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_withFrameRateCategory_smoothSwitchOnly_60_120_vrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    // VRR compatibility is determined by the presence of a vrr config in the DisplayMode.
    auto selector = createSelector(kVrrModes_60_120, kModeId120);

    struct Case {
        // Params
        FrameRateCategory frameRateCategory = FrameRateCategory::Default;
        bool smoothSwitchOnly = false;

        // Expected result
        Fps expectedFrameRate = 0_Hz;
    };

    // Note that `smoothSwitchOnly` should not have an effect.
    const std::initializer_list<Case> testCases = {
            {FrameRateCategory::Default, false, 120_Hz},
            // TODO(b/266481656): Once this bug is fixed, NoPreference should be a lower frame rate.
            {FrameRateCategory::NoPreference, false, 120_Hz},
            {FrameRateCategory::Low, false, 30_Hz},
            {FrameRateCategory::Normal, false, 60_Hz},
            {FrameRateCategory::High, false, 120_Hz},
            {FrameRateCategory::Default, true, 120_Hz},
            // TODO(b/266481656): Once this bug is fixed, NoPreference should be a lower frame rate.
            {FrameRateCategory::NoPreference, true, 120_Hz},
            {FrameRateCategory::Low, true, 30_Hz},
            {FrameRateCategory::Normal, true, 60_Hz},
            {FrameRateCategory::High, true, 120_Hz},
    };

    for (auto testCase : testCases) {
        std::vector<LayerRequirement> layers;
        ALOGI("**** %s: Testing frameRateCategory=%s (smooth=%d)", __func__,
              ftl::enum_string(testCase.frameRateCategory).c_str(), testCase.smoothSwitchOnly);

        if (testCase.frameRateCategory != FrameRateCategory::Default) {
            std::stringstream ss;
            ss << "ExplicitCategory (" << ftl::enum_string(testCase.frameRateCategory)
               << " smooth:" << testCase.smoothSwitchOnly << ")";
            LayerRequirement layer = {.name = ss.str(),
                                      .vote = LayerVoteType::ExplicitCategory,
                                      .frameRateCategory = testCase.frameRateCategory,
                                      .frameRateCategorySmoothSwitchOnly =
                                              testCase.smoothSwitchOnly,
                                      .weight = 1.f};
            layers.push_back(layer);
        }

        auto actualFrameRateMode = selector.getBestFrameRateMode(layers);
        EXPECT_EQ(testCase.expectedFrameRate, actualFrameRateMode.fps)
                << "Did not get expected frame rate for category="
                << ftl::enum_string(testCase.frameRateCategory)
                << " (smooth=" << testCase.smoothSwitchOnly << ")";

        // Expect all cases to be able to stay at the mode with TE 240 due to VRR compatibility.
        EXPECT_EQ(kVrrMode120TE240->getId(), actualFrameRateMode.modePtr->getId())
                << "Did not get expected mode for category="
                << ftl::enum_string(testCase.frameRateCategory)
                << " (smooth=" << testCase.smoothSwitchOnly << ")";
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_ExplicitDefault) {
    auto selector = createSelector(kModes_60_90_72_120, kModeId60);

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

        const auto bestMode = selector.getBestFrameRateMode(layers).modePtr;
        EXPECT_EQ(expected, bestMode->getPeakFps())
                << "expected " << expected << " for " << desired << " but got "
                << bestMode->getPeakFps() << "(" << bestMode->getVsyncRate() << ")";
    }
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_ExplicitExactOrMultiple_WithFractionalRefreshRates) {
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Test that 23.976 will prefer 60 over 59.94 and 30
    {
        auto selector = createSelector(makeModes(kMode24, kMode25, kMode30, kMode30Frac, kMode60,
                                                 kMode60Frac),
                                       kModeId60);

        lr.vote = LayerVoteType::ExplicitExactOrMultiple;
        lr.desiredRefreshRate = 23.976_Hz;
        lr.name = "ExplicitExactOrMultiple 23.976 Hz";
        EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
    }

    // Test that 24 will choose 23.976 if 24 is not supported
    {
        auto selector = createSelector(makeModes(kMode24Frac, kMode25, kMode30, kMode30Frac,
                                                 kMode60, kMode60Frac),
                                       kModeId60);

        lr.desiredRefreshRate = 24_Hz;
        lr.name = "ExplicitExactOrMultiple 24 Hz";
        EXPECT_EQ(kModeId24Frac, selector.getBestFrameRateMode(layers).modePtr->getId());
    }

    // Test that 29.97 will prefer 59.94 over 60 and 30
    {
        auto selector = createSelector(makeModes(kMode24, kMode24Frac, kMode25, kMode30, kMode60,
                                                 kMode60Frac),
                                       kModeId60);

        lr.desiredRefreshRate = 29.97_Hz;
        lr.name = "ExplicitExactOrMultiple 29.97 Hz";
        EXPECT_EQ(kModeId60Frac, selector.getBestFrameRateMode(layers).modePtr->getId());
    }

    // Test that 29.97 will choose 60 if 59.94 is not supported
    {
        auto selector = createSelector(makeModes(kMode30, kMode60), kModeId60);

        lr.desiredRefreshRate = 29.97_Hz;
        lr.name = "ExplicitExactOrMultiple 29.97 Hz";
        EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
    }

    // Test that 59.94 will choose 60 if 59.94 is not supported
    {
        auto selector = createSelector(makeModes(kMode60, kMode30Frac, kMode30), kModeId60);

        lr.desiredRefreshRate = 59.94_Hz;
        lr.name = "ExplicitExactOrMultiple 59.94 Hz";
        EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_ExplicitExact_WithFractionalRefreshRates) {
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    // Test that voting for supported refresh rate will select this refresh rate
    {
        auto selector = createSelector(kModes_24_25_30_50_60_Frac, kModeId60);

        for (auto desired : {23.976_Hz, 24_Hz, 25_Hz, 29.97_Hz, 30_Hz, 50_Hz, 59.94_Hz, 60_Hz}) {
            lr.vote = LayerVoteType::ExplicitExact;
            lr.desiredRefreshRate = desired;
            std::stringstream ss;
            ss << "ExplicitExact " << desired;
            lr.name = ss.str();

            EXPECT_EQ(lr.desiredRefreshRate,
                      selector.getBestFrameRateMode(layers).modePtr->getPeakFps());
        }
    }
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_withDisplayManagerRequestingSingleRate_ignoresTouchFlag) {
    auto selector = createSelector(kModes_60_90, kModeId90);

    constexpr FpsRange k90 = {90_Hz, 90_Hz};
    constexpr FpsRange k60_90 = {60_Hz, 90_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {k90, k90}, {k60_90, k60_90}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = true;

    const auto [rankedFrameRate, signals] =
            selector.getRankedFrameRates(layers, {.touch = true, .idle = true});

    EXPECT_EQ(rankedFrameRate.begin()->frameRateMode.modePtr, kMode60);
    EXPECT_FALSE(signals.touch);
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_withDisplayManagerRequestingSingleRate_ignoresIdleFlag) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    constexpr FpsRange k60 = {60_Hz, 60_Hz};
    constexpr FpsRange k60_90 = {60_Hz, 90_Hz};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {k60, k60}, {k60_90, k60_90}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 90_Hz;
    lr.name = "90Hz ExplicitDefault";
    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers, {.idle = true}).modePtr);
}

TEST_P(RefreshRateSelectorTest, testDisplayModeOrdering) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId60);

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

    auto expectedRanking = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{120_Hz, kMode120},
                        {90_Hz, kMode90},
                        {72_Hz, kMode72},
                        {60_Hz, kMode60},
                        {30_Hz, kMode30}};
            case Config::FrameRateOverride::Enabled:
                return {{120_Hz, kMode120}, {90_Hz, kMode90},  {72_Hz, kMode72}, {60_Hz, kMode60},
                        {45_Hz, kMode90},   {40_Hz, kMode120}, {36_Hz, kMode72}, {30_Hz, kMode30}};
        }
    }();

    auto actualRanking = selector.getRankedFrameRates(layers, {}).ranking;
    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].frameRateMode)
                << "Expected " << expectedRanking[i].fps.getIntValue() << " ("
                << expectedRanking[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << actualRanking[i].frameRateMode.fps.getIntValue() << " ("
                << actualRanking[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
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

    expectedRanking = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{120_Hz, kMode120},
                        {90_Hz, kMode90},
                        {72_Hz, kMode72},
                        {60_Hz, kMode60},
                        {30_Hz, kMode30}};
            case Config::FrameRateOverride::Enabled:
                return {{120_Hz, kMode120}, {90_Hz, kMode90},  {72_Hz, kMode72}, {60_Hz, kMode60},
                        {45_Hz, kMode90},   {40_Hz, kMode120}, {36_Hz, kMode72}, {30_Hz, kMode30}};
        }
    }();
    actualRanking = selector.getRankedFrameRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].frameRateMode)
                << "Expected " << expectedRanking[i].fps.getIntValue() << " ("
                << expectedRanking[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << actualRanking[i].frameRateMode.fps.getIntValue() << " ("
                << actualRanking[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
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

    expectedRanking = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{30_Hz, kMode30},
                        {60_Hz, kMode60},
                        {90_Hz, kMode90},
                        {120_Hz, kMode120},
                        {72_Hz, kMode72}};
            case Config::FrameRateOverride::Enabled:
                return {{30_Hz, kMode30}, {60_Hz, kMode60},  {90_Hz, kMode90}, {120_Hz, kMode120},
                        {45_Hz, kMode90}, {40_Hz, kMode120}, {72_Hz, kMode72}, {36_Hz, kMode72}};
        }
    }();
    actualRanking = selector.getRankedFrameRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].frameRateMode)
                << "Expected " << expectedRanking[i].fps.getIntValue() << " ("
                << expectedRanking[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << actualRanking[i].frameRateMode.fps.getIntValue() << " ("
                << actualRanking[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
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

    expectedRanking = []() -> std::vector<FrameRateMode> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{90_Hz, kMode90},
                        {60_Hz, kMode60},
                        {120_Hz, kMode120},
                        {72_Hz, kMode72},
                        {30_Hz, kMode30}};
            case Config::FrameRateOverride::Enabled:
                return {{90_Hz, kMode90}, {60_Hz, kMode60},  {120_Hz, kMode120}, {72_Hz, kMode72},
                        {45_Hz, kMode90}, {40_Hz, kMode120}, {36_Hz, kMode72},   {30_Hz, kMode30}};
        }
    }();
    actualRanking = selector.getRankedFrameRates(layers, {}).ranking;

    ASSERT_EQ(expectedRanking.size(), actualRanking.size());

    for (size_t i = 0; i < expectedRanking.size(); ++i) {
        EXPECT_EQ(expectedRanking[i], actualRanking[i].frameRateMode)
                << "Expected " << expectedRanking[i].fps.getIntValue() << " ("
                << expectedRanking[i].modePtr->getVsyncRate().getIntValue() << ")"
                << " Actual " << actualRanking[i].frameRateMode.fps.getIntValue() << " ("
                << actualRanking[i].frameRateMode.modePtr->getVsyncRate().getIntValue() << ")";
    }
}

TEST_P(RefreshRateSelectorTest,
       getBestFrameRateMode_withDisplayManagerRequestingSingleRate_onlySwitchesRatesForExplicitFocusedLayers) {
    auto selector = createSelector(kModes_60_90, kModeId90);

    constexpr FpsRange k90 = {90_Hz, 90_Hz};
    constexpr FpsRange k60_90 = {60_Hz, 90_Hz};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId90, {k90, k90}, {k60_90, k60_90}}));

    const auto [ranking, signals] = selector.getRankedFrameRates({}, {});
    EXPECT_EQ(ranking.front().frameRateMode.modePtr, kMode90);
    EXPECT_FALSE(signals.touch);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& lr = layers[0];

    lr.vote = LayerVoteType::ExplicitExactOrMultiple;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitExactOrMultiple";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::ExplicitDefault;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz ExplicitDefault";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.focused = true;
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Heuristic;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Heuristic";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Max;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Max";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.vote = LayerVoteType::Min;
    lr.desiredRefreshRate = 60_Hz;
    lr.name = "60Hz Min";
    lr.focused = false;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);

    lr.focused = true;
    EXPECT_EQ(kMode90, selector.getBestFrameRateMode(layers).modePtr);
}

TEST_P(RefreshRateSelectorTest, groupSwitchingNotAllowed) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    // The default policy doesn't allow group switching. Verify that no
    // group switches are performed.
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 90_Hz;
    layer.seamlessness = Seamlessness::SeamedAndSeamless;
    layer.name = "90Hz ExplicitDefault";
    layer.focused = true;

    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithOneLayer) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

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
    EXPECT_EQ(kModeId90, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithOneLayerOnlySeamless) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

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
    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithOneLayerOnlySeamlessDefaultFps) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveMode(kModeId90, 90_Hz);

    // Verify that we won't do a seamless switch if we request the same mode as the default
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::OnlySeamless;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;
    EXPECT_EQ(kModeId90, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithOneLayerDefaultSeamlessness) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveMode(kModeId90, 90_Hz);

    // Verify that if the active mode is in another group and there are no layers with
    // Seamlessness::SeamedAndSeamless, we should switch back to the default group.

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];
    layer.vote = LayerVoteType::ExplicitDefault;
    layer.desiredRefreshRate = 60_Hz;
    layer.seamlessness = Seamlessness::Default;
    layer.name = "60Hz ExplicitDefault";
    layer.focused = true;

    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithTwoLayersOnlySeamlessAndSeamed) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveMode(kModeId90, 90_Hz);

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

    EXPECT_EQ(kModeId90, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithTwoLayersDefaultFocusedAndSeamed) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveMode(kModeId90, 90_Hz);

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

    EXPECT_EQ(kModeId90, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, groupSwitchingWithTwoLayersDefaultNotFocusedAndSeamed) {
    auto selector = createSelector(kModes_60_90_G1, kModeId60);

    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    selector.setActiveMode(kModeId90, 90_Hz);

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

    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, nonSeamlessVotePrefersSeamlessSwitches) {
    auto selector = createSelector(kModes_30_60, kModeId60);

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

    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode(layers).modePtr->getId());

    selector.setActiveMode(kModeId120, 120_Hz);
    EXPECT_EQ(kModeId120, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, nonSeamlessExactAndSeamlessMultipleLayers) {
    auto selector = createSelector(kModes_25_30_50_60, kModeId60);

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

    EXPECT_EQ(kModeId50, selector.getBestFrameRateMode(layers).modePtr->getId());

    auto& seamedLayer = layers[0];
    seamedLayer.desiredRefreshRate = 30_Hz;
    seamedLayer.name = "30Hz ExplicitDefault";
    selector.setActiveMode(kModeId30, 30_Hz);

    EXPECT_EQ(kModeId25, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, minLayersDontTrigerSeamedSwitch) {
    auto selector = createSelector(kModes_60_90_G1, kModeId90);

    // Allow group switching.
    RefreshRateSelector::DisplayManagerPolicy policy;
    policy.defaultMode = selector.getCurrentPolicy().defaultMode;
    policy.allowGroupSwitching = true;
    EXPECT_EQ(SetPolicyResult::Changed, selector.setPolicy(policy));

    std::vector<LayerRequirement> layers = {
            {.name = "Min", .vote = LayerVoteType::Min, .weight = 1.f, .focused = true}};

    EXPECT_EQ(kModeId90, selector.getBestFrameRateMode(layers).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, primaryVsAppRequestPolicy) {
    auto selector = createSelector(kModes_30_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    struct Args {
        bool touch = false;
        bool focused = true;
    };

    // Returns the mode selected by getBestFrameRateMode for a single layer with the given
    // arguments.
    const auto getFrameRate = [&](LayerVoteType voteType, Fps fps,
                                  Args args = {}) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = fps;
        layers[0].focused = args.focused;
        return selector.getBestFrameRateMode(layers, {.touch = args.touch}).modePtr->getId();
    };

    constexpr FpsRange k30_60 = {30_Hz, 60_Hz};
    constexpr FpsRange k30_90 = {30_Hz, 90_Hz};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {k30_60, k30_60}, {k30_90, k30_90}}));

    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode().modePtr->getId());
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
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 60_Hz}}));

    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::NoVote, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Min, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Max, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::Heuristic, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitDefault, 90_Hz));
    EXPECT_EQ(kModeId60, getFrameRate(LayerVoteType::ExplicitExactOrMultiple, 90_Hz));
}

TEST_P(RefreshRateSelectorTest, idle) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    const auto getIdleDisplayModeId = [&](LayerVoteType voteType,
                                          bool touchActive) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = 90_Hz;

        const auto [ranking, signals] =
                selector.getRankedFrameRates(layers, {.touch = touchActive, .idle = true});

        // Refresh rate will be chosen by either touch state or idle state.
        EXPECT_EQ(!touchActive, signals.idle);
        return ranking.front().frameRateMode.modePtr->getId();
    };

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {60_Hz, 90_Hz}}));

    // Idle should be lower priority than touch boost.
    {
        constexpr bool kTouchActive = true;
        EXPECT_EQ(kModeId90, getIdleDisplayModeId(LayerVoteType::NoVote, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleDisplayModeId(LayerVoteType::Min, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleDisplayModeId(LayerVoteType::Max, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleDisplayModeId(LayerVoteType::Heuristic, kTouchActive));
        EXPECT_EQ(kModeId90, getIdleDisplayModeId(LayerVoteType::ExplicitDefault, kTouchActive));
        EXPECT_EQ(kModeId90,
                  getIdleDisplayModeId(LayerVoteType::ExplicitExactOrMultiple, kTouchActive));
    }

    // With no layers, idle should still be lower priority than touch boost.
    EXPECT_EQ(kModeId90,
              selector.getBestFrameRateMode({}, {.touch = true, .idle = true}).modePtr->getId());

    // Idle should be higher precedence than other layer frame rate considerations.
    selector.setActiveMode(kModeId90, 90_Hz);

    {
        constexpr bool kTouchActive = false;
        EXPECT_EQ(kModeId60, getIdleDisplayModeId(LayerVoteType::NoVote, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleDisplayModeId(LayerVoteType::Min, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleDisplayModeId(LayerVoteType::Max, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleDisplayModeId(LayerVoteType::Heuristic, kTouchActive));
        EXPECT_EQ(kModeId60, getIdleDisplayModeId(LayerVoteType::ExplicitDefault, kTouchActive));
        EXPECT_EQ(kModeId60,
                  getIdleDisplayModeId(LayerVoteType::ExplicitExactOrMultiple, kTouchActive));
    }

    // Idle should be applied rather than the active mode when there are no layers.
    EXPECT_EQ(kModeId60, selector.getBestFrameRateMode({}, {.idle = true}).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, findClosestKnownFrameRate) {
    auto selector = createSelector(kModes_60_90, kModeId60);

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

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_KnownFrameRate) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    struct Expectation {
        Fps fps;
        ftl::NonNull<DisplayModePtr> mode;
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
        EXPECT_EQ(mode, selector.getBestFrameRateMode(layers).modePtr);
    }
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_ExplicitExact) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = 30_Hz;

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    if (GetParam() == Config::FrameRateOverride::Disabled) {
        EXPECT_FRAME_RATE_MODE(kMode30, 30_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
        EXPECT_FRAME_RATE_MODE(kMode30, 30_Hz,
                               selector.getBestScoredFrameRate(layers, {.touch = true})
                                       .frameRateMode);

    } else {
        EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
        EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz,
                               selector.getBestScoredFrameRate(layers, {.touch = true})
                                       .frameRateMode);
    }

    explicitExactOrMultipleLayer.desiredRefreshRate = 120_Hz;
    explicitExactLayer.desiredRefreshRate = 60_Hz;

    if (GetParam() == Config::FrameRateOverride::Disabled) {
        EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
    } else {
        EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
    }

    explicitExactLayer.desiredRefreshRate = 72_Hz;
    EXPECT_FRAME_RATE_MODE(kMode72, 72_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);

    explicitExactLayer.desiredRefreshRate = 90_Hz;
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);

    explicitExactLayer.desiredRefreshRate = 120_Hz;
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_ReadsCache) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId60);

    using GlobalSignals = RefreshRateSelector::GlobalSignals;
    const auto args = std::make_pair(std::vector<LayerRequirement>{},
                                     GlobalSignals{.touch = true, .idle = true});

    const RefreshRateSelector::RankedFrameRates result = {{RefreshRateSelector::ScoredFrameRate{
                                                                  {90_Hz, kMode90}}},
                                                          GlobalSignals{.touch = true}};

    selector.mutableGetRankedRefreshRatesCache() = {args, result};

    EXPECT_EQ(result, selector.getRankedFrameRates(args.first, args.second));
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_WritesCache) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId60);

    EXPECT_FALSE(selector.mutableGetRankedRefreshRatesCache());

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    RefreshRateSelector::GlobalSignals globalSignals{.touch = true, .idle = true};

    const auto result = selector.getRankedFrameRates(layers, globalSignals);

    const auto& cache = selector.mutableGetRankedRefreshRatesCache();
    ASSERT_TRUE(cache);

    EXPECT_EQ(cache->arguments, std::make_pair(layers, globalSignals));
    EXPECT_EQ(cache->result, result);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_ExplicitExactTouchBoost) {
    auto selector = createSelector(kModes_60_120, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}, {.weight = 0.5f}};
    auto& explicitExactLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitExactLayer.vote = LayerVoteType::ExplicitExact;
    explicitExactLayer.name = "ExplicitExact";
    explicitExactLayer.desiredRefreshRate = 30_Hz;

    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
    if (GetParam() == Config::FrameRateOverride::Disabled) {
        EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);
    } else {
        EXPECT_EQ(kMode120, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);
    }

    explicitExactOrMultipleLayer.vote = LayerVoteType::NoVote;

    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers, {.touch = true}).modePtr);
}

TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_FractionalRefreshRates_ExactAndDefault) {
    auto selector = createSelector(kModes_24_25_30_50_60_Frac, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 0.5f}, {.weight = 0.5f}};
    auto& explicitDefaultLayer = layers[0];
    auto& explicitExactOrMultipleLayer = layers[1];

    explicitExactOrMultipleLayer.vote = LayerVoteType::ExplicitExactOrMultiple;
    explicitExactOrMultipleLayer.name = "ExplicitExactOrMultiple";
    explicitExactOrMultipleLayer.desiredRefreshRate = 60_Hz;

    explicitDefaultLayer.vote = LayerVoteType::ExplicitDefault;
    explicitDefaultLayer.name = "ExplicitDefault";
    explicitDefaultLayer.desiredRefreshRate = 59.94_Hz;

    EXPECT_EQ(kMode60, selector.getBestFrameRateMode(layers).modePtr);
}

// b/190578904
TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_withCloseRefreshRates) {
    if (g_noSlowTests) {
        GTEST_SKIP();
    }

    const int kMinRefreshRate = RefreshRateSelector::kMinSupportedFrameRate.getIntValue();
    constexpr int kMaxRefreshRate = 240;

    DisplayModes displayModes;
    for (int fps = kMinRefreshRate; fps < kMaxRefreshRate; fps++) {
        const DisplayModeId modeId(fps);
        displayModes.try_emplace(modeId,
                                 createDisplayMode(modeId,
                                                   Fps::fromValue(static_cast<float>(fps))));
    }

    const auto selector = createSelector(std::move(displayModes), DisplayModeId(kMinRefreshRate));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    const auto testRefreshRate = [&](Fps fps, LayerVoteType vote) {
        layers[0].desiredRefreshRate = fps;
        layers[0].vote = vote;
        EXPECT_EQ(fps.getIntValue(),
                  selector.getBestFrameRateMode(layers).modePtr->getPeakFps().getIntValue())
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
TEST_P(RefreshRateSelectorTest, getBestFrameRateMode_conflictingVotes) {
    constexpr DisplayModeId kActiveModeId{0};
    DisplayModes displayModes = makeModes(createDisplayMode(kActiveModeId, 43_Hz),
                                          createDisplayMode(DisplayModeId(1), 53_Hz),
                                          createDisplayMode(DisplayModeId(2), 55_Hz),
                                          createDisplayMode(DisplayModeId(3), 60_Hz));

    const RefreshRateSelector::GlobalSignals globalSignals = {.touch = false, .idle = false};
    const auto selector = createSelector(std::move(displayModes), kActiveModeId);

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

    EXPECT_EQ(53_Hz, selector.getBestFrameRateMode(layers, globalSignals).modePtr->getPeakFps());
}

TEST_P(RefreshRateSelectorTest, modeComparison) {
    EXPECT_LT(kMode60->getPeakFps(), kMode90->getPeakFps());
    EXPECT_GE(kMode60->getPeakFps(), kMode60->getPeakFps());
    EXPECT_GE(kMode90->getPeakFps(), kMode90->getPeakFps());
}

TEST_P(RefreshRateSelectorTest, testKernelIdleTimerAction) {
    using KernelIdleTimerAction = RefreshRateSelector::KernelIdleTimerAction;

    auto selector = createSelector(kModes_60_90, kModeId90);

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

TEST_P(RefreshRateSelectorTest, testKernelIdleTimerActionFor120Hz) {
    using KernelIdleTimerAction = RefreshRateSelector::KernelIdleTimerAction;

    auto selector = createSelector(kModes_60_120, kModeId120);

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

TEST_P(RefreshRateSelectorTest, getFrameRateDivisor) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId30);

    const auto frameRate = 30_Hz;
    Fps displayRefreshRate = selector.getActiveMode().getPeakFps();
    EXPECT_EQ(1, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveMode(kModeId60, 60_Hz);
    displayRefreshRate = selector.getActiveMode().getPeakFps();
    EXPECT_EQ(2, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveMode(kModeId72, 72_Hz);
    displayRefreshRate = selector.getActiveMode().getPeakFps();
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveMode(kModeId90, 90_Hz);
    displayRefreshRate = selector.getActiveMode().getPeakFps();
    EXPECT_EQ(3, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveMode(kModeId120, 120_Hz);
    displayRefreshRate = selector.getActiveMode().getPeakFps();
    EXPECT_EQ(4, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, frameRate));

    selector.setActiveMode(kModeId90, 90_Hz);
    displayRefreshRate = selector.getActiveMode().getPeakFps();
    EXPECT_EQ(4, RefreshRateSelector::getFrameRateDivisor(displayRefreshRate, 22.5_Hz));

    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(24_Hz, 25_Hz));
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(24_Hz, 23.976_Hz));
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(30_Hz, 29.97_Hz));
    EXPECT_EQ(0, RefreshRateSelector::getFrameRateDivisor(60_Hz, 59.94_Hz));
}

TEST_P(RefreshRateSelectorTest, isFractionalPairOrMultiple) {
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

TEST_P(RefreshRateSelectorTest, test23976Chooses120) {
    auto selector = createSelector(kModes_60_90_120, kModeId120);
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "23.976 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 23.976_Hz;
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, test23976Chooses60IfThresholdIs120) {
    auto selector =
            createSelector(kModes_60_90_120, kModeId120, {.frameRateMultipleThreshold = 120});
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "23.976 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 23.976_Hz;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, test25Chooses60) {
    auto selector = createSelector(kModes_60_90_120, kModeId120);
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "25 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 25.00_Hz;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, test2997Chooses60) {
    auto selector = createSelector(kModes_60_90_120, kModeId120);
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "29.97 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 29.97_Hz;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, test50Chooses120) {
    auto selector = createSelector(kModes_60_90_120, kModeId120);
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "50 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 50.00_Hz;
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, test50Chooses60IfThresholdIs120) {
    auto selector =
            createSelector(kModes_60_90_120, kModeId120, {.frameRateMultipleThreshold = 120});
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "50 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 50.00_Hz;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, test5994Chooses60) {
    auto selector = createSelector(kModes_60_90_120, kModeId120);
    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "59.94 ExplicitExactOrMultiple";
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[0].desiredRefreshRate = 59.94_Hz;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_noLayers) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

    EXPECT_TRUE(selector.getFrameRateOverrides({}, 120_Hz, {}).empty());
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_NonExplicit) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 60_Hz;

    layers[0].vote = LayerVoteType::NoVote;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());

    layers[0].vote = LayerVoteType::Min;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());

    layers[0].vote = LayerVoteType::Max;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());

    layers[0].vote = LayerVoteType::Heuristic;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_Disabled) {
    if (GetParam() != Config::FrameRateOverride::Disabled) {
        return;
    }

    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 60_Hz;

    layers[0].vote = LayerVoteType::ExplicitDefault;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());

    layers[0].vote = LayerVoteType::ExplicitExact;
    EXPECT_TRUE(selector.getFrameRateOverrides(layers, 120_Hz, {}).empty());
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_60on120) {
    if (GetParam() == Config::FrameRateOverride::Disabled) {
        return;
    }

    ASSERT_TRUE(GetParam() == Config::FrameRateOverride::AppOverrideNativeRefreshRates ||
                GetParam() == Config::FrameRateOverride::AppOverride ||
                GetParam() == Config::FrameRateOverride::Enabled);

    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

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

    layers[0].vote = LayerVoteType::ExplicitExact;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_twoUids) {
    if (GetParam() == Config::FrameRateOverride::Disabled) {
        return;
    }

    ASSERT_TRUE(GetParam() == Config::FrameRateOverride::AppOverrideNativeRefreshRates ||
                GetParam() == Config::FrameRateOverride::AppOverride ||
                GetParam() == Config::FrameRateOverride::Enabled);

    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

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

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_withFrameRateCategory) {
    if (GetParam() == Config::FrameRateOverride::Disabled) {
        return;
    }

    ASSERT_TRUE(GetParam() == Config::FrameRateOverride::AppOverrideNativeRefreshRates ||
                GetParam() == Config::FrameRateOverride::AppOverride ||
                GetParam() == Config::FrameRateOverride::Enabled);

    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

    std::vector<LayerRequirement> layers = {{.ownerUid = 1234, .weight = 1.f},
                                            {.ownerUid = 1234, .weight = 1.f}};

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitCategory High";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::High;
    auto frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitCategory Normal";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Normal;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitCategory Low";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Low;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitCategory NoPreference";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::NoPreference;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // HighHint case *without* touch boost has frame rate override.
    // For example, game and touch interaction.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitDefault 60";
    layers[1].vote = LayerVoteType::ExplicitDefault;
    layers[1].desiredRefreshRate = 60_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Default;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitExactOrMultiple 30";
    layers[1].vote = LayerVoteType::ExplicitExactOrMultiple;
    layers[1].desiredRefreshRate = 30_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Default;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitExact 60";
    layers[1].vote = LayerVoteType::ExplicitExact;
    layers[1].desiredRefreshRate = 60_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Default;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // HighHint case with touch boost and thus should skip frame rate override.
    layers[0].name = "ExplicitCategory HighHint";
    layers[0].vote = LayerVoteType::ExplicitCategory;
    layers[0].desiredRefreshRate = 0_Hz;
    layers[0].frameRateCategory = FrameRateCategory::HighHint;
    layers[1].name = "ExplicitGte 60";
    layers[1].vote = LayerVoteType::ExplicitGte;
    layers[1].desiredRefreshRate = 60_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Default;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_TRUE(frameRateOverrides.empty());
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_TRUE(frameRateOverrides.empty());

    // ExplicitCategory case that expects no global touch boost and thus has frame rate override.
    layers[0].name = "ExplicitDefault 60";
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].frameRateCategory = FrameRateCategory::Default;
    layers[1].name = "ExplicitCategory High";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::High;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(120_Hz, frameRateOverrides.at(1234));
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(120_Hz, frameRateOverrides.at(1234));

    // ExplicitCategory case that expects no global touch boost and thus has frame rate override.
    layers[0].name = "ExplicitDefault 60";
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].frameRateCategory = FrameRateCategory::Default;
    layers[1].name = "ExplicitCategory Normal";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Normal;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    // ExplicitCategory case that expects no global touch boost and thus has frame rate override.
    layers[0].name = "ExplicitDefault 60";
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].frameRateCategory = FrameRateCategory::Default;
    layers[1].name = "ExplicitCategory Low";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::Low;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    // ExplicitCategory case that expects no global touch boost and thus has frame rate override.
    layers[0].name = "ExplicitDefault 60";
    layers[0].vote = LayerVoteType::ExplicitDefault;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].frameRateCategory = FrameRateCategory::Default;
    layers[1].name = "ExplicitCategory NoPreference";
    layers[1].vote = LayerVoteType::ExplicitCategory;
    layers[1].desiredRefreshRate = 0_Hz;
    layers[1].frameRateCategory = FrameRateCategory::NoPreference;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_touch) {
    if (GetParam() == Config::FrameRateOverride::Disabled) {
        return;
    }

    ASSERT_TRUE(GetParam() == Config::FrameRateOverride::AppOverrideNativeRefreshRates ||
                GetParam() == Config::FrameRateOverride::AppOverride ||
                GetParam() == Config::FrameRateOverride::Enabled);

    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

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

    layers[0].vote = LayerVoteType::ExplicitGte;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {.touch = true});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_DivisorIsNotDisplayRefreshRate) {
    if (GetParam() == Config::FrameRateOverride::Disabled) {
        return;
    }

    ASSERT_TRUE(GetParam() == Config::FrameRateOverride::AppOverrideNativeRefreshRates ||
                GetParam() == Config::FrameRateOverride::AppOverride ||
                GetParam() == Config::FrameRateOverride::Enabled);

    auto selector = createSelector(kModes_60_120, kModeId120);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 30_Hz;

    const auto expetedFps =
            GetParam() == Config::FrameRateOverride::AppOverrideNativeRefreshRates ? 60_Hz : 30_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;
    auto frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(expetedFps, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(expetedFps, frameRateOverrides.at(1234));

    layers[0].vote = LayerVoteType::ExplicitExact;
    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    ASSERT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(expetedFps, frameRateOverrides.at(1234));
}

TEST_P(RefreshRateSelectorTest, renderFrameRateInvalidPolicy) {
    auto selector = createSelector(kModes_60_120, kModeId120);

    // The render frame rate cannot be greater than the physical refresh rate
    {
        const FpsRange physical = {60_Hz, 60_Hz};
        const FpsRange render = {60_Hz, 120_Hz};
        EXPECT_EQ(SetPolicyResult::Invalid,
                  selector.setDisplayManagerPolicy(
                          {kModeId60, {physical, render}, {physical, render}}));
    }
}

TEST_P(RefreshRateSelectorTest, renderFrameRateRestrictsPhysicalRefreshRate) {
    auto selector = createSelector(kModes_60_120, kModeId120);

    {
        const FpsRange physical = {0_Hz, 120_Hz};
        const FpsRange render = {0_Hz, 60_Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId60, {physical, render}, {physical, render}}));
        const auto expectedMaxMode =
                GetParam() == Config::FrameRateOverride::Enabled ? kMode120 : kMode60;
        EXPECT_EQ(expectedMaxMode, selector.getMaxRefreshRateByPolicy());
        EXPECT_EQ(kMode60, selector.getMinRefreshRateByPolicy());
    }

    {
        const FpsRange physical = {0_Hz, 120_Hz};
        const FpsRange render = {120_Hz, 120_Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId60, {physical, render}, {physical, render}}));
        EXPECT_EQ(kMode120, selector.getMaxRefreshRateByPolicy());
        EXPECT_EQ(kMode120, selector.getMinRefreshRateByPolicy());
    }
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverrides_InPolicy) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    {
        const FpsRange physical = {120_Hz, 120_Hz};
        const FpsRange render = {60_Hz, 90_Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId120, {physical, render}, {physical, render}}));
    }

    layers[0].name = "30Hz";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 30_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    auto frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    EXPECT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(60_Hz, frameRateOverrides.at(1234));

    {
        const FpsRange physical = {120_Hz, 120_Hz};
        const FpsRange render = {30_Hz, 90_Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId120, {physical, render}, {physical, render}}));
    }

    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    EXPECT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(30_Hz, frameRateOverrides.at(1234));

    {
        const FpsRange physical = {120_Hz, 120_Hz};
        const FpsRange render = {30_Hz, 30_Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy(
                          {kModeId120, {physical, render}, {physical, render}}));
    }

    layers[0].name = "60Hz";
    layers[0].ownerUid = 1234;
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitDefault;

    frameRateOverrides = selector.getFrameRateOverrides(layers, 120_Hz, {});
    EXPECT_EQ(1u, frameRateOverrides.size());
    EXPECT_EQ(1u, frameRateOverrides.count(1234));
    EXPECT_EQ(30_Hz, frameRateOverrides.at(1234));
}

TEST_P(RefreshRateSelectorTest, renderFrameRates) {
    auto selector = createSelector(kModes_30_60_72_90_120, kModeId120);

    // [renderRate, refreshRate]
    const auto expected = []() -> std::vector<std::pair<Fps, Fps>> {
        switch (GetParam()) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
            case Config::FrameRateOverride::AppOverride:
                return {{30_Hz, 30_Hz},
                        {60_Hz, 60_Hz},
                        {72_Hz, 72_Hz},
                        {90_Hz, 90_Hz},
                        {120_Hz, 120_Hz}};
            case Config::FrameRateOverride::Enabled:
                return {{30_Hz, 30_Hz}, {36_Hz, 72_Hz}, {40_Hz, 120_Hz}, {45_Hz, 90_Hz},
                        {60_Hz, 60_Hz}, {72_Hz, 72_Hz}, {90_Hz, 90_Hz},  {120_Hz, 120_Hz}};
        }
    }();

    const auto& primaryRefreshRates = selector.getPrimaryFrameRates();
    ASSERT_EQ(expected.size(), primaryRefreshRates.size());

    for (size_t i = 0; i < expected.size(); i++) {
        const auto [expectedRenderRate, expectedRefreshRate] = expected[i];
        EXPECT_EQ(expectedRenderRate, primaryRefreshRates[i].fps);
        EXPECT_EQ(expectedRefreshRate, primaryRefreshRates[i].modePtr->getPeakFps());
    }
}

TEST_P(RefreshRateSelectorTest, refreshRateIsCappedWithRenderFrameRate) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    auto selector = createSelector(kModes_60_120, kModeId60);

    constexpr FpsRange k0_120Hz = {0_Hz, 120_Hz};
    constexpr FpsRange k0_60Hz = {0_Hz, 60_Hz};

    constexpr FpsRanges kAppRequest = {/*physical*/ k0_120Hz,
                                       /*render*/ k0_120Hz};

    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, selector.getBestScoredFrameRate().frameRateMode);
    {
        constexpr FpsRanges kPrimary = {/*physical*/ k0_120Hz,
                                        /*render*/ k0_120Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy({/*defaultMode*/ kModeId60,
                                                    /*primaryRanges*/
                                                    kPrimary,
                                                    /*appRequestRanges*/
                                                    kAppRequest}));
    }
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, selector.getBestScoredFrameRate().frameRateMode);

    {
        constexpr FpsRanges kPrimary = {/*physical*/ k0_60Hz,
                                        /*render*/ k0_60Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy({/*defaultMode*/ kModeId60,
                                                    /*primaryRanges*/
                                                    kPrimary,
                                                    /*appRequestRanges*/
                                                    kAppRequest}));
    }
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate().frameRateMode);

    {
        constexpr FpsRanges kPrimary = {/*physical*/ k0_120Hz,
                                        /*render*/ k0_60Hz};
        EXPECT_EQ(SetPolicyResult::Changed,
                  selector.setDisplayManagerPolicy({/*defaultMode*/ kModeId60,
                                                    /*primaryRanges*/
                                                    kPrimary,
                                                    /*appRequestRanges*/
                                                    kAppRequest}));
    }
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate().frameRateMode);
}

TEST_P(RefreshRateSelectorTest, renderFrameRates_60_120) {
    auto selector = createSelector(kModes_60_120, kModeId120);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    auto& layer = layers[0];

    const auto expectedRenderRate =
            GetParam() == Config::FrameRateOverride::Enabled ? 30_Hz : 60_Hz;

    layer.name = "30Hz ExplicitDefault";
    layer.desiredRefreshRate = 30_Hz;
    layer.vote = LayerVoteType::ExplicitDefault;
    EXPECT_FRAME_RATE_MODE(kMode60, expectedRenderRate,
                           selector.getBestScoredFrameRate(layers).frameRateMode);

    layer.name = "30Hz Heuristic";
    layer.desiredRefreshRate = 30_Hz;
    layer.vote = LayerVoteType::Heuristic;
    EXPECT_FRAME_RATE_MODE(kMode60, expectedRenderRate,
                           selector.getBestScoredFrameRate(layers).frameRateMode);

    layer.name = "30Hz ExplicitExactOrMultiple";
    layer.desiredRefreshRate = 30_Hz;
    layer.vote = LayerVoteType::ExplicitExactOrMultiple;
    EXPECT_FRAME_RATE_MODE(kMode60, expectedRenderRate,
                           selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, idleWhenLowestRefreshRateIsNotDivisor) {
    auto selector = createSelector(kModes_35_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";

    const auto getIdleDisplayModeId = [&](LayerVoteType voteType,
                                          bool touchActive) -> DisplayModeId {
        layers[0].vote = voteType;
        layers[0].desiredRefreshRate = 90_Hz;

        const auto [ranking, signals] =
                selector.getRankedFrameRates(layers, {.touch = touchActive, .idle = true});

        // Refresh rate will be chosen by either touch state or idle state.
        EXPECT_EQ(!touchActive, signals.idle);
        return ranking.front().frameRateMode.modePtr->getId();
    };

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({kModeId60, {0_Hz, 90_Hz}}));

    // With no layers, idle should still be lower priority than touch boost.
    EXPECT_EQ(kModeId90,
              selector.getBestFrameRateMode({}, {.touch = true, .idle = true}).modePtr->getId());

    // Idle should be higher precedence than other layer frame rate considerations.
    selector.setActiveMode(kModeId90, 90_Hz);
    {
        constexpr bool kTouchActive = false;
        EXPECT_EQ(kModeId35, getIdleDisplayModeId(LayerVoteType::NoVote, kTouchActive));
        EXPECT_EQ(kModeId35, getIdleDisplayModeId(LayerVoteType::Min, kTouchActive));
        EXPECT_EQ(kModeId35, getIdleDisplayModeId(LayerVoteType::Max, kTouchActive));
        EXPECT_EQ(kModeId35, getIdleDisplayModeId(LayerVoteType::Heuristic, kTouchActive));
        EXPECT_EQ(kModeId35, getIdleDisplayModeId(LayerVoteType::ExplicitDefault, kTouchActive));
        EXPECT_EQ(kModeId35,
                  getIdleDisplayModeId(LayerVoteType::ExplicitExactOrMultiple, kTouchActive));
    }

    // Idle should be applied rather than the active mode when there are no layers.
    EXPECT_EQ(kModeId35, selector.getBestFrameRateMode({}, {.idle = true}).modePtr->getId());
}

TEST_P(RefreshRateSelectorTest, policyCanBeInfinity) {
    auto selector = createSelector(kModes_60_120, kModeId120);

    constexpr Fps inf = Fps::fromValue(std::numeric_limits<float>::infinity());

    using namespace fps_approx_ops;
    selector.setDisplayManagerPolicy({kModeId60, {0_Hz, inf}});

    // With no layers, idle should still be lower priority than touch boost.
    EXPECT_EQ(kMode120, selector.getMaxRefreshRateByPolicy());
    EXPECT_EQ(kMode60, selector.getMinRefreshRateByPolicy());
}

TEST_P(RefreshRateSelectorTest, SupportsLowPhysicalRefreshRates) {
    auto selector = createSelector(kModes_1_5_10, kModeId10);

    EXPECT_EQ(kMode10, selector.getMaxRefreshRateByPolicy());
    EXPECT_EQ(kMode1, selector.getMinRefreshRateByPolicy());
}

// TODO(b/266481656): Once this bug is fixed, we can remove this test
// And test for VRR when we remove this work around for VRR.
TEST_P(RefreshRateSelectorTest, noLowerFrameRateOnMinVote) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].vote = LayerVoteType::Min;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);

    constexpr FpsRanges kCappedAt60 = {{30_Hz, 90_Hz}, {30_Hz, 60_Hz}};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {DisplayModeId(kModeId60), kCappedAt60, kCappedAt60}));
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, frameRateIsCappedByPolicy) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    auto selector = createSelector(kModes_60_90, kModeId60);

    constexpr FpsRanges kCappedAt30 = {{60_Hz, 90_Hz}, {30_Hz, 30_Hz}};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {DisplayModeId(kModeId60), kCappedAt30, kCappedAt30}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].vote = LayerVoteType::Min;
    EXPECT_FRAME_RATE_MODE(kMode60, 30_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, frameRateNotInRange) {
    auto selector = createSelector(kModes_60_90, kModeId60);

    constexpr FpsRanges k60Only = {{60_Hz, 90_Hz}, {60_Hz, 60_Hz}};
    constexpr FpsRanges kAll = {{0_Hz, 90_Hz}, {0_Hz, 90_Hz}};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy({DisplayModeId(kModeId60), k60Only, kAll}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].vote = LayerVoteType::Heuristic;
    layers[0].desiredRefreshRate = 45_Hz;
    EXPECT_FRAME_RATE_MODE(kMode60, 60_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, frameRateIsLowerThanMinSupported) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    auto selector = createSelector(kModes_60_90, kModeId60);

    constexpr Fps kMin = RefreshRateSelector::kMinSupportedFrameRate;
    constexpr FpsRanges kLowerThanMin = {{60_Hz, 90_Hz}, {kMin / 2, kMin / 2}};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {DisplayModeId(kModeId60), kLowerThanMin, kLowerThanMin}));
}

// b/296079213
TEST_P(RefreshRateSelectorTest, frameRateOverrideInBlockingZone60_120) {
    auto selector = createSelector(kModes_60_120, kModeId120);

    const FpsRange only120 = {120_Hz, 120_Hz};
    const FpsRange allRange = {0_Hz, 120_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, allRange}, {allRange, allRange}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "30Hz ExplicitExactOrMultiple";
    layers[0].desiredRefreshRate = 30_Hz;
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;

    if (GetParam() != Config::FrameRateOverride::Enabled) {
        EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
    } else {
        EXPECT_FRAME_RATE_MODE(kMode120, 30_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
    }
}

TEST_P(RefreshRateSelectorTest, frameRateOverrideInBlockingZone60_90) {
    auto selector = createSelector(kModes_60_90, kModeId90);

    const FpsRange only90 = {90_Hz, 90_Hz};
    const FpsRange allRange = {0_Hz, 90_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId90, {only90, allRange}, {allRange, allRange}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "30Hz ExplicitExactOrMultiple";
    layers[0].desiredRefreshRate = 30_Hz;
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;

    if (GetParam() != Config::FrameRateOverride::Enabled) {
        EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
    } else {
        EXPECT_FRAME_RATE_MODE(kMode90, 30_Hz,
                               selector.getBestScoredFrameRate(layers).frameRateMode);
    }
}

TEST_P(RefreshRateSelectorTest, frameRateOverrideInBlockingZone60_90_NonDivisor) {
    auto selector = createSelector(kModes_60_90, kModeId90);

    const FpsRange only90 = {90_Hz, 90_Hz};
    const FpsRange allRange = {0_Hz, 90_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId90, {only90, allRange}, {allRange, allRange}}));

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "60Hz ExplicitExactOrMultiple";
    layers[0].desiredRefreshRate = 60_Hz;
    layers[0].vote = LayerVoteType::ExplicitExactOrMultiple;

    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, selector.getBestScoredFrameRate(layers).frameRateMode);
}

// VRR tests
TEST_P(RefreshRateSelectorTest, singleMinMaxRateForVrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    auto selector = createSelector(kVrrMode_120, kModeId120);
    EXPECT_TRUE(selector.supportsFrameRateOverride());

    const auto minRate = selector.getMinSupportedRefreshRate();
    const auto performanceRate = selector.getMaxSupportedRefreshRate();
    const auto minRateByPolicy = selector.getMinRefreshRateByPolicy();
    const auto performanceRateByPolicy = selector.getMaxRefreshRateByPolicy();

    EXPECT_EQ(kVrrMode120TE240, minRate);
    EXPECT_EQ(kVrrMode120TE240, performanceRate);
    EXPECT_EQ(kVrrMode120TE240, minRateByPolicy);
    EXPECT_EQ(kVrrMode120TE240, performanceRateByPolicy);
}

TEST_P(RefreshRateSelectorTest, renderRateChangesWithPolicyChangeForVrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    auto selector = createSelector(kVrrModes_60_120, kModeId120);

    const FpsRange only120 = {120_Hz, 120_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, only120}, {only120, only120}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 120_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    const FpsRange range120 = {0_Hz, 120_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range120}, {only120, range120}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 120_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    const FpsRange range90 = {0_Hz, 90_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range90}, {only120, range90}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 80_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    const FpsRange range80 = {0_Hz, 80_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range80}, {only120, range80}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 80_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    const FpsRange range60 = {0_Hz, 60_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range60}, {only120, range60}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 60_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    const FpsRange range48 = {0_Hz, 48_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range48}, {only120, range48}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 48_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    const FpsRange range30 = {0_Hz, 30_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range30}, {only120, range30}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 30_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, modeChangesWithPolicyChangeForVrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    auto selector = createSelector(kVrrModes_60_120, kModeId120);

    const FpsRange range120 = {0_Hz, 120_Hz};
    const FpsRange range60 = {0_Hz, 60_Hz};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {range120, range60}, {range120, range60}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode120TE240, 60_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId60, {range60, range60}, {range60, range60}}));
    EXPECT_FRAME_RATE_MODE(kVrrMode60TE120, 60_Hz,
                           selector.getBestScoredFrameRate({}).frameRateMode);
}

TEST_P(RefreshRateSelectorTest, getFrameRateOverridesForVrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    auto selector = createSelector(kVrrMode_120, kModeId120);
    // TODO(b/297600226) Run at lower than 30 Fps for dVRR
    const std::vector<Fps> desiredRefreshRates = {30_Hz, 34.285_Hz, 40_Hz, 48_Hz,
                                                  60_Hz, 80_Hz,     120_Hz};
    const std::vector<LayerVoteType> layerVotes = {LayerVoteType::ExplicitDefault,
                                                   LayerVoteType::ExplicitExactOrMultiple,
                                                   LayerVoteType::ExplicitExact};

    std::vector<LayerRequirement> layers = {{.weight = 1.f}};
    layers[0].name = "Test layer";
    layers[0].ownerUid = 1234;

    for (auto desiredRefreshRate : desiredRefreshRates) {
        layers[0].desiredRefreshRate = desiredRefreshRate;
        for (auto vote : layerVotes) {
            layers[0].vote = vote;
            auto frameRateOverrides = selector.getFrameRateOverrides(layers, 240_Hz, {});
            EXPECT_EQ(1u, frameRateOverrides.size());
            ASSERT_EQ(1u, frameRateOverrides.count(1234));
            EXPECT_EQ(desiredRefreshRate, frameRateOverrides.at(1234));
        }
    }
}

TEST_P(RefreshRateSelectorTest, renderFrameRatesForVrr) {
    if (GetParam() != Config::FrameRateOverride::Enabled) {
        return;
    }

    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    auto selector = createSelector(kVrrMode_120, kModeId120);
    const FpsRange only120 = {120_Hz, 120_Hz};
    const FpsRange range120 = {0_Hz, 120_Hz};

    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {only120, range120}, {only120, range120}}));

    std::vector<Fps> expected = {20_Hz, 21.818_Hz, 24_Hz, 26.666_Hz, 30_Hz, 34.285_Hz,
                                 40_Hz, 48_Hz,     60_Hz, 80_Hz,     120_Hz};

    auto primaryRefreshRates = selector.getPrimaryFrameRates();
    ASSERT_EQ(expected.size(), primaryRefreshRates.size());

    for (size_t i = 0; i < expected.size(); i++) {
        EXPECT_EQ(expected[i], primaryRefreshRates[i].fps);
        EXPECT_EQ(120_Hz, primaryRefreshRates[i].modePtr->getPeakFps());
    }

    // Render range (0,90)
    const FpsRange range90 = {0_Hz, 90_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {range120, range90}, {range120, range90}}));

    expected = {20_Hz, 21.818_Hz, 24_Hz, 26.666_Hz, 30_Hz, 34.285_Hz, 40_Hz, 48_Hz, 60_Hz, 80_Hz};

    primaryRefreshRates = selector.getPrimaryFrameRates();
    ASSERT_EQ(expected.size(), primaryRefreshRates.size());
    for (size_t i = 0; i < expected.size(); i++) {
        EXPECT_EQ(expected[i], primaryRefreshRates[i].fps);
        EXPECT_EQ(120_Hz, primaryRefreshRates[i].modePtr->getPeakFps());
    }

    // Render range (0,60)
    const FpsRange range60 = {0_Hz, 60_Hz};
    EXPECT_EQ(SetPolicyResult::Changed,
              selector.setDisplayManagerPolicy(
                      {kModeId120, {range120, range60}, {range120, range60}}));
    expected = {20_Hz, 21.818_Hz, 24_Hz, 26.666_Hz, 30_Hz, 34.285_Hz, 40_Hz, 48_Hz, 60_Hz};

    primaryRefreshRates = selector.getPrimaryFrameRates();
    ASSERT_EQ(expected.size(), primaryRefreshRates.size());
    for (size_t i = 0; i < expected.size(); i++) {
        EXPECT_EQ(expected[i], primaryRefreshRates[i].fps);
        EXPECT_EQ(120_Hz, primaryRefreshRates[i].modePtr->getPeakFps());
    }
}
} // namespace
} // namespace android::scheduler
