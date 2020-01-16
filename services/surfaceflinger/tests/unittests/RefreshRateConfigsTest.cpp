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

#include "DisplayHardware/HWC2.h"
#include "Scheduler/RefreshRateConfigs.h"

using namespace std::chrono_literals;
using testing::_;

namespace android {
namespace scheduler {

using RefreshRate = RefreshRateConfigs::RefreshRate;

class RefreshRateConfigsTest : public testing::Test {
protected:
    static inline const HwcConfigIndexType HWC_CONFIG_ID_60 = HwcConfigIndexType(0);
    static inline const HwcConfigIndexType HWC_CONFIG_ID_90 = HwcConfigIndexType(1);
    static inline const HwcConfigGroupType HWC_GROUP_ID_0 = HwcConfigGroupType(0);
    static inline const HwcConfigGroupType HWC_GROUP_ID_1 = HwcConfigGroupType(1);
    static constexpr int64_t VSYNC_60 = 16666667;
    static constexpr int64_t VSYNC_60_POINT_4 = 16666665;
    static constexpr int64_t VSYNC_90 = 11111111;

    RefreshRateConfigsTest();
    ~RefreshRateConfigsTest();
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
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(RefreshRateConfigsTest, oneDeviceConfig_SwitchingSupported) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());
}

TEST_F(RefreshRateConfigsTest, oneDeviceConfig_SwitchingNotSupported) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/false, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    ASSERT_FALSE(refreshRateConfigs->refreshRateSwitchingSupported());
}

TEST_F(RefreshRateConfigsTest, invalidPolicy) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    ASSERT_LT(refreshRateConfigs->setPolicy(HwcConfigIndexType(10), 60, 60, nullptr), 0);
    ASSERT_LT(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_60, 20, 40, nullptr), 0);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60},
             {HWC_CONFIG_ID_90, HWC_GROUP_ID_0, VSYNC_90}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());

    const auto minRate = refreshRateConfigs->getMinRefreshRate();
    const auto performanceRate = refreshRateConfigs->getMaxRefreshRate();

    RefreshRate expectedDefaultConfig = {HWC_CONFIG_ID_60, VSYNC_60, HWC_GROUP_ID_0, "60fps", 60};
    ASSERT_EQ(expectedDefaultConfig, minRate);
    RefreshRate expectedPerformanceConfig = {HWC_CONFIG_ID_90, VSYNC_90, HWC_GROUP_ID_0, "90fps",
                                             90};
    ASSERT_EQ(expectedPerformanceConfig, performanceRate);

    const auto minRateByPolicy = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto performanceRateByPolicy = refreshRateConfigs->getMaxRefreshRateByPolicy();
    ASSERT_EQ(minRateByPolicy, minRate);
    ASSERT_EQ(performanceRateByPolicy, performanceRate);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap_differentGroups) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60},
             {HWC_CONFIG_ID_90, HWC_GROUP_ID_1, VSYNC_90}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());
    const auto minRate = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto performanceRate = refreshRateConfigs->getMaxRefreshRate();
    const auto minRate60 = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    RefreshRate expectedDefaultConfig = {HWC_CONFIG_ID_60, VSYNC_60, HWC_GROUP_ID_0, "60fps", 60};
    ASSERT_EQ(expectedDefaultConfig, minRate);
    ASSERT_EQ(expectedDefaultConfig, minRate60);
    ASSERT_EQ(expectedDefaultConfig, performanceRate60);

    ASSERT_GE(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_90, 60, 90, nullptr), 0);
    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);

    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());
    const auto minRate90 = refreshRateConfigs->getMinRefreshRateByPolicy();
    const auto performanceRate90 = refreshRateConfigs->getMaxRefreshRateByPolicy();

    RefreshRate expectedPerformanceConfig = {HWC_CONFIG_ID_90, VSYNC_90, HWC_GROUP_ID_1, "90fps",
                                             90};
    ASSERT_EQ(expectedPerformanceConfig, performanceRate);
    ASSERT_EQ(expectedPerformanceConfig, minRate90);
    ASSERT_EQ(expectedPerformanceConfig, performanceRate90);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_policyChange) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60},
             {HWC_CONFIG_ID_90, HWC_GROUP_ID_0, VSYNC_90}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());
    auto minRate = refreshRateConfigs->getMinRefreshRateByPolicy();
    auto performanceRate = refreshRateConfigs->getMaxRefreshRateByPolicy();

    RefreshRate expectedDefaultConfig = {HWC_CONFIG_ID_60, VSYNC_60, HWC_GROUP_ID_0, "60fps", 60};
    ASSERT_EQ(expectedDefaultConfig, minRate);
    RefreshRate expectedPerformanceConfig = {HWC_CONFIG_ID_90, VSYNC_90, HWC_GROUP_ID_0, "90fps",
                                             90};
    ASSERT_EQ(expectedPerformanceConfig, performanceRate);

    ASSERT_GE(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_60, 60, 60, nullptr), 0);
    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());

    auto minRate60 = refreshRateConfigs->getMinRefreshRateByPolicy();
    auto performanceRate60 = refreshRateConfigs->getMaxRefreshRateByPolicy();
    ASSERT_EQ(expectedDefaultConfig, minRate60);
    ASSERT_EQ(expectedDefaultConfig, performanceRate60);
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getCurrentRefreshRate) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60},
             {HWC_CONFIG_ID_90, HWC_GROUP_ID_0, VSYNC_90}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);
    {
        auto current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.configId, HWC_CONFIG_ID_60);
    }

    refreshRateConfigs->setCurrentConfigId(HWC_CONFIG_ID_90);
    {
        auto current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.configId, HWC_CONFIG_ID_90);
    }

    ASSERT_GE(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_90, 90, 90, nullptr), 0);
    {
        auto current = refreshRateConfigs->getCurrentRefreshRate();
        EXPECT_EQ(current.configId, HWC_CONFIG_ID_90);
    }
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_getRefreshRateForContent) {
    std::vector<RefreshRateConfigs::InputConfig> configs{
            {{HWC_CONFIG_ID_60, HWC_GROUP_ID_0, VSYNC_60},
             {HWC_CONFIG_ID_90, HWC_GROUP_ID_0, VSYNC_90}}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfigId=*/HWC_CONFIG_ID_60);

    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());

    RefreshRate expected60Config = {HWC_CONFIG_ID_60, VSYNC_60, HWC_GROUP_ID_0, "60fps", 60};
    RefreshRate expected90Config = {HWC_CONFIG_ID_90, VSYNC_90, HWC_GROUP_ID_0, "90fps", 90};

    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(90.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(60.0f));
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(45.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(30.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(24.0f));

    ASSERT_GE(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_60, 60, 60, nullptr), 0);
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(90.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(60.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(45.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(30.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(24.0f));

    ASSERT_GE(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_90, 90, 90, nullptr), 0);
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(90.0f));
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(60.0f));
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(45.0f));
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(30.0f));
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(24.0f));
    ASSERT_GE(refreshRateConfigs->setPolicy(HWC_CONFIG_ID_60, 0, 120, nullptr), 0);
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(90.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(60.0f));
    ASSERT_EQ(expected90Config, refreshRateConfigs->getRefreshRateForContent(45.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(30.0f));
    ASSERT_EQ(expected60Config, refreshRateConfigs->getRefreshRateForContent(24.0f));
}

TEST_F(RefreshRateConfigsTest, testInPolicy) {
    RefreshRate expectedDefaultConfig = {HWC_CONFIG_ID_60, VSYNC_60_POINT_4, HWC_GROUP_ID_0,
                                         "60fps", 60};
    ASSERT_TRUE(expectedDefaultConfig.inPolicy(60.000004f, 60.000004f));
    ASSERT_TRUE(expectedDefaultConfig.inPolicy(59.0f, 60.1f));
    ASSERT_FALSE(expectedDefaultConfig.inPolicy(75.0f, 90.0f));
    ASSERT_FALSE(expectedDefaultConfig.inPolicy(60.0011f, 90.0f));
    ASSERT_FALSE(expectedDefaultConfig.inPolicy(50.0f, 59.998f));
}

} // namespace
} // namespace scheduler
} // namespace android
