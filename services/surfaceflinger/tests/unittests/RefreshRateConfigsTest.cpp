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

using RefreshRateType = RefreshRateConfigs::RefreshRateType;
using RefreshRate = RefreshRateConfigs::RefreshRate;

class RefreshRateConfigsTest : public testing::Test {
protected:
    static constexpr int CONFIG_ID_60 = 0;
    static constexpr hwc2_config_t HWC2_CONFIG_ID_60 = 0;
    static constexpr int CONFIG_ID_90 = 1;
    static constexpr hwc2_config_t HWC2_CONFIG_ID_90 = 1;
    static constexpr int64_t VSYNC_60 = 16666667;
    static constexpr int64_t VSYNC_90 = 11111111;

    RefreshRateConfigsTest();
    ~RefreshRateConfigsTest();

    void assertRatesEqual(const RefreshRate& left, const RefreshRate& right) {
        ASSERT_EQ(left.configId, right.configId);
        ASSERT_EQ(left.name, right.name);
        ASSERT_EQ(left.fps, right.fps);
        ASSERT_EQ(left.vsyncPeriod, right.vsyncPeriod);
    }
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
TEST_F(RefreshRateConfigsTest, oneDeviceConfig_isRejected) {
    std::vector<RefreshRateConfigs::InputConfig> configs{{HWC2_CONFIG_ID_60, VSYNC_60}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfig=*/0);
    ASSERT_FALSE(refreshRateConfigs->refreshRateSwitchingSupported());
}

TEST_F(RefreshRateConfigsTest, twoDeviceConfigs_storesFullRefreshRateMap) {
    std::vector<RefreshRateConfigs::InputConfig> configs{{HWC2_CONFIG_ID_60, VSYNC_60},
                                                         {HWC2_CONFIG_ID_90, VSYNC_90}};
    auto refreshRateConfigs =
            std::make_unique<RefreshRateConfigs>(/*refreshRateSwitching=*/true, configs,
                                                 /*currentConfig=*/0);

    ASSERT_TRUE(refreshRateConfigs->refreshRateSwitchingSupported());
    const auto& rates = refreshRateConfigs->getRefreshRateMap();
    ASSERT_EQ(2, rates.size());
    const auto& defaultRate = rates.find(RefreshRateType::DEFAULT);
    const auto& performanceRate = rates.find(RefreshRateType::PERFORMANCE);
    ASSERT_NE(rates.end(), defaultRate);
    ASSERT_NE(rates.end(), performanceRate);

    RefreshRate expectedDefaultConfig = {CONFIG_ID_60, "60fps", 60, VSYNC_60, HWC2_CONFIG_ID_60};
    assertRatesEqual(expectedDefaultConfig, defaultRate->second);
    RefreshRate expectedPerformanceConfig = {CONFIG_ID_90, "90fps", 90, VSYNC_90,
                                             HWC2_CONFIG_ID_90};
    assertRatesEqual(expectedPerformanceConfig, performanceRate->second);

    assertRatesEqual(expectedDefaultConfig,
                     refreshRateConfigs->getRefreshRateFromType(RefreshRateType::DEFAULT));
    assertRatesEqual(expectedPerformanceConfig,
                     refreshRateConfigs->getRefreshRateFromType(RefreshRateType::PERFORMANCE));
}
} // namespace
} // namespace scheduler
} // namespace android
