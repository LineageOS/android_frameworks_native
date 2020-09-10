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
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <log/log.h>
#include <thread>

#include "Scheduler/RefreshRateStats.h"
#include "mock/DisplayHardware/MockDisplay.h"
#include "mock/MockTimeStats.h"

using namespace std::chrono_literals;
using android::hardware::graphics::composer::hal::PowerMode;
using testing::_;
using testing::AtLeast;

namespace android {
namespace scheduler {

class RefreshRateStatsTest : public testing::Test {
protected:
    static inline const auto CONFIG_ID_0 = HwcConfigIndexType(0);
    static inline const auto CONFIG_ID_1 = HwcConfigIndexType(1);
    static inline const auto CONFIG_GROUP_0 = 0;
    static constexpr int64_t VSYNC_90 = 11111111;
    static constexpr int64_t VSYNC_60 = 16666667;

    RefreshRateStatsTest();
    ~RefreshRateStatsTest();

    void init(const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs) {
        mRefreshRateConfigs =
                std::make_unique<RefreshRateConfigs>(configs, /*currentConfig=*/CONFIG_ID_0);
        mRefreshRateStats = std::make_unique<RefreshRateStats>(*mRefreshRateConfigs, mTimeStats,
                                                               /*currentConfigId=*/CONFIG_ID_0,
                                                               /*currentPowerMode=*/PowerMode::OFF);
    }

    Hwc2::mock::Display mDisplay;
    mock::TimeStats mTimeStats;
    std::unique_ptr<RefreshRateConfigs> mRefreshRateConfigs;
    std::unique_ptr<RefreshRateStats> mRefreshRateStats;

    std::shared_ptr<const HWC2::Display::Config> createConfig(HwcConfigIndexType configId,
                                                              int32_t configGroup,
                                                              int64_t vsyncPeriod);
};

RefreshRateStatsTest::RefreshRateStatsTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

RefreshRateStatsTest::~RefreshRateStatsTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

std::shared_ptr<const HWC2::Display::Config> RefreshRateStatsTest::createConfig(
        HwcConfigIndexType configId, int32_t configGroup, int64_t vsyncPeriod) {
    return HWC2::Display::Config::Builder(mDisplay, configId.value())
            .setVsyncPeriod(int32_t(vsyncPeriod))
            .setConfigGroup(configGroup)
            .build();
}

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(RefreshRateStatsTest, oneConfigTest) {
    init({createConfig(CONFIG_ID_0, CONFIG_GROUP_0, VSYNC_90)});

    EXPECT_CALL(mTimeStats, recordRefreshRate(0, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(90, _)).Times(AtLeast(1));

    std::unordered_map<std::string, int64_t> times = mRefreshRateStats->getTotalTimes();
    ASSERT_EQ(1, times.size());
    EXPECT_NE(0u, times.count("ScreenOff"));
    // Setting up tests on mobile harness can be flaky with time passing, so testing for
    // exact time changes can result in flaxy numbers. To avoid that remember old
    // numbers to make sure the correct values are increasing in the next test.
    int screenOff = times["ScreenOff"];

    // Screen is off by default.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(0u, times.count("90fps"));

    mRefreshRateStats->setConfigMode(CONFIG_ID_0);
    mRefreshRateStats->setPowerMode(PowerMode::ON);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    ASSERT_EQ(1u, times.count("90fps"));
    EXPECT_LT(0, times["90fps"]);

    mRefreshRateStats->setPowerMode(PowerMode::DOZE);
    int ninety = mRefreshRateStats->getTotalTimes()["90fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_0);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    // Because the power mode is not PowerMode::ON, switching the config
    // does not update refresh rates that come from the config.
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
}

TEST_F(RefreshRateStatsTest, twoConfigsTest) {
    init({createConfig(CONFIG_ID_0, CONFIG_GROUP_0, VSYNC_90),
          createConfig(CONFIG_ID_1, CONFIG_GROUP_0, VSYNC_60)});

    EXPECT_CALL(mTimeStats, recordRefreshRate(0, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(60, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(90, _)).Times(AtLeast(1));

    std::unordered_map<std::string, int64_t> times = mRefreshRateStats->getTotalTimes();
    ASSERT_EQ(1, times.size());
    EXPECT_NE(0u, times.count("ScreenOff"));
    // Setting up tests on mobile harness can be flaky with time passing, so testing for
    // exact time changes can result in flaxy numbers. To avoid that remember old
    // numbers to make sure the correct values are increasing in the next test.
    int screenOff = times["ScreenOff"];

    // Screen is off by default.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_0);
    mRefreshRateStats->setPowerMode(PowerMode::ON);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    ASSERT_EQ(1u, times.count("90fps"));
    EXPECT_LT(0, times["90fps"]);

    // When power mode is normal, time for configs updates.
    mRefreshRateStats->setConfigMode(CONFIG_ID_1);
    int ninety = mRefreshRateStats->getTotalTimes()["90fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    ASSERT_EQ(1u, times.count("60fps"));
    EXPECT_LT(0, times["60fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_0);
    int sixty = mRefreshRateStats->getTotalTimes()["60fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_LT(ninety, times["90fps"]);
    EXPECT_EQ(sixty, times["60fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_1);
    ninety = mRefreshRateStats->getTotalTimes()["90fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    EXPECT_LT(sixty, times["60fps"]);

    // Because the power mode is not PowerMode::ON, switching the config
    // does not update refresh rates that come from the config.
    mRefreshRateStats->setPowerMode(PowerMode::DOZE);
    mRefreshRateStats->setConfigMode(CONFIG_ID_0);
    sixty = mRefreshRateStats->getTotalTimes()["60fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    EXPECT_EQ(sixty, times["60fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_1);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    EXPECT_EQ(sixty, times["60fps"]);
}
} // namespace
} // namespace scheduler
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
