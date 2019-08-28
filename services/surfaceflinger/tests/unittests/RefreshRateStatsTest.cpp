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

#include "Scheduler/RefreshRateStats.h"
#include "mock/MockTimeStats.h"

using namespace std::chrono_literals;
using testing::_;
using testing::AtLeast;

namespace android {
namespace scheduler {

class RefreshRateStatsTest : public testing::Test {
protected:
    static constexpr int CONFIG_ID_90 = 0;
    static constexpr int CONFIG_ID_60 = 1;
    static constexpr int64_t VSYNC_90 = 11111111;
    static constexpr int64_t VSYNC_60 = 16666667;

    RefreshRateStatsTest();
    ~RefreshRateStatsTest();

    void init(const std::vector<RefreshRateConfigs::InputConfig>& configs) {
        mRefreshRateConfigs = std::make_unique<RefreshRateConfigs>(
                /*refreshRateSwitching=*/true, configs, /*currentConfig=*/0);
        mRefreshRateStats =
                std::make_unique<RefreshRateStats>(*mRefreshRateConfigs, mTimeStats,
                                                   /*currentConfig=*/0,
                                                   /*currentPowerMode=*/HWC_POWER_MODE_OFF);
    }

    mock::TimeStats mTimeStats;
    std::unique_ptr<RefreshRateConfigs> mRefreshRateConfigs;
    std::unique_ptr<RefreshRateStats> mRefreshRateStats;
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

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(RefreshRateStatsTest, oneConfigTest) {
    init({{CONFIG_ID_90, VSYNC_90}});

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

    mRefreshRateStats->setConfigMode(CONFIG_ID_90);
    mRefreshRateStats->setPowerMode(HWC_POWER_MODE_NORMAL);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    ASSERT_EQ(1u, times.count("90fps"));
    EXPECT_LT(0, times["90fps"]);

    mRefreshRateStats->setPowerMode(HWC_POWER_MODE_DOZE);
    int ninety = mRefreshRateStats->getTotalTimes()["90fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_90);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    // Because the power mode is not HWC_POWER_MODE_NORMAL, switching the config
    // does not update refresh rates that come from the config.
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
}

TEST_F(RefreshRateStatsTest, twoConfigsTest) {
    init({{CONFIG_ID_90, VSYNC_90}, {CONFIG_ID_60, VSYNC_60}});

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

    mRefreshRateStats->setConfigMode(CONFIG_ID_90);
    mRefreshRateStats->setPowerMode(HWC_POWER_MODE_NORMAL);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    ASSERT_EQ(1u, times.count("90fps"));
    EXPECT_LT(0, times["90fps"]);

    // When power mode is normal, time for configs updates.
    mRefreshRateStats->setConfigMode(CONFIG_ID_60);
    int ninety = mRefreshRateStats->getTotalTimes()["90fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    ASSERT_EQ(1u, times.count("60fps"));
    EXPECT_LT(0, times["60fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_90);
    int sixty = mRefreshRateStats->getTotalTimes()["60fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_LT(ninety, times["90fps"]);
    EXPECT_EQ(sixty, times["60fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_60);
    ninety = mRefreshRateStats->getTotalTimes()["90fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    EXPECT_LT(sixty, times["60fps"]);

    // Because the power mode is not HWC_POWER_MODE_NORMAL, switching the config
    // does not update refresh rates that come from the config.
    mRefreshRateStats->setPowerMode(HWC_POWER_MODE_DOZE);
    mRefreshRateStats->setConfigMode(CONFIG_ID_90);
    sixty = mRefreshRateStats->getTotalTimes()["60fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90fps"]);
    EXPECT_EQ(sixty, times["60fps"]);

    mRefreshRateStats->setConfigMode(CONFIG_ID_60);
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
