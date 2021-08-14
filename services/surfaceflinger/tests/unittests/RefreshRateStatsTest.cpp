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

#include "DisplayHardware/DisplayMode.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "Scheduler/RefreshRateStats.h"
#include "mock/MockTimeStats.h"

using namespace std::chrono_literals;
using android::hardware::graphics::composer::hal::PowerMode;
using testing::_;
using testing::AtLeast;

namespace android {
namespace scheduler {

class RefreshRateStatsTest : public testing::Test {
protected:
    static inline const auto CONFIG_ID_0 = DisplayModeId(0);
    static inline const auto CONFIG_ID_1 = DisplayModeId(1);
    static inline const auto CONFIG_GROUP_0 = 0;
    static constexpr int64_t VSYNC_90 = 11111111;
    static constexpr int64_t VSYNC_60 = 16666667;

    RefreshRateStatsTest();
    ~RefreshRateStatsTest();

    void init(const DisplayModes& configs) {
        mRefreshRateConfigs =
                std::make_unique<RefreshRateConfigs>(configs, /*currentConfig=*/CONFIG_ID_0);

        const auto currFps = mRefreshRateConfigs->getRefreshRateFromModeId(CONFIG_ID_0).getFps();
        mRefreshRateStats = std::make_unique<RefreshRateStats>(mTimeStats, currFps,
                                                               /*currentPowerMode=*/PowerMode::OFF);
    }

    mock::TimeStats mTimeStats;
    std::unique_ptr<RefreshRateConfigs> mRefreshRateConfigs;
    std::unique_ptr<RefreshRateStats> mRefreshRateStats;

    DisplayModePtr createDisplayMode(DisplayModeId modeId, int32_t group, int64_t vsyncPeriod);
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

DisplayModePtr RefreshRateStatsTest::createDisplayMode(DisplayModeId modeId, int32_t group,
                                                       int64_t vsyncPeriod) {
    return DisplayMode::Builder(static_cast<hal::HWConfigId>(modeId.value()))
            .setId(modeId)
            .setVsyncPeriod(static_cast<int32_t>(vsyncPeriod))
            .setGroup(group)
            .build();
}

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(RefreshRateStatsTest, oneConfigTest) {
    init({createDisplayMode(CONFIG_ID_0, CONFIG_GROUP_0, VSYNC_90)});

    EXPECT_CALL(mTimeStats, recordRefreshRate(0, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(90, _)).Times(AtLeast(1));

    std::unordered_map<std::string, int64_t> times = mRefreshRateStats->getTotalTimes();
    ASSERT_EQ(1, times.size());
    EXPECT_NE(0u, times.count("ScreenOff"));
    // Setting up tests on mobile harness can be flaky with time passing, so testing for
    // exact time changes can result in flaxy numbers. To avoid that remember old
    // numbers to make sure the correct values are increasing in the next test.
    auto screenOff = times["ScreenOff"];

    // Screen is off by default.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(0u, times.count("90.00fps"));

    const auto config0Fps = mRefreshRateConfigs->getRefreshRateFromModeId(CONFIG_ID_0).getFps();
    mRefreshRateStats->setRefreshRate(config0Fps);
    mRefreshRateStats->setPowerMode(PowerMode::ON);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    ASSERT_EQ(1u, times.count("90.00fps"));
    EXPECT_LT(0, times["90.00fps"]);

    mRefreshRateStats->setPowerMode(PowerMode::DOZE);
    auto ninety = mRefreshRateStats->getTotalTimes()["90.00fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90.00fps"]);

    mRefreshRateStats->setRefreshRate(config0Fps);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    // Because the power mode is not PowerMode::ON, switching the config
    // does not update refresh rates that come from the config.
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90.00fps"]);
}

TEST_F(RefreshRateStatsTest, twoConfigsTest) {
    init({createDisplayMode(CONFIG_ID_0, CONFIG_GROUP_0, VSYNC_90),
          createDisplayMode(CONFIG_ID_1, CONFIG_GROUP_0, VSYNC_60)});

    EXPECT_CALL(mTimeStats, recordRefreshRate(0, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(60, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(90, _)).Times(AtLeast(1));

    std::unordered_map<std::string, int64_t> times = mRefreshRateStats->getTotalTimes();
    ASSERT_EQ(1, times.size());
    EXPECT_NE(0u, times.count("ScreenOff"));
    // Setting up tests on mobile harness can be flaky with time passing, so testing for
    // exact time changes can result in flaxy numbers. To avoid that remember old
    // numbers to make sure the correct values are increasing in the next test.
    auto screenOff = times["ScreenOff"];

    // Screen is off by default.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);

    const auto config0Fps = mRefreshRateConfigs->getRefreshRateFromModeId(CONFIG_ID_0).getFps();
    const auto config1Fps = mRefreshRateConfigs->getRefreshRateFromModeId(CONFIG_ID_1).getFps();
    mRefreshRateStats->setRefreshRate(config0Fps);
    mRefreshRateStats->setPowerMode(PowerMode::ON);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    ASSERT_EQ(1u, times.count("90.00fps"));
    EXPECT_LT(0, times["90.00fps"]);

    // When power mode is normal, time for configs updates.
    mRefreshRateStats->setRefreshRate(config1Fps);
    auto ninety = mRefreshRateStats->getTotalTimes()["90.00fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90.00fps"]);
    ASSERT_EQ(1u, times.count("60.00fps"));
    EXPECT_LT(0, times["60.00fps"]);

    mRefreshRateStats->setRefreshRate(config0Fps);
    auto sixty = mRefreshRateStats->getTotalTimes()["60.00fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_LT(ninety, times["90.00fps"]);
    EXPECT_EQ(sixty, times["60.00fps"]);

    mRefreshRateStats->setRefreshRate(config1Fps);
    ninety = mRefreshRateStats->getTotalTimes()["90.00fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_EQ(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90.00fps"]);
    EXPECT_LT(sixty, times["60.00fps"]);

    // Because the power mode is not PowerMode::ON, switching the config
    // does not update refresh rates that come from the config.
    mRefreshRateStats->setPowerMode(PowerMode::DOZE);
    mRefreshRateStats->setRefreshRate(config0Fps);
    sixty = mRefreshRateStats->getTotalTimes()["60.00fps"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90.00fps"]);
    EXPECT_EQ(sixty, times["60.00fps"]);

    mRefreshRateStats->setRefreshRate(config1Fps);
    screenOff = mRefreshRateStats->getTotalTimes()["ScreenOff"];
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();
    EXPECT_LT(screenOff, times["ScreenOff"]);
    EXPECT_EQ(ninety, times["90.00fps"]);
    EXPECT_EQ(sixty, times["60.00fps"]);
}
} // namespace
} // namespace scheduler
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
