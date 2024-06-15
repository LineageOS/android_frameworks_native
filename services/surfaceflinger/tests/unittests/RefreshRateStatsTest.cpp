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
using android::hardware::graphics::composer::hal::PowerMode;
using testing::_;
using testing::AtLeast;

namespace android::scheduler {

class RefreshRateStatsTest : public testing::Test {
protected:
    RefreshRateStatsTest();
    ~RefreshRateStatsTest();

    void resetStats(Fps fps) {
        mRefreshRateStats = std::make_unique<RefreshRateStats>(mTimeStats, fps);
    }

    mock::TimeStats mTimeStats;
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

TEST_F(RefreshRateStatsTest, oneMode) {
    resetStats(90_Hz);

    EXPECT_CALL(mTimeStats, recordRefreshRate(0, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(90, _)).Times(AtLeast(1));

    auto times = mRefreshRateStats->getTotalTimes();
    ASSERT_TRUE(times.contains("ScreenOff"));
    EXPECT_EQ(1u, times.size());

    // Screen is off by default.
    std::chrono::milliseconds screenOff = times.get("ScreenOff")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_LT(screenOff, times.get("ScreenOff")->get());
    EXPECT_FALSE(times.contains("90.00 Hz"));

    mRefreshRateStats->setRefreshRate(90_Hz);
    mRefreshRateStats->setPowerMode(PowerMode::ON);
    screenOff = mRefreshRateStats->getTotalTimes().get("ScreenOff")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_EQ(screenOff, times.get("ScreenOff")->get());
    ASSERT_TRUE(times.contains("90.00 Hz"));
    EXPECT_LT(0ms, times.get("90.00 Hz")->get());

    mRefreshRateStats->setPowerMode(PowerMode::DOZE);
    const auto ninety = mRefreshRateStats->getTotalTimes().get("90.00 Hz")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_LT(screenOff, times.get("ScreenOff")->get());
    EXPECT_EQ(ninety, times.get("90.00 Hz")->get());

    mRefreshRateStats->setRefreshRate(90_Hz);
    screenOff = mRefreshRateStats->getTotalTimes().get("ScreenOff")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    // Stats are not updated while the screen is off.
    EXPECT_LT(screenOff, times.get("ScreenOff")->get());
    EXPECT_EQ(ninety, times.get("90.00 Hz")->get());
}

TEST_F(RefreshRateStatsTest, twoModes) {
    resetStats(90_Hz);

    EXPECT_CALL(mTimeStats, recordRefreshRate(0, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(60, _)).Times(AtLeast(1));
    EXPECT_CALL(mTimeStats, recordRefreshRate(90, _)).Times(AtLeast(1));

    auto times = mRefreshRateStats->getTotalTimes();
    ASSERT_TRUE(times.contains("ScreenOff"));
    EXPECT_EQ(1u, times.size());

    // Screen is off by default.
    std::chrono::milliseconds screenOff = times.get("ScreenOff")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_LT(screenOff, times.get("ScreenOff")->get());
    EXPECT_FALSE(times.contains("60.00 Hz"));
    EXPECT_FALSE(times.contains("90.00 Hz"));

    mRefreshRateStats->setRefreshRate(90_Hz);
    mRefreshRateStats->setPowerMode(PowerMode::ON);
    screenOff = mRefreshRateStats->getTotalTimes().get("ScreenOff")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_EQ(screenOff, times.get("ScreenOff")->get());
    ASSERT_TRUE(times.contains("90.00 Hz"));
    EXPECT_LT(0ms, times.get("90.00 Hz")->get());

    mRefreshRateStats->setRefreshRate(60_Hz);
    auto ninety = mRefreshRateStats->getTotalTimes().get("90.00 Hz")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_EQ(screenOff, times.get("ScreenOff")->get());
    EXPECT_EQ(ninety, times.get("90.00 Hz")->get());
    ASSERT_TRUE(times.contains("60.00 Hz"));
    EXPECT_LT(0ms, times.get("60.00 Hz")->get());

    mRefreshRateStats->setRefreshRate(90_Hz);
    auto sixty = mRefreshRateStats->getTotalTimes().get("60.00 Hz")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_EQ(screenOff, times.get("ScreenOff")->get());
    EXPECT_LT(ninety, times.get("90.00 Hz")->get());
    EXPECT_EQ(sixty, times.get("60.00 Hz")->get());

    mRefreshRateStats->setRefreshRate(60_Hz);
    ninety = mRefreshRateStats->getTotalTimes().get("90.00 Hz")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_EQ(screenOff, times.get("ScreenOff")->get());
    EXPECT_EQ(ninety, times.get("90.00 Hz")->get());
    EXPECT_LT(sixty, times.get("60.00 Hz")->get());

    // Stats are not updated while the screen is off.
    mRefreshRateStats->setPowerMode(PowerMode::DOZE);
    mRefreshRateStats->setRefreshRate(90_Hz);
    sixty = mRefreshRateStats->getTotalTimes().get("60.00 Hz")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_LT(screenOff, times.get("ScreenOff")->get());
    EXPECT_EQ(ninety, times.get("90.00 Hz")->get());
    EXPECT_EQ(sixty, times.get("60.00 Hz")->get());

    mRefreshRateStats->setRefreshRate(60_Hz);
    screenOff = mRefreshRateStats->getTotalTimes().get("ScreenOff")->get();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    times = mRefreshRateStats->getTotalTimes();

    EXPECT_LT(screenOff, times.get("ScreenOff")->get());
    EXPECT_EQ(ninety, times.get("90.00 Hz")->get());
    EXPECT_EQ(sixty, times.get("60.00 Hz")->get());
}

} // namespace
} // namespace android::scheduler
