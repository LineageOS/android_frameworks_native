/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <input/LatencyStatistics.h>
#include <cmath>
#include <limits>
#include <thread>

namespace android {
namespace test {

TEST(LatencyStatisticsTest, ResetStats) {
    LatencyStatistics stats{5min};
    stats.addValue(5.0);
    stats.addValue(19.3);
    stats.addValue(20);
    stats.reset();

    ASSERT_EQ(stats.getCount(), 0u);
    ASSERT_EQ(std::isnan(stats.getStDev()), true);
    ASSERT_EQ(std::isnan(stats.getMean()), true);
}

TEST(LatencyStatisticsTest, AddStatsValue) {
    LatencyStatistics stats{5min};
    stats.addValue(5.0);

    ASSERT_EQ(stats.getMin(), 5.0);
    ASSERT_EQ(stats.getMax(), 5.0);
    ASSERT_EQ(stats.getCount(), 1u);
    ASSERT_EQ(stats.getMean(), 5.0);
    ASSERT_EQ(stats.getStDev(), 0.0);
}

TEST(LatencyStatisticsTest, AddMultipleStatsValue) {
    LatencyStatistics stats{5min};
    stats.addValue(4.0);
    stats.addValue(6.0);
    stats.addValue(8.0);
    stats.addValue(10.0);

    float stdev = stats.getStDev();

    ASSERT_EQ(stats.getMin(), 4.0);
    ASSERT_EQ(stats.getMax(), 10.0);
    ASSERT_EQ(stats.getCount(), 4u);
    ASSERT_EQ(stats.getMean(), 7.0);
    ASSERT_EQ(stdev * stdev, 5.0);
}

TEST(LatencyStatisticsTest, ShouldReportStats) {
    LatencyStatistics stats{0min};
    stats.addValue(5.0);

    std::this_thread::sleep_for(1us);

    ASSERT_EQ(stats.shouldReport(), true);
}

} // namespace test
} // namespace android