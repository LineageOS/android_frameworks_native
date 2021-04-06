/*
 * Copyright 2020 The Android Open Source Project
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
#define LOG_TAG "LayerInfoTest"

#include <gtest/gtest.h>

#include "Fps.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/LayerInfo.h"

namespace android::scheduler {

class LayerInfoTest : public testing::Test {
protected:
    using FrameTimeData = LayerInfo::FrameTimeData;

    void setFrameTimes(const std::deque<FrameTimeData>& frameTimes) {
        layerInfo.mFrameTimes = frameTimes;
    }

    void setLastRefreshRate(Fps fps) {
        layerInfo.mLastRefreshRate.reported = fps;
        layerInfo.mLastRefreshRate.calculated = fps;
    }

    auto calculateAverageFrameTime() { return layerInfo.calculateAverageFrameTime(); }

    LayerInfo layerInfo{"TestLayerInfo", 0, LayerHistory::LayerVoteType::Heuristic};
};

namespace {

TEST_F(LayerInfoTest, prefersPresentTime) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = Fps(50.0f);
    constexpr auto kPeriod = kExpectedFps.getPeriodNsecs();
    constexpr int kNumFrames = 10;
    for (int i = 1; i <= kNumFrames; i++) {
        frameTimes.push_back(FrameTimeData{.presentTime = kPeriod * i,
                                           .queueTime = 0,
                                           .pendingModeChange = false});
    }
    setFrameTimes(frameTimes);
    const auto averageFrameTime = calculateAverageFrameTime();
    ASSERT_TRUE(averageFrameTime.has_value());
    const auto averageFps = Fps::fromPeriodNsecs(*averageFrameTime);
    ASSERT_TRUE(kExpectedFps.equalsWithMargin(averageFps))
            << "Expected " << averageFps << " to be equal to " << kExpectedFps;
}

TEST_F(LayerInfoTest, fallbacksToQueueTimeIfNoPresentTime) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = Fps(50.0f);
    constexpr auto kPeriod = kExpectedFps.getPeriodNsecs();
    constexpr int kNumFrames = 10;
    for (int i = 1; i <= kNumFrames; i++) {
        frameTimes.push_back(FrameTimeData{.presentTime = 0,
                                           .queueTime = kPeriod * i,
                                           .pendingModeChange = false});
    }
    setFrameTimes(frameTimes);
    setLastRefreshRate(Fps(20.0f)); // Set to some valid value
    const auto averageFrameTime = calculateAverageFrameTime();
    ASSERT_TRUE(averageFrameTime.has_value());
    const auto averageFps = Fps::fromPeriodNsecs(*averageFrameTime);
    ASSERT_TRUE(kExpectedFps.equalsWithMargin(averageFps))
            << "Expected " << averageFps << " to be equal to " << kExpectedFps;
}

TEST_F(LayerInfoTest, returnsNulloptIfThereWasConfigChange) {
    std::deque<FrameTimeData> frameTimesWithoutConfigChange;
    const auto period = Fps(50.0f).getPeriodNsecs();
    constexpr int kNumFrames = 10;
    for (int i = 1; i <= kNumFrames; i++) {
        frameTimesWithoutConfigChange.push_back(FrameTimeData{.presentTime = period * i,
                                                              .queueTime = period * i,
                                                              .pendingModeChange = false});
    }

    setFrameTimes(frameTimesWithoutConfigChange);
    ASSERT_TRUE(calculateAverageFrameTime().has_value());

    {
        // Config change in the first record
        auto frameTimes = frameTimesWithoutConfigChange;
        frameTimes[0].pendingModeChange = true;
        setFrameTimes(frameTimes);
        ASSERT_FALSE(calculateAverageFrameTime().has_value());
    }

    {
        // Config change in the last record
        auto frameTimes = frameTimesWithoutConfigChange;
        frameTimes[frameTimes.size() - 1].pendingModeChange = true;
        setFrameTimes(frameTimes);
        ASSERT_FALSE(calculateAverageFrameTime().has_value());
    }

    {
        // Config change in the middle
        auto frameTimes = frameTimesWithoutConfigChange;
        frameTimes[frameTimes.size() / 2].pendingModeChange = true;
        setFrameTimes(frameTimes);
        ASSERT_FALSE(calculateAverageFrameTime().has_value());
    }
}

// A frame can be recorded twice with very close presentation or queue times.
// Make sure that this doesn't influence the calculated average FPS.
TEST_F(LayerInfoTest, ignoresSmallPeriods) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = Fps(50.0f);
    constexpr auto kExpectedPeriod = kExpectedFps.getPeriodNsecs();
    constexpr auto kSmallPeriod = Fps(150.0f).getPeriodNsecs();
    constexpr int kNumIterations = 10;
    for (int i = 1; i <= kNumIterations; i++) {
        frameTimes.push_back(FrameTimeData{.presentTime = kExpectedPeriod * i,
                                           .queueTime = 0,
                                           .pendingModeChange = false});

        // A duplicate frame
        frameTimes.push_back(FrameTimeData{.presentTime = kExpectedPeriod * i + kSmallPeriod,
                                           .queueTime = 0,
                                           .pendingModeChange = false});
    }
    setFrameTimes(frameTimes);
    const auto averageFrameTime = calculateAverageFrameTime();
    ASSERT_TRUE(averageFrameTime.has_value());
    const auto averageFps = Fps::fromPeriodNsecs(*averageFrameTime);
    ASSERT_TRUE(kExpectedFps.equalsWithMargin(averageFps))
            << "Expected " << averageFps << " to be equal to " << kExpectedFps;
}

// There may be a big period of time between two frames. Make sure that
// this doesn't influence the calculated average FPS.
TEST_F(LayerInfoTest, ignoresLargePeriods) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = Fps(50.0f);
    constexpr auto kExpectedPeriod = kExpectedFps.getPeriodNsecs();
    constexpr auto kLargePeriod = Fps(9.0f).getPeriodNsecs();

    auto record = [&](nsecs_t time) {
        frameTimes.push_back(
                FrameTimeData{.presentTime = time, .queueTime = 0, .pendingModeChange = false});
    };

    auto time = kExpectedPeriod; // Start with non-zero time.
    record(time);
    time += kLargePeriod;
    record(time);
    constexpr int kNumIterations = 10;
    for (int i = 1; i <= kNumIterations; i++) {
        time += kExpectedPeriod;
        record(time);
    }

    setFrameTimes(frameTimes);
    const auto averageFrameTime = calculateAverageFrameTime();
    ASSERT_TRUE(averageFrameTime.has_value());
    const auto averageFps = Fps::fromPeriodNsecs(*averageFrameTime);
    ASSERT_TRUE(kExpectedFps.equalsWithMargin(averageFps))
            << "Expected " << averageFps << " to be equal to " << kExpectedFps;
}

} // namespace
} // namespace android::scheduler
