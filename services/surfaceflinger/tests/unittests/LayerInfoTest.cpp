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

#include <scheduler/Fps.h>

#include <common/test/FlagUtils.h>
#include "FpsOps.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/LayerInfo.h"
#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/MockSchedulerCallback.h"

#include <com_android_graphics_surfaceflinger_flags.h>

namespace android::scheduler {

using android::mock::createDisplayMode;

class LayerInfoTest : public testing::Test {
protected:
    using FrameTimeData = LayerInfo::FrameTimeData;

    static constexpr Fps LO_FPS = 30_Hz;
    static constexpr Fps HI_FPS = 90_Hz;

    LayerInfoTest() { mFlinger.resetScheduler(mScheduler); }

    void setFrameTimes(const std::deque<FrameTimeData>& frameTimes) {
        layerInfo.mFrameTimes = frameTimes;
    }

    void setLastRefreshRate(Fps fps) {
        layerInfo.mLastRefreshRate.reported = fps;
        layerInfo.mLastRefreshRate.calculated = fps;
    }

    auto calculateAverageFrameTime() { return layerInfo.calculateAverageFrameTime(); }

    LayerInfo layerInfo{"TestLayerInfo", 0, LayerHistory::LayerVoteType::Heuristic};

    std::shared_ptr<RefreshRateSelector> mSelector =
            std::make_shared<RefreshRateSelector>(makeModes(createDisplayMode(DisplayModeId(0),
                                                                              LO_FPS),
                                                            createDisplayMode(DisplayModeId(1),
                                                                              HI_FPS)),
                                                  DisplayModeId(0));
    mock::SchedulerCallback mSchedulerCallback;
    TestableSurfaceFlinger mFlinger;
    TestableScheduler* mScheduler = new TestableScheduler(mSelector, mFlinger, mSchedulerCallback);
};

namespace {

using namespace com::android::graphics::surfaceflinger;

TEST_F(LayerInfoTest, prefersPresentTime) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = 50_Hz;
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
    ASSERT_EQ(kExpectedFps, Fps::fromPeriodNsecs(*averageFrameTime));
}

TEST_F(LayerInfoTest, fallbacksToQueueTimeIfNoPresentTime) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = 50_Hz;
    constexpr auto kPeriod = kExpectedFps.getPeriodNsecs();
    constexpr int kNumFrames = 10;
    for (int i = 1; i <= kNumFrames; i++) {
        frameTimes.push_back(FrameTimeData{.presentTime = 0,
                                           .queueTime = kPeriod * i,
                                           .pendingModeChange = false});
    }
    setFrameTimes(frameTimes);
    setLastRefreshRate(20_Hz); // Set to some valid value.
    const auto averageFrameTime = calculateAverageFrameTime();
    ASSERT_TRUE(averageFrameTime.has_value());
    ASSERT_EQ(kExpectedFps, Fps::fromPeriodNsecs(*averageFrameTime));
}

TEST_F(LayerInfoTest, returnsNulloptIfThereWasConfigChange) {
    std::deque<FrameTimeData> frameTimesWithoutConfigChange;
    const auto period = (50_Hz).getPeriodNsecs();
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
    constexpr auto kExpectedFps = 50_Hz;
    constexpr auto kExpectedPeriod = kExpectedFps.getPeriodNsecs();
    constexpr auto kSmallPeriod = (250_Hz).getPeriodNsecs();
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
    ASSERT_EQ(kExpectedFps, Fps::fromPeriodNsecs(*averageFrameTime));
}

// There may be a big period of time between two frames. Make sure that
// this doesn't influence the calculated average FPS.
TEST_F(LayerInfoTest, ignoresLargePeriods) {
    std::deque<FrameTimeData> frameTimes;
    constexpr auto kExpectedFps = 50_Hz;
    constexpr auto kExpectedPeriod = kExpectedFps.getPeriodNsecs();
    constexpr auto kLargePeriod = (9_Hz).getPeriodNsecs();

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
    ASSERT_EQ(kExpectedFps, Fps::fromPeriodNsecs(*averageFrameTime));
}

TEST_F(LayerInfoTest, getRefreshRateVote_explicitVote) {
    LayerInfo::LayerVote vote = {.type = LayerHistory::LayerVoteType::ExplicitDefault,
                                 .fps = 20_Hz};
    layerInfo.setLayerVote(vote);

    auto actualVotes =
            layerInfo.getRefreshRateVote(*mScheduler->refreshRateSelector(), systemTime());
    ASSERT_EQ(actualVotes.size(), 1u);
    ASSERT_EQ(actualVotes[0].type, vote.type);
    ASSERT_EQ(actualVotes[0].fps, vote.fps);
    ASSERT_EQ(actualVotes[0].seamlessness, vote.seamlessness);
    ASSERT_EQ(actualVotes[0].category, vote.category);
}

TEST_F(LayerInfoTest, getRefreshRateVote_explicitVoteWithCategory) {
    LayerInfo::LayerVote vote = {.type = LayerHistory::LayerVoteType::ExplicitDefault,
                                 .fps = 20_Hz,
                                 .category = FrameRateCategory::High,
                                 .categorySmoothSwitchOnly = true};
    layerInfo.setLayerVote(vote);

    auto actualVotes =
            layerInfo.getRefreshRateVote(*mScheduler->refreshRateSelector(), systemTime());
    ASSERT_EQ(actualVotes.size(), 2u);
    ASSERT_EQ(actualVotes[0].type, LayerHistory::LayerVoteType::ExplicitCategory);
    ASSERT_EQ(actualVotes[0].category, vote.category);
    ASSERT_TRUE(actualVotes[0].categorySmoothSwitchOnly);
    ASSERT_EQ(actualVotes[1].type, vote.type);
    ASSERT_EQ(actualVotes[1].fps, vote.fps);
    ASSERT_EQ(actualVotes[1].seamlessness, vote.seamlessness);
    ASSERT_EQ(actualVotes[1].category, FrameRateCategory::Default);
    ASSERT_TRUE(actualVotes[1].categorySmoothSwitchOnly);
}

TEST_F(LayerInfoTest, getRefreshRateVote_explicitCategory) {
    LayerInfo::LayerVote vote = {.type = LayerHistory::LayerVoteType::ExplicitDefault,
                                 .category = FrameRateCategory::High};
    layerInfo.setLayerVote(vote);

    auto actualVotes =
            layerInfo.getRefreshRateVote(*mScheduler->refreshRateSelector(), systemTime());
    ASSERT_EQ(actualVotes.size(), 1u);
    ASSERT_EQ(actualVotes[0].type, LayerHistory::LayerVoteType::ExplicitCategory);
    ASSERT_EQ(actualVotes[0].category, vote.category);
    ASSERT_EQ(actualVotes[0].fps, 0_Hz);
}

TEST_F(LayerInfoTest, getRefreshRateVote_categoryNoPreference) {
    LayerInfo::LayerVote vote = {.type = LayerHistory::LayerVoteType::ExplicitDefault,
                                 .category = FrameRateCategory::NoPreference};
    layerInfo.setLayerVote(vote);

    auto actualVotes =
            layerInfo.getRefreshRateVote(*mScheduler->refreshRateSelector(), systemTime());
    ASSERT_EQ(actualVotes.size(), 1u);
    ASSERT_EQ(actualVotes[0].type, LayerHistory::LayerVoteType::ExplicitCategory);
    ASSERT_EQ(actualVotes[0].category, vote.category);
    ASSERT_EQ(actualVotes[0].fps, 0_Hz);
}

TEST_F(LayerInfoTest, getRefreshRateVote_noData) {
    LayerInfo::LayerVote vote = {
            .type = LayerHistory::LayerVoteType::Heuristic,
    };
    layerInfo.setLayerVote(vote);

    auto actualVotes =
            layerInfo.getRefreshRateVote(*mScheduler->refreshRateSelector(), systemTime());
    ASSERT_EQ(actualVotes.size(), 1u);
    ASSERT_EQ(actualVotes[0].type, LayerHistory::LayerVoteType::Max);
    ASSERT_EQ(actualVotes[0].fps, vote.fps);
}

TEST_F(LayerInfoTest, isFrontBuffered) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);
    ASSERT_FALSE(layerInfo.isFrontBuffered());

    LayerProps prop = {.isFrontBuffered = true};
    layerInfo.setLastPresentTime(0, 0, LayerHistory::LayerUpdateType::Buffer, true, prop);
    ASSERT_TRUE(layerInfo.isFrontBuffered());

    prop.isFrontBuffered = false;
    layerInfo.setLastPresentTime(0, 0, LayerHistory::LayerUpdateType::Buffer, true, prop);
    ASSERT_FALSE(layerInfo.isFrontBuffered());
}

} // namespace
} // namespace android::scheduler
