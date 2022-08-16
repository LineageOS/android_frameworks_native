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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "LayerHistoryTest"

#include <Layer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include "FpsOps.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/LayerInfo.h"
#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockLayer.h"
#include "mock/MockSchedulerCallback.h"

using testing::_;
using testing::Return;
using testing::ReturnRef;

namespace android::scheduler {

using MockLayer = android::mock::MockLayer;

using android::mock::createDisplayMode;

class LayerHistoryTest : public testing::Test {
protected:
    static constexpr auto PRESENT_TIME_HISTORY_SIZE = LayerInfo::HISTORY_SIZE;
    static constexpr auto MAX_FREQUENT_LAYER_PERIOD_NS = LayerInfo::kMaxPeriodForFrequentLayerNs;
    static constexpr auto FREQUENT_LAYER_WINDOW_SIZE = LayerInfo::kFrequentLayerWindowSize;
    static constexpr auto PRESENT_TIME_HISTORY_DURATION = LayerInfo::HISTORY_DURATION;
    static constexpr auto REFRESH_RATE_AVERAGE_HISTORY_DURATION =
            LayerInfo::RefreshRateHistory::HISTORY_DURATION;

    static constexpr Fps LO_FPS = 30_Hz;
    static constexpr auto LO_FPS_PERIOD = LO_FPS.getPeriodNsecs();

    static constexpr Fps HI_FPS = 90_Hz;
    static constexpr auto HI_FPS_PERIOD = HI_FPS.getPeriodNsecs();

    LayerHistoryTest() { mFlinger.resetScheduler(mScheduler); }

    LayerHistory& history() { return mScheduler->mutableLayerHistory(); }
    const LayerHistory& history() const { return mScheduler->mutableLayerHistory(); }

    LayerHistory::Summary summarizeLayerHistory(nsecs_t now) {
        // LayerHistory::summarize makes no guarantee of the order of the elements in the summary
        // however, for testing only, a stable order is required, therefore we sort the list here.
        // Any tests requiring ordered results must create layers with names.
        auto summary = history().summarize(*mScheduler->refreshRateConfigs(), now);
        std::sort(summary.begin(), summary.end(),
                  [](const RefreshRateConfigs::LayerRequirement& a,
                     const RefreshRateConfigs::LayerRequirement& b) -> bool {
                      return a.name < b.name;
                  });
        return summary;
    }

    size_t layerCount() const { return mScheduler->layerHistorySize(); }
    size_t activeLayerCount() const NO_THREAD_SAFETY_ANALYSIS {
        return history().mActiveLayerInfos.size();
    }

    auto frequentLayerCount(nsecs_t now) const NO_THREAD_SAFETY_ANALYSIS {
        const auto& infos = history().mActiveLayerInfos;
        return std::count_if(infos.begin(), infos.end(), [now](const auto& pair) {
            return pair.second.second->isFrequent(now);
        });
    }

    auto animatingLayerCount(nsecs_t now) const NO_THREAD_SAFETY_ANALYSIS {
        const auto& infos = history().mActiveLayerInfos;
        return std::count_if(infos.begin(), infos.end(), [now](const auto& pair) {
            return pair.second.second->isAnimating(now);
        });
    }

    void setDefaultLayerVote(Layer* layer,
                             LayerHistory::LayerVoteType vote) NO_THREAD_SAFETY_ANALYSIS {
        auto [found, layerPair] = history().findLayer(layer->getSequence());
        if (found != LayerHistory::LayerStatus::NotFound) {
            layerPair->second->setDefaultLayerVote(vote);
        }
    }

    auto createLayer() { return sp<MockLayer>::make(mFlinger.flinger()); }
    auto createLayer(std::string name) {
        return sp<MockLayer>::make(mFlinger.flinger(), std::move(name));
    }

    void recordFramesAndExpect(const sp<MockLayer>& layer, nsecs_t& time, Fps frameRate,
                               Fps desiredRefreshRate, int numFrames) {
        LayerHistory::Summary summary;
        for (int i = 0; i < numFrames; i++) {
            history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
            time += frameRate.getPeriodNsecs();

            summary = summarizeLayerHistory(time);
        }

        ASSERT_EQ(1, summary.size());
        ASSERT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
        ASSERT_EQ(desiredRefreshRate, summary[0].desiredRefreshRate);
    }

    std::shared_ptr<RefreshRateConfigs> mConfigs =
            std::make_shared<RefreshRateConfigs>(makeModes(createDisplayMode(DisplayModeId(0),
                                                                             LO_FPS),
                                                           createDisplayMode(DisplayModeId(1),
                                                                             HI_FPS)),
                                                 DisplayModeId(0));

    mock::SchedulerCallback mSchedulerCallback;

    TestableScheduler* mScheduler = new TestableScheduler(mConfigs, mSchedulerCallback);

    TestableSurfaceFlinger mFlinger;
};

namespace {

TEST_F(LayerHistoryTest, oneLayer) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    // history().registerLayer(layer, LayerHistory::LayerVoteType::Max);

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();

    // No layers returned if no layers are active.
    EXPECT_TRUE(summarizeLayerHistory(time).empty());
    EXPECT_EQ(0, activeLayerCount());

    // Max returned if active layers have insufficient history.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE - 1; i++) {
        history().record(layer.get(), 0, time, LayerHistory::LayerUpdateType::Buffer);
        ASSERT_EQ(1, summarizeLayerHistory(time).size());
        EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
        EXPECT_EQ(1, activeLayerCount());
        time += LO_FPS_PERIOD;
    }

    // Max is returned since we have enough history but there is no timestamp votes.
    for (int i = 0; i < 10; i++) {
        history().record(layer.get(), 0, time, LayerHistory::LayerUpdateType::Buffer);
        ASSERT_EQ(1, summarizeLayerHistory(time).size());
        EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
        EXPECT_EQ(1, activeLayerCount());
        time += LO_FPS_PERIOD;
    }
}

TEST_F(LayerHistoryTest, oneInvisibleLayer) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();

    history().record(layer.get(), 0, time, LayerHistory::LayerUpdateType::Buffer);
    auto summary = summarizeLayerHistory(time);
    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    // Layer is still considered inactive so we expect to get Min
    EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());

    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(false));
    history().record(layer.get(), 0, time, LayerHistory::LayerUpdateType::Buffer);

    summary = summarizeLayerHistory(time);
    EXPECT_TRUE(summarizeLayerHistory(time).empty());
    EXPECT_EQ(0, activeLayerCount());
}

TEST_F(LayerHistoryTest, explicitTimestamp) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
    }

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(LO_FPS, summarizeLayerHistory(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, oneLayerNoVote) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    setDefaultLayerVote(layer.get(), LayerHistory::LayerVoteType::NoVote);

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
    }

    ASSERT_TRUE(summarizeLayerHistory(time).empty());
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer became inactive
    time += MAX_ACTIVE_LAYER_PERIOD_NS.count();
    ASSERT_TRUE(summarizeLayerHistory(time).empty());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, oneLayerMinVote) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    setDefaultLayerVote(layer.get(), LayerHistory::LayerVoteType::Min);

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
    }

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Min, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer became inactive
    time += MAX_ACTIVE_LAYER_PERIOD_NS.count();
    ASSERT_TRUE(summarizeLayerHistory(time).empty());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, oneLayerMaxVote) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    setDefaultLayerVote(layer.get(), LayerHistory::LayerVoteType::Max);

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
    }

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer became inactive
    time += MAX_ACTIVE_LAYER_PERIOD_NS.count();
    ASSERT_TRUE(summarizeLayerHistory(time).empty());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, oneLayerExplicitVote) {
    auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree())
            .WillRepeatedly(
                    Return(Layer::FrameRate(73.4_Hz, Layer::FrameRateCompatibility::Default)));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
    }

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::ExplicitDefault, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(73.4_Hz, summarizeLayerHistory(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer became inactive, but the vote stays
    setDefaultLayerVote(layer.get(), LayerHistory::LayerVoteType::Heuristic);
    time += MAX_ACTIVE_LAYER_PERIOD_NS.count();
    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::ExplicitDefault, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(73.4_Hz, summarizeLayerHistory(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, oneLayerExplicitExactVote) {
    auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree())
            .WillRepeatedly(Return(
                    Layer::FrameRate(73.4_Hz, Layer::FrameRateCompatibility::ExactOrMultiple)));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = systemTime();
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
    }

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::ExplicitExactOrMultiple,
              summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(73.4_Hz, summarizeLayerHistory(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer became inactive, but the vote stays
    setDefaultLayerVote(layer.get(), LayerHistory::LayerVoteType::Heuristic);
    time += MAX_ACTIVE_LAYER_PERIOD_NS.count();
    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::ExplicitExactOrMultiple,
              summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(73.4_Hz, summarizeLayerHistory(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, multipleLayers) {
    auto layer1 = createLayer("A");
    auto layer2 = createLayer("B");
    auto layer3 = createLayer("C");

    EXPECT_CALL(*layer1, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer1, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_CALL(*layer2, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer2, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_CALL(*layer3, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer3, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();

    EXPECT_EQ(3, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    LayerHistory::Summary summary;

    // layer1 is active but infrequent.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer1.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += MAX_FREQUENT_LAYER_PERIOD_NS.count();
        summary = summarizeLayerHistory(time);
    }

    ASSERT_EQ(1, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Min, summary[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer2 is frequent and has high refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
        summary = summarizeLayerHistory(time);
    }

    // layer1 is still active but infrequent.
    history().record(layer1.get(), time, time, LayerHistory::LayerUpdateType::Buffer);

    ASSERT_EQ(2, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Min, summary[0].vote);
    ASSERT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[1].vote);
    EXPECT_EQ(HI_FPS, summarizeLayerHistory(time)[1].desiredRefreshRate);

    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer1 is no longer active.
    // layer2 is frequent and has low refresh rate.
    for (int i = 0; i < 2 * PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
        summary = summarizeLayerHistory(time);
    }

    ASSERT_EQ(1, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(LO_FPS, summary[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer2 still has low refresh rate.
    // layer3 has high refresh rate but not enough history.
    constexpr int RATIO = LO_FPS_PERIOD / HI_FPS_PERIOD;
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE - 1; i++) {
        if (i % RATIO == 0) {
            history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        }

        history().record(layer3.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
        summary = summarizeLayerHistory(time);
    }

    ASSERT_EQ(2, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(LO_FPS, summary[0].desiredRefreshRate);
    EXPECT_EQ(LayerHistory::LayerVoteType::Max, summary[1].vote);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer3 becomes recently active.
    history().record(layer3.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
    summary = summarizeLayerHistory(time);
    ASSERT_EQ(2, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(LO_FPS, summary[0].desiredRefreshRate);
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[1].vote);
    EXPECT_EQ(HI_FPS, summary[1].desiredRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer1 expires.
    layer1.clear();
    summary = summarizeLayerHistory(time);
    ASSERT_EQ(2, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(LO_FPS, summary[0].desiredRefreshRate);
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[1].vote);
    EXPECT_EQ(HI_FPS, summary[1].desiredRefreshRate);
    EXPECT_EQ(2, layerCount());
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer2 still has low refresh rate.
    // layer3 becomes inactive.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
        summary = summarizeLayerHistory(time);
    }

    ASSERT_EQ(1, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(LO_FPS, summary[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer2 expires.
    layer2.clear();
    summary = summarizeLayerHistory(time);
    EXPECT_TRUE(summary.empty());
    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer3 becomes active and has high refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE + FREQUENT_LAYER_WINDOW_SIZE + 1; i++) {
        history().record(layer3.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
        summary = summarizeLayerHistory(time);
    }

    ASSERT_EQ(1, summary.size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Heuristic, summary[0].vote);
    EXPECT_EQ(HI_FPS, summary[0].desiredRefreshRate);
    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer3 expires.
    layer3.clear();
    summary = summarizeLayerHistory(time);
    EXPECT_TRUE(summary.empty());
    EXPECT_EQ(0, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, inactiveLayers) {
    auto layer = createLayer();

    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();

    // the very first updates makes the layer frequent
    for (int i = 0; i < FREQUENT_LAYER_WINDOW_SIZE - 1; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += MAX_FREQUENT_LAYER_PERIOD_NS.count();

        EXPECT_EQ(1, layerCount());
        ASSERT_EQ(1, summarizeLayerHistory(time).size());
        EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
        EXPECT_EQ(1, activeLayerCount());
        EXPECT_EQ(1, frequentLayerCount(time));
    }

    // the next update with the MAX_FREQUENT_LAYER_PERIOD_NS will get us to infrequent
    history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
    time += MAX_FREQUENT_LAYER_PERIOD_NS.count();

    EXPECT_EQ(1, layerCount());
    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Min, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // advance the time for the previous frame to be inactive
    time += MAX_ACTIVE_LAYER_PERIOD_NS.count();

    // Now event if we post a quick few frame we should stay infrequent
    for (int i = 0; i < FREQUENT_LAYER_WINDOW_SIZE - 1; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;

        EXPECT_EQ(1, layerCount());
        ASSERT_EQ(1, summarizeLayerHistory(time).size());
        EXPECT_EQ(LayerHistory::LayerVoteType::Min, summarizeLayerHistory(time)[0].vote);
        EXPECT_EQ(1, activeLayerCount());
        EXPECT_EQ(0, frequentLayerCount(time));
    }

    // More quick frames will get us to frequent again
    history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
    time += HI_FPS_PERIOD;

    EXPECT_EQ(1, layerCount());
    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, invisibleExplicitLayer) {
    auto explicitVisiblelayer = createLayer();
    auto explicitInvisiblelayer = createLayer();

    EXPECT_CALL(*explicitVisiblelayer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*explicitVisiblelayer, getFrameRateForLayerTree())
            .WillRepeatedly(Return(
                    Layer::FrameRate(60_Hz, Layer::FrameRateCompatibility::ExactOrMultiple)));

    EXPECT_CALL(*explicitInvisiblelayer, isVisible()).WillRepeatedly(Return(false));
    EXPECT_CALL(*explicitInvisiblelayer, getFrameRateForLayerTree())
            .WillRepeatedly(Return(
                    Layer::FrameRate(90_Hz, Layer::FrameRateCompatibility::ExactOrMultiple)));

    nsecs_t time = systemTime();

    // Post a buffer to the layers to make them active
    history().record(explicitVisiblelayer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
    history().record(explicitInvisiblelayer.get(), time, time,
                     LayerHistory::LayerUpdateType::Buffer);

    EXPECT_EQ(2, layerCount());
    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::ExplicitExactOrMultiple,
              summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(60_Hz, summarizeLayerHistory(time)[0].desiredRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, infrequentAnimatingLayer) {
    auto layer = createLayer();

    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
    EXPECT_EQ(0, animatingLayerCount(time));

    // layer is active but infrequent.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += MAX_FREQUENT_LAYER_PERIOD_NS.count();
    }

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Min, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
    EXPECT_EQ(0, animatingLayerCount(time));

    // another update with the same cadence keep in infrequent
    history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
    time += MAX_FREQUENT_LAYER_PERIOD_NS.count();

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Min, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
    EXPECT_EQ(0, animatingLayerCount(time));

    // an update as animation will immediately vote for Max
    history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::AnimationTX);
    time += MAX_FREQUENT_LAYER_PERIOD_NS.count();

    ASSERT_EQ(1, summarizeLayerHistory(time).size());
    EXPECT_EQ(LayerHistory::LayerVoteType::Max, summarizeLayerHistory(time)[0].vote);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
    EXPECT_EQ(1, animatingLayerCount(time));
}

TEST_F(LayerHistoryTest, getFramerate) {
    auto layer = createLayer();

    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
    EXPECT_EQ(0, animatingLayerCount(time));

    // layer is active but infrequent.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += MAX_FREQUENT_LAYER_PERIOD_NS.count();
    }

    float expectedFramerate = 1e9f / MAX_FREQUENT_LAYER_PERIOD_NS.count();
    EXPECT_FLOAT_EQ(expectedFramerate, history().getLayerFramerate(time, layer->getSequence()));
}

TEST_F(LayerHistoryTest, heuristicLayer60Hz) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();
    for (float fps = 54.0f; fps < 65.0f; fps += 0.1f) {
        recordFramesAndExpect(layer, time, Fps::fromValue(fps), 60_Hz, PRESENT_TIME_HISTORY_SIZE);
    }
}

TEST_F(LayerHistoryTest, heuristicLayer60_30Hz) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();
    recordFramesAndExpect(layer, time, 60_Hz, 60_Hz, PRESENT_TIME_HISTORY_SIZE);

    recordFramesAndExpect(layer, time, 60_Hz, 60_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 30_Hz, 60_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 30_Hz, 30_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 60_Hz, 30_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 60_Hz, 60_Hz, PRESENT_TIME_HISTORY_SIZE);
}

TEST_F(LayerHistoryTest, heuristicLayerNotOscillating) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    nsecs_t time = systemTime();

    recordFramesAndExpect(layer, time, 27.1_Hz, 30_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 26.9_Hz, 30_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 26_Hz, 24_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 26.9_Hz, 24_Hz, PRESENT_TIME_HISTORY_SIZE);
    recordFramesAndExpect(layer, time, 27.1_Hz, 30_Hz, PRESENT_TIME_HISTORY_SIZE);
}

class LayerHistoryTestParameterized : public LayerHistoryTest,
                                      public testing::WithParamInterface<std::chrono::nanoseconds> {
};

TEST_P(LayerHistoryTestParameterized, HeuristicLayerWithInfrequentLayer) {
    std::chrono::nanoseconds infrequentUpdateDelta = GetParam();
    auto heuristicLayer = createLayer("HeuristicLayer");

    EXPECT_CALL(*heuristicLayer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*heuristicLayer, getFrameRateForLayerTree())
            .WillRepeatedly(Return(Layer::FrameRate()));

    auto infrequentLayer = createLayer("InfrequentLayer");
    EXPECT_CALL(*infrequentLayer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*infrequentLayer, getFrameRateForLayerTree())
            .WillRepeatedly(Return(Layer::FrameRate()));

    const nsecs_t startTime = systemTime();

    const std::chrono::nanoseconds heuristicUpdateDelta = 41'666'667ns;
    history().record(heuristicLayer.get(), startTime, startTime,
                     LayerHistory::LayerUpdateType::Buffer);
    history().record(infrequentLayer.get(), startTime, startTime,
                     LayerHistory::LayerUpdateType::Buffer);

    nsecs_t time = startTime;
    nsecs_t lastInfrequentUpdate = startTime;
    const int totalInfrequentLayerUpdates = FREQUENT_LAYER_WINDOW_SIZE * 5;
    int infrequentLayerUpdates = 0;
    while (infrequentLayerUpdates <= totalInfrequentLayerUpdates) {
        time += heuristicUpdateDelta.count();
        history().record(heuristicLayer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);

        if (time - lastInfrequentUpdate >= infrequentUpdateDelta.count()) {
            ALOGI("submitting infrequent frame [%d/%d]", infrequentLayerUpdates,
                  totalInfrequentLayerUpdates);
            lastInfrequentUpdate = time;
            history().record(infrequentLayer.get(), time, time,
                             LayerHistory::LayerUpdateType::Buffer);
            infrequentLayerUpdates++;
        }

        if (time - startTime > PRESENT_TIME_HISTORY_DURATION.count()) {
            ASSERT_NE(0, summarizeLayerHistory(time).size());
            ASSERT_GE(2, summarizeLayerHistory(time).size());

            bool max = false;
            bool min = false;
            Fps heuristic;
            for (const auto& layer : summarizeLayerHistory(time)) {
                if (layer.vote == LayerHistory::LayerVoteType::Heuristic) {
                    heuristic = layer.desiredRefreshRate;
                } else if (layer.vote == LayerHistory::LayerVoteType::Max) {
                    max = true;
                } else if (layer.vote == LayerHistory::LayerVoteType::Min) {
                    min = true;
                }
            }

            if (infrequentLayerUpdates > FREQUENT_LAYER_WINDOW_SIZE) {
                EXPECT_EQ(24_Hz, heuristic);
                EXPECT_FALSE(max);
                if (summarizeLayerHistory(time).size() == 2) {
                    EXPECT_TRUE(min);
                }
            }
        }
    }
}

INSTANTIATE_TEST_CASE_P(LeapYearTests, LayerHistoryTestParameterized,
                        ::testing::Values(1s, 2s, 3s, 4s, 5s));

} // namespace
} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
