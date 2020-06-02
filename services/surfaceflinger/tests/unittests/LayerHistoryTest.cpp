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
#define LOG_TAG "LayerHistoryTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include "Scheduler/LayerHistory.h"
#include "Scheduler/LayerInfo.h"
#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/MockLayer.h"

using testing::_;
using testing::Return;

namespace android::scheduler {

class LayerHistoryTest : public testing::Test {
protected:
    static constexpr auto PRESENT_TIME_HISTORY_SIZE = LayerInfo::PresentTimeHistory::HISTORY_SIZE;
    static constexpr auto MAX_FREQUENT_LAYER_PERIOD_NS = LayerInfo::MAX_FREQUENT_LAYER_PERIOD_NS;

    static constexpr float LO_FPS = 30.f;
    static constexpr nsecs_t LO_FPS_PERIOD = 33'333'333;

    static constexpr float HI_FPS = 90.f;
    static constexpr nsecs_t HI_FPS_PERIOD = 11'111'111;

    LayerHistoryTest() { mFlinger.resetScheduler(mScheduler); }

    impl::LayerHistory& history() { return *mScheduler->mutableLayerHistory(); }
    const impl::LayerHistory& history() const { return *mScheduler->mutableLayerHistory(); }

    size_t layerCount() const { return mScheduler->layerHistorySize(); }
    size_t activeLayerCount() const NO_THREAD_SAFETY_ANALYSIS { return history().mActiveLayersEnd; }

    size_t frequentLayerCount(nsecs_t now) const NO_THREAD_SAFETY_ANALYSIS {
        const auto& infos = history().mLayerInfos;
        return std::count_if(infos.begin(), infos.begin() + history().mActiveLayersEnd,
                             [now](const auto& pair) { return pair.second->isFrequent(now); });
    }

    auto createLayer() { return sp<mock::MockLayer>(new mock::MockLayer(mFlinger.flinger())); }

    Hwc2::mock::Display mDisplay;
    RefreshRateConfigs mConfigs{{HWC2::Display::Config::Builder(mDisplay, 0)
                                         .setVsyncPeriod(int32_t(LO_FPS_PERIOD))
                                         .setConfigGroup(0)
                                         .build(),
                                 HWC2::Display::Config::Builder(mDisplay, 1)
                                         .setVsyncPeriod(int32_t(HI_FPS_PERIOD))
                                         .setConfigGroup(0)
                                         .build()},
                                HwcConfigIndexType(0)};
    TestableScheduler* const mScheduler{new TestableScheduler(mConfigs, false)};
    TestableSurfaceFlinger mFlinger;

    const nsecs_t mTime = systemTime();
};

namespace {

TEST_F(LayerHistoryTest, oneLayer) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameSelectionPriority()).WillRepeatedly(Return(1));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    // no layers are returned if no layers are active.
    ASSERT_TRUE(history().summarize(mTime).empty());
    EXPECT_EQ(0, activeLayerCount());

    // no layers are returned if active layers have insufficient history.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE - 1; i++) {
        history().record(layer.get(), 0, mTime, LayerHistory::LayerUpdateType::Buffer);
        ASSERT_TRUE(history().summarize(mTime).empty());
        EXPECT_EQ(1, activeLayerCount());
    }

    // High FPS is returned once enough history has been recorded.
    for (int i = 0; i < 10; i++) {
        history().record(layer.get(), 0, mTime, LayerHistory::LayerUpdateType::Buffer);
        ASSERT_EQ(1, history().summarize(mTime).size());
        EXPECT_FLOAT_EQ(HI_FPS, history().summarize(mTime)[0].desiredRefreshRate);
        EXPECT_EQ(1, activeLayerCount());
    }
}

TEST_F(LayerHistoryTest, explicitTimestamp) {
    const auto layer = createLayer();
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer, getFrameSelectionPriority()).WillRepeatedly(Return(1));
    EXPECT_CALL(*layer, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = mTime;
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
    }

    ASSERT_EQ(1, history().summarize(mTime).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(mTime)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, multipleLayers) {
    auto layer1 = createLayer();
    auto layer2 = createLayer();
    auto layer3 = createLayer();

    EXPECT_CALL(*layer1, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer1, getFrameSelectionPriority()).WillRepeatedly(Return(1));
    EXPECT_CALL(*layer1, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_CALL(*layer2, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer2, getFrameSelectionPriority()).WillRepeatedly(Return(1));
    EXPECT_CALL(*layer2, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));

    EXPECT_CALL(*layer3, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer3, getFrameSelectionPriority()).WillRepeatedly(Return(1));
    EXPECT_CALL(*layer3, getFrameRateForLayerTree()).WillRepeatedly(Return(Layer::FrameRate()));
    nsecs_t time = mTime;

    EXPECT_EQ(3, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer1 is active but infrequent.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer1.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += MAX_FREQUENT_LAYER_PERIOD_NS.count();
    }

    ASSERT_EQ(1, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer2 is frequent and has high refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
    }

    // layer1 is still active but infrequent.
    history().record(layer1.get(), time, time, LayerHistory::LayerUpdateType::Buffer);

    ASSERT_EQ(2, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time)[1].desiredRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer1 is no longer active.
    // layer2 is frequent and has low refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
    }

    ASSERT_EQ(1, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
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
    }

    ASSERT_EQ(1, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer3 becomes recently active.
    history().record(layer3.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(2, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time)[1].desiredRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer1 expires.
    layer1.clear();
    ASSERT_EQ(2, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time)[1].desiredRefreshRate);
    EXPECT_EQ(2, layerCount());
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer2 still has low refresh rate.
    // layer3 becomes inactive.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += LO_FPS_PERIOD;
    }

    ASSERT_EQ(1, history().summarize(time).size());
    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer2 expires.
    layer2.clear();
    ASSERT_TRUE(history().summarize(time).empty());
    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer3 becomes active and has high refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer3.get(), time, time, LayerHistory::LayerUpdateType::Buffer);
        time += HI_FPS_PERIOD;
    }

    ASSERT_EQ(1, history().summarize(time).size());
    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time)[0].desiredRefreshRate);
    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer3 expires.
    layer3.clear();
    ASSERT_TRUE(history().summarize(time).empty());
    EXPECT_EQ(0, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

} // namespace
} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
