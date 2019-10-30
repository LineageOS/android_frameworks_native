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

    LayerHistory& history() { return mScheduler->mutableLayerHistory(); }
    const LayerHistory& history() const { return mScheduler->mutableLayerHistory(); }

    size_t layerCount() const NO_THREAD_SAFETY_ANALYSIS { return history().mLayerInfos.size(); }
    size_t activeLayerCount() const NO_THREAD_SAFETY_ANALYSIS { return history().mActiveLayersEnd; }

    size_t frequentLayerCount(nsecs_t now) const NO_THREAD_SAFETY_ANALYSIS {
        const auto& infos = history().mLayerInfos;
        return std::count_if(infos.begin(), infos.begin() + history().mActiveLayersEnd,
                             [now](const auto& pair) { return pair.second->isFrequent(now); });
    }

    auto createLayer() { return sp<mock::MockLayer>(new mock::MockLayer(mFlinger.flinger())); }

    RefreshRateConfigs mConfigs{true,
                                {RefreshRateConfigs::InputConfig{0, LO_FPS_PERIOD},
                                 RefreshRateConfigs::InputConfig{1, HI_FPS_PERIOD}},
                                0};
    TestableScheduler* const mScheduler{new TestableScheduler(mConfigs)};
    TestableSurfaceFlinger mFlinger;

    const nsecs_t mTime = systemTime();
};

namespace {

TEST_F(LayerHistoryTest, oneLayer) {
    const auto layer = createLayer();
    constexpr bool isHDR = false;
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    // 0 FPS is returned if no layers are active.
    EXPECT_FLOAT_EQ(0, history().summarize(mTime).maxRefreshRate);
    EXPECT_EQ(0, activeLayerCount());

    // 0 FPS is returned if active layers have insufficient history.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE - 1; i++) {
        history().record(layer.get(), 0, isHDR, mTime);
        EXPECT_FLOAT_EQ(0, history().summarize(mTime).maxRefreshRate);
        EXPECT_EQ(1, activeLayerCount());
    }

    // High FPS is returned once enough history has been recorded.
    for (int i = 0; i < 10; i++) {
        history().record(layer.get(), 0, isHDR, mTime);
        EXPECT_FLOAT_EQ(HI_FPS, history().summarize(mTime).maxRefreshRate);
        EXPECT_EQ(1, activeLayerCount());
    }
}

TEST_F(LayerHistoryTest, oneHDRLayer) {
    const auto layer = createLayer();
    constexpr bool isHDR = true;
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    history().record(layer.get(), 0, isHDR, mTime);
    auto summary = history().summarize(mTime);
    EXPECT_FLOAT_EQ(0, summary.maxRefreshRate);
    EXPECT_TRUE(summary.isHDR);
    EXPECT_EQ(1, activeLayerCount());

    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(false));

    summary = history().summarize(mTime);
    EXPECT_FLOAT_EQ(0, summary.maxRefreshRate);
    EXPECT_FALSE(summary.isHDR);
    EXPECT_EQ(0, activeLayerCount());
}

TEST_F(LayerHistoryTest, explicitTimestamp) {
    const auto layer = createLayer();
    constexpr bool isHDR = false;
    EXPECT_CALL(*layer, isVisible()).WillRepeatedly(Return(true));

    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());

    nsecs_t time = mTime;
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer.get(), time, isHDR, time);
        time += LO_FPS_PERIOD;
    }

    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(mTime).maxRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));
}

TEST_F(LayerHistoryTest, multipleLayers) {
    auto layer1 = createLayer();
    auto layer2 = createLayer();
    auto layer3 = createLayer();
    constexpr bool isHDR = false;

    EXPECT_CALL(*layer1, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer2, isVisible()).WillRepeatedly(Return(true));
    EXPECT_CALL(*layer3, isVisible()).WillRepeatedly(Return(true));

    nsecs_t time = mTime;

    EXPECT_EQ(3, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer1 is active but infrequent.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer1.get(), time, isHDR, time);
        time += MAX_FREQUENT_LAYER_PERIOD_NS.count();
    }

    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer2 is frequent and has high refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, isHDR, time);
        time += HI_FPS_PERIOD;
    }

    // layer1 is still active but infrequent.
    history().record(layer1.get(), time, isHDR, time);

    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer1 is no longer active.
    // layer2 is frequent and has low refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, isHDR, time);
        time += LO_FPS_PERIOD;
    }

    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer2 still has low refresh rate.
    // layer3 has high refresh rate but not enough history.
    constexpr int RATIO = LO_FPS_PERIOD / HI_FPS_PERIOD;
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE - 1; i++) {
        if (i % RATIO == 0) {
            history().record(layer2.get(), time, isHDR, time);
        }

        history().record(layer3.get(), time, isHDR, time);
        time += HI_FPS_PERIOD;
    }

    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer3 becomes recently active.
    history().record(layer3.get(), time, isHDR, time);
    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer1 expires.
    layer1.clear();
    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(2, layerCount());
    EXPECT_EQ(2, activeLayerCount());
    EXPECT_EQ(2, frequentLayerCount(time));

    // layer2 still has low refresh rate.
    // layer3 becomes inactive.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer2.get(), time, isHDR, time);
        time += LO_FPS_PERIOD;
    }

    EXPECT_FLOAT_EQ(LO_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer2 expires.
    layer2.clear();
    EXPECT_FLOAT_EQ(0, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));

    // layer3 becomes active and has high refresh rate.
    for (int i = 0; i < PRESENT_TIME_HISTORY_SIZE; i++) {
        history().record(layer3.get(), time, isHDR, time);
        time += HI_FPS_PERIOD;
    }

    EXPECT_FLOAT_EQ(HI_FPS, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(1, layerCount());
    EXPECT_EQ(1, activeLayerCount());
    EXPECT_EQ(1, frequentLayerCount(time));

    // layer3 expires.
    layer3.clear();
    EXPECT_FLOAT_EQ(0, history().summarize(time).maxRefreshRate);
    EXPECT_EQ(0, layerCount());
    EXPECT_EQ(0, activeLayerCount());
    EXPECT_EQ(0, frequentLayerCount(time));
}

} // namespace
} // namespace android::scheduler
