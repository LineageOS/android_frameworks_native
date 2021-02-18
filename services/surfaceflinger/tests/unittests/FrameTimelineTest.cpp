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


#include "gmock/gmock-spec-builders.h"
#include "mock/MockTimeStats.h"
#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <FrameTimeline/FrameTimeline.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <perfetto/trace/trace.pb.h>
#include <cinttypes>

using namespace std::chrono_literals;
using testing::_;
using testing::AtLeast;
using testing::Contains;
using FrameTimelineEvent = perfetto::protos::FrameTimelineEvent;
using ProtoExpectedDisplayFrameStart =
        perfetto::protos::FrameTimelineEvent_ExpectedDisplayFrameStart;
using ProtoExpectedSurfaceFrameStart =
        perfetto::protos::FrameTimelineEvent_ExpectedSurfaceFrameStart;
using ProtoActualDisplayFrameStart = perfetto::protos::FrameTimelineEvent_ActualDisplayFrameStart;
using ProtoActualSurfaceFrameStart = perfetto::protos::FrameTimelineEvent_ActualSurfaceFrameStart;
using ProtoFrameEnd = perfetto::protos::FrameTimelineEvent_FrameEnd;
using ProtoPresentType = perfetto::protos::FrameTimelineEvent_PresentType;
using ProtoJankType = perfetto::protos::FrameTimelineEvent_JankType;

namespace android::frametimeline {

class FrameTimelineTest : public testing::Test {
public:
    FrameTimelineTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~FrameTimelineTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    static void SetUpTestSuite() {
        // Need to initialize tracing in process for testing, and only once per test suite.
        perfetto::TracingInitArgs args;
        args.backends = perfetto::kInProcessBackend;
        perfetto::Tracing::Initialize(args);
    }

    void SetUp() override {
        mTimeStats = std::make_shared<mock::TimeStats>();
        mFrameTimeline = std::make_unique<impl::FrameTimeline>(mTimeStats, kSurfaceFlingerPid,
                                                               kTestThresholds);
        mFrameTimeline->registerDataSource();
        mTokenManager = &mFrameTimeline->mTokenManager;
        mTraceCookieCounter = &mFrameTimeline->mTraceCookieCounter;
        maxDisplayFrames = &mFrameTimeline->mMaxDisplayFrames;
        maxTokenRetentionTime = mTokenManager->kMaxRetentionTime;
    }

    // Each tracing session can be used for a single block of Start -> Stop.
    static std::unique_ptr<perfetto::TracingSession> getTracingSessionForTest() {
        perfetto::TraceConfig cfg;
        cfg.set_duration_ms(500);
        cfg.add_buffers()->set_size_kb(1024);
        auto* ds_cfg = cfg.add_data_sources()->mutable_config();
        ds_cfg->set_name(impl::FrameTimeline::kFrameTimelineDataSource);

        auto tracingSession = perfetto::Tracing::NewTrace(perfetto::kInProcessBackend);
        tracingSession->Setup(cfg);
        return tracingSession;
    }

    std::vector<perfetto::protos::TracePacket> readFrameTimelinePacketsBlocking(
            perfetto::TracingSession* tracingSession) {
        std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
        perfetto::protos::Trace trace;
        EXPECT_TRUE(trace.ParseFromArray(raw_trace.data(), int(raw_trace.size())));

        std::vector<perfetto::protos::TracePacket> packets;
        for (const auto& packet : trace.packet()) {
            if (!packet.has_frame_timeline_event()) {
                continue;
            }
            packets.emplace_back(packet);
        }
        return packets;
    }

    void addEmptyDisplayFrame() {
        auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
        mFrameTimeline->setSfPresent(2500, presentFence1);
    }

    void flushTokens(nsecs_t flushTime) {
        std::lock_guard<std::mutex> lock(mTokenManager->mMutex);
        mTokenManager->flushTokens(flushTime);
    }

    SurfaceFrame& getSurfaceFrame(size_t displayFrameIdx, size_t surfaceFrameIdx) {
        std::lock_guard<std::mutex> lock(mFrameTimeline->mMutex);
        return *(mFrameTimeline->mDisplayFrames[displayFrameIdx]
                         ->getSurfaceFrames()[surfaceFrameIdx]);
    }

    std::shared_ptr<impl::FrameTimeline::DisplayFrame> getDisplayFrame(size_t idx) {
        std::lock_guard<std::mutex> lock(mFrameTimeline->mMutex);
        return mFrameTimeline->mDisplayFrames[idx];
    }

    static bool compareTimelineItems(const TimelineItem& a, const TimelineItem& b) {
        return a.startTime == b.startTime && a.endTime == b.endTime &&
                a.presentTime == b.presentTime;
    }

    const std::map<int64_t, TokenManagerPrediction>& getPredictions() const {
        return mTokenManager->mPredictions;
    }

    uint32_t getNumberOfDisplayFrames() const {
        std::lock_guard<std::mutex> lock(mFrameTimeline->mMutex);
        return static_cast<uint32_t>(mFrameTimeline->mDisplayFrames.size());
    }

    int64_t snoopCurrentTraceCookie() const { return mTraceCookieCounter->mTraceCookie; }

    void flushTrace() {
        using FrameTimelineDataSource = impl::FrameTimeline::FrameTimelineDataSource;
        FrameTimelineDataSource::Trace(
                [&](FrameTimelineDataSource::TraceContext ctx) { ctx.Flush(); });
    }

    std::shared_ptr<mock::TimeStats> mTimeStats;
    std::unique_ptr<impl::FrameTimeline> mFrameTimeline;
    impl::TokenManager* mTokenManager;
    TraceCookieCounter* mTraceCookieCounter;
    FenceToFenceTimeMap fenceFactory;
    uint32_t* maxDisplayFrames;
    nsecs_t maxTokenRetentionTime;
    static constexpr pid_t kSurfaceFlingerPid = 666;
    static constexpr nsecs_t kPresentThreshold = std::chrono::nanoseconds(2ns).count();
    static constexpr nsecs_t kDeadlineThreshold = std::chrono::nanoseconds(2ns).count();
    static constexpr nsecs_t kStartThreshold = std::chrono::nanoseconds(2ns).count();
    static constexpr JankClassificationThresholds kTestThresholds{kPresentThreshold,
                                                                  kDeadlineThreshold,
                                                                  kStartThreshold};
};

static const std::string sLayerNameOne = "layer1";
static const std::string sLayerNameTwo = "layer2";
static constexpr const uid_t sUidOne = 0;
static constexpr pid_t sPidOne = 10;
static constexpr pid_t sPidTwo = 20;
static constexpr int32_t sInputEventId = 5;

TEST_F(FrameTimelineTest, tokenManagerRemovesStalePredictions) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({0, 0, 0});
    EXPECT_EQ(getPredictions().size(), 1u);
    flushTokens(systemTime() + maxTokenRetentionTime);
    int64_t token2 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    std::optional<TimelineItem> predictions = mTokenManager->getPredictionsForToken(token1);

    // token1 should have expired
    EXPECT_EQ(getPredictions().size(), 1u);
    EXPECT_EQ(predictions.has_value(), false);

    predictions = mTokenManager->getPredictionsForToken(token2);
    EXPECT_EQ(compareTimelineItems(*predictions, TimelineItem(10, 20, 30)), true);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_getOwnerPidReturnsCorrectPid) {
    auto surfaceFrame1 = mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne,
                                                                    sLayerNameOne, sLayerNameOne);
    auto surfaceFrame2 = mFrameTimeline->createSurfaceFrameForToken({}, sPidTwo, sUidOne,
                                                                    sLayerNameOne, sLayerNameOne);
    EXPECT_EQ(surfaceFrame1->getOwnerPid(), sPidOne);
    EXPECT_EQ(surfaceFrame2->getOwnerPid(), sPidTwo);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_noToken) {
    auto surfaceFrame = mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne,
                                                                   sLayerNameOne, sLayerNameOne);
    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::None);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_expiredToken) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({0, 0, 0});
    flushTokens(systemTime() + maxTokenRetentionTime);
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerNameOne, sLayerNameOne);

    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::Expired);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_validToken) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerNameOne, sLayerNameOne);

    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::Valid);
    EXPECT_EQ(compareTimelineItems(surfaceFrame->getPredictions(), TimelineItem(10, 20, 30)), true);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_validInputEventId) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    constexpr int32_t inputEventId = 1;
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({token1, inputEventId}, sPidOne, sUidOne,
                                                       sLayerNameOne, sLayerNameOne);

    EXPECT_EQ(inputEventId, surfaceFrame->getInputEventId());
}

TEST_F(FrameTimelineTest, presentFenceSignaled_droppedFramesNotUpdated) {
    // Global increment
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t token2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    // Trigger a flush by calling setSfPresent for the next frame
    mFrameTimeline->setSfWakeUp(token2, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);

    auto& droppedSurfaceFrame = getSurfaceFrame(0, 0);
    EXPECT_EQ(droppedSurfaceFrame.getPresentState(), SurfaceFrame::PresentState::Dropped);
    EXPECT_EQ(droppedSurfaceFrame.getActuals().presentTime, 0);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_presentedFramesUpdated) {
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_)).Times(2);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 30});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 56, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameTwo, sLayerNameTwo);
    mFrameTimeline->setSfWakeUp(sfToken1, 22, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    auto& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    auto& presentedSurfaceFrame2 = getSurfaceFrame(0, 1);
    presentFence1->signalForTest(42);

    // Fences haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);
    EXPECT_EQ(presentedSurfaceFrame1.getActuals().presentTime, 0);
    EXPECT_EQ(presentedSurfaceFrame2.getActuals().presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto surfaceFrame3 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken2, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, Fps::fromPeriodNsecs(11));
    surfaceFrame3->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame3);
    mFrameTimeline->setSfPresent(56, presentFence2);
    displayFrame = getDisplayFrame(0);

    // Fences have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 42);
    EXPECT_EQ(presentedSurfaceFrame1.getActuals().presentTime, 42);
    EXPECT_EQ(presentedSurfaceFrame2.getActuals().presentTime, 42);
    EXPECT_NE(surfaceFrame1->getJankType(), std::nullopt);
    EXPECT_NE(surfaceFrame2->getJankType(), std::nullopt);
}

TEST_F(FrameTimelineTest, displayFramesSlidingWindowMovesAfterLimit) {
    // Insert kMaxDisplayFrames' count of DisplayFrames to fill the deque
    int frameTimeFactor = 0;
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_))
            .Times(static_cast<int32_t>(*maxDisplayFrames));
    for (size_t i = 0; i < *maxDisplayFrames; i++) {
        auto presentFence = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
        int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions(
                {10 + frameTimeFactor, 20 + frameTimeFactor, 30 + frameTimeFactor});
        int64_t sfToken = mTokenManager->generateTokenForPredictions(
                {22 + frameTimeFactor, 26 + frameTimeFactor, 30 + frameTimeFactor});
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId},
                                                           sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne);
        mFrameTimeline->setSfWakeUp(sfToken, 22 + frameTimeFactor, Fps::fromPeriodNsecs(11));
        surfaceFrame->setPresentState(SurfaceFrame::PresentState::Presented);
        mFrameTimeline->addSurfaceFrame(surfaceFrame);
        mFrameTimeline->setSfPresent(27 + frameTimeFactor, presentFence);
        presentFence->signalForTest(32 + frameTimeFactor);
        frameTimeFactor += 30;
    }
    auto displayFrame0 = getDisplayFrame(0);

    // The 0th Display Frame should have actuals 22, 27, 32
    EXPECT_EQ(compareTimelineItems(displayFrame0->getActuals(), TimelineItem(22, 27, 32)), true);

    // Add one more display frame
    auto presentFence = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions(
            {10 + frameTimeFactor, 20 + frameTimeFactor, 30 + frameTimeFactor});
    int64_t sfToken = mTokenManager->generateTokenForPredictions(
            {22 + frameTimeFactor, 26 + frameTimeFactor, 30 + frameTimeFactor});
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken, 22 + frameTimeFactor, Fps::fromPeriodNsecs(11));
    surfaceFrame->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame);
    mFrameTimeline->setSfPresent(27 + frameTimeFactor, presentFence);
    presentFence->signalForTest(32 + frameTimeFactor);
    displayFrame0 = getDisplayFrame(0);

    // The window should have slided by 1 now and the previous 0th display frame
    // should have been removed from the deque
    EXPECT_EQ(compareTimelineItems(displayFrame0->getActuals(), TimelineItem(52, 57, 62)), true);
}

TEST_F(FrameTimelineTest, surfaceFrameEndTimeAcquireFenceAfterQueue) {
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, 0, "acquireFenceAfterQueue",
                                                       "acquireFenceAfterQueue");
    surfaceFrame->setActualQueueTime(123);
    surfaceFrame->setAcquireFenceTime(456);
    EXPECT_EQ(surfaceFrame->getActuals().endTime, 456);
}

TEST_F(FrameTimelineTest, surfaceFrameEndTimeAcquireFenceBeforeQueue) {
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, 0, "acquireFenceAfterQueue",
                                                       "acquireFenceAfterQueue");
    surfaceFrame->setActualQueueTime(456);
    surfaceFrame->setAcquireFenceTime(123);
    EXPECT_EQ(surfaceFrame->getActuals().endTime, 456);
}

TEST_F(FrameTimelineTest, setMaxDisplayFramesSetsSizeProperly) {
    auto presentFence = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    presentFence->signalForTest(2);

    // Size shouldn't exceed maxDisplayFrames - 64
    for (size_t i = 0; i < *maxDisplayFrames + 10; i++) {
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne);
        int64_t sfToken = mTokenManager->generateTokenForPredictions({22, 26, 30});
        mFrameTimeline->setSfWakeUp(sfToken, 22, Fps::fromPeriodNsecs(11));
        surfaceFrame->setPresentState(SurfaceFrame::PresentState::Presented);
        mFrameTimeline->addSurfaceFrame(surfaceFrame);
        mFrameTimeline->setSfPresent(27, presentFence);
    }
    EXPECT_EQ(getNumberOfDisplayFrames(), *maxDisplayFrames);

    // Increase the size to 256
    mFrameTimeline->setMaxDisplayFrames(256);
    EXPECT_EQ(*maxDisplayFrames, 256u);

    for (size_t i = 0; i < *maxDisplayFrames + 10; i++) {
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne);
        int64_t sfToken = mTokenManager->generateTokenForPredictions({22, 26, 30});
        mFrameTimeline->setSfWakeUp(sfToken, 22, Fps::fromPeriodNsecs(11));
        surfaceFrame->setPresentState(SurfaceFrame::PresentState::Presented);
        mFrameTimeline->addSurfaceFrame(surfaceFrame);
        mFrameTimeline->setSfPresent(27, presentFence);
    }
    EXPECT_EQ(getNumberOfDisplayFrames(), *maxDisplayFrames);

    // Shrink the size to 128
    mFrameTimeline->setMaxDisplayFrames(128);
    EXPECT_EQ(*maxDisplayFrames, 128u);

    for (size_t i = 0; i < *maxDisplayFrames + 10; i++) {
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne);
        int64_t sfToken = mTokenManager->generateTokenForPredictions({22, 26, 30});
        mFrameTimeline->setSfWakeUp(sfToken, 22, Fps::fromPeriodNsecs(11));
        surfaceFrame->setPresentState(SurfaceFrame::PresentState::Presented);
        mFrameTimeline->addSurfaceFrame(surfaceFrame);
        mFrameTimeline->setSfPresent(27, presentFence);
    }
    EXPECT_EQ(getNumberOfDisplayFrames(), *maxDisplayFrames);
}

// Tests related to TimeStats
TEST_F(FrameTimelineTest, presentFenceSignaled_reportsLongSfCpu) {
    Fps refreshRate = Fps(11);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                   sLayerNameOne,
                                                   JankType::SurfaceFlingerCpuDeadlineMissed,
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(3ms)
                                                           .count(),
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(10ms)
                                                           .count(),
                                                   0}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(10ms).count(), std::chrono::nanoseconds(20ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(52ms).count(), std::chrono::nanoseconds(56ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(52ms).count(), refreshRate);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(20ms).count());
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(70ms).count());

    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(59ms).count(), presentFence1);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsDisplayMiss) {
    Fps refreshRate = Fps::fromPeriodNsecs(30);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                                sLayerNameOne, JankType::DisplayHAL,
                                                                0, 0, 0}));

    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(10ms).count(), std::chrono::nanoseconds(20ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(52ms).count(), std::chrono::nanoseconds(56ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(52ms).count(), refreshRate);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(20ms).count());
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(90ms).count());
    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(56ms).count(), presentFence1);
    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::DisplayHAL);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppMiss) {
    Fps refreshRate = Fps(11.0);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                   sLayerNameOne, JankType::AppDeadlineMissed, 0, 0,
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(25ms)
                                                           .count()}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(10ms).count(), std::chrono::nanoseconds(20ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(82ms).count(), std::chrono::nanoseconds(86ms).count(),
             std::chrono::nanoseconds(90ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(45ms).count());
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(52ms).count(), refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(90ms).count());
    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(86ms).count(), presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::AppDeadlineMissed);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsSfScheduling) {
    Fps refreshRate = Fps::fromPeriodNsecs(std::chrono::nanoseconds(32ms).count());
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                   sLayerNameOne,
                                                   JankType::SurfaceFlingerScheduling, 0, 0,
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(-10ms)
                                                           .count()}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(40ms).count(), std::chrono::nanoseconds(60ms).count(),
             std::chrono::nanoseconds(92ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(52ms).count(), std::chrono::nanoseconds(56ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(50ms).count());
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(52ms).count(), refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(60ms).count());
    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(56ms).count(), presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::SurfaceFlingerScheduling);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsSfPredictionError) {
    Fps refreshRate = Fps(16.66f);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                   sLayerNameOne, JankType::PredictionError, 0,
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(5ms)
                                                           .count(),
                                                   0}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(30ms).count(), std::chrono::nanoseconds(40ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(52ms).count(), std::chrono::nanoseconds(56ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(40ms).count());
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(52ms).count(), refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(65ms).count());
    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(56ms).count(), presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::PredictionError);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppBufferStuffing) {
    Fps refreshRate = Fps::fromPeriodNsecs(std::chrono::nanoseconds(32ms).count());
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                   sLayerNameOne,
                                                   JankType::BufferStuffing |
                                                           JankType::SurfaceFlingerScheduling,
                                                   0, 0, 0}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(30ms).count(), std::chrono::nanoseconds(40ms).count(),
             std::chrono::nanoseconds(58ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(82ms).count(), std::chrono::nanoseconds(86ms).count(),
             std::chrono::nanoseconds(90ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(40ms).count());
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(82ms).count(), refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented,
                                   /*previousLatchTime*/
                                   std::chrono::nanoseconds(56ms).count());
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(90ms).count());
    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(86ms).count(), presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(),
              JankType::BufferStuffing | JankType::SurfaceFlingerScheduling);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppMissWithRenderRate) {
    Fps refreshRate = Fps(11.0);
    Fps renderRate = Fps(30.0);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, renderRate, sUidOne, sLayerNameOne,
                                                   JankType::AppDeadlineMissed, 0, 0,
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(25ms)
                                                           .count()}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(10ms).count(), std::chrono::nanoseconds(20ms).count(),
             std::chrono::nanoseconds(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::nanoseconds(82ms).count(), std::chrono::nanoseconds(86ms).count(),
             std::chrono::nanoseconds(90ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(std::chrono::nanoseconds(45ms).count());
    mFrameTimeline->setSfWakeUp(sfToken1, std::chrono::nanoseconds(52ms).count(), refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    surfaceFrame1->setRenderRate(renderRate);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(std::chrono::nanoseconds(90ms).count());
    mFrameTimeline->setSfPresent(std::chrono::nanoseconds(86ms).count(), presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::AppDeadlineMissed);
}

/*
 * Tracing Tests
 *
 * Trace packets are flushed all the way only when the next packet is traced.
 * For example: trace<Display/Surface>Frame() will create a TracePacket but not flush it. Only when
 * another TracePacket is created, the previous one is guaranteed to be flushed. The following tests
 * will have additional empty frames created for this reason.
 */
TEST_F(FrameTimelineTest, tracing_noPacketsSentWithoutTraceStart) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t token2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    // Trigger a flushPresentFence (which will call trace function) by calling setSfPresent for the
    // next frame
    mFrameTimeline->setSfWakeUp(token2, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 0u);
}

TEST_F(FrameTimelineTest, tracing_sanityTest) {
    auto tracingSession = getTracingSessionForTest();
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t token2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token2, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    // Trigger a flushPresentFence (which will call trace function) by calling setSfPresent for the
    // next frame
    mFrameTimeline->setSfWakeUp(token2, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);
    presentFence2->signalForTest(55);

    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // Display Frame 1 has 8 packets - 4 from DisplayFrame and 4 from SurfaceFrame.
    EXPECT_EQ(packets.size(), 8u);
}

TEST_F(FrameTimelineTest, traceDisplayFrame_invalidTokenDoesNotEmitTracePacket) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(-1, 20, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    // Trigger a flushPresentFence (which will call trace function) by calling setSfPresent for the
    // next frame
    mFrameTimeline->setSfWakeUp(token1, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);
    presentFence2->signalForTest(60);

    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 0u);
}

TEST_F(FrameTimelineTest, traceSurfaceFrame_invalidTokenDoesNotEmitTracePacket) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t token2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    auto surfaceFrame1 = mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne,
                                                                    sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    // Trigger a flushPresentFence (which will call trace function) by calling setSfPresent for the
    // next frame
    mFrameTimeline->setSfWakeUp(token2, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);
    presentFence2->signalForTest(60);

    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // Display Frame 1 has 4 packets (SurfaceFrame shouldn't be traced since it has an invalid
    // token).
    EXPECT_EQ(packets.size(), 4u);
}

void validateTraceEvent(const ProtoExpectedDisplayFrameStart& received,
                        const ProtoExpectedDisplayFrameStart& source) {
    ASSERT_TRUE(received.has_cookie());
    EXPECT_EQ(received.cookie(), source.cookie());

    ASSERT_TRUE(received.has_token());
    EXPECT_EQ(received.token(), source.token());

    ASSERT_TRUE(received.has_pid());
    EXPECT_EQ(received.pid(), source.pid());
}

void validateTraceEvent(const ProtoActualDisplayFrameStart& received,
                        const ProtoActualDisplayFrameStart& source) {
    ASSERT_TRUE(received.has_cookie());
    EXPECT_EQ(received.cookie(), source.cookie());

    ASSERT_TRUE(received.has_token());
    EXPECT_EQ(received.token(), source.token());

    ASSERT_TRUE(received.has_pid());
    EXPECT_EQ(received.pid(), source.pid());

    ASSERT_TRUE(received.has_present_type());
    EXPECT_EQ(received.present_type(), source.present_type());
    ASSERT_TRUE(received.has_on_time_finish());
    EXPECT_EQ(received.on_time_finish(), source.on_time_finish());
    ASSERT_TRUE(received.has_gpu_composition());
    EXPECT_EQ(received.gpu_composition(), source.gpu_composition());
    ASSERT_TRUE(received.has_jank_type());
    EXPECT_EQ(received.jank_type(), source.jank_type());
}

void validateTraceEvent(const ProtoExpectedSurfaceFrameStart& received,
                        const ProtoExpectedSurfaceFrameStart& source) {
    ASSERT_TRUE(received.has_cookie());
    EXPECT_EQ(received.cookie(), source.cookie());

    ASSERT_TRUE(received.has_token());
    EXPECT_EQ(received.token(), source.token());

    ASSERT_TRUE(received.has_display_frame_token());
    EXPECT_EQ(received.display_frame_token(), source.display_frame_token());

    ASSERT_TRUE(received.has_pid());
    EXPECT_EQ(received.pid(), source.pid());

    ASSERT_TRUE(received.has_layer_name());
    EXPECT_EQ(received.layer_name(), source.layer_name());
}

void validateTraceEvent(const ProtoActualSurfaceFrameStart& received,
                        const ProtoActualSurfaceFrameStart& source) {
    ASSERT_TRUE(received.has_cookie());
    EXPECT_EQ(received.cookie(), source.cookie());

    ASSERT_TRUE(received.has_token());
    EXPECT_EQ(received.token(), source.token());

    ASSERT_TRUE(received.has_display_frame_token());
    EXPECT_EQ(received.display_frame_token(), source.display_frame_token());

    ASSERT_TRUE(received.has_pid());
    EXPECT_EQ(received.pid(), source.pid());

    ASSERT_TRUE(received.has_layer_name());
    EXPECT_EQ(received.layer_name(), source.layer_name());

    ASSERT_TRUE(received.has_present_type());
    EXPECT_EQ(received.present_type(), source.present_type());
    ASSERT_TRUE(received.has_on_time_finish());
    EXPECT_EQ(received.on_time_finish(), source.on_time_finish());
    ASSERT_TRUE(received.has_gpu_composition());
    EXPECT_EQ(received.gpu_composition(), source.gpu_composition());
    ASSERT_TRUE(received.has_jank_type());
    EXPECT_EQ(received.jank_type(), source.jank_type());
}

void validateTraceEvent(const ProtoFrameEnd& received, const ProtoFrameEnd& source) {
    ASSERT_TRUE(received.has_cookie());
    EXPECT_EQ(received.cookie(), source.cookie());
}

TEST_F(FrameTimelineTest, traceDisplayFrame_emitsValidTracePacket) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t displayFrameToken1 = mTokenManager->generateTokenForPredictions({10, 25, 30});
    int64_t displayFrameToken2 = mTokenManager->generateTokenForPredictions({40, 50, 60});

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(displayFrameToken1, 20, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(26, presentFence1);
    presentFence1->signalForTest(31);

    int64_t traceCookie = snoopCurrentTraceCookie();
    ProtoExpectedDisplayFrameStart protoExpectedDisplayFrameStart;
    protoExpectedDisplayFrameStart.set_cookie(traceCookie + 1);
    protoExpectedDisplayFrameStart.set_token(displayFrameToken1);
    protoExpectedDisplayFrameStart.set_pid(kSurfaceFlingerPid);

    ProtoFrameEnd protoExpectedDisplayFrameEnd;
    protoExpectedDisplayFrameEnd.set_cookie(traceCookie + 1);

    ProtoActualDisplayFrameStart protoActualDisplayFrameStart;
    protoActualDisplayFrameStart.set_cookie(traceCookie + 2);
    protoActualDisplayFrameStart.set_token(displayFrameToken1);
    protoActualDisplayFrameStart.set_pid(kSurfaceFlingerPid);
    protoActualDisplayFrameStart.set_present_type(
            ProtoPresentType(FrameTimelineEvent::PRESENT_ON_TIME));
    protoActualDisplayFrameStart.set_on_time_finish(true);
    protoActualDisplayFrameStart.set_gpu_composition(false);
    protoActualDisplayFrameStart.set_jank_type(ProtoJankType(FrameTimelineEvent::JANK_NONE));

    ProtoFrameEnd protoActualDisplayFrameEnd;
    protoActualDisplayFrameEnd.set_cookie(traceCookie + 2);

    // Trigger a flushPresentFence (which will call trace function) by calling setSfPresent for the
    // next frame
    mFrameTimeline->setSfWakeUp(displayFrameToken2, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);
    presentFence2->signalForTest(55);

    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 4u);

    // Packet - 0 : ExpectedDisplayFrameStart
    const auto& packet0 = packets[0];
    ASSERT_TRUE(packet0.has_timestamp());
    EXPECT_EQ(packet0.timestamp(), 10u);
    ASSERT_TRUE(packet0.has_frame_timeline_event());

    const auto& event0 = packet0.frame_timeline_event();
    ASSERT_TRUE(event0.has_expected_display_frame_start());
    const auto& expectedDisplayFrameStart = event0.expected_display_frame_start();
    validateTraceEvent(expectedDisplayFrameStart, protoExpectedDisplayFrameStart);

    // Packet - 1 : FrameEnd (ExpectedDisplayFrame)
    const auto& packet1 = packets[1];
    ASSERT_TRUE(packet1.has_timestamp());
    EXPECT_EQ(packet1.timestamp(), 25u);
    ASSERT_TRUE(packet1.has_frame_timeline_event());

    const auto& event1 = packet1.frame_timeline_event();
    ASSERT_TRUE(event1.has_frame_end());
    const auto& expectedDisplayFrameEnd = event1.frame_end();
    validateTraceEvent(expectedDisplayFrameEnd, protoExpectedDisplayFrameEnd);

    // Packet - 2 : ActualDisplayFrameStart
    const auto& packet2 = packets[2];
    ASSERT_TRUE(packet2.has_timestamp());
    EXPECT_EQ(packet2.timestamp(), 20u);
    ASSERT_TRUE(packet2.has_frame_timeline_event());

    const auto& event2 = packet2.frame_timeline_event();
    ASSERT_TRUE(event2.has_actual_display_frame_start());
    const auto& actualDisplayFrameStart = event2.actual_display_frame_start();
    validateTraceEvent(actualDisplayFrameStart, protoActualDisplayFrameStart);

    // Packet - 3 : FrameEnd (ActualDisplayFrame)
    const auto& packet3 = packets[3];
    ASSERT_TRUE(packet3.has_timestamp());
    EXPECT_EQ(packet3.timestamp(), 26u);
    ASSERT_TRUE(packet3.has_frame_timeline_event());

    const auto& event3 = packet3.frame_timeline_event();
    ASSERT_TRUE(event3.has_frame_end());
    const auto& actualDisplayFrameEnd = event3.frame_end();
    validateTraceEvent(actualDisplayFrameEnd, protoActualDisplayFrameEnd);
}

TEST_F(FrameTimelineTest, traceSurfaceFrame_emitsValidTracePacket) {
    auto tracingSession = getTracingSessionForTest();
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions({10, 25, 40});
    int64_t displayFrameToken1 = mTokenManager->generateTokenForPredictions({30, 35, 40});
    int64_t displayFrameToken2 = mTokenManager->generateTokenForPredictions({40, 50, 60});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setActualStartTime(0);
    surfaceFrame1->setActualQueueTime(15);
    surfaceFrame1->setAcquireFenceTime(20);

    // First 2 cookies will be used by the DisplayFrame
    int64_t traceCookie = snoopCurrentTraceCookie() + 2;

    ProtoExpectedSurfaceFrameStart protoExpectedSurfaceFrameStart;
    protoExpectedSurfaceFrameStart.set_cookie(traceCookie + 1);
    protoExpectedSurfaceFrameStart.set_token(surfaceFrameToken);
    protoExpectedSurfaceFrameStart.set_display_frame_token(displayFrameToken1);
    protoExpectedSurfaceFrameStart.set_pid(sPidOne);
    protoExpectedSurfaceFrameStart.set_layer_name(sLayerNameOne);

    ProtoFrameEnd protoExpectedSurfaceFrameEnd;
    protoExpectedSurfaceFrameEnd.set_cookie(traceCookie + 1);

    ProtoActualSurfaceFrameStart protoActualSurfaceFrameStart;
    protoActualSurfaceFrameStart.set_cookie(traceCookie + 2);
    protoActualSurfaceFrameStart.set_token(surfaceFrameToken);
    protoActualSurfaceFrameStart.set_display_frame_token(displayFrameToken1);
    protoActualSurfaceFrameStart.set_pid(sPidOne);
    protoActualSurfaceFrameStart.set_layer_name(sLayerNameOne);
    protoActualSurfaceFrameStart.set_present_type(
            ProtoPresentType(FrameTimelineEvent::PRESENT_ON_TIME));
    protoActualSurfaceFrameStart.set_on_time_finish(true);
    protoActualSurfaceFrameStart.set_gpu_composition(false);
    protoActualSurfaceFrameStart.set_jank_type(ProtoJankType(FrameTimelineEvent::JANK_NONE));

    ProtoFrameEnd protoActualSurfaceFrameEnd;
    protoActualSurfaceFrameEnd.set_cookie(traceCookie + 2);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(displayFrameToken1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(26, presentFence1);
    presentFence1->signalForTest(40);

    // Trigger a flushPresentFence (which will call trace function) by calling setSfPresent for the
    // next frame
    mFrameTimeline->setSfWakeUp(displayFrameToken2, 50, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(55, presentFence2);
    presentFence2->signalForTest(55);

    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 8u);

    // Packet - 4 : ExpectedSurfaceFrameStart
    const auto& packet4 = packets[4];
    ASSERT_TRUE(packet4.has_timestamp());
    EXPECT_EQ(packet4.timestamp(), 10u);
    ASSERT_TRUE(packet4.has_frame_timeline_event());

    const auto& event4 = packet4.frame_timeline_event();
    ASSERT_TRUE(event4.has_expected_surface_frame_start());
    const auto& expectedSurfaceFrameStart = event4.expected_surface_frame_start();
    validateTraceEvent(expectedSurfaceFrameStart, protoExpectedSurfaceFrameStart);

    // Packet - 5 : FrameEnd (ExpectedSurfaceFrame)
    const auto& packet5 = packets[5];
    ASSERT_TRUE(packet5.has_timestamp());
    EXPECT_EQ(packet5.timestamp(), 25u);
    ASSERT_TRUE(packet5.has_frame_timeline_event());

    const auto& event5 = packet5.frame_timeline_event();
    ASSERT_TRUE(event5.has_frame_end());
    const auto& expectedSurfaceFrameEnd = event5.frame_end();
    validateTraceEvent(expectedSurfaceFrameEnd, protoExpectedSurfaceFrameEnd);

    // Packet - 6 : ActualSurfaceFrameStart
    const auto& packet6 = packets[6];
    ASSERT_TRUE(packet6.has_timestamp());
    EXPECT_EQ(packet6.timestamp(), 10u);
    ASSERT_TRUE(packet6.has_frame_timeline_event());

    const auto& event6 = packet6.frame_timeline_event();
    ASSERT_TRUE(event6.has_actual_surface_frame_start());
    const auto& actualSurfaceFrameStart = event6.actual_surface_frame_start();
    validateTraceEvent(actualSurfaceFrameStart, protoActualSurfaceFrameStart);

    // Packet - 7 : FrameEnd (ActualSurfaceFrame)
    const auto& packet7 = packets[7];
    ASSERT_TRUE(packet7.has_timestamp());
    EXPECT_EQ(packet7.timestamp(), 20u);
    ASSERT_TRUE(packet7.has_frame_timeline_event());

    const auto& event7 = packet7.frame_timeline_event();
    ASSERT_TRUE(event7.has_frame_end());
    const auto& actualSurfaceFrameEnd = event7.frame_end();
    validateTraceEvent(actualSurfaceFrameEnd, protoActualSurfaceFrameEnd);
}

// Tests for Jank classification
TEST_F(FrameTimelineTest, jankClassification_presentOnTimeDoesNotClassify) {
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 30});
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken1, 22, Fps::fromPeriodNsecs(11));
    surfaceFrame->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    auto& presentedSurfaceFrame = getSurfaceFrame(0, 0);
    presentFence1->signalForTest(29);

    // Fences haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);
    EXPECT_EQ(presentedSurfaceFrame.getActuals().presentTime, 0);

    addEmptyDisplayFrame();
    displayFrame = getDisplayFrame(0);

    // Fences have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 29);
    EXPECT_EQ(presentedSurfaceFrame.getActuals().presentTime, 29);
    EXPECT_EQ(displayFrame->getFramePresentMetadata(), FramePresentMetadata::OnTimePresent);
    EXPECT_EQ(displayFrame->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame->getJankType(), JankType::None);
}

TEST_F(FrameTimelineTest, jankClassification_displayFrameOnTimeFinishEarlyPresent) {
    Fps vsyncRate = Fps::fromPeriodNsecs(11);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 56, 70});
    mFrameTimeline->setSfWakeUp(sfToken1, 22, vsyncRate);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    presentFence1->signalForTest(30);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, vsyncRate);
    mFrameTimeline->setSfPresent(56, presentFence2);
    displayFrame = getDisplayFrame(0);

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 30);
    EXPECT_EQ(displayFrame->getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(displayFrame->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame->getJankType(), JankType::SurfaceFlingerScheduling);

    // Fences for the second frame haven't been flushed yet, so it should be 0
    auto displayFrame2 = getDisplayFrame(1);
    presentFence2->signalForTest(65);
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 0);
    addEmptyDisplayFrame();
    displayFrame2 = getDisplayFrame(1);

    // Fences for the second frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 65);
    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::PredictionError);
}

TEST_F(FrameTimelineTest, jankClassification_displayFrameOnTimeFinishLatePresent) {
    Fps vsyncRate = Fps::fromPeriodNsecs(11);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 56, 70});
    mFrameTimeline->setSfWakeUp(sfToken1, 22, vsyncRate);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    presentFence1->signalForTest(50);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, vsyncRate);
    mFrameTimeline->setSfPresent(56, presentFence2);
    displayFrame = getDisplayFrame(0);

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 50);
    EXPECT_EQ(displayFrame->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame->getJankType(), JankType::DisplayHAL);

    // Fences for the second frame haven't been flushed yet, so it should be 0
    auto displayFrame2 = getDisplayFrame(1);
    presentFence2->signalForTest(75);
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 0);

    addEmptyDisplayFrame();
    displayFrame2 = getDisplayFrame(1);

    // Fences for the second frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 75);
    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::PredictionError);
}

TEST_F(FrameTimelineTest, jankClassification_displayFrameLateFinishEarlyPresent) {
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({12, 18, 40});
    mFrameTimeline->setSfWakeUp(sfToken1, 12, Fps::fromPeriodNsecs(11));

    mFrameTimeline->setSfPresent(22, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    presentFence1->signalForTest(28);

    // Fences haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);

    addEmptyDisplayFrame();
    displayFrame = getDisplayFrame(0);

    // Fences have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 28);
    EXPECT_EQ(displayFrame->getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(displayFrame->getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(displayFrame->getJankType(), JankType::SurfaceFlingerScheduling);
}

TEST_F(FrameTimelineTest, jankClassification_displayFrameLateFinishLatePresent) {
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 40});
    mFrameTimeline->setSfWakeUp(sfToken1, 12, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(36, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    presentFence1->signalForTest(52);

    // Fences haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);

    addEmptyDisplayFrame();
    displayFrame = getDisplayFrame(0);

    // Fences have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 52);
    EXPECT_EQ(displayFrame->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame->getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(displayFrame->getJankType(), JankType::SurfaceFlingerCpuDeadlineMissed);
}

TEST_F(FrameTimelineTest, jankClassification_surfaceFrameOnTimeFinishEarlyPresent) {
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 56, 70});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 16, 40});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({25, 36, 70});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(16);
    mFrameTimeline->setSfWakeUp(sfToken1, 22, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame1 = getDisplayFrame(0);
    auto& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    presentFence1->signalForTest(30);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 0);
    auto actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken2, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(36);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, Fps::fromPeriodNsecs(11));
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(56, presentFence2);
    auto displayFrame2 = getDisplayFrame(1);
    auto& presentedSurfaceFrame2 = getSurfaceFrame(1, 0);

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 30);
    EXPECT_EQ(displayFrame1->getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(displayFrame1->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame1->getJankType(), JankType::SurfaceFlingerScheduling);

    actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 30);
    EXPECT_EQ(presentedSurfaceFrame1.getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(presentedSurfaceFrame1.getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(presentedSurfaceFrame1.getJankType(), JankType::SurfaceFlingerScheduling);

    // Fences for the second frame haven't been flushed yet, so it should be 0
    presentFence2->signalForTest(65);
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 0);
    auto actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 0);

    ::testing::Mock::VerifyAndClearExpectations(mTimeStats.get());

    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{Fps::fromPeriodNsecs(11), std::nullopt, sUidOne,
                                                   sLayerNameOne, JankType::PredictionError, 0, 5,
                                                   0}));

    addEmptyDisplayFrame();

    // Fences for the second frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 65);
    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::PredictionError);

    actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 65);
    EXPECT_EQ(presentedSurfaceFrame2.getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(presentedSurfaceFrame2.getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(presentedSurfaceFrame2.getJankType(), JankType::PredictionError);
}

TEST_F(FrameTimelineTest, jankClassification_surfaceFrameOnTimeFinishLatePresent) {
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 56, 70});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 16, 40});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({25, 36, 70});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(16);
    mFrameTimeline->setSfWakeUp(sfToken1, 22, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame1 = getDisplayFrame(0);
    auto& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    presentFence1->signalForTest(50);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 0);
    auto actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken2, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(36);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, Fps::fromPeriodNsecs(11));
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(56, presentFence2);
    auto displayFrame2 = getDisplayFrame(1);
    auto& presentedSurfaceFrame2 = getSurfaceFrame(1, 0);

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 50);
    EXPECT_EQ(displayFrame1->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame1->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame1->getJankType(), JankType::DisplayHAL);

    actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 50);
    EXPECT_EQ(presentedSurfaceFrame1.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame1.getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(presentedSurfaceFrame1.getJankType(), JankType::DisplayHAL);

    // Fences for the second frame haven't been flushed yet, so it should be 0
    presentFence2->signalForTest(86);
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 0);
    auto actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 0);

    ::testing::Mock::VerifyAndClearExpectations(mTimeStats.get());

    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{Fps::fromPeriodNsecs(11), std::nullopt, sUidOne,
                                                   sLayerNameOne, JankType::PredictionError, 0, 5,
                                                   0}));

    addEmptyDisplayFrame();

    // Fences for the second frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 86);
    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::PredictionError);

    actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 86);
    EXPECT_EQ(presentedSurfaceFrame2.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame2.getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(presentedSurfaceFrame2.getJankType(), JankType::PredictionError);
}

TEST_F(FrameTimelineTest, jankClassification_surfaceFrameLateFinishEarlyPresent) {
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));

    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({42, 46, 50});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 26, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(40);
    mFrameTimeline->setSfWakeUp(sfToken1, 42, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(46, presentFence1);
    auto displayFrame1 = getDisplayFrame(0);
    auto& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    presentFence1->signalForTest(50);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 0);
    auto actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 0);

    addEmptyDisplayFrame();

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 50);
    EXPECT_EQ(displayFrame1->getFramePresentMetadata(), FramePresentMetadata::OnTimePresent);
    EXPECT_EQ(displayFrame1->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame1->getJankType(), JankType::None);

    actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 50);
    EXPECT_EQ(presentedSurfaceFrame1.getFramePresentMetadata(), FramePresentMetadata::EarlyPresent);
    EXPECT_EQ(presentedSurfaceFrame1.getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(presentedSurfaceFrame1.getJankType(), JankType::Unknown);
}

TEST_F(FrameTimelineTest, jankClassification_surfaceFrameLateFinishLatePresent) {
    // First frame - DisplayFrame is not janky. This should classify the SurfaceFrame as
    // AppDeadlineMissed. Second frame - DisplayFrame is janky. This should propagate DisplayFrame's
    // jank to the SurfaceFrame.

    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_)).Times(2);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({32, 36, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({42, 46, 50});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 16, 30});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({25, 36, 50});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(26);
    mFrameTimeline->setSfWakeUp(sfToken1, 32, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(36, presentFence1);
    auto displayFrame1 = getDisplayFrame(0);
    auto& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    presentFence1->signalForTest(40);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 0);
    auto actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken2, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(40);
    mFrameTimeline->setSfWakeUp(sfToken2, 43, Fps::fromPeriodNsecs(11));
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(56, presentFence2);
    auto displayFrame2 = getDisplayFrame(1);
    auto& presentedSurfaceFrame2 = getSurfaceFrame(1, 0);

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 40);
    EXPECT_EQ(displayFrame1->getFramePresentMetadata(), FramePresentMetadata::OnTimePresent);
    EXPECT_EQ(displayFrame1->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame1->getJankType(), JankType::None);

    actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 40);
    EXPECT_EQ(presentedSurfaceFrame1.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame1.getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(presentedSurfaceFrame1.getJankType(), JankType::AppDeadlineMissed);

    // Fences for the second frame haven't been flushed yet, so it should be 0
    presentFence2->signalForTest(60);
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 0);
    auto actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 0);

    addEmptyDisplayFrame();

    // Fences for the second frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 60);
    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::SurfaceFlingerCpuDeadlineMissed);

    actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 60);
    EXPECT_EQ(presentedSurfaceFrame2.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame2.getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(presentedSurfaceFrame2.getJankType(), JankType::SurfaceFlingerCpuDeadlineMissed);
}

TEST_F(FrameTimelineTest, jankClassification_multiJankBufferStuffingAndAppDeadlineMissed) {
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_)).Times(2);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({40, 50, 60});

    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 56, 60});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({112, 116, 120});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(50);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, Fps::fromPeriodNsecs(30));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(56, presentFence1);
    auto displayFrame1 = getDisplayFrame(0);
    auto& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    presentFence1->signalForTest(60);

    // Fences for the first frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 0);
    auto actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken2, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerNameOne, sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(84);
    mFrameTimeline->setSfWakeUp(sfToken2, 112, Fps::fromPeriodNsecs(30));
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented, 54);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(116, presentFence2);
    auto displayFrame2 = getDisplayFrame(1);
    auto& presentedSurfaceFrame2 = getSurfaceFrame(1, 0);
    presentFence2->signalForTest(120);

    // Fences for the first frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame1->getActuals().presentTime, 60);
    actuals1 = presentedSurfaceFrame1.getActuals();
    EXPECT_EQ(actuals1.endTime, 50);
    EXPECT_EQ(actuals1.presentTime, 60);

    EXPECT_EQ(displayFrame1->getFramePresentMetadata(), FramePresentMetadata::OnTimePresent);
    EXPECT_EQ(displayFrame1->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame1->getJankType(), JankType::None);

    EXPECT_EQ(presentedSurfaceFrame1.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame1.getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(presentedSurfaceFrame1.getJankType(), JankType::AppDeadlineMissed);

    // Fences for the second frame haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 0);
    auto actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 0);

    addEmptyDisplayFrame();

    // Fences for the second frame have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 120);
    actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 120);

    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::OnTimePresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::None);

    EXPECT_EQ(presentedSurfaceFrame2.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame2.getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(presentedSurfaceFrame2.getJankType(),
              JankType::AppDeadlineMissed | JankType::BufferStuffing);
}
} // namespace android::frametimeline
