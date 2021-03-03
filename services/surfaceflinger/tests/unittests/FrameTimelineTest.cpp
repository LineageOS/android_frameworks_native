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
                                                               kTestThresholds, kHwcDuration);
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
        // Trigger a flushPresentFence by calling setSfPresent for the next frame
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
    static constexpr nsecs_t kHwcDuration = std::chrono::nanoseconds(3ns).count();
};

static const std::string sLayerNameOne = "layer1";
static const std::string sLayerNameTwo = "layer2";
static constexpr const uid_t sUidOne = 0;
static constexpr pid_t sPidOne = 10;
static constexpr pid_t sPidTwo = 20;
static constexpr int32_t sInputEventId = 5;
static constexpr int32_t sLayerIdOne = 1;
static constexpr int32_t sLayerIdTwo = 2;

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
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerIdOne,
                                                       sLayerNameOne, sLayerNameOne);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({}, sPidTwo, sUidOne, sLayerIdOne,
                                                       sLayerNameOne, sLayerNameOne);
    EXPECT_EQ(surfaceFrame1->getOwnerPid(), sPidOne);
    EXPECT_EQ(surfaceFrame2->getOwnerPid(), sPidTwo);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_noToken) {
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerIdOne,
                                                       sLayerNameOne, sLayerNameOne);
    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::None);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_expiredToken) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({0, 0, 0});
    flushTokens(systemTime() + maxTokenRetentionTime);
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);

    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::Expired);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_validToken) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);

    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::Valid);
    EXPECT_EQ(compareTimelineItems(surfaceFrame->getPredictions(), TimelineItem(10, 20, 30)), true);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_validInputEventId) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    constexpr int32_t inputEventId = 1;
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({token1, inputEventId}, sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);

    EXPECT_EQ(inputEventId, surfaceFrame->getInputEventId());
}

TEST_F(FrameTimelineTest, presentFenceSignaled_droppedFramesNotUpdated) {
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setDropTime(12);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    addEmptyDisplayFrame();

    auto& droppedSurfaceFrame = getSurfaceFrame(0, 0);
    EXPECT_EQ(droppedSurfaceFrame.getPresentState(), SurfaceFrame::PresentState::Dropped);
    EXPECT_EQ(0u, droppedSurfaceFrame.getActuals().endTime);
    EXPECT_EQ(12u, droppedSurfaceFrame.getDropTime());
    EXPECT_EQ(droppedSurfaceFrame.getActuals().presentTime, 0);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_presentedFramesUpdated) {
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_)).Times(2);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 30});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdTwo, sLayerNameTwo,
                                                       sLayerNameTwo);
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

    addEmptyDisplayFrame();

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
                                                           sPidOne, sUidOne, sLayerIdOne,
                                                           sLayerNameOne, sLayerNameOne);
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
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
    auto surfaceFrame = mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, 0, sLayerIdOne,
                                                                   "acquireFenceAfterQueue",
                                                                   "acquireFenceAfterQueue");
    surfaceFrame->setActualQueueTime(123);
    surfaceFrame->setAcquireFenceTime(456);
    EXPECT_EQ(surfaceFrame->getActuals().endTime, 456);
}

TEST_F(FrameTimelineTest, surfaceFrameEndTimeAcquireFenceBeforeQueue) {
    auto surfaceFrame = mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, 0, sLayerIdOne,
                                                                   "acquireFenceAfterQueue",
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
                mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerIdOne,
                                                           sLayerNameOne, sLayerNameOne);
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
                mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerIdOne,
                                                           sLayerNameOne, sLayerNameOne);
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
                mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerIdOne,
                                                           sLayerNameOne, sLayerNameOne);
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
    Fps refreshRate = Fps::fromPeriodNsecs(11);
    // Deadline delta is 2ms because, sf's adjusted deadline is 60 - composerTime(3) = 57ms.
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                   sLayerNameOne,
                                                   JankType::SurfaceFlingerCpuDeadlineMissed, 2, 10,
                                                   0}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 60, 60});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, refreshRate);
    surfaceFrame1->setAcquireFenceTime(20);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(70);

    mFrameTimeline->setSfPresent(59, presentFence1);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsDisplayMiss) {
    Fps refreshRate = Fps::fromPeriodNsecs(30);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                                sLayerNameOne, JankType::DisplayHAL,
                                                                -1, 0, 0}));

    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 60, 60});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, refreshRate);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    surfaceFrame1->setAcquireFenceTime(20);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(90);
    mFrameTimeline->setSfPresent(56, presentFence1);
    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::DisplayHAL);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppMiss) {
    Fps refreshRate = Fps(11.0);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                                sLayerNameOne,
                                                                JankType::AppDeadlineMissed, -1, 0,
                                                                25}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({82, 90, 90});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(45);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(90);
    mFrameTimeline->setSfPresent(86, presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::AppDeadlineMissed);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsSfScheduling) {
    Fps refreshRate = Fps::fromPeriodNsecs(32);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                                sLayerNameOne,
                                                                JankType::SurfaceFlingerScheduling,
                                                                -1, 0, -10}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({40, 60, 92});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 60, 60});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(50);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(60);
    mFrameTimeline->setSfPresent(56, presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::SurfaceFlingerScheduling);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsSfPredictionError) {
    Fps refreshRate = Fps::fromPeriodNsecs(16);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                                sLayerNameOne,
                                                                JankType::PredictionError, -1, 5,
                                                                0}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({30, 40, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 60, 60});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(40);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(65);
    mFrameTimeline->setSfPresent(56, presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::PredictionError);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppBufferStuffing) {
    Fps refreshRate = Fps::fromPeriodNsecs(32);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(TimeStats::JankyFramesInfo{refreshRate, std::nullopt, sUidOne,
                                                                sLayerNameOne,
                                                                JankType::BufferStuffing, -1, 0,
                                                                0}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({30, 40, 58});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({82, 90, 90});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(40);
    mFrameTimeline->setSfWakeUp(sfToken1, 82, refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented,
                                   /*previousLatchTime*/ 56);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(90);
    mFrameTimeline->setSfPresent(86, presentFence1);

    EXPECT_EQ(surfaceFrame1->getJankType(), JankType::BufferStuffing);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppMissWithRenderRate) {
    Fps refreshRate = Fps::fromPeriodNsecs(11);
    Fps renderRate = Fps::fromPeriodNsecs(30);
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(
                        TimeStats::JankyFramesInfo{refreshRate, renderRate, sUidOne, sLayerNameOne,
                                                   JankType::AppDeadlineMissed, -1, 0, 25}));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({82, 90, 90});

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(45);
    mFrameTimeline->setSfWakeUp(sfToken1, 52, refreshRate);

    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    surfaceFrame1->setRenderRate(renderRate);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(90);
    mFrameTimeline->setSfPresent(86, presentFence1);

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
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    addEmptyDisplayFrame();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 0u);
}

TEST_F(FrameTimelineTest, tracing_sanityTest) {
    auto tracingSession = getTracingSessionForTest();
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t token2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({token1, sInputEventId}, sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token2, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    addEmptyDisplayFrame();
    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // Display Frame 1 has 8 packets - 4 from DisplayFrame and 4 from SurfaceFrame.
    EXPECT_EQ(packets.size(), 8u);
}

TEST_F(FrameTimelineTest, traceDisplayFrame_invalidTokenDoesNotEmitTracePacket) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(-1, 20, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    addEmptyDisplayFrame();
    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 0u);
}

TEST_F(FrameTimelineTest, traceSurfaceFrame_invalidTokenDoesNotEmitTracePacket) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({}, sPidOne, sUidOne, sLayerIdOne,
                                                       sLayerNameOne, sLayerNameOne);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    addEmptyDisplayFrame();
    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // Display Frame 1 has 4 packets (SurfaceFrame shouldn't be traced since it has an invalid
    // token).
    EXPECT_EQ(packets.size(), 4u);
}

ProtoExpectedDisplayFrameStart createProtoExpectedDisplayFrameStart(int64_t cookie, int64_t token,
                                                                    pid_t pid) {
    ProtoExpectedDisplayFrameStart proto;
    proto.set_cookie(cookie);
    proto.set_token(token);
    proto.set_pid(pid);
    return proto;
}

ProtoActualDisplayFrameStart createProtoActualDisplayFrameStart(
        int64_t cookie, int64_t token, pid_t pid, ProtoPresentType presentType, bool onTimeFinish,
        bool gpuComposition, ProtoJankType jankType) {
    ProtoActualDisplayFrameStart proto;
    proto.set_cookie(cookie);
    proto.set_token(token);
    proto.set_pid(pid);
    proto.set_present_type(presentType);
    proto.set_on_time_finish(onTimeFinish);
    proto.set_gpu_composition(gpuComposition);
    proto.set_jank_type(jankType);
    return proto;
}

ProtoExpectedSurfaceFrameStart createProtoExpectedSurfaceFrameStart(int64_t cookie, int64_t token,
                                                                    int64_t displayFrameToken,
                                                                    pid_t pid,
                                                                    std::string layerName) {
    ProtoExpectedSurfaceFrameStart proto;
    proto.set_cookie(cookie);
    proto.set_token(token);
    proto.set_display_frame_token(displayFrameToken);
    proto.set_pid(pid);
    proto.set_layer_name(layerName);
    return proto;
}

ProtoActualSurfaceFrameStart createProtoActualSurfaceFrameStart(
        int64_t cookie, int64_t token, int64_t displayFrameToken, pid_t pid, std::string layerName,
        ProtoPresentType presentType, bool onTimeFinish, bool gpuComposition,
        ProtoJankType jankType) {
    ProtoActualSurfaceFrameStart proto;
    proto.set_cookie(cookie);
    proto.set_token(token);
    proto.set_display_frame_token(displayFrameToken);
    proto.set_pid(pid);
    proto.set_layer_name(layerName);
    proto.set_present_type(presentType);
    proto.set_on_time_finish(onTimeFinish);
    proto.set_gpu_composition(gpuComposition);
    proto.set_jank_type(jankType);
    return proto;
}

ProtoFrameEnd createProtoFrameEnd(int64_t cookie) {
    ProtoFrameEnd proto;
    proto.set_cookie(cookie);
    return proto;
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

    tracingSession->StartBlocking();
    int64_t displayFrameToken1 = mTokenManager->generateTokenForPredictions({10, 30, 30});

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(displayFrameToken1, 20, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(26, presentFence1);
    presentFence1->signalForTest(31);

    int64_t traceCookie = snoopCurrentTraceCookie();
    auto protoExpectedDisplayFrameStart =
            createProtoExpectedDisplayFrameStart(traceCookie + 1, displayFrameToken1,
                                                 kSurfaceFlingerPid);
    auto protoExpectedDisplayFrameEnd = createProtoFrameEnd(traceCookie + 1);
    auto protoActualDisplayFrameStart =
            createProtoActualDisplayFrameStart(traceCookie + 2, displayFrameToken1,
                                               kSurfaceFlingerPid,
                                               FrameTimelineEvent::PRESENT_ON_TIME, true, false,
                                               FrameTimelineEvent::JANK_NONE);
    auto protoActualDisplayFrameEnd = createProtoFrameEnd(traceCookie + 2);

    addEmptyDisplayFrame();
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
    EXPECT_EQ(packet1.timestamp(), 30u);
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
    EXPECT_EQ(packet3.timestamp(), 31u);
    ASSERT_TRUE(packet3.has_frame_timeline_event());

    const auto& event3 = packet3.frame_timeline_event();
    ASSERT_TRUE(event3.has_frame_end());
    const auto& actualDisplayFrameEnd = event3.frame_end();
    validateTraceEvent(actualDisplayFrameEnd, protoActualDisplayFrameEnd);
}

TEST_F(FrameTimelineTest, traceDisplayFrame_predictionExpiredDoesNotTraceExpectedTimeline) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    int64_t displayFrameToken1 = mTokenManager->generateTokenForPredictions({10, 25, 30});
    // Flush the token so that it would expire
    flushTokens(systemTime() + maxTokenRetentionTime);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(displayFrameToken1, 20, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(26, presentFence1);
    presentFence1->signalForTest(31);

    int64_t traceCookie = snoopCurrentTraceCookie();

    auto protoActualDisplayFrameStart =
            createProtoActualDisplayFrameStart(traceCookie + 1, displayFrameToken1,
                                               kSurfaceFlingerPid,
                                               FrameTimelineEvent::PRESENT_UNSPECIFIED, false,
                                               false, FrameTimelineEvent::JANK_UNKNOWN);
    auto protoActualDisplayFrameEnd = createProtoFrameEnd(traceCookie + 1);

    addEmptyDisplayFrame();
    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // Only actual timeline packets should be in the trace
    EXPECT_EQ(packets.size(), 2u);

    // Packet - 0 : ActualDisplayFrameStart
    const auto& packet0 = packets[0];
    ASSERT_TRUE(packet0.has_timestamp());
    EXPECT_EQ(packet0.timestamp(), 20u);
    ASSERT_TRUE(packet0.has_frame_timeline_event());

    const auto& event0 = packet0.frame_timeline_event();
    ASSERT_TRUE(event0.has_actual_display_frame_start());
    const auto& actualDisplayFrameStart = event0.actual_display_frame_start();
    validateTraceEvent(actualDisplayFrameStart, protoActualDisplayFrameStart);

    // Packet - 1 : FrameEnd (ActualDisplayFrame)
    const auto& packet1 = packets[1];
    ASSERT_TRUE(packet1.has_timestamp());
    EXPECT_EQ(packet1.timestamp(), 31u);
    ASSERT_TRUE(packet1.has_frame_timeline_event());

    const auto& event1 = packet1.frame_timeline_event();
    ASSERT_TRUE(event1.has_frame_end());
    const auto& actualDisplayFrameEnd = event1.frame_end();
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

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setActualQueueTime(10);
    surfaceFrame1->setDropTime(15);

    surfaceFrame2->setActualQueueTime(15);
    surfaceFrame2->setAcquireFenceTime(20);

    // First 2 cookies will be used by the DisplayFrame
    int64_t traceCookie = snoopCurrentTraceCookie() + 2;

    auto protoDroppedSurfaceFrameExpectedStart =
            createProtoExpectedSurfaceFrameStart(traceCookie + 1, surfaceFrameToken,
                                                 displayFrameToken1, sPidOne, sLayerNameOne);
    auto protoDroppedSurfaceFrameExpectedEnd = createProtoFrameEnd(traceCookie + 1);
    auto protoDroppedSurfaceFrameActualStart =
            createProtoActualSurfaceFrameStart(traceCookie + 2, surfaceFrameToken,
                                               displayFrameToken1, sPidOne, sLayerNameOne,
                                               FrameTimelineEvent::PRESENT_DROPPED, false, false,
                                               FrameTimelineEvent::JANK_NONE);
    auto protoDroppedSurfaceFrameActualEnd = createProtoFrameEnd(traceCookie + 2);

    auto protoPresentedSurfaceFrameExpectedStart =
            createProtoExpectedSurfaceFrameStart(traceCookie + 3, surfaceFrameToken,
                                                 displayFrameToken1, sPidOne, sLayerNameOne);
    auto protoPresentedSurfaceFrameExpectedEnd = createProtoFrameEnd(traceCookie + 3);
    auto protoPresentedSurfaceFrameActualStart =
            createProtoActualSurfaceFrameStart(traceCookie + 4, surfaceFrameToken,
                                               displayFrameToken1, sPidOne, sLayerNameOne,
                                               FrameTimelineEvent::PRESENT_ON_TIME, true, false,
                                               FrameTimelineEvent::JANK_NONE);
    auto protoPresentedSurfaceFrameActualEnd = createProtoFrameEnd(traceCookie + 4);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(displayFrameToken1, 20, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Dropped);
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(26, presentFence1);
    presentFence1->signalForTest(40);

    addEmptyDisplayFrame();
    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // 4 DisplayFrame + 4 DroppedSurfaceFrame + 4 PresentedSurfaceFrame
    EXPECT_EQ(packets.size(), 12u);

    // Packet - 4 : ExpectedSurfaceFrameStart1
    const auto& packet4 = packets[4];
    ASSERT_TRUE(packet4.has_timestamp());
    EXPECT_EQ(packet4.timestamp(), 10u);
    ASSERT_TRUE(packet4.has_frame_timeline_event());

    const auto& event4 = packet4.frame_timeline_event();
    ASSERT_TRUE(event4.has_expected_surface_frame_start());
    const auto& expectedSurfaceFrameStart1 = event4.expected_surface_frame_start();
    validateTraceEvent(expectedSurfaceFrameStart1, protoDroppedSurfaceFrameExpectedStart);

    // Packet - 5 : FrameEnd (ExpectedSurfaceFrame1)
    const auto& packet5 = packets[5];
    ASSERT_TRUE(packet5.has_timestamp());
    EXPECT_EQ(packet5.timestamp(), 25u);
    ASSERT_TRUE(packet5.has_frame_timeline_event());

    const auto& event5 = packet5.frame_timeline_event();
    ASSERT_TRUE(event5.has_frame_end());
    const auto& expectedSurfaceFrameEnd1 = event5.frame_end();
    validateTraceEvent(expectedSurfaceFrameEnd1, protoDroppedSurfaceFrameExpectedEnd);

    // Packet - 6 : ActualSurfaceFrameStart1
    const auto& packet6 = packets[6];
    ASSERT_TRUE(packet6.has_timestamp());
    EXPECT_EQ(packet6.timestamp(), 10u);
    ASSERT_TRUE(packet6.has_frame_timeline_event());

    const auto& event6 = packet6.frame_timeline_event();
    ASSERT_TRUE(event6.has_actual_surface_frame_start());
    const auto& actualSurfaceFrameStart1 = event6.actual_surface_frame_start();
    validateTraceEvent(actualSurfaceFrameStart1, protoDroppedSurfaceFrameActualStart);

    // Packet - 7 : FrameEnd (ActualSurfaceFrame1)
    const auto& packet7 = packets[7];
    ASSERT_TRUE(packet7.has_timestamp());
    EXPECT_EQ(packet7.timestamp(), 15u);
    ASSERT_TRUE(packet7.has_frame_timeline_event());

    const auto& event7 = packet7.frame_timeline_event();
    ASSERT_TRUE(event7.has_frame_end());
    const auto& actualSurfaceFrameEnd1 = event7.frame_end();
    validateTraceEvent(actualSurfaceFrameEnd1, protoDroppedSurfaceFrameActualEnd);

    // Packet - 8 : ExpectedSurfaceFrameStart2
    const auto& packet8 = packets[8];
    ASSERT_TRUE(packet8.has_timestamp());
    EXPECT_EQ(packet8.timestamp(), 10u);
    ASSERT_TRUE(packet8.has_frame_timeline_event());

    const auto& event8 = packet8.frame_timeline_event();
    ASSERT_TRUE(event8.has_expected_surface_frame_start());
    const auto& expectedSurfaceFrameStart2 = event8.expected_surface_frame_start();
    validateTraceEvent(expectedSurfaceFrameStart2, protoPresentedSurfaceFrameExpectedStart);

    // Packet - 9 : FrameEnd (ExpectedSurfaceFrame2)
    const auto& packet9 = packets[9];
    ASSERT_TRUE(packet9.has_timestamp());
    EXPECT_EQ(packet9.timestamp(), 25u);
    ASSERT_TRUE(packet9.has_frame_timeline_event());

    const auto& event9 = packet9.frame_timeline_event();
    ASSERT_TRUE(event9.has_frame_end());
    const auto& expectedSurfaceFrameEnd2 = event9.frame_end();
    validateTraceEvent(expectedSurfaceFrameEnd2, protoPresentedSurfaceFrameExpectedEnd);

    // Packet - 10 : ActualSurfaceFrameStart2
    const auto& packet10 = packets[10];
    ASSERT_TRUE(packet10.has_timestamp());
    EXPECT_EQ(packet10.timestamp(), 10u);
    ASSERT_TRUE(packet10.has_frame_timeline_event());

    const auto& event10 = packet10.frame_timeline_event();
    ASSERT_TRUE(event10.has_actual_surface_frame_start());
    const auto& actualSurfaceFrameStart2 = event10.actual_surface_frame_start();
    validateTraceEvent(actualSurfaceFrameStart2, protoPresentedSurfaceFrameActualStart);

    // Packet - 11 : FrameEnd (ActualSurfaceFrame2)
    const auto& packet11 = packets[11];
    ASSERT_TRUE(packet11.has_timestamp());
    EXPECT_EQ(packet11.timestamp(), 20u);
    ASSERT_TRUE(packet11.has_frame_timeline_event());

    const auto& event11 = packet11.frame_timeline_event();
    ASSERT_TRUE(event11.has_frame_end());
    const auto& actualSurfaceFrameEnd2 = event11.frame_end();
    validateTraceEvent(actualSurfaceFrameEnd2, protoPresentedSurfaceFrameActualEnd);
}

TEST_F(FrameTimelineTest, traceSurfaceFrame_predictionExpiredDoesNotTraceExpectedTimeline) {
    auto tracingSession = getTracingSessionForTest();
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    constexpr nsecs_t appStartTime = std::chrono::nanoseconds(10ms).count();
    constexpr nsecs_t appEndTime = std::chrono::nanoseconds(20ms).count();
    constexpr nsecs_t appPresentTime = std::chrono::nanoseconds(30ms).count();
    int64_t surfaceFrameToken =
            mTokenManager->generateTokenForPredictions({appStartTime, appEndTime, appPresentTime});

    // Flush the token so that it would expire
    flushTokens(systemTime() + maxTokenRetentionTime);
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, /*inputEventId*/ 0},
                                                       sPidOne, sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setActualQueueTime(appEndTime);
    surfaceFrame1->setAcquireFenceTime(appEndTime);

    constexpr nsecs_t sfStartTime = std::chrono::nanoseconds(20ms).count();
    constexpr nsecs_t sfEndTime = std::chrono::nanoseconds(30ms).count();
    constexpr nsecs_t sfPresentTime = std::chrono::nanoseconds(30ms).count();
    int64_t displayFrameToken =
            mTokenManager->generateTokenForPredictions({sfStartTime, sfEndTime, sfPresentTime});

    // First 2 cookies will be used by the DisplayFrame
    int64_t traceCookie = snoopCurrentTraceCookie() + 2;

    auto protoActualSurfaceFrameStart =
            createProtoActualSurfaceFrameStart(traceCookie + 1, surfaceFrameToken,
                                               displayFrameToken, sPidOne, sLayerNameOne,
                                               FrameTimelineEvent::PRESENT_UNSPECIFIED, false,
                                               false, FrameTimelineEvent::JANK_UNKNOWN);
    auto protoActualSurfaceFrameEnd = createProtoFrameEnd(traceCookie + 1);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(displayFrameToken, sfStartTime, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(sfEndTime, presentFence1);
    presentFence1->signalForTest(sfPresentTime);

    addEmptyDisplayFrame();
    flushTrace();
    tracingSession->StopBlocking();

    auto packets = readFrameTimelinePacketsBlocking(tracingSession.get());
    // Display Frame 4 packets + SurfaceFrame 2 packets
    ASSERT_EQ(packets.size(), 6u);

    // Packet - 4 : ActualSurfaceFrameStart
    const auto& packet4 = packets[4];
    ASSERT_TRUE(packet4.has_timestamp());
    EXPECT_EQ(packet4.timestamp(),
              static_cast<uint64_t>(appEndTime - SurfaceFrame::kPredictionExpiredStartTimeDelta));
    ASSERT_TRUE(packet4.has_frame_timeline_event());

    const auto& event4 = packet4.frame_timeline_event();
    ASSERT_TRUE(event4.has_actual_surface_frame_start());
    const auto& actualSurfaceFrameStart = event4.actual_surface_frame_start();
    validateTraceEvent(actualSurfaceFrameStart, protoActualSurfaceFrameStart);

    // Packet - 5 : FrameEnd (ActualSurfaceFrame)
    const auto& packet5 = packets[5];
    ASSERT_TRUE(packet5.has_timestamp());
    EXPECT_EQ(packet5.timestamp(), static_cast<uint64_t>(appEndTime));
    ASSERT_TRUE(packet5.has_frame_timeline_event());

    const auto& event5 = packet5.frame_timeline_event();
    ASSERT_TRUE(event5.has_frame_end());
    const auto& actualSurfaceFrameEnd = event5.frame_end();
    validateTraceEvent(actualSurfaceFrameEnd, protoActualSurfaceFrameEnd);
}

// Tests for Jank classification
TEST_F(FrameTimelineTest, jankClassification_presentOnTimeDoesNotClassify) {
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 30, 30});
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 30, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 60, 70});
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
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 30, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 60, 70});
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

TEST_F(FrameTimelineTest, jankClassification_displayFrameLateStartLateFinishLatePresent) {
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 40});
    mFrameTimeline->setSfWakeUp(sfToken1, 26, Fps::fromPeriodNsecs(11));
    mFrameTimeline->setSfPresent(36, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    presentFence1->signalForTest(52);

    // Fences haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->getActuals().presentTime, 0);

    addEmptyDisplayFrame();
    displayFrame = getDisplayFrame(0);

    // Fences have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->getActuals().presentTime, 52);
    EXPECT_EQ(displayFrame->getFrameStartMetadata(), FrameStartMetadata::LateStart);
    EXPECT_EQ(displayFrame->getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(displayFrame->getFrameReadyMetadata(), FrameReadyMetadata::LateFinish);
    EXPECT_EQ(displayFrame->getJankType(), JankType::SurfaceFlingerScheduling);
}

TEST_F(FrameTimelineTest, jankClassification_surfaceFrameOnTimeFinishEarlyPresent) {
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 30, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 60, 70});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 16, 40});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({25, 36, 70});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame1->setAcquireFenceTime(16);
    mFrameTimeline->setSfWakeUp(sfToken1, 22, Fps::fromPeriodNsecs(11));
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    mFrameTimeline->setSfPresent(27, presentFence1);
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
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(36);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, Fps::fromPeriodNsecs(11));
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(57, presentFence2);
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
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 30, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 60, 70});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 16, 40});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({25, 36, 70});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(36);
    mFrameTimeline->setSfWakeUp(sfToken2, 52, Fps::fromPeriodNsecs(11));
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(57, presentFence2);
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
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({42, 50, 50});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 26, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({32, 40, 40});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({42, 50, 50});
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({5, 16, 30});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({25, 36, 50});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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

    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 60, 60});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({112, 120, 120});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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

TEST_F(FrameTimelineTest, jankClassification_appDeadlineAdjustedForBufferStuffing) {
    // Layer specific increment
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(_)).Times(2);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({40, 50, 60});

    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({52, 60, 60});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({82, 90, 90});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken({surfaceFrameToken1, sInputEventId}, sPidOne,
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
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
                                                       sUidOne, sLayerIdOne, sLayerNameOne,
                                                       sLayerNameOne);
    surfaceFrame2->setAcquireFenceTime(80);
    mFrameTimeline->setSfWakeUp(sfToken2, 82, Fps::fromPeriodNsecs(30));
    // Setting previous latch time to 54, adjusted deadline will be 54 + vsyncTime(30) = 84
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented, 54);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    mFrameTimeline->setSfPresent(86, presentFence2);
    auto displayFrame2 = getDisplayFrame(1);
    auto& presentedSurfaceFrame2 = getSurfaceFrame(1, 0);
    presentFence2->signalForTest(90);

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
    EXPECT_EQ(displayFrame2->getActuals().presentTime, 90);
    actuals2 = presentedSurfaceFrame2.getActuals();
    EXPECT_EQ(actuals2.presentTime, 90);

    EXPECT_EQ(displayFrame2->getFramePresentMetadata(), FramePresentMetadata::OnTimePresent);
    EXPECT_EQ(displayFrame2->getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(displayFrame2->getJankType(), JankType::None);

    EXPECT_EQ(presentedSurfaceFrame2.getFramePresentMetadata(), FramePresentMetadata::LatePresent);
    EXPECT_EQ(presentedSurfaceFrame2.getFrameReadyMetadata(), FrameReadyMetadata::OnTimeFinish);
    EXPECT_EQ(presentedSurfaceFrame2.getJankType(), JankType::BufferStuffing);
}

TEST_F(FrameTimelineTest, computeFps_noLayerIds_returnsZero) {
    EXPECT_EQ(mFrameTimeline->computeFps({}), 0.0f);
}

TEST_F(FrameTimelineTest, computeFps_singleDisplayFrame_returnsZero) {
    const auto oneHundredMs = std::chrono::nanoseconds(100ms).count();

    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(oneHundredMs);
    mFrameTimeline->setSfPresent(oneHundredMs, presentFence1);

    EXPECT_EQ(mFrameTimeline->computeFps({sLayerIdOne}), 0.0f);
}

TEST_F(FrameTimelineTest, computeFps_twoDisplayFrames_oneLayer) {
    const auto oneHundredMs = std::chrono::nanoseconds(100ms).count();
    const auto twoHundredMs = std::chrono::nanoseconds(200ms).count();
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(oneHundredMs);
    mFrameTimeline->setSfPresent(oneHundredMs, presentFence1);

    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    presentFence2->signalForTest(twoHundredMs);
    mFrameTimeline->setSfPresent(twoHundredMs, presentFence2);

    EXPECT_EQ(mFrameTimeline->computeFps({sLayerIdOne}), 10.0);
}

TEST_F(FrameTimelineTest, computeFps_twoDisplayFrames_twoLayers) {
    const auto oneHundredMs = std::chrono::nanoseconds(100ms).count();
    const auto twoHundredMs = std::chrono::nanoseconds(200ms).count();
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(oneHundredMs);
    mFrameTimeline->setSfPresent(oneHundredMs, presentFence1);

    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdTwo, sLayerNameTwo, sLayerNameTwo);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    presentFence2->signalForTest(twoHundredMs);
    mFrameTimeline->setSfPresent(twoHundredMs, presentFence2);

    EXPECT_EQ(mFrameTimeline->computeFps({sLayerIdOne, sLayerIdTwo}), 10.0f);
}

TEST_F(FrameTimelineTest, computeFps_filtersOutLayers) {
    const auto oneHundredMs = std::chrono::nanoseconds(100ms).count();
    const auto twoHundredMs = std::chrono::nanoseconds(200ms).count();
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(oneHundredMs);
    mFrameTimeline->setSfPresent(oneHundredMs, presentFence1);

    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdTwo, sLayerNameTwo, sLayerNameTwo);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    presentFence2->signalForTest(twoHundredMs);
    mFrameTimeline->setSfPresent(twoHundredMs, presentFence2);

    EXPECT_EQ(mFrameTimeline->computeFps({sLayerIdOne}), 0.0f);
}

TEST_F(FrameTimelineTest, computeFps_averagesOverMultipleFrames) {
    const auto oneHundredMs = std::chrono::nanoseconds(100ms).count();
    const auto twoHundredMs = std::chrono::nanoseconds(200ms).count();
    const auto threeHundredMs = std::chrono::nanoseconds(300ms).count();
    const auto fiveHundredMs = std::chrono::nanoseconds(500ms).count();
    const auto sixHundredMs = std::chrono::nanoseconds(600ms).count();
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame1->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame1);
    presentFence1->signalForTest(oneHundredMs);
    mFrameTimeline->setSfPresent(oneHundredMs, presentFence1);

    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame2->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame2);
    presentFence2->signalForTest(twoHundredMs);
    mFrameTimeline->setSfPresent(twoHundredMs, presentFence2);

    auto surfaceFrame3 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdTwo, sLayerNameTwo, sLayerNameTwo);
    auto presentFence3 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame3->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame3);
    presentFence3->signalForTest(threeHundredMs);
    mFrameTimeline->setSfPresent(threeHundredMs, presentFence3);

    auto surfaceFrame4 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence4 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    surfaceFrame4->setPresentState(SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(surfaceFrame4);
    presentFence4->signalForTest(fiveHundredMs);
    mFrameTimeline->setSfPresent(fiveHundredMs, presentFence4);

    auto surfaceFrame5 =
            mFrameTimeline->createSurfaceFrameForToken(FrameTimelineInfo(), sPidOne, sUidOne,
                                                       sLayerIdOne, sLayerNameOne, sLayerNameOne);
    auto presentFence5 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    // Dropped frames will be excluded from fps computation
    surfaceFrame5->setPresentState(SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->addSurfaceFrame(surfaceFrame5);
    presentFence5->signalForTest(sixHundredMs);
    mFrameTimeline->setSfPresent(sixHundredMs, presentFence5);

    EXPECT_EQ(mFrameTimeline->computeFps({sLayerIdOne}), 5.0f);
}

} // namespace android::frametimeline
