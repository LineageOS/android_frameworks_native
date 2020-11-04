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
#include <cinttypes>

using namespace std::chrono_literals;
using testing::Contains;

MATCHER_P(HasBit, bit, "") {
    return (arg & bit) != 0;
}

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

    void SetUp() override {
        mTimeStats = std::make_shared<mock::TimeStats>();
        mFrameTimeline = std::make_unique<impl::FrameTimeline>(mTimeStats);
        mTokenManager = &mFrameTimeline->mTokenManager;
        maxDisplayFrames = &mFrameTimeline->mMaxDisplayFrames;
        maxTokenRetentionTime = mTokenManager->kMaxRetentionTime;
    }

    void flushTokens(nsecs_t flushTime) {
        std::lock_guard<std::mutex> lock(mTokenManager->mMutex);
        mTokenManager->flushTokens(flushTime);
    }

    SurfaceFrame& getSurfaceFrame(size_t displayFrameIdx, size_t surfaceFrameIdx) {
        std::lock_guard<std::mutex> lock(mFrameTimeline->mMutex);
        return *(mFrameTimeline->mDisplayFrames[displayFrameIdx]->surfaceFrames[surfaceFrameIdx]);
    }

    std::shared_ptr<impl::FrameTimeline::DisplayFrame> getDisplayFrame(size_t idx) {
        std::lock_guard<std::mutex> lock(mFrameTimeline->mMutex);
        return mFrameTimeline->mDisplayFrames[idx];
    }

    static bool compareTimelineItems(const TimelineItem& a, const TimelineItem& b) {
        return a.startTime == b.startTime && a.endTime == b.endTime &&
                a.presentTime == b.presentTime;
    }

    const std::unordered_map<int64_t, TimelineItem>& getPredictions() {
        return mTokenManager->mPredictions;
    }

    uint32_t getNumberOfDisplayFrames() {
        std::lock_guard<std::mutex> lock(mFrameTimeline->mMutex);
        return static_cast<uint32_t>(mFrameTimeline->mDisplayFrames.size());
    }

    std::shared_ptr<mock::TimeStats> mTimeStats;
    std::unique_ptr<impl::FrameTimeline> mFrameTimeline;
    impl::TokenManager* mTokenManager;
    FenceToFenceTimeMap fenceFactory;
    uint32_t* maxDisplayFrames;
    nsecs_t maxTokenRetentionTime;
};

static const std::string sLayerNameOne = "layer1";
static const std::string sLayerNameTwo = "layer2";
static constexpr const uid_t sUidOne = 0;
static constexpr pid_t sPidOne = 10;
static constexpr pid_t sPidTwo = 20;

TEST_F(FrameTimelineTest, tokenManagerRemovesStalePredictions) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({0, 0, 0});
    EXPECT_EQ(getPredictions().size(), 1);
    flushTokens(systemTime() + maxTokenRetentionTime);
    int64_t token2 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    std::optional<TimelineItem> predictions = mTokenManager->getPredictionsForToken(token1);

    // token1 should have expired
    EXPECT_EQ(getPredictions().size(), 1);
    EXPECT_EQ(predictions.has_value(), false);

    predictions = mTokenManager->getPredictionsForToken(token2);
    EXPECT_EQ(compareTimelineItems(*predictions, TimelineItem(10, 20, 30)), true);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_getOwnerPidReturnsCorrectPid) {
    auto surfaceFrame1 = mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                                    sLayerNameOne, std::nullopt);
    auto surfaceFrame2 = mFrameTimeline->createSurfaceFrameForToken(sPidTwo, sUidOne, sLayerNameOne,
                                                                    sLayerNameOne, std::nullopt);
    EXPECT_EQ(surfaceFrame1->getOwnerPid(), sPidOne);
    EXPECT_EQ(surfaceFrame2->getOwnerPid(), sPidTwo);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_noToken) {
    auto surfaceFrame = mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                                   sLayerNameOne, std::nullopt);
    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::None);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_expiredToken) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({0, 0, 0});
    flushTokens(systemTime() + maxTokenRetentionTime);
    auto surfaceFrame = mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                                   sLayerNameOne, token1);

    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::Expired);
}

TEST_F(FrameTimelineTest, createSurfaceFrameForToken_validToken) {
    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    auto surfaceFrame = mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                                   sLayerNameOne, token1);

    EXPECT_EQ(surfaceFrame->getPredictionState(), PredictionState::Valid);
    EXPECT_EQ(compareTimelineItems(surfaceFrame->getPredictions(), TimelineItem(10, 20, 30)), true);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_droppedFramesNotUpdated) {
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    int64_t token1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t token2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    auto surfaceFrame1 = mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                                    sLayerNameOne, token1);

    // Set up the display frame
    mFrameTimeline->setSfWakeUp(token1, 20);
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame1), SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->setSfPresent(25, presentFence1);
    presentFence1->signalForTest(30);

    // Trigger a flush by calling setSfPresent for the next frame
    mFrameTimeline->setSfWakeUp(token2, 50);
    mFrameTimeline->setSfPresent(55, presentFence2);

    auto& droppedSurfaceFrame = getSurfaceFrame(0, 0);
    EXPECT_EQ(droppedSurfaceFrame.getPresentState(), SurfaceFrame::PresentState::Dropped);
    EXPECT_EQ(droppedSurfaceFrame.getActuals().presentTime, 0);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_presentedFramesUpdated) {
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions({10, 20, 30});
    int64_t surfaceFrameToken2 = mTokenManager->generateTokenForPredictions({40, 50, 60});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions({22, 26, 30});
    int64_t sfToken2 = mTokenManager->generateTokenForPredictions({52, 56, 60});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                       sLayerNameOne, surfaceFrameToken1);
    auto surfaceFrame2 =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameTwo,
                                                       sLayerNameTwo, surfaceFrameToken1);
    mFrameTimeline->setSfWakeUp(sfToken1, 22);
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame1),
                                    SurfaceFrame::PresentState::Presented);
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame2),
                                    SurfaceFrame::PresentState::Presented);
    mFrameTimeline->setSfPresent(26, presentFence1);
    auto displayFrame = getDisplayFrame(0);
    SurfaceFrame& presentedSurfaceFrame1 = getSurfaceFrame(0, 0);
    SurfaceFrame& presentedSurfaceFrame2 = getSurfaceFrame(0, 1);
    presentFence1->signalForTest(42);

    // Fences haven't been flushed yet, so it should be 0
    EXPECT_EQ(displayFrame->surfaceFlingerActuals.presentTime, 0);
    EXPECT_EQ(presentedSurfaceFrame1.getActuals().presentTime, 0);
    EXPECT_EQ(presentedSurfaceFrame2.getActuals().presentTime, 0);

    // Trigger a flush by finalizing the next DisplayFrame
    auto presentFence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    auto surfaceFrame3 =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                       sLayerNameOne, surfaceFrameToken2);
    mFrameTimeline->setSfWakeUp(sfToken2, 52);
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame3), SurfaceFrame::PresentState::Dropped);
    mFrameTimeline->setSfPresent(56, presentFence2);
    displayFrame = getDisplayFrame(0);

    // Fences have flushed, so the present timestamps should be updated
    EXPECT_EQ(displayFrame->surfaceFlingerActuals.presentTime, 42);
    EXPECT_EQ(presentedSurfaceFrame1.getActuals().presentTime, 42);
    EXPECT_EQ(presentedSurfaceFrame2.getActuals().presentTime, 42);
}

TEST_F(FrameTimelineTest, displayFramesSlidingWindowMovesAfterLimit) {
    // Insert kMaxDisplayFrames' count of DisplayFrames to fill the deque
    int frameTimeFactor = 0;
    for (size_t i = 0; i < *maxDisplayFrames; i++) {
        auto presentFence = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
        int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions(
                {10 + frameTimeFactor, 20 + frameTimeFactor, 30 + frameTimeFactor});
        int64_t sfToken = mTokenManager->generateTokenForPredictions(
                {22 + frameTimeFactor, 26 + frameTimeFactor, 30 + frameTimeFactor});
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne, surfaceFrameToken);
        mFrameTimeline->setSfWakeUp(sfToken, 22 + frameTimeFactor);
        mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame),
                                        SurfaceFrame::PresentState::Presented);
        mFrameTimeline->setSfPresent(27 + frameTimeFactor, presentFence);
        presentFence->signalForTest(32 + frameTimeFactor);
        frameTimeFactor += 30;
    }
    auto displayFrame0 = getDisplayFrame(0);

    // The 0th Display Frame should have actuals 22, 27, 32
    EXPECT_EQ(compareTimelineItems(displayFrame0->surfaceFlingerActuals, TimelineItem(22, 27, 32)),
              true);

    // Add one more display frame
    auto presentFence = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken = mTokenManager->generateTokenForPredictions(
            {10 + frameTimeFactor, 20 + frameTimeFactor, 30 + frameTimeFactor});
    int64_t sfToken = mTokenManager->generateTokenForPredictions(
            {22 + frameTimeFactor, 26 + frameTimeFactor, 30 + frameTimeFactor});
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                       sLayerNameOne, surfaceFrameToken);
    mFrameTimeline->setSfWakeUp(sfToken, 22 + frameTimeFactor);
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame), SurfaceFrame::PresentState::Presented);
    mFrameTimeline->setSfPresent(27 + frameTimeFactor, presentFence);
    presentFence->signalForTest(32 + frameTimeFactor);
    displayFrame0 = getDisplayFrame(0);

    // The window should have slided by 1 now and the previous 0th display frame
    // should have been removed from the deque
    EXPECT_EQ(compareTimelineItems(displayFrame0->surfaceFlingerActuals, TimelineItem(52, 57, 62)),
              true);
}

TEST_F(FrameTimelineTest, surfaceFrameEndTimeAcquireFenceAfterQueue) {
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, 0, "acquireFenceAfterQueue",
                                                       "acquireFenceAfterQueue", std::nullopt);
    surfaceFrame->setActualQueueTime(123);
    surfaceFrame->setAcquireFenceTime(456);
    EXPECT_EQ(surfaceFrame->getActuals().endTime, 456);
}

TEST_F(FrameTimelineTest, surfaceFrameEndTimeAcquireFenceBeforeQueue) {
    auto surfaceFrame =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, 0, "acquireFenceAfterQueue",
                                                       "acquireFenceAfterQueue", std::nullopt);
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
                mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne, std::nullopt);
        int64_t sfToken = mTokenManager->generateTokenForPredictions({22, 26, 30});
        mFrameTimeline->setSfWakeUp(sfToken, 22);
        mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame),
                                        SurfaceFrame::PresentState::Presented);
        mFrameTimeline->setSfPresent(27, presentFence);
    }
    EXPECT_EQ(getNumberOfDisplayFrames(), *maxDisplayFrames);

    // Increase the size to 256
    mFrameTimeline->setMaxDisplayFrames(256);
    EXPECT_EQ(*maxDisplayFrames, 256);

    for (size_t i = 0; i < *maxDisplayFrames + 10; i++) {
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne, std::nullopt);
        int64_t sfToken = mTokenManager->generateTokenForPredictions({22, 26, 30});
        mFrameTimeline->setSfWakeUp(sfToken, 22);
        mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame),
                                        SurfaceFrame::PresentState::Presented);
        mFrameTimeline->setSfPresent(27, presentFence);
    }
    EXPECT_EQ(getNumberOfDisplayFrames(), *maxDisplayFrames);

    // Shrink the size to 128
    mFrameTimeline->setMaxDisplayFrames(128);
    EXPECT_EQ(*maxDisplayFrames, 128);

    for (size_t i = 0; i < *maxDisplayFrames + 10; i++) {
        auto surfaceFrame =
                mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                           sLayerNameOne, std::nullopt);
        int64_t sfToken = mTokenManager->generateTokenForPredictions({22, 26, 30});
        mFrameTimeline->setSfWakeUp(sfToken, 22);
        mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame),
                                        SurfaceFrame::PresentState::Presented);
        mFrameTimeline->setSfPresent(27, presentFence);
    }
    EXPECT_EQ(getNumberOfDisplayFrames(), *maxDisplayFrames);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsLongSfCpu) {
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(sUidOne, sLayerNameOne,
                                     HasBit(TimeStats::JankType::SurfaceFlingerDeadlineMissed)));
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(HasBit(TimeStats::JankType::SurfaceFlingerDeadlineMissed)));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::duration_cast<std::chrono::nanoseconds>(10ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(20ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::duration_cast<std::chrono::nanoseconds>(52ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(56ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                       sLayerNameOne, surfaceFrameToken1);
    mFrameTimeline->setSfWakeUp(sfToken1,
                                std::chrono::duration_cast<std::chrono::nanoseconds>(52ms).count());
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame1),
                                    SurfaceFrame::PresentState::Presented);
    presentFence1->signalForTest(
            std::chrono::duration_cast<std::chrono::nanoseconds>(90ms).count());

    mFrameTimeline->setSfPresent(std::chrono::duration_cast<std::chrono::nanoseconds>(59ms).count(),
                                 presentFence1);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsDisplayMiss) {
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(sUidOne, sLayerNameOne, HasBit(TimeStats::JankType::Display)));
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(HasBit(TimeStats::JankType::Display)));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::duration_cast<std::chrono::nanoseconds>(10ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(20ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::duration_cast<std::chrono::nanoseconds>(52ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(56ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                       sLayerNameOne, surfaceFrameToken1);
    mFrameTimeline->setSfWakeUp(sfToken1,
                                std::chrono::duration_cast<std::chrono::nanoseconds>(52ms).count());
    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame1),
                                    SurfaceFrame::PresentState::Presented);
    presentFence1->signalForTest(
            std::chrono::duration_cast<std::chrono::nanoseconds>(90ms).count());
    mFrameTimeline->setSfPresent(std::chrono::duration_cast<std::chrono::nanoseconds>(59ms).count(),
                                 presentFence1);
}

TEST_F(FrameTimelineTest, presentFenceSignaled_reportsAppMiss) {
    EXPECT_CALL(*mTimeStats,
                incrementJankyFrames(sUidOne, sLayerNameOne,
                                     HasBit(TimeStats::JankType::AppDeadlineMissed)));
    EXPECT_CALL(*mTimeStats, incrementJankyFrames(HasBit(TimeStats::JankType::AppDeadlineMissed)));
    auto presentFence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    int64_t surfaceFrameToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::duration_cast<std::chrono::nanoseconds>(10ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(20ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(60ms).count()});
    int64_t sfToken1 = mTokenManager->generateTokenForPredictions(
            {std::chrono::duration_cast<std::chrono::nanoseconds>(52ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(56ms).count(),
             std::chrono::duration_cast<std::chrono::nanoseconds>(60ms).count()});
    auto surfaceFrame1 =
            mFrameTimeline->createSurfaceFrameForToken(sPidOne, sUidOne, sLayerNameOne,
                                                       sLayerNameOne, surfaceFrameToken1);
    surfaceFrame1->setAcquireFenceTime(
            std::chrono::duration_cast<std::chrono::nanoseconds>(45ms).count());
    mFrameTimeline->setSfWakeUp(sfToken1,
                                std::chrono::duration_cast<std::chrono::nanoseconds>(52ms).count());

    mFrameTimeline->addSurfaceFrame(std::move(surfaceFrame1),
                                    SurfaceFrame::PresentState::Presented);
    presentFence1->signalForTest(
            std::chrono::duration_cast<std::chrono::nanoseconds>(90ms).count());
    mFrameTimeline->setSfPresent(std::chrono::duration_cast<std::chrono::nanoseconds>(56ms).count(),
                                 presentFence1);
}

} // namespace android::frametimeline
