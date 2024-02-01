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
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <scheduler/interface/ICompositor.h>

#include "FrameTimeline.h"
#include "Scheduler/MessageQueue.h"
#include "mock/MockVSyncDispatch.h"
#include "utils/Timers.h"

namespace android {

using namespace std::chrono_literals;
using namespace testing;

using CallbackToken = scheduler::VSyncDispatch::CallbackToken;

struct NoOpCompositor final : ICompositor {
    void configure() override {}
    bool commit(PhysicalDisplayId, const scheduler::FrameTargets&) override { return false; }
    CompositeResultsPerDisplay composite(PhysicalDisplayId,
                                         const scheduler::FrameTargeters&) override {
        return {};
    }
    void sample() override {}
    void sendNotifyExpectedPresentHint(PhysicalDisplayId) {}
} gNoOpCompositor;

class TestableMessageQueue : public impl::MessageQueue {
    struct MockHandler : MessageQueue::Handler {
        using MessageQueue::Handler::Handler;

        MOCK_METHOD(void, dispatchFrame, (VsyncId, TimePoint), (override));
        MOCK_METHOD(bool, isFramePending, (), (const, override));
        MOCK_METHOD(TimePoint, getExpectedVsyncTime, (), (const override));
    };

    explicit TestableMessageQueue(sp<MockHandler> handler)
          : impl::MessageQueue(gNoOpCompositor, handler), mHandler(std::move(handler)) {}

    // impl::MessageQueue overrides:
    void onFrameSignal(ICompositor&, VsyncId, TimePoint) override {}

public:
    TestableMessageQueue() : TestableMessageQueue(sp<MockHandler>::make(*this)) {}

    using impl::MessageQueue::vsyncCallback;

    const sp<MockHandler> mHandler;
};

struct MockTokenManager : frametimeline::TokenManager {
    MOCK_METHOD1(generateTokenForPredictions, int64_t(frametimeline::TimelineItem&& prediction));
    MOCK_CONST_METHOD1(getPredictionsForToken, std::optional<frametimeline::TimelineItem>(int64_t));
};

struct MessageQueueTest : testing::Test {
    void SetUp() override {
        EXPECT_CALL(*mVSyncDispatch, registerCallback(_, "sf")).WillOnce(Return(mCallbackToken));
        EXPECT_NO_FATAL_FAILURE(
                mEventQueue.initVsyncInternal(mVSyncDispatch, mTokenManager, kDuration));
        EXPECT_CALL(*mVSyncDispatch, unregisterCallback(mCallbackToken)).Times(1);
    }

    std::shared_ptr<mock::VSyncDispatch> mVSyncDispatch = std::make_shared<mock::VSyncDispatch>();
    MockTokenManager mTokenManager;
    TestableMessageQueue mEventQueue;

    const CallbackToken mCallbackToken{5};

    static constexpr Duration kDuration = 100ms;
    static constexpr Duration kDifferentDuration = 250ms;
};

namespace {

TEST_F(MessageQueueTest, commit) {
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                                 .readyDuration = 0,
                                                                 .lastVsync = 0};
    EXPECT_FALSE(mEventQueue.getScheduledFrameResult());

    const auto timePoint = TimePoint::fromNs(1234);
    const auto scheduleResult = scheduler::ScheduleResult{timePoint, timePoint};
    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(scheduleResult));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    const auto scheduledFrameResult = mEventQueue.getScheduledFrameResult();
    ASSERT_TRUE(scheduledFrameResult);
    EXPECT_EQ(1234, scheduledFrameResult->callbackTime.ns());
    EXPECT_EQ(1234, scheduledFrameResult->vsyncTime.ns());
}

TEST_F(MessageQueueTest, commitTwice) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                                 .readyDuration = 0,
                                                                 .lastVsync = 0};

    auto timePoint = TimePoint::fromNs(1234);
    auto scheduleResult = scheduler::ScheduleResult{timePoint, timePoint};
    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(scheduleResult));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    auto scheduledFrameResult = mEventQueue.getScheduledFrameResult();
    ASSERT_TRUE(scheduledFrameResult);
    EXPECT_EQ(1234, scheduledFrameResult->callbackTime.ns());
    EXPECT_EQ(1234, scheduledFrameResult->vsyncTime.ns());

    timePoint = TimePoint::fromNs(4567);
    scheduleResult = scheduler::ScheduleResult{timePoint, timePoint};
    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(scheduleResult));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    scheduledFrameResult = mEventQueue.getScheduledFrameResult();
    ASSERT_TRUE(scheduledFrameResult);
    EXPECT_EQ(4567, scheduledFrameResult->callbackTime.ns());
    EXPECT_EQ(4567, scheduledFrameResult->vsyncTime.ns());
}

TEST_F(MessageQueueTest, commitTwiceWithCallback) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                                 .readyDuration = 0,
                                                                 .lastVsync = 0};

    const auto timePoint = TimePoint::fromNs(1234);
    auto scheduleResult = scheduler::ScheduleResult{timePoint, timePoint};
    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(scheduleResult));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    auto scheduledFrameResult = mEventQueue.getScheduledFrameResult();
    ASSERT_TRUE(scheduledFrameResult);
    EXPECT_EQ(1234, scheduledFrameResult->callbackTime.ns());
    EXPECT_EQ(1234, scheduledFrameResult->vsyncTime.ns());

    constexpr TimePoint kStartTime = TimePoint::fromNs(100);
    constexpr TimePoint kEndTime = kStartTime + kDuration;
    constexpr TimePoint kPresentTime = TimePoint::fromNs(500);
    constexpr VsyncId vsyncId{42};

    EXPECT_CALL(mTokenManager,
                generateTokenForPredictions(frametimeline::TimelineItem(kStartTime.ns(),
                                                                        kEndTime.ns(),
                                                                        kPresentTime.ns())))
            .WillOnce(Return(ftl::to_underlying(vsyncId)));
    EXPECT_CALL(*mEventQueue.mHandler, dispatchFrame(vsyncId, kPresentTime)).Times(1);
    EXPECT_NO_FATAL_FAILURE(
            mEventQueue.vsyncCallback(kPresentTime.ns(), kStartTime.ns(), kEndTime.ns()));

    EXPECT_FALSE(mEventQueue.getScheduledFrameResult());

    const auto timingAfterCallback =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                     .readyDuration = 0,
                                                     .lastVsync = kPresentTime.ns()};
    scheduleResult = scheduler::ScheduleResult{TimePoint::fromNs(0), TimePoint::fromNs(0)};
    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timingAfterCallback))
            .WillOnce(Return(scheduleResult));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());
}

TEST_F(MessageQueueTest, commitWithDurationChange) {
    EXPECT_NO_FATAL_FAILURE(mEventQueue.setDuration(kDifferentDuration));

    const auto timing =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDifferentDuration.ns(),
                                                     .readyDuration = 0,
                                                     .lastVsync = 0};

    const auto scheduleResult =
            scheduler::ScheduleResult{TimePoint::fromNs(0), TimePoint::fromNs(0)};
    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(scheduleResult));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());
}

TEST_F(MessageQueueTest, scheduleResultWhenFrameIsPending) {
    const auto timePoint = TimePoint::now();
    EXPECT_CALL(*mEventQueue.mHandler, isFramePending()).WillOnce(Return(true));
    EXPECT_CALL(*mEventQueue.mHandler, getExpectedVsyncTime()).WillRepeatedly(Return(timePoint));

    const auto scheduledFrameResult = mEventQueue.getScheduledFrameResult();

    ASSERT_TRUE(scheduledFrameResult);
    EXPECT_NEAR(static_cast<double>(TimePoint::now().ns()),
                static_cast<double>(scheduledFrameResult->callbackTime.ns()), ms2ns(1));
    EXPECT_EQ(timePoint, scheduledFrameResult->vsyncTime);
}

} // namespace
} // namespace android
