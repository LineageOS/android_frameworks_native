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

#include "FrameTimeline.h"
#include "Scheduler/MessageQueue.h"
#include "SurfaceFlinger.h"

namespace android {

using namespace std::chrono_literals;
using namespace testing;

using CallbackToken = scheduler::VSyncDispatch::CallbackToken;

struct NoOpCompositor final : ICompositor {
    bool commit(nsecs_t, int64_t, nsecs_t) override { return false; }
    void composite(nsecs_t, int64_t) override {}
    void sample() override {}
} gNoOpCompositor;

class TestableMessageQueue : public impl::MessageQueue {
    struct MockHandler : MessageQueue::Handler {
        using MessageQueue::Handler::Handler;

        MOCK_METHOD(void, dispatchFrame, (int64_t, nsecs_t), (override));
    };

    explicit TestableMessageQueue(sp<MockHandler> handler)
          : impl::MessageQueue(gNoOpCompositor, handler), mHandler(std::move(handler)) {}

public:
    TestableMessageQueue() : TestableMessageQueue(sp<MockHandler>::make(*this)) {}

    using impl::MessageQueue::vsyncCallback;

    const sp<MockHandler> mHandler;
};

struct MockVSyncDispatch : scheduler::VSyncDispatch {
    MOCK_METHOD(CallbackToken, registerCallback, (Callback, std::string), (override));
    MOCK_METHOD(void, unregisterCallback, (CallbackToken), (override));
    MOCK_METHOD(scheduler::ScheduleResult, schedule, (CallbackToken, ScheduleTiming), (override));
    MOCK_METHOD(scheduler::CancelResult, cancel, (CallbackToken token), (override));
    MOCK_METHOD(void, dump, (std::string&), (const, override));
};

struct MockTokenManager : frametimeline::TokenManager {
    MOCK_METHOD1(generateTokenForPredictions, int64_t(frametimeline::TimelineItem&& prediction));
    MOCK_CONST_METHOD1(getPredictionsForToken, std::optional<frametimeline::TimelineItem>(int64_t));
};

struct MessageQueueTest : testing::Test {
    void SetUp() override {
        EXPECT_CALL(mVSyncDispatch, registerCallback(_, "sf")).WillOnce(Return(mCallbackToken));
        EXPECT_NO_FATAL_FAILURE(mEventQueue.initVsync(mVSyncDispatch, mTokenManager, mDuration));
        EXPECT_CALL(mVSyncDispatch, unregisterCallback(mCallbackToken)).Times(1);
    }

    MockVSyncDispatch mVSyncDispatch;
    MockTokenManager mTokenManager;
    TestableMessageQueue mEventQueue;

    const CallbackToken mCallbackToken{5};
    constexpr static auto mDuration = std::chrono::nanoseconds(100ms);
    constexpr static auto mDifferentDuration = std::chrono::nanoseconds(250ms);
};

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */
TEST_F(MessageQueueTest, commit) {
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};
    EXPECT_FALSE(mEventQueue.getScheduledFrameTime());

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(1234));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(1234, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());
}

TEST_F(MessageQueueTest, commitTwice) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(1234));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(1234, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(4567));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(4567, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());
}

TEST_F(MessageQueueTest, commitTwiceWithCallback) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(1234));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(1234, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());

    const auto startTime = 100;
    const auto endTime = startTime + mDuration.count();
    const auto presentTime = 500;
    const auto vsyncId = 42;
    EXPECT_CALL(mTokenManager,
                generateTokenForPredictions(
                        frametimeline::TimelineItem(startTime, endTime, presentTime)))
            .WillOnce(Return(vsyncId));
    EXPECT_CALL(*mEventQueue.mHandler, dispatchFrame(vsyncId, presentTime)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.vsyncCallback(presentTime, startTime, endTime));

    EXPECT_FALSE(mEventQueue.getScheduledFrameTime());

    const auto timingAfterCallback =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                     .readyDuration = 0,
                                                     .earliestVsync = presentTime};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timingAfterCallback)).WillOnce(Return(0));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());
}

TEST_F(MessageQueueTest, commitWithDurationChange) {
    EXPECT_NO_FATAL_FAILURE(mEventQueue.setDuration(mDifferentDuration));

    const auto timing =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDifferentDuration.count(),
                                                     .readyDuration = 0,
                                                     .earliestVsync = 0};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(0));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());
}

} // namespace
} // namespace android
