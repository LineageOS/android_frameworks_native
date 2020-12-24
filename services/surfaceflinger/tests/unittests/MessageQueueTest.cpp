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

class TestableMessageQueue : public impl::MessageQueue {
public:
    class MockHandler : public MessageQueue::Handler {
    public:
        explicit MockHandler(MessageQueue& queue) : MessageQueue::Handler(queue) {}
        ~MockHandler() override = default;
        MOCK_METHOD2(dispatchInvalidate, void(int64_t vsyncId, nsecs_t expectedVSyncTimestamp));
    };

    TestableMessageQueue() = default;
    ~TestableMessageQueue() override = default;

    void initHandler(const sp<MockHandler>& handler) { mHandler = handler; }

    void triggerVsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime, nsecs_t readyTime) {
        vsyncCallback(vsyncTime, targetWakeupTime, readyTime);
    }
};

class MockVSyncDispatch : public scheduler::VSyncDispatch {
public:
    MockVSyncDispatch() = default;
    ~MockVSyncDispatch() override = default;

    MOCK_METHOD2(registerCallback,
                 CallbackToken(std::function<void(nsecs_t, nsecs_t, nsecs_t)> const&, std::string));
    MOCK_METHOD1(unregisterCallback, void(CallbackToken));
    MOCK_METHOD2(schedule, scheduler::ScheduleResult(CallbackToken, ScheduleTiming));
    MOCK_METHOD1(cancel, scheduler::CancelResult(CallbackToken token));
    MOCK_CONST_METHOD1(dump, void(std::string&));
};

class MockTokenManager : public frametimeline::TokenManager {
public:
    MockTokenManager() = default;
    ~MockTokenManager() override = default;

    MOCK_METHOD1(generateTokenForPredictions, int64_t(frametimeline::TimelineItem&& prediction));
    MOCK_CONST_METHOD1(getPredictionsForToken, std::optional<frametimeline::TimelineItem>(int64_t));
};

class MessageQueueTest : public testing::Test {
public:
    MessageQueueTest() = default;
    ~MessageQueueTest() override = default;

    void SetUp() override {
        EXPECT_NO_FATAL_FAILURE(mEventQueue.initHandler(mHandler));

        EXPECT_CALL(mVSyncDispatch, registerCallback(_, "sf")).WillOnce(Return(mCallbackToken));
        EXPECT_NO_FATAL_FAILURE(mEventQueue.initVsync(mVSyncDispatch, mTokenManager, mDuration));
        EXPECT_CALL(mVSyncDispatch, unregisterCallback(mCallbackToken)).Times(1);
    }

    sp<TestableMessageQueue::MockHandler> mHandler =
            new TestableMessageQueue::MockHandler(mEventQueue);
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
TEST_F(MessageQueueTest, invalidate) {
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};
    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.invalidate());
}

TEST_F(MessageQueueTest, invalidateTwice) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.invalidate());

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.invalidate());
}

TEST_F(MessageQueueTest, invalidateTwiceWithCallback) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.invalidate());

    const auto startTime = 100;
    const auto endTime = startTime + mDuration.count();
    const auto presentTime = 500;
    const auto vsyncId = 42;
    EXPECT_CALL(mTokenManager,
                generateTokenForPredictions(
                        frametimeline::TimelineItem(startTime, endTime, presentTime)))
            .WillOnce(Return(vsyncId));
    EXPECT_CALL(*mHandler, dispatchInvalidate(vsyncId, presentTime)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.triggerVsyncCallback(presentTime, startTime, endTime));

    const auto timingAfterCallback =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDuration.count(),
                                                     .readyDuration = 0,
                                                     .earliestVsync = presentTime};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timingAfterCallback)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.invalidate());
}

TEST_F(MessageQueueTest, invalidateWithDurationChange) {
    EXPECT_NO_FATAL_FAILURE(mEventQueue.setDuration(mDifferentDuration));

    const auto timing =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = mDifferentDuration.count(),
                                                     .readyDuration = 0,
                                                     .earliestVsync = 0};

    EXPECT_CALL(mVSyncDispatch, schedule(mCallbackToken, timing)).Times(1);
    EXPECT_NO_FATAL_FAILURE(mEventQueue.invalidate());
}

} // namespace
} // namespace android
