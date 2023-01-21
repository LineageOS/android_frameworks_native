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

namespace android {

using namespace std::chrono_literals;
using namespace testing;

using CallbackToken = scheduler::VSyncDispatch::CallbackToken;

struct NoOpCompositor final : ICompositor {
    void configure() override {}
    bool commit(const scheduler::FrameTarget&) override { return false; }
    CompositeResult composite(scheduler::FrameTargeter&) override { return {}; }
    void sample() override {}
} gNoOpCompositor;

class TestableMessageQueue : public impl::MessageQueue {
    struct MockHandler : MessageQueue::Handler {
        using MessageQueue::Handler::Handler;

        MOCK_METHOD(void, dispatchFrame, (VsyncId, TimePoint), (override));
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
        EXPECT_NO_FATAL_FAILURE(mEventQueue.initVsync(mVSyncDispatch, mTokenManager, kDuration));
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
                                                                 .earliestVsync = 0};
    EXPECT_FALSE(mEventQueue.getScheduledFrameTime());

    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(1234));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(1234, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());
}

TEST_F(MessageQueueTest, commitTwice) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};

    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(1234));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(1234, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());

    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(4567));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(4567, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());
}

TEST_F(MessageQueueTest, commitTwiceWithCallback) {
    InSequence s;
    const auto timing = scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                                 .readyDuration = 0,
                                                                 .earliestVsync = 0};

    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(1234));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());

    ASSERT_TRUE(mEventQueue.getScheduledFrameTime());
    EXPECT_EQ(1234, mEventQueue.getScheduledFrameTime()->time_since_epoch().count());

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

    EXPECT_FALSE(mEventQueue.getScheduledFrameTime());

    const auto timingAfterCallback =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDuration.ns(),
                                                     .readyDuration = 0,
                                                     .earliestVsync = kPresentTime.ns()};

    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timingAfterCallback)).WillOnce(Return(0));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());
}

TEST_F(MessageQueueTest, commitWithDurationChange) {
    EXPECT_NO_FATAL_FAILURE(mEventQueue.setDuration(kDifferentDuration));

    const auto timing =
            scheduler::VSyncDispatch::ScheduleTiming{.workDuration = kDifferentDuration.ns(),
                                                     .readyDuration = 0,
                                                     .earliestVsync = 0};

    EXPECT_CALL(*mVSyncDispatch, schedule(mCallbackToken, timing)).WillOnce(Return(0));
    EXPECT_NO_FATAL_FAILURE(mEventQueue.scheduleFrame());
}

} // namespace
} // namespace android
