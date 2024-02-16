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
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"
#define LOG_NDEBUG 0

#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <scheduler/TimeKeeper.h>

#include <common/test/FlagUtils.h>
#include "Scheduler/VSyncDispatchTimerQueue.h"
#include "Scheduler/VSyncTracker.h"
#include "mock/MockVSyncTracker.h"

#include <com_android_graphics_surfaceflinger_flags.h>

using namespace testing;
using namespace std::literals;

namespace android::scheduler {
using namespace com::android::graphics::surfaceflinger;

class MockVSyncTracker : public mock::VSyncTracker {
public:
    MockVSyncTracker(nsecs_t period) : mPeriod{period} {
        ON_CALL(*this, nextAnticipatedVSyncTimeFrom(_, _))
                .WillByDefault(Invoke(this, &MockVSyncTracker::nextVSyncTime));
        ON_CALL(*this, addVsyncTimestamp(_)).WillByDefault(Return(true));
        ON_CALL(*this, currentPeriod())
                .WillByDefault(Invoke(this, &MockVSyncTracker::getCurrentPeriod));
    }

    nsecs_t nextVSyncTime(nsecs_t timePoint, std::optional<nsecs_t>) const {
        if (timePoint % mPeriod == 0) {
            return timePoint;
        }
        return (timePoint - (timePoint % mPeriod) + mPeriod);
    }

    nsecs_t getCurrentPeriod() const { return mPeriod; }

protected:
    nsecs_t const mPeriod;
};

class ControllableClock : public TimeKeeper {
public:
    ControllableClock() {
        ON_CALL(*this, alarmAt(_, _))
                .WillByDefault(Invoke(this, &ControllableClock::alarmAtDefaultBehavior));
        ON_CALL(*this, now()).WillByDefault(Invoke(this, &ControllableClock::fakeTime));
    }

    MOCK_METHOD(nsecs_t, now, (), (const));
    MOCK_METHOD(void, alarmAt, (std::function<void()>, nsecs_t), (override));
    MOCK_METHOD(void, alarmCancel, (), (override));
    MOCK_METHOD(void, dump, (std::string&), (const, override));

    void alarmAtDefaultBehavior(std::function<void()> const& callback, nsecs_t time) {
        mCallback = callback;
        mNextCallbackTime = time;
    }

    nsecs_t fakeTime() const { return mCurrentTime; }

    void advanceToNextCallback() {
        mCurrentTime = mNextCallbackTime;
        if (mCallback) {
            mCallback();
        }
    }

    void advanceBy(nsecs_t advancement) {
        mCurrentTime += advancement;
        if (mCurrentTime >= (mNextCallbackTime + mLag) && mCallback) {
            mCallback();
        }
    };

    void setLag(nsecs_t lag) { mLag = lag; }

private:
    std::function<void()> mCallback;
    nsecs_t mNextCallbackTime = 0;
    nsecs_t mCurrentTime = 0;
    nsecs_t mLag = 0;
};

class CountingCallback {
public:
    CountingCallback(std::shared_ptr<VSyncDispatch> dispatch)
          : mDispatch(std::move(dispatch)),
            mToken(mDispatch->registerCallback(std::bind(&CountingCallback::counter, this,
                                                         std::placeholders::_1,
                                                         std::placeholders::_2,
                                                         std::placeholders::_3),
                                               "test")) {}
    ~CountingCallback() { mDispatch->unregisterCallback(mToken); }

    operator VSyncDispatch::CallbackToken() const { return mToken; }

    void counter(nsecs_t time, nsecs_t wakeup_time, nsecs_t readyTime) {
        mCalls.push_back(time);
        mWakeupTime.push_back(wakeup_time);
        mReadyTime.push_back(readyTime);
    }

    std::shared_ptr<VSyncDispatch> mDispatch;
    VSyncDispatch::CallbackToken mToken;
    std::vector<nsecs_t> mCalls;
    std::vector<nsecs_t> mWakeupTime;
    std::vector<nsecs_t> mReadyTime;
};

class PausingCallback {
public:
    PausingCallback(std::shared_ptr<VSyncDispatch> dispatch, std::chrono::milliseconds pauseAmount)
          : mDispatch(std::move(dispatch)),
            mToken(mDispatch->registerCallback(std::bind(&PausingCallback::pause, this,
                                                         std::placeholders::_1,
                                                         std::placeholders::_2),
                                               "test")),
            mRegistered(true),
            mPauseAmount(pauseAmount) {}
    ~PausingCallback() { unregister(); }

    operator VSyncDispatch::CallbackToken() const { return mToken; }

    void pause(nsecs_t, nsecs_t) {
        std::unique_lock lock(mMutex);
        mPause = true;
        mCv.notify_all();

        mCv.wait_for(lock, mPauseAmount, [this] { return !mPause; });

        mResourcePresent = (mResource.lock() != nullptr);
    }

    bool waitForPause() {
        std::unique_lock lock(mMutex);
        auto waiting = mCv.wait_for(lock, 10s, [this] { return mPause; });
        return waiting;
    }

    void stashResource(std::weak_ptr<void> const& resource) { mResource = resource; }

    bool resourcePresent() { return mResourcePresent; }

    void unpause() {
        std::unique_lock lock(mMutex);
        mPause = false;
        mCv.notify_all();
    }

    void unregister() {
        if (mRegistered) {
            mDispatch->unregisterCallback(mToken);
            mRegistered = false;
        }
    }

    std::shared_ptr<VSyncDispatch> mDispatch;
    VSyncDispatch::CallbackToken mToken;
    bool mRegistered = true;

    std::mutex mMutex;
    std::condition_variable mCv;
    bool mPause = false;
    std::weak_ptr<void> mResource;
    bool mResourcePresent = false;
    std::chrono::milliseconds const mPauseAmount;
};

class VSyncDispatchTimerQueueTest : public testing::Test {
protected:
    std::unique_ptr<TimeKeeper> createTimeKeeper() {
        class TimeKeeperWrapper : public TimeKeeper {
        public:
            TimeKeeperWrapper(TimeKeeper& control) : mControllableClock(control) {}

            nsecs_t now() const final { return mControllableClock.now(); }

            void alarmAt(std::function<void()> callback, nsecs_t time) final {
                mControllableClock.alarmAt(std::move(callback), time);
            }

            void alarmCancel() final { mControllableClock.alarmCancel(); }
            void dump(std::string&) const final {}

        private:
            TimeKeeper& mControllableClock;
        };
        return std::make_unique<TimeKeeperWrapper>(mMockClock);
    }

    ~VSyncDispatchTimerQueueTest() {
        // destructor of  dispatch will cancelAlarm(). Ignore final cancel in common test.
        Mock::VerifyAndClearExpectations(&mMockClock);
    }

    void advanceToNextCallback() { mMockClock.advanceToNextCallback(); }

    NiceMock<ControllableClock> mMockClock;
    static nsecs_t constexpr mDispatchGroupThreshold = 5;
    nsecs_t const mPeriod = 1000;
    nsecs_t const mVsyncMoveThreshold = 300;
    std::shared_ptr<NiceMock<MockVSyncTracker>> mStubTracker =
            std::make_shared<NiceMock<MockVSyncTracker>>(mPeriod);
    std::shared_ptr<VSyncDispatch> mDispatch =
            std::make_shared<VSyncDispatchTimerQueue>(createTimeKeeper(), mStubTracker,
                                                      mDispatchGroupThreshold, mVsyncMoveThreshold);
};

TEST_F(VSyncDispatchTimerQueueTest, unregistersSetAlarmOnDestruction) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());
    {
        std::shared_ptr<VSyncDispatch> mDispatch =
                std::make_shared<VSyncDispatchTimerQueue>(createTimeKeeper(), mStubTracker,
                                                          mDispatchGroupThreshold,
                                                          mVsyncMoveThreshold);
        CountingCallback cb(mDispatch);
        const auto result =
                mDispatch->schedule(cb,
                                    {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(900, result->callbackTime.ns());
        EXPECT_EQ(1000, result->vsyncTime.ns());
    }
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFuture) {
    auto intended = mPeriod - 230;
    EXPECT_CALL(mMockClock, alarmAt(_, 900));

    CountingCallback cb(mDispatch);
    const auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 100, .readyDuration = 0, .lastVsync = intended});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(900, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(mPeriod));
}

TEST_F(VSyncDispatchTimerQueueTest, updateAlarmSettingFuture) {
    auto intended = mPeriod - 230;
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 700)).InSequence(seq);

    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 100, .readyDuration = 0, .lastVsync = intended});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(900, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    result =
            mDispatch->update(cb, {.workDuration = 300, .readyDuration = 0, .lastVsync = intended});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(700, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(mPeriod));
    EXPECT_THAT(cb.mWakeupTime[0], Eq(700));
}

TEST_F(VSyncDispatchTimerQueueTest, updateDoesntSchedule) {
    auto intended = mPeriod - 230;
    EXPECT_CALL(mMockClock, alarmAt(_, _)).Times(0);

    CountingCallback cb(mDispatch);
    const auto result =
            mDispatch->update(cb, {.workDuration = 300, .readyDuration = 0, .lastVsync = intended});
    EXPECT_FALSE(result.has_value());
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFutureWithAdjustmentToTrueVsync) {
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(1000, std::optional<nsecs_t>(mPeriod)))
            .WillOnce(Return(1150));
    EXPECT_CALL(mMockClock, alarmAt(_, 1050));

    CountingCallback cb(mDispatch);
    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod});
    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(1150));
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingAdjustmentPast) {
    auto const now = 234;
    mMockClock.advanceBy(234);
    auto const workDuration = 10 * mPeriod;
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(now + workDuration, std::optional<nsecs_t>(mPeriod)))
            .WillOnce(Return(mPeriod * 11));
    EXPECT_CALL(mMockClock, alarmAt(_, mPeriod));

    CountingCallback cb(mDispatch);
    const auto result = mDispatch->schedule(cb,
                                            {.workDuration = workDuration,
                                             .readyDuration = 0,
                                             .lastVsync = mPeriod});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(mPeriod, result->callbackTime.ns());
    EXPECT_EQ(workDuration + mPeriod, result->vsyncTime.ns());
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancel) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb(mDispatch);
    const auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(mPeriod - 100, result->callbackTime.ns());
    EXPECT_EQ(mPeriod, result->vsyncTime.ns());
    EXPECT_EQ(mDispatch->cancel(cb), CancelResult::Cancelled);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancelTooLate) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb(mDispatch);
    const auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(mPeriod - 100, result->callbackTime.ns());
    EXPECT_EQ(mPeriod, result->vsyncTime.ns());
    mMockClock.advanceBy(950);
    EXPECT_EQ(mDispatch->cancel(cb), CancelResult::TooLate);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancelTooLateWhenRunning) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    PausingCallback cb(mDispatch, std::chrono::duration_cast<std::chrono::milliseconds>(1s));
    const auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(mPeriod - 100, result->callbackTime.ns());
    EXPECT_EQ(mPeriod, result->vsyncTime.ns());

    std::thread pausingThread([&] { mMockClock.advanceToNextCallback(); });
    EXPECT_TRUE(cb.waitForPause());
    EXPECT_EQ(mDispatch->cancel(cb), CancelResult::TooLate);
    cb.unpause();
    pausingThread.join();
}

TEST_F(VSyncDispatchTimerQueueTest, unregisterSynchronizes) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    auto resource = std::make_shared<int>(110);

    PausingCallback cb(mDispatch, 50ms);
    cb.stashResource(resource);
    const auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(mPeriod - 100, result->callbackTime.ns());
    EXPECT_EQ(mPeriod, result->vsyncTime.ns());

    std::thread pausingThread([&] { mMockClock.advanceToNextCallback(); });
    EXPECT_TRUE(cb.waitForPause());

    cb.unregister();
    resource.reset();

    cb.unpause();
    pausingThread.join();

    EXPECT_TRUE(cb.resourcePresent());
}

TEST_F(VSyncDispatchTimerQueueTest, basicTwoAlarmSetting) {
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(1000, std::optional<nsecs_t>(1000)))
            .Times(4)
            .WillOnce(Return(1055))
            .WillOnce(Return(1063))
            .WillOnce(Return(1063))
            .WillOnce(Return(1075));

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 955)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 813)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 975)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod});
    mDispatch->schedule(cb1, {.workDuration = 250, .readyDuration = 0, .lastVsync = mPeriod});

    advanceToNextCallback();
    advanceToNextCallback();

    ASSERT_THAT(cb0.mCalls.size(), Eq(1));
    EXPECT_THAT(cb0.mCalls[0], Eq(1075));
    ASSERT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb1.mCalls[0], Eq(1063));
}

TEST_F(VSyncDispatchTimerQueueTest, noCloseCallbacksAfterPeriodChange) {
    EXPECT_CALL(*mStubTracker.get(), nextAnticipatedVSyncTimeFrom(_, _))
            .Times(4)
            .WillOnce(Return(1000))
            .WillOnce(Return(2000))
            .WillOnce(Return(2500))
            .WillOnce(Return(4000));

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 3900)).InSequence(seq);

    CountingCallback cb(mDispatch);

    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 0});

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(1000));

    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(2));
    EXPECT_THAT(cb.mCalls[1], Eq(2000));

    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 2000});

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(3));
    EXPECT_THAT(cb.mCalls[2], Eq(4000));
}

TEST_F(VSyncDispatchTimerQueueTest, rearmsFaroutTimeoutWhenCancellingCloseOne) {
    EXPECT_CALL(*mStubTracker.get(), nextAnticipatedVSyncTimeFrom(_, _))
            .Times(4)
            .WillOnce(Return(10000))
            .WillOnce(Return(1000))
            .WillOnce(Return(10000))
            .WillOnce(Return(10000));

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 9900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 750)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 9900)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 100, .readyDuration = 0, .lastVsync = mPeriod * 10});
    mDispatch->schedule(cb1, {.workDuration = 250, .readyDuration = 0, .lastVsync = mPeriod});
    mDispatch->cancel(cb1);
}

TEST_F(VSyncDispatchTimerQueueTest, noUnnecessaryRearmsWhenRescheduling) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 700)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 200, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 300, .readyDuration = 0, .lastVsync = 1000});
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, necessaryRearmsWhenModifying) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 200, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, modifyIntoGroup) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1590)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1600)).InSequence(seq);

    auto offset = 400;
    auto closeOffset = offset + mDispatchGroupThreshold - 1;
    auto notCloseOffset = offset + 2 * mDispatchGroupThreshold;

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 200, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = closeOffset, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();
    ASSERT_THAT(cb0.mCalls.size(), Eq(1));
    EXPECT_THAT(cb0.mCalls[0], Eq(mPeriod));
    ASSERT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb1.mCalls[0], Eq(mPeriod));

    mDispatch->schedule(cb0, {.workDuration = 400, .readyDuration = 0, .lastVsync = 2000});
    mDispatch->schedule(cb1,
                        {.workDuration = notCloseOffset, .readyDuration = 0, .lastVsync = 2000});
    advanceToNextCallback();
    ASSERT_THAT(cb1.mCalls.size(), Eq(2));
    EXPECT_THAT(cb1.mCalls[1], Eq(2000));

    advanceToNextCallback();
    ASSERT_THAT(cb0.mCalls.size(), Eq(2));
    EXPECT_THAT(cb0.mCalls[1], Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueTest, rearmsWhenEndingAndDoesntCancel) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 800)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 200, .readyDuration = 0, .lastVsync = 1000});
    advanceToNextCallback();
    EXPECT_EQ(mDispatch->cancel(cb0), CancelResult::Cancelled);
}

TEST_F(VSyncDispatchTimerQueueTest, setAlarmCallsAtCorrectTimeWithChangingVsync) {
    EXPECT_CALL(*mStubTracker.get(), nextAnticipatedVSyncTimeFrom(_, _))
            .Times(3)
            .WillOnce(Return(950))
            .WillOnce(Return(1975))
            .WillOnce(Return(2950));

    CountingCallback cb(mDispatch);
    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 920});

    mMockClock.advanceBy(850);
    EXPECT_THAT(cb.mCalls.size(), Eq(1));

    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1900});
    mMockClock.advanceBy(900);
    EXPECT_THAT(cb.mCalls.size(), Eq(1));
    mMockClock.advanceBy(125);
    EXPECT_THAT(cb.mCalls.size(), Eq(2));

    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 2900});
    mMockClock.advanceBy(975);
    EXPECT_THAT(cb.mCalls.size(), Eq(3));
}

TEST_F(VSyncDispatchTimerQueueTest, callbackReentrancy) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);

    VSyncDispatch::CallbackToken tmp;
    tmp = mDispatch->registerCallback(
            [&](auto, auto, auto) {
                mDispatch->schedule(tmp,
                                    {.workDuration = 100, .readyDuration = 0, .lastVsync = 2000});
            },
            "o.o");

    mDispatch->schedule(tmp, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, callbackReentrantWithPastWakeup) {
    VSyncDispatch::CallbackToken tmp;
    std::optional<nsecs_t> lastTarget;
    tmp = mDispatch->registerCallback(
            [&](auto timestamp, auto, auto) {
                auto result = mDispatch->schedule(tmp,
                                                  {.workDuration = 400,
                                                   .readyDuration = 0,
                                                   .lastVsync = timestamp - mVsyncMoveThreshold});
                EXPECT_TRUE(result.has_value());
                EXPECT_EQ(mPeriod + timestamp - 400, result->callbackTime.ns());
                EXPECT_EQ(mPeriod + timestamp, result->vsyncTime.ns());
                result = mDispatch->schedule(tmp,
                                             {.workDuration = 400,
                                              .readyDuration = 0,
                                              .lastVsync = timestamp});
                EXPECT_TRUE(result.has_value());
                EXPECT_EQ(mPeriod + timestamp - 400, result->callbackTime.ns());
                EXPECT_EQ(mPeriod + timestamp, result->vsyncTime.ns());
                result = mDispatch->schedule(tmp,
                                             {.workDuration = 400,
                                              .readyDuration = 0,
                                              .lastVsync = timestamp + mVsyncMoveThreshold});
                EXPECT_TRUE(result.has_value());
                EXPECT_EQ(mPeriod + timestamp - 400, result->callbackTime.ns());
                EXPECT_EQ(mPeriod + timestamp, result->vsyncTime.ns());
                lastTarget = timestamp;
            },
            "oo");

    mDispatch->schedule(tmp, {.workDuration = 999, .readyDuration = 0, .lastVsync = 1000});
    advanceToNextCallback();
    EXPECT_THAT(lastTarget, Eq(1000));

    advanceToNextCallback();
    EXPECT_THAT(lastTarget, Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueTest, modificationsAroundVsyncTime) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 1000)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 950)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1950)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);

    CountingCallback cb(mDispatch);
    mDispatch->schedule(cb, {.workDuration = 0, .readyDuration = 0, .lastVsync = 1000});

    mMockClock.advanceBy(750);
    mDispatch->schedule(cb, {.workDuration = 50, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();
    mDispatch->schedule(cb, {.workDuration = 50, .readyDuration = 0, .lastVsync = 2000});

    mMockClock.advanceBy(800);
    mDispatch->schedule(cb, {.workDuration = 100, .readyDuration = 0, .lastVsync = 2000});
}

TEST_F(VSyncDispatchTimerQueueTest, lateModifications) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 850)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1800)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch->schedule(cb0, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();
    mDispatch->schedule(cb0, {.workDuration = 200, .readyDuration = 0, .lastVsync = 2000});
    mDispatch->schedule(cb1, {.workDuration = 150, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, doesntCancelPriorValidTimerForFutureMod) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);
    mDispatch->schedule(cb0, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb1, {.workDuration = 500, .readyDuration = 0, .lastVsync = 20000});
}

TEST_F(VSyncDispatchTimerQueueTest, setsTimerAfterCancellation) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    mDispatch->schedule(cb0, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->cancel(cb0);
    mDispatch->schedule(cb0, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
}

TEST_F(VSyncDispatchTimerQueueTest, makingUpIdsError) {
    VSyncDispatch::CallbackToken token(100);
    EXPECT_FALSE(
            mDispatch->schedule(token, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000})
                    .has_value());
    EXPECT_THAT(mDispatch->cancel(token), Eq(CancelResult::Error));
}

TEST_F(VSyncDispatchTimerQueueTest, canMoveCallbackBackwardsInTime) {
    CountingCallback cb0(mDispatch);
    auto result =
            mDispatch->schedule(cb0, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    result = mDispatch->schedule(cb0, {.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(900, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
}

// b/1450138150
TEST_F(VSyncDispatchTimerQueueTest, doesNotMoveCallbackBackwardsAndSkipAScheduledTargetVSync) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, false);

    EXPECT_CALL(mMockClock, alarmAt(_, 500));
    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    mMockClock.advanceBy(400);

    result = mDispatch->schedule(cb, {.workDuration = 800, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1200, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());

    advanceToNextCallback();
    ASSERT_THAT(cb.mCalls.size(), Eq(1));
}

// b/1450138150
TEST_F(VSyncDispatchTimerQueueTest, movesCallbackBackwardsAndSkipAScheduledTargetVSync) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, true);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 400)).InSequence(seq);
    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    mMockClock.advanceBy(400);

    result = mDispatch->schedule(cb, {.workDuration = 800, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(400, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    advanceToNextCallback();
    ASSERT_THAT(cb.mCalls.size(), Eq(1));
}

TEST_F(VSyncDispatchTimerQueueTest, targetOffsetMovingBackALittleCanStillSchedule) {
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(1000, std::optional<nsecs_t>(1000)))
            .Times(2)
            .WillOnce(Return(1000))
            .WillOnce(Return(1002));
    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    mMockClock.advanceBy(400);
    result = mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(602, result->callbackTime.ns());
    EXPECT_EQ(1002, result->vsyncTime.ns());
}

TEST_F(VSyncDispatchTimerQueueTest, canScheduleNegativeOffsetAgainstDifferentPeriods) {
    CountingCallback cb0(mDispatch);
    auto result =
            mDispatch->schedule(cb0, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    advanceToNextCallback();
    result =
            mDispatch->schedule(cb0, {.workDuration = 1100, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(900, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());
}

TEST_F(VSyncDispatchTimerQueueTest, canScheduleLargeNegativeOffset) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1100)).InSequence(seq);
    CountingCallback cb0(mDispatch);
    auto result =
            mDispatch->schedule(cb0, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    advanceToNextCallback();
    result =
            mDispatch->schedule(cb0, {.workDuration = 1900, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1100, result->callbackTime.ns());
    EXPECT_EQ(3000, result->vsyncTime.ns());
}

TEST_F(VSyncDispatchTimerQueueTest, scheduleUpdatesDoesNotAffectSchedulingState) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, false);

    EXPECT_CALL(mMockClock, alarmAt(_, 600));

    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    result = mDispatch->schedule(cb, {.workDuration = 1400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());

    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, scheduleUpdatesDoesAffectSchedulingState) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, true);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 0)).InSequence(seq);

    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    result = mDispatch->schedule(cb, {.workDuration = 1400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(0, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, helperMove) {
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).Times(1);
    EXPECT_CALL(mMockClock, alarmCancel()).Times(1);

    VSyncCallbackRegistration cb(
            mDispatch, [](auto, auto, auto) {}, "");
    VSyncCallbackRegistration cb1(std::move(cb));
    cb.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
    cb.cancel();

    cb1.schedule({.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    cb1.cancel();
}

TEST_F(VSyncDispatchTimerQueueTest, helperMoveAssign) {
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).Times(1);
    EXPECT_CALL(mMockClock, alarmCancel()).Times(1);

    VSyncCallbackRegistration cb(
            mDispatch, [](auto, auto, auto) {}, "");
    VSyncCallbackRegistration cb1(
            mDispatch, [](auto, auto, auto) {}, "");
    cb1 = std::move(cb);
    cb.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 1000});
    cb.cancel();

    cb1.schedule({.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    cb1.cancel();
}

// b/154303580
TEST_F(VSyncDispatchTimerQueueTest, skipsSchedulingIfTimerReschedulingIsImminent) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    auto result =
            mDispatch->schedule(cb1, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    result = mDispatch->schedule(cb2, {.workDuration = 100, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1900, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());
    mMockClock.advanceBy(80);

    EXPECT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb2.mCalls.size(), Eq(0));
}

// b/154303580.
// If the same callback tries to reschedule itself after it's too late, timer opts to apply the
// update later, as opposed to blocking the calling thread.
TEST_F(VSyncDispatchTimerQueueTest, skipsSchedulingIfTimerReschedulingIsImminentSameCallback) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, false);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1630)).InSequence(seq);
    CountingCallback cb(mDispatch);

    auto result =
            mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    result = mDispatch->schedule(cb, {.workDuration = 370, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1630, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());
    mMockClock.advanceBy(80);

    EXPECT_THAT(cb.mCalls.size(), Eq(1));
}

// b/154303580.
// If the same callback tries to reschedule itself after it's too late, timer opts to apply the
// update later, as opposed to blocking the calling thread.
TEST_F(VSyncDispatchTimerQueueTest, doesntSkipSchedulingIfTimerReschedulingIsImminentSameCallback) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, true);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1630)).InSequence(seq);
    CountingCallback cb(mDispatch);

    auto result =
            mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    result = mDispatch->schedule(cb, {.workDuration = 370, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    mMockClock.advanceBy(80);

    ASSERT_EQ(1, cb.mCalls.size());
    EXPECT_EQ(1000, cb.mCalls[0]);

    ASSERT_EQ(1, cb.mWakeupTime.size());
    EXPECT_EQ(600, cb.mWakeupTime[0]);
}

// b/154303580.
TEST_F(VSyncDispatchTimerQueueTest, skipsRearmingWhenNotNextScheduled) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    auto result =
            mDispatch->schedule(cb1, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    result = mDispatch->schedule(cb2, {.workDuration = 100, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1900, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch->cancel(cb2), CancelResult::Cancelled);

    mMockClock.advanceBy(80);

    EXPECT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb2.mCalls.size(), Eq(0));
}

TEST_F(VSyncDispatchTimerQueueTest, rearmsWhenCancelledAndIsNextScheduled) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    auto result =
            mDispatch->schedule(cb1, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    result = mDispatch->schedule(cb2, {.workDuration = 100, .readyDuration = 0, .lastVsync = 2000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1900, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch->cancel(cb1), CancelResult::Cancelled);

    EXPECT_THAT(cb1.mCalls.size(), Eq(0));
    EXPECT_THAT(cb2.mCalls.size(), Eq(0));
    mMockClock.advanceToNextCallback();

    EXPECT_THAT(cb1.mCalls.size(), Eq(0));
    EXPECT_THAT(cb2.mCalls.size(), Eq(1));
}

TEST_F(VSyncDispatchTimerQueueTest, laggedTimerGroupsCallbacksWithinLag) {
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    Sequence seq;
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(1000, std::optional<nsecs_t>(1000)))
            .InSequence(seq)
            .WillOnce(Return(1000));
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(1000, std::optional<nsecs_t>(1000)))
            .InSequence(seq)
            .WillOnce(Return(1000));

    auto result =
            mDispatch->schedule(cb1, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(600, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    result = mDispatch->schedule(cb2, {.workDuration = 390, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(610, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    mMockClock.setLag(100);
    mMockClock.advanceBy(700);

    ASSERT_THAT(cb1.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb1.mWakeupTime[0], Eq(600));
    ASSERT_THAT(cb1.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb1.mReadyTime[0], Eq(1000));
    ASSERT_THAT(cb2.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb2.mWakeupTime[0], Eq(610));
    ASSERT_THAT(cb2.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb2.mReadyTime[0], Eq(1000));
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFutureWithReadyDuration) {
    auto intended = mPeriod - 230;
    EXPECT_CALL(mMockClock, alarmAt(_, 900));

    CountingCallback cb(mDispatch);
    const auto result =
            mDispatch->schedule(cb,
                                {.workDuration = 70, .readyDuration = 30, .lastVsync = intended});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(900, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(mPeriod));
    ASSERT_THAT(cb.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb.mWakeupTime[0], 900);
    ASSERT_THAT(cb.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb.mReadyTime[0], 970);
}

TEST_F(VSyncDispatchTimerQueueTest, updatesVsyncTimeForCloseWakeupTime) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, false);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);

    CountingCallback cb(mDispatch);

    mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb, {.workDuration = 1400, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(2000));
    ASSERT_THAT(cb.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb.mWakeupTime[0], Eq(600));
    ASSERT_THAT(cb.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb.mReadyTime[0], Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueTest, doesNotUpdatesVsyncTimeForCloseWakeupTime) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, true);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 0)).InSequence(seq);

    CountingCallback cb(mDispatch);

    mDispatch->schedule(cb, {.workDuration = 400, .readyDuration = 0, .lastVsync = 1000});
    mDispatch->schedule(cb, {.workDuration = 1400, .readyDuration = 0, .lastVsync = 1000});

    advanceToNextCallback();

    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(1000));
    ASSERT_THAT(cb.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb.mWakeupTime[0], Eq(0));
    ASSERT_THAT(cb.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb.mReadyTime[0], Eq(1000));
}

TEST_F(VSyncDispatchTimerQueueTest, skipAVsyc) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, false);

    EXPECT_CALL(mMockClock, alarmAt(_, 500));
    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    mMockClock.advanceBy(300);

    result = mDispatch->schedule(cb, {.workDuration = 800, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1200, result->callbackTime.ns());
    EXPECT_EQ(2000, result->vsyncTime.ns());

    advanceToNextCallback();
    ASSERT_THAT(cb.mCalls.size(), Eq(1));
}

TEST_F(VSyncDispatchTimerQueueTest, dontskipAVsyc) {
    SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, true);

    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 300)).InSequence(seq);
    CountingCallback cb(mDispatch);
    auto result =
            mDispatch->schedule(cb, {.workDuration = 500, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(500, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());
    mMockClock.advanceBy(300);

    result = mDispatch->schedule(cb, {.workDuration = 800, .readyDuration = 0, .lastVsync = 1000});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(300, result->callbackTime.ns());
    EXPECT_EQ(1000, result->vsyncTime.ns());

    advanceToNextCallback();
    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(1000));
    ASSERT_THAT(cb.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb.mWakeupTime[0], Eq(300));
    ASSERT_THAT(cb.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb.mReadyTime[0], Eq(1000));
}

class VSyncDispatchTimerQueueEntryTest : public testing::Test {
protected:
    nsecs_t const mPeriod = 1000;
    nsecs_t const mVsyncMoveThreshold = 200;
    std::shared_ptr<NiceMock<MockVSyncTracker>> mStubTracker =
            std::make_shared<NiceMock<MockVSyncTracker>>(mPeriod);
};

TEST_F(VSyncDispatchTimerQueueEntryTest, stateAfterInitialization) {
    std::string name("basicname");
    VSyncDispatchTimerQueueEntry entry(
            name, [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.name(), Eq(name));
    EXPECT_FALSE(entry.lastExecutedVsyncTarget());
    EXPECT_FALSE(entry.wakeupTime());
}

TEST_F(VSyncDispatchTimerQueueEntryTest, stateScheduling) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    const auto scheduleResult =
            entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                           *mStubTracker, 0);
    EXPECT_EQ(900, scheduleResult.callbackTime.ns());
    EXPECT_EQ(1000, scheduleResult.vsyncTime.ns());
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(900));

    entry.disarm();
    EXPECT_FALSE(entry.wakeupTime());
}

TEST_F(VSyncDispatchTimerQueueEntryTest, stateSchedulingReallyLongWakeupLatency) {
    auto const duration = 500;
    auto const now = 8750;

    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(now + duration, std::optional<nsecs_t>(994)))
            .Times(1)
            .WillOnce(Return(10000));
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    const auto scheduleResult =
            entry.schedule({.workDuration = 500, .readyDuration = 0, .lastVsync = 994},
                           *mStubTracker, now);
    EXPECT_EQ(9500, scheduleResult.callbackTime.ns());
    EXPECT_EQ(10000, scheduleResult.vsyncTime.ns());
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(9500));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, runCallback) {
    auto callCount = 0;
    auto vsyncCalledTime = 0;
    auto wakeupCalledTime = 0;
    auto readyCalledTime = 0;
    VSyncDispatchTimerQueueEntry entry(
            "test",
            [&](auto vsyncTime, auto wakeupTime, auto readyTime) {
                callCount++;
                vsyncCalledTime = vsyncTime;
                wakeupCalledTime = wakeupTime;
                readyCalledTime = readyTime;
            },
            mVsyncMoveThreshold);

    const auto scheduleResult =
            entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                           *mStubTracker, 0);
    EXPECT_EQ(900, scheduleResult.callbackTime.ns());
    EXPECT_EQ(1000, scheduleResult.vsyncTime.ns());
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(900));

    auto const ready = entry.readyTime();
    ASSERT_TRUE(ready);
    EXPECT_THAT(*ready, Eq(1000));

    entry.callback(entry.executing(), *wakeup, *ready);

    EXPECT_THAT(callCount, Eq(1));
    EXPECT_THAT(vsyncCalledTime, Eq(mPeriod));
    EXPECT_THAT(wakeupCalledTime, Eq(*wakeup));
    EXPECT_FALSE(entry.wakeupTime());
    auto lastCalledTarget = entry.lastExecutedVsyncTarget();
    ASSERT_TRUE(lastCalledTarget);
    EXPECT_THAT(*lastCalledTarget, Eq(mPeriod));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, updateCallback) {
    EXPECT_CALL(*mStubTracker.get(), nextAnticipatedVSyncTimeFrom(_, _))
            .Times(2)
            .WillOnce(Return(1000))
            .WillOnce(Return(1020));

    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    entry.update(*mStubTracker, 0);
    EXPECT_FALSE(entry.wakeupTime());

    const auto scheduleResult =
            entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                           *mStubTracker, 0);
    EXPECT_EQ(900, scheduleResult.callbackTime.ns());
    EXPECT_EQ(1000, scheduleResult.vsyncTime.ns());
    auto wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(wakeup, Eq(900));

    entry.update(*mStubTracker, 0);
    wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(920));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, skipsUpdateIfJustScheduled) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_EQ(900,
              entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                             *mStubTracker.get(), 0)
                      .callbackTime.ns());
    entry.update(*mStubTracker.get(), 0);

    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(wakeup));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, willSnapToNextTargettableVSync) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    auto scheduleResult =
            entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                           *mStubTracker, 0);

    EXPECT_EQ(900, scheduleResult.callbackTime.ns());
    EXPECT_EQ(1000, scheduleResult.vsyncTime.ns());
    entry.executing(); // 1000 is executing
    // had 1000 not been executing, this could have been scheduled for time 800.
    scheduleResult = entry.schedule({.workDuration = 200, .readyDuration = 0, .lastVsync = 500},
                                    *mStubTracker, 0);
    EXPECT_EQ(1800, scheduleResult.callbackTime.ns());
    EXPECT_EQ(2000, scheduleResult.vsyncTime.ns());
    EXPECT_THAT(*entry.wakeupTime(), Eq(1800));
    EXPECT_THAT(*entry.readyTime(), Eq(2000));

    scheduleResult = entry.schedule({.workDuration = 50, .readyDuration = 0, .lastVsync = 500},
                                    *mStubTracker, 0);
    EXPECT_EQ(1950, scheduleResult.callbackTime.ns());
    EXPECT_EQ(2000, scheduleResult.vsyncTime.ns());
    EXPECT_THAT(*entry.wakeupTime(), Eq(1950));
    EXPECT_THAT(*entry.readyTime(), Eq(2000));

    scheduleResult = entry.schedule({.workDuration = 200, .readyDuration = 0, .lastVsync = 1001},
                                    *mStubTracker, 0);
    EXPECT_EQ(1800, scheduleResult.callbackTime.ns());
    EXPECT_EQ(2000, scheduleResult.vsyncTime.ns());
    EXPECT_THAT(*entry.wakeupTime(), Eq(1800));
    EXPECT_THAT(*entry.readyTime(), Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueEntryTest,
       willRequestNextEstimateWhenSnappingToNextTargettableVSync) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    Sequence seq;
    EXPECT_CALL(*mStubTracker.get(), nextAnticipatedVSyncTimeFrom(500, std::optional<nsecs_t>(500)))
            .InSequence(seq)
            .WillOnce(Return(1000));
    EXPECT_CALL(*mStubTracker.get(), nextAnticipatedVSyncTimeFrom(500, std::optional<nsecs_t>(500)))
            .InSequence(seq)
            .WillOnce(Return(1000));
    EXPECT_CALL(*mStubTracker.get(),
                nextAnticipatedVSyncTimeFrom(1000 + mVsyncMoveThreshold,
                                             std::optional<nsecs_t>(1000)))
            .InSequence(seq)
            .WillOnce(Return(2000));

    auto scheduleResult =
            entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                           *mStubTracker, 0);
    EXPECT_EQ(900, scheduleResult.callbackTime.ns());
    EXPECT_EQ(1000, scheduleResult.vsyncTime.ns());

    entry.executing(); // 1000 is executing

    scheduleResult = entry.schedule({.workDuration = 200, .readyDuration = 0, .lastVsync = 500},
                                    *mStubTracker, 0);
    EXPECT_EQ(1800, scheduleResult.callbackTime.ns());
    EXPECT_EQ(2000, scheduleResult.vsyncTime.ns());
}

TEST_F(VSyncDispatchTimerQueueEntryTest, reportsScheduledIfStillTime) {
    VSyncDispatchTimerQueueEntry entry("test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_EQ(900,
              entry.schedule({.workDuration = 100, .readyDuration = 0, .lastVsync = 500},
                             *mStubTracker, 0)
                      .callbackTime.ns());
    EXPECT_EQ(800,
              entry.schedule({.workDuration = 200, .readyDuration = 0, .lastVsync = 500},
                             *mStubTracker, 0)
                      .callbackTime.ns());
    EXPECT_EQ(950,
              entry.schedule({.workDuration = 50, .readyDuration = 0, .lastVsync = 500},
                             *mStubTracker, 0)
                      .callbackTime.ns());
    {
        SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, true);
        EXPECT_EQ(0,
                  entry.schedule({.workDuration = 1200, .readyDuration = 0, .lastVsync = 500},
                                 *mStubTracker, 0)
                          .callbackTime.ns());
    }
    {
        SET_FLAG_FOR_TEST(flags::dont_skip_on_early_ro, false);
        EXPECT_EQ(800,
                  entry.schedule({.workDuration = 1200, .readyDuration = 0, .lastVsync = 500},
                                 *mStubTracker, 0)
                          .callbackTime.ns());
    }
}

TEST_F(VSyncDispatchTimerQueueEntryTest, storesPendingUpdatesUntilUpdateAndDontSkip) {
    static constexpr auto effectualOffset = 200;
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_FALSE(entry.hasPendingWorkloadUpdate());
    entry.addPendingWorkloadUpdate(*mStubTracker.get(), 0,
                                   {.workDuration = 100, .readyDuration = 0, .lastVsync = 400});
    entry.addPendingWorkloadUpdate(*mStubTracker.get(), 0,
                                   {.workDuration = effectualOffset,
                                    .readyDuration = 0,
                                    .lastVsync = 400});
    EXPECT_TRUE(entry.hasPendingWorkloadUpdate());
    entry.update(*mStubTracker, 0);
    EXPECT_FALSE(entry.hasPendingWorkloadUpdate());
    EXPECT_THAT(*entry.wakeupTime(), Eq(mPeriod - effectualOffset));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, runCallbackWithReadyDuration) {
    auto callCount = 0;
    auto vsyncCalledTime = 0;
    auto wakeupCalledTime = 0;
    auto readyCalledTime = 0;
    VSyncDispatchTimerQueueEntry entry(
            "test",
            [&](auto vsyncTime, auto wakeupTime, auto readyTime) {
                callCount++;
                vsyncCalledTime = vsyncTime;
                wakeupCalledTime = wakeupTime;
                readyCalledTime = readyTime;
            },
            mVsyncMoveThreshold);

    const auto scheduleResult =
            entry.schedule({.workDuration = 70, .readyDuration = 30, .lastVsync = 500},
                           *mStubTracker, 0);
    EXPECT_EQ(900, scheduleResult.callbackTime.ns());
    EXPECT_EQ(mPeriod, scheduleResult.vsyncTime.ns());
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(900));

    auto const ready = entry.readyTime();
    ASSERT_TRUE(ready);
    EXPECT_THAT(*ready, Eq(970));

    entry.callback(entry.executing(), *wakeup, *ready);

    EXPECT_THAT(callCount, Eq(1));
    EXPECT_THAT(vsyncCalledTime, Eq(mPeriod));
    EXPECT_THAT(wakeupCalledTime, Eq(*wakeup));
    EXPECT_FALSE(entry.wakeupTime());
    auto lastCalledTarget = entry.lastExecutedVsyncTarget();
    ASSERT_TRUE(lastCalledTarget);
    EXPECT_THAT(*lastCalledTarget, Eq(mPeriod));
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
