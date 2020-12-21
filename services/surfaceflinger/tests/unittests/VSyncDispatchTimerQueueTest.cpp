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

#include "Scheduler/TimeKeeper.h"
#include "Scheduler/VSyncDispatchTimerQueue.h"
#include "Scheduler/VSyncTracker.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

using namespace testing;
using namespace std::literals;
namespace android::scheduler {

class MockVSyncTracker : public VSyncTracker {
public:
    MockVSyncTracker(nsecs_t period) : mPeriod{period} {
        ON_CALL(*this, nextAnticipatedVSyncTimeFrom(_))
                .WillByDefault(Invoke(this, &MockVSyncTracker::nextVSyncTime));
        ON_CALL(*this, addVsyncTimestamp(_)).WillByDefault(Return(true));
    }

    MOCK_METHOD1(addVsyncTimestamp, bool(nsecs_t));
    MOCK_CONST_METHOD1(nextAnticipatedVSyncTimeFrom, nsecs_t(nsecs_t));
    MOCK_CONST_METHOD0(currentPeriod, nsecs_t());
    MOCK_METHOD1(setPeriod, void(nsecs_t));
    MOCK_METHOD0(resetModel, void());
    MOCK_CONST_METHOD0(needsMoreSamples, bool());
    MOCK_CONST_METHOD2(isVSyncInPhase, bool(nsecs_t, int));
    MOCK_CONST_METHOD1(dump, void(std::string&));

    nsecs_t nextVSyncTime(nsecs_t timePoint) const {
        if (timePoint % mPeriod == 0) {
            return timePoint;
        }
        return (timePoint - (timePoint % mPeriod) + mPeriod);
    }

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

    MOCK_CONST_METHOD0(now, nsecs_t());
    MOCK_METHOD2(alarmAt, void(std::function<void()> const&, nsecs_t time));
    MOCK_METHOD0(alarmCancel, void());
    MOCK_CONST_METHOD1(dump, void(std::string&));

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
    CountingCallback(VSyncDispatch& dispatch)
          : mDispatch(dispatch),
            mToken(dispatch.registerCallback(std::bind(&CountingCallback::counter, this,
                                                       std::placeholders::_1, std::placeholders::_2,
                                                       std::placeholders::_3),
                                             "test")) {}
    ~CountingCallback() { mDispatch.unregisterCallback(mToken); }

    operator VSyncDispatch::CallbackToken() const { return mToken; }

    void counter(nsecs_t time, nsecs_t wakeup_time, nsecs_t readyTime) {
        mCalls.push_back(time);
        mWakeupTime.push_back(wakeup_time);
        mReadyTime.push_back(readyTime);
    }

    VSyncDispatch& mDispatch;
    VSyncDispatch::CallbackToken mToken;
    std::vector<nsecs_t> mCalls;
    std::vector<nsecs_t> mWakeupTime;
    std::vector<nsecs_t> mReadyTime;
};

class PausingCallback {
public:
    PausingCallback(VSyncDispatch& dispatch, std::chrono::milliseconds pauseAmount)
          : mDispatch(dispatch),
            mToken(dispatch.registerCallback(std::bind(&PausingCallback::pause, this,
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
            mDispatch.unregisterCallback(mToken);
            mRegistered = false;
        }
    }

    VSyncDispatch& mDispatch;
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
            void alarmAt(std::function<void()> const& callback, nsecs_t time) final {
                mControllableClock.alarmAt(callback, time);
            }
            void alarmCancel() final { mControllableClock.alarmCancel(); }
            nsecs_t now() const final { return mControllableClock.now(); }
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
    NiceMock<MockVSyncTracker> mStubTracker{mPeriod};
    VSyncDispatchTimerQueue mDispatch{createTimeKeeper(), mStubTracker, mDispatchGroupThreshold,
                                      mVsyncMoveThreshold};
};

TEST_F(VSyncDispatchTimerQueueTest, unregistersSetAlarmOnDestruction) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());
    {
        VSyncDispatchTimerQueue mDispatch{createTimeKeeper(), mStubTracker, mDispatchGroupThreshold,
                                          mVsyncMoveThreshold};
        CountingCallback cb(mDispatch);
        EXPECT_EQ(mDispatch.schedule(cb,
                                     {.workDuration = 100,
                                      .readyDuration = 0,
                                      .earliestVsync = 1000}),
                  ScheduleResult::Scheduled);
    }
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFuture) {
    auto intended = mPeriod - 230;
    EXPECT_CALL(mMockClock, alarmAt(_, 900));

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 100,
                                  .readyDuration = 0,
                                  .earliestVsync = intended}),
              ScheduleResult::Scheduled);
    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(mPeriod));
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFutureWithAdjustmentToTrueVsync) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000)).WillOnce(Return(1150));
    EXPECT_CALL(mMockClock, alarmAt(_, 1050));

    CountingCallback cb(mDispatch);
    mDispatch.schedule(cb, {.workDuration = 100, .readyDuration = 0, .earliestVsync = mPeriod});
    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(1150));
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingAdjustmentPast) {
    auto const now = 234;
    mMockClock.advanceBy(234);
    auto const workDuration = 10 * mPeriod;
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(now + workDuration))
            .WillOnce(Return(mPeriod * 11));
    EXPECT_CALL(mMockClock, alarmAt(_, mPeriod));

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = workDuration,
                                  .readyDuration = 0,
                                  .earliestVsync = mPeriod}),
              ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancel) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 100,
                                  .readyDuration = 0,
                                  .earliestVsync = mPeriod}),
              ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.cancel(cb), CancelResult::Cancelled);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancelTooLate) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 100,
                                  .readyDuration = 0,
                                  .earliestVsync = mPeriod}),
              ScheduleResult::Scheduled);
    mMockClock.advanceBy(950);
    EXPECT_EQ(mDispatch.cancel(cb), CancelResult::TooLate);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancelTooLateWhenRunning) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    PausingCallback cb(mDispatch, std::chrono::duration_cast<std::chrono::milliseconds>(1s));
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 100,
                                  .readyDuration = 0,
                                  .earliestVsync = mPeriod}),
              ScheduleResult::Scheduled);

    std::thread pausingThread([&] { mMockClock.advanceToNextCallback(); });
    EXPECT_TRUE(cb.waitForPause());
    EXPECT_EQ(mDispatch.cancel(cb), CancelResult::TooLate);
    cb.unpause();
    pausingThread.join();
}

TEST_F(VSyncDispatchTimerQueueTest, unregisterSynchronizes) {
    EXPECT_CALL(mMockClock, alarmAt(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    auto resource = std::make_shared<int>(110);

    PausingCallback cb(mDispatch, 50ms);
    cb.stashResource(resource);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 100,
                                  .readyDuration = 0,
                                  .earliestVsync = mPeriod}),
              ScheduleResult::Scheduled);

    std::thread pausingThread([&] { mMockClock.advanceToNextCallback(); });
    EXPECT_TRUE(cb.waitForPause());

    cb.unregister();
    resource.reset();

    cb.unpause();
    pausingThread.join();

    EXPECT_TRUE(cb.resourcePresent());
}

TEST_F(VSyncDispatchTimerQueueTest, basicTwoAlarmSetting) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000))
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

    mDispatch.schedule(cb0, {.workDuration = 100, .readyDuration = 0, .earliestVsync = mPeriod});
    mDispatch.schedule(cb1, {.workDuration = 250, .readyDuration = 0, .earliestVsync = mPeriod});

    advanceToNextCallback();
    advanceToNextCallback();

    ASSERT_THAT(cb0.mCalls.size(), Eq(1));
    EXPECT_THAT(cb0.mCalls[0], Eq(1075));
    ASSERT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb1.mCalls[0], Eq(1063));
}

TEST_F(VSyncDispatchTimerQueueTest, rearmsFaroutTimeoutWhenCancellingCloseOne) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(_))
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

    mDispatch.schedule(cb0,
                       {.workDuration = 100, .readyDuration = 0, .earliestVsync = mPeriod * 10});
    mDispatch.schedule(cb1, {.workDuration = 250, .readyDuration = 0, .earliestVsync = mPeriod});
    mDispatch.cancel(cb1);
}

TEST_F(VSyncDispatchTimerQueueTest, noUnnecessaryRearmsWhenRescheduling) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 700)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 200, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 300, .readyDuration = 0, .earliestVsync = 1000});
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, necessaryRearmsWhenModifying) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 200, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000});
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

    mDispatch.schedule(cb0, {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 200, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1,
                       {.workDuration = closeOffset, .readyDuration = 0, .earliestVsync = 1000});

    advanceToNextCallback();
    ASSERT_THAT(cb0.mCalls.size(), Eq(1));
    EXPECT_THAT(cb0.mCalls[0], Eq(mPeriod));
    ASSERT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb1.mCalls[0], Eq(mPeriod));

    mDispatch.schedule(cb0, {.workDuration = 400, .readyDuration = 0, .earliestVsync = 2000});
    mDispatch.schedule(cb1,
                       {.workDuration = notCloseOffset, .readyDuration = 0, .earliestVsync = 2000});
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

    mDispatch.schedule(cb0, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 200, .readyDuration = 0, .earliestVsync = 1000});
    advanceToNextCallback();
    EXPECT_EQ(mDispatch.cancel(cb0), CancelResult::Cancelled);
}

TEST_F(VSyncDispatchTimerQueueTest, setAlarmCallsAtCorrectTimeWithChangingVsync) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(_))
            .Times(3)
            .WillOnce(Return(950))
            .WillOnce(Return(1975))
            .WillOnce(Return(2950));

    CountingCallback cb(mDispatch);
    mDispatch.schedule(cb, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 920});

    mMockClock.advanceBy(850);
    EXPECT_THAT(cb.mCalls.size(), Eq(1));

    mDispatch.schedule(cb, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 1900});
    mMockClock.advanceBy(900);
    EXPECT_THAT(cb.mCalls.size(), Eq(1));
    mMockClock.advanceBy(125);
    EXPECT_THAT(cb.mCalls.size(), Eq(2));

    mDispatch.schedule(cb, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 2900});
    mMockClock.advanceBy(975);
    EXPECT_THAT(cb.mCalls.size(), Eq(3));
}

TEST_F(VSyncDispatchTimerQueueTest, callbackReentrancy) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);

    VSyncDispatch::CallbackToken tmp;
    tmp = mDispatch.registerCallback(
            [&](auto, auto, auto) {
                mDispatch.schedule(tmp,
                                   {.workDuration = 100,
                                    .readyDuration = 0,
                                    .earliestVsync = 2000});
            },
            "o.o");

    mDispatch.schedule(tmp, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000});
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, callbackReentrantWithPastWakeup) {
    VSyncDispatch::CallbackToken tmp;
    std::optional<nsecs_t> lastTarget;
    tmp = mDispatch.registerCallback(
            [&](auto timestamp, auto, auto) {
                EXPECT_EQ(mDispatch.schedule(tmp,
                                             {.workDuration = 400,
                                              .readyDuration = 0,
                                              .earliestVsync = timestamp - mVsyncMoveThreshold}),
                          ScheduleResult::Scheduled);
                EXPECT_EQ(mDispatch.schedule(tmp,
                                             {.workDuration = 400,
                                              .readyDuration = 0,
                                              .earliestVsync = timestamp}),
                          ScheduleResult::Scheduled);
                EXPECT_EQ(mDispatch.schedule(tmp,
                                             {.workDuration = 400,
                                              .readyDuration = 0,
                                              .earliestVsync = timestamp + mVsyncMoveThreshold}),
                          ScheduleResult::Scheduled);
                lastTarget = timestamp;
            },
            "oo");

    mDispatch.schedule(tmp, {.workDuration = 999, .readyDuration = 0, .earliestVsync = 1000});
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
    mDispatch.schedule(cb, {.workDuration = 0, .readyDuration = 0, .earliestVsync = 1000});

    mMockClock.advanceBy(750);
    mDispatch.schedule(cb, {.workDuration = 50, .readyDuration = 0, .earliestVsync = 1000});

    advanceToNextCallback();
    mDispatch.schedule(cb, {.workDuration = 50, .readyDuration = 0, .earliestVsync = 2000});

    mMockClock.advanceBy(800);
    mDispatch.schedule(cb, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 2000});
}

TEST_F(VSyncDispatchTimerQueueTest, lateModifications) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 850)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1800)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000});

    advanceToNextCallback();
    mDispatch.schedule(cb0, {.workDuration = 200, .readyDuration = 0, .earliestVsync = 2000});
    mDispatch.schedule(cb1, {.workDuration = 150, .readyDuration = 0, .earliestVsync = 1000});

    advanceToNextCallback();
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, doesntCancelPriorValidTimerForFutureMod) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);
    mDispatch.schedule(cb0, {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.schedule(cb1, {.workDuration = 500, .readyDuration = 0, .earliestVsync = 20000});
}

TEST_F(VSyncDispatchTimerQueueTest, setsTimerAfterCancellation) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 900)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    mDispatch.schedule(cb0, {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000});
    mDispatch.cancel(cb0);
    mDispatch.schedule(cb0, {.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000});
}

TEST_F(VSyncDispatchTimerQueueTest, makingUpIdsError) {
    VSyncDispatch::CallbackToken token(100);
    EXPECT_THAT(mDispatch.schedule(token,
                                   {.workDuration = 100,
                                    .readyDuration = 0,
                                    .earliestVsync = 1000}),
                Eq(ScheduleResult::Error));
    EXPECT_THAT(mDispatch.cancel(token), Eq(CancelResult::Error));
}

TEST_F(VSyncDispatchTimerQueueTest, canMoveCallbackBackwardsInTime) {
    CountingCallback cb0(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb0,
                                 {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb0,
                                 {.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
}

// b/1450138150
TEST_F(VSyncDispatchTimerQueueTest, doesNotMoveCallbackBackwardsAndSkipAScheduledTargetVSync) {
    EXPECT_CALL(mMockClock, alarmAt(_, 500));
    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    mMockClock.advanceBy(400);

    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 800, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    advanceToNextCallback();
    ASSERT_THAT(cb.mCalls.size(), Eq(1));
}

TEST_F(VSyncDispatchTimerQueueTest, targetOffsetMovingBackALittleCanStillSchedule) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000))
            .Times(2)
            .WillOnce(Return(1000))
            .WillOnce(Return(1002));
    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    mMockClock.advanceBy(400);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, canScheduleNegativeOffsetAgainstDifferentPeriods) {
    CountingCallback cb0(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb0,
                                 {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    advanceToNextCallback();
    EXPECT_EQ(mDispatch.schedule(cb0,
                                 {.workDuration = 1100, .readyDuration = 0, .earliestVsync = 2000}),
              ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, canScheduleLargeNegativeOffset) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1100)).InSequence(seq);
    CountingCallback cb0(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb0,
                                 {.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    advanceToNextCallback();
    EXPECT_EQ(mDispatch.schedule(cb0,
                                 {.workDuration = 1900, .readyDuration = 0, .earliestVsync = 2000}),
              ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, scheduleUpdatesDoesNotAffectSchedulingState) {
    EXPECT_CALL(mMockClock, alarmAt(_, 600));

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);

    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 1400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);

    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, helperMove) {
    EXPECT_CALL(mMockClock, alarmAt(_, 500)).Times(1);
    EXPECT_CALL(mMockClock, alarmCancel()).Times(1);

    VSyncCallbackRegistration cb(
            mDispatch, [](auto, auto, auto) {}, "");
    VSyncCallbackRegistration cb1(std::move(cb));
    cb.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000});
    cb.cancel();

    cb1.schedule({.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000});
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
    cb.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 1000});
    cb.cancel();

    cb1.schedule({.workDuration = 500, .readyDuration = 0, .earliestVsync = 1000});
    cb1.cancel();
}

// b/154303580
TEST_F(VSyncDispatchTimerQueueTest, skipsSchedulingIfTimerReschedulingIsImminent) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1900)).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb1,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.schedule(cb2,
                                 {.workDuration = 100, .readyDuration = 0, .earliestVsync = 2000}),
              ScheduleResult::Scheduled);
    mMockClock.advanceBy(80);

    EXPECT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb2.mCalls.size(), Eq(0));
}

// b/154303580.
// If the same callback tries to reschedule itself after it's too late, timer opts to apply the
// update later, as opposed to blocking the calling thread.
TEST_F(VSyncDispatchTimerQueueTest, skipsSchedulingIfTimerReschedulingIsImminentSameCallback) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmAt(_, 1630)).InSequence(seq);
    CountingCallback cb(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 370, .readyDuration = 0, .earliestVsync = 2000}),
              ScheduleResult::Scheduled);
    mMockClock.advanceBy(80);

    EXPECT_THAT(cb.mCalls.size(), Eq(1));
}

// b/154303580.
TEST_F(VSyncDispatchTimerQueueTest, skipsRearmingWhenNotNextScheduled) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb1,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb2,
                                 {.workDuration = 100, .readyDuration = 0, .earliestVsync = 2000}),
              ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.cancel(cb2), CancelResult::Cancelled);

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

    EXPECT_EQ(mDispatch.schedule(cb1,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb2,
                                 {.workDuration = 100, .readyDuration = 0, .earliestVsync = 2000}),
              ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.cancel(cb1), CancelResult::Cancelled);

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
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000))
            .InSequence(seq)
            .WillOnce(Return(1000));
    EXPECT_CALL(mMockClock, alarmAt(_, 600)).InSequence(seq);
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000))
            .InSequence(seq)
            .WillOnce(Return(1000));

    EXPECT_EQ(mDispatch.schedule(cb1,
                                 {.workDuration = 400, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb2,
                                 {.workDuration = 390, .readyDuration = 0, .earliestVsync = 1000}),
              ScheduleResult::Scheduled);

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
    EXPECT_EQ(mDispatch.schedule(cb,
                                 {.workDuration = 70,
                                  .readyDuration = 30,
                                  .earliestVsync = intended}),
              ScheduleResult::Scheduled);
    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(mPeriod));
    ASSERT_THAT(cb.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb.mWakeupTime[0], 900);
    ASSERT_THAT(cb.mReadyTime.size(), Eq(1));
    EXPECT_THAT(cb.mReadyTime[0], 970);
}

class VSyncDispatchTimerQueueEntryTest : public testing::Test {
protected:
    nsecs_t const mPeriod = 1000;
    nsecs_t const mVsyncMoveThreshold = 200;
    NiceMock<MockVSyncTracker> mStubTracker{mPeriod};
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
    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(900));

    entry.disarm();
    EXPECT_FALSE(entry.wakeupTime());
}

TEST_F(VSyncDispatchTimerQueueEntryTest, stateSchedulingReallyLongWakeupLatency) {
    auto const duration = 500;
    auto const now = 8750;

    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(now + duration))
            .Times(1)
            .WillOnce(Return(10000));
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    EXPECT_THAT(entry.schedule({.workDuration = 500, .readyDuration = 0, .earliestVsync = 994},
                               mStubTracker, now),
                Eq(ScheduleResult::Scheduled));
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

    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
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
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(_))
            .Times(2)
            .WillOnce(Return(1000))
            .WillOnce(Return(1020));

    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    entry.update(mStubTracker, 0);
    EXPECT_FALSE(entry.wakeupTime());

    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    auto wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(wakeup, Eq(900));

    entry.update(mStubTracker, 0);
    wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(920));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, skipsUpdateIfJustScheduled) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    entry.update(mStubTracker, 0);

    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(wakeup));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, willSnapToNextTargettableVSync) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    entry.executing(); // 1000 is executing
    // had 1000 not been executing, this could have been scheduled for time 800.
    EXPECT_THAT(entry.schedule({.workDuration = 200, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(*entry.wakeupTime(), Eq(1800));
    EXPECT_THAT(*entry.readyTime(), Eq(2000));

    EXPECT_THAT(entry.schedule({.workDuration = 50, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(*entry.wakeupTime(), Eq(1950));
    EXPECT_THAT(*entry.readyTime(), Eq(2000));

    EXPECT_THAT(entry.schedule({.workDuration = 200, .readyDuration = 0, .earliestVsync = 1001},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(*entry.wakeupTime(), Eq(1800));
    EXPECT_THAT(*entry.readyTime(), Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueEntryTest,
       willRequestNextEstimateWhenSnappingToNextTargettableVSync) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);

    Sequence seq;
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(500))
            .InSequence(seq)
            .WillOnce(Return(1000));
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(500))
            .InSequence(seq)
            .WillOnce(Return(1000));
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000 + mVsyncMoveThreshold))
            .InSequence(seq)
            .WillOnce(Return(2000));

    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));

    entry.executing(); // 1000 is executing

    EXPECT_THAT(entry.schedule({.workDuration = 200, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, reportsScheduledIfStillTime) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.schedule({.workDuration = 100, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(entry.schedule({.workDuration = 200, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(entry.schedule({.workDuration = 50, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(entry.schedule({.workDuration = 1200, .readyDuration = 0, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, storesPendingUpdatesUntilUpdate) {
    static constexpr auto effectualOffset = 200;
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_FALSE(entry.hasPendingWorkloadUpdate());
    entry.addPendingWorkloadUpdate({.workDuration = 100, .readyDuration = 0, .earliestVsync = 400});
    entry.addPendingWorkloadUpdate(
            {.workDuration = effectualOffset, .readyDuration = 0, .earliestVsync = 400});
    EXPECT_TRUE(entry.hasPendingWorkloadUpdate());
    entry.update(mStubTracker, 0);
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

    EXPECT_THAT(entry.schedule({.workDuration = 70, .readyDuration = 30, .earliestVsync = 500},
                               mStubTracker, 0),
                Eq(ScheduleResult::Scheduled));
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
