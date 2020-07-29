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
        ON_CALL(*this, alarmIn(_, _))
                .WillByDefault(Invoke(this, &ControllableClock::alarmInDefaultBehavior));
        ON_CALL(*this, now()).WillByDefault(Invoke(this, &ControllableClock::fakeTime));
    }

    MOCK_CONST_METHOD0(now, nsecs_t());
    MOCK_METHOD2(alarmIn, void(std::function<void()> const&, nsecs_t time));
    MOCK_METHOD0(alarmCancel, void());
    MOCK_CONST_METHOD1(dump, void(std::string&));

    void alarmInDefaultBehavior(std::function<void()> const& callback, nsecs_t time) {
        mCallback = callback;
        mNextCallbackTime = time + mCurrentTime;
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
                                                       std::placeholders::_1,
                                                       std::placeholders::_2),
                                             "test")) {}
    ~CountingCallback() { mDispatch.unregisterCallback(mToken); }

    operator VSyncDispatch::CallbackToken() const { return mToken; }

    void counter(nsecs_t time, nsecs_t wakeup_time) {
        mCalls.push_back(time);
        mWakeupTime.push_back(wakeup_time);
    }

    VSyncDispatch& mDispatch;
    VSyncDispatch::CallbackToken mToken;
    std::vector<nsecs_t> mCalls;
    std::vector<nsecs_t> mWakeupTime;
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
        std::unique_lock<std::mutex> lk(mMutex);
        mPause = true;
        mCv.notify_all();

        mCv.wait_for(lk, mPauseAmount, [this] { return !mPause; });

        mResourcePresent = (mResource.lock() != nullptr);
    }

    bool waitForPause() {
        std::unique_lock<std::mutex> lk(mMutex);
        auto waiting = mCv.wait_for(lk, 10s, [this] { return mPause; });
        return waiting;
    }

    void stashResource(std::weak_ptr<void> const& resource) { mResource = resource; }

    bool resourcePresent() { return mResourcePresent; }

    void unpause() {
        std::unique_lock<std::mutex> lk(mMutex);
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
            void alarmIn(std::function<void()> const& callback, nsecs_t time) final {
                mControllableClock.alarmIn(callback, time);
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
    EXPECT_CALL(mMockClock, alarmIn(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());
    {
        VSyncDispatchTimerQueue mDispatch{createTimeKeeper(), mStubTracker, mDispatchGroupThreshold,
                                          mVsyncMoveThreshold};
        CountingCallback cb(mDispatch);
        EXPECT_EQ(mDispatch.schedule(cb, 100, 1000), ScheduleResult::Scheduled);
    }
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFuture) {
    auto intended = mPeriod - 230;
    EXPECT_CALL(mMockClock, alarmIn(_, 900));

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, 100, intended), ScheduleResult::Scheduled);
    advanceToNextCallback();

    ASSERT_THAT(cb.mCalls.size(), Eq(1));
    EXPECT_THAT(cb.mCalls[0], Eq(mPeriod));
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmSettingFutureWithAdjustmentToTrueVsync) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000)).WillOnce(Return(1150));
    EXPECT_CALL(mMockClock, alarmIn(_, 1050));

    CountingCallback cb(mDispatch);
    mDispatch.schedule(cb, 100, mPeriod);
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
    EXPECT_CALL(mMockClock, alarmIn(_, mPeriod - now));

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, workDuration, mPeriod), ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancel) {
    EXPECT_CALL(mMockClock, alarmIn(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, 100, mPeriod), ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.cancel(cb), CancelResult::Cancelled);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancelTooLate) {
    EXPECT_CALL(mMockClock, alarmIn(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, 100, mPeriod), ScheduleResult::Scheduled);
    mMockClock.advanceBy(950);
    EXPECT_EQ(mDispatch.cancel(cb), CancelResult::TooLate);
}

TEST_F(VSyncDispatchTimerQueueTest, basicAlarmCancelTooLateWhenRunning) {
    EXPECT_CALL(mMockClock, alarmIn(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    PausingCallback cb(mDispatch, std::chrono::duration_cast<std::chrono::milliseconds>(1s));
    EXPECT_EQ(mDispatch.schedule(cb, 100, mPeriod), ScheduleResult::Scheduled);

    std::thread pausingThread([&] { mMockClock.advanceToNextCallback(); });
    EXPECT_TRUE(cb.waitForPause());
    EXPECT_EQ(mDispatch.cancel(cb), CancelResult::TooLate);
    cb.unpause();
    pausingThread.join();
}

TEST_F(VSyncDispatchTimerQueueTest, unregisterSynchronizes) {
    EXPECT_CALL(mMockClock, alarmIn(_, 900));
    EXPECT_CALL(mMockClock, alarmCancel());

    auto resource = std::make_shared<int>(110);

    PausingCallback cb(mDispatch, 50ms);
    cb.stashResource(resource);
    EXPECT_EQ(mDispatch.schedule(cb, 100, mPeriod), ScheduleResult::Scheduled);

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
    EXPECT_CALL(mMockClock, alarmIn(_, 955)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 813)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 162)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 100, mPeriod);
    mDispatch.schedule(cb1, 250, mPeriod);

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
    EXPECT_CALL(mMockClock, alarmIn(_, 9900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 750)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 9900)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 100, mPeriod * 10);
    mDispatch.schedule(cb1, 250, mPeriod);
    mDispatch.cancel(cb1);
}

TEST_F(VSyncDispatchTimerQueueTest, noUnnecessaryRearmsWhenRescheduling) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 100)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 400, 1000);
    mDispatch.schedule(cb1, 200, 1000);
    mDispatch.schedule(cb1, 300, 1000);
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, necessaryRearmsWhenModifying) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 100)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 400, 1000);
    mDispatch.schedule(cb1, 200, 1000);
    mDispatch.schedule(cb1, 500, 1000);
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, modifyIntoGroup) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 1000)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 990)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 10)).InSequence(seq);

    auto offset = 400;
    auto closeOffset = offset + mDispatchGroupThreshold - 1;
    auto notCloseOffset = offset + 2 * mDispatchGroupThreshold;

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 400, 1000);
    mDispatch.schedule(cb1, 200, 1000);
    mDispatch.schedule(cb1, closeOffset, 1000);

    advanceToNextCallback();
    ASSERT_THAT(cb0.mCalls.size(), Eq(1));
    EXPECT_THAT(cb0.mCalls[0], Eq(mPeriod));
    ASSERT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb1.mCalls[0], Eq(mPeriod));

    mDispatch.schedule(cb0, 400, 2000);
    mDispatch.schedule(cb1, notCloseOffset, 2000);
    advanceToNextCallback();
    ASSERT_THAT(cb1.mCalls.size(), Eq(2));
    EXPECT_THAT(cb1.mCalls[1], Eq(2000));

    advanceToNextCallback();
    ASSERT_THAT(cb0.mCalls.size(), Eq(2));
    EXPECT_THAT(cb0.mCalls[1], Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueTest, rearmsWhenEndingAndDoesntCancel) {
    EXPECT_CALL(mMockClock, alarmIn(_, 900));
    EXPECT_CALL(mMockClock, alarmIn(_, 800));
    EXPECT_CALL(mMockClock, alarmIn(_, 100));
    EXPECT_CALL(mMockClock, alarmCancel());

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 100, 1000);
    mDispatch.schedule(cb1, 200, 1000);
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
    mDispatch.schedule(cb, 100, 920);

    mMockClock.advanceBy(850);
    EXPECT_THAT(cb.mCalls.size(), Eq(1));

    mDispatch.schedule(cb, 100, 1900);
    mMockClock.advanceBy(900);
    EXPECT_THAT(cb.mCalls.size(), Eq(1));
    mMockClock.advanceBy(125);
    EXPECT_THAT(cb.mCalls.size(), Eq(2));

    mDispatch.schedule(cb, 100, 2900);
    mMockClock.advanceBy(975);
    EXPECT_THAT(cb.mCalls.size(), Eq(3));
}

TEST_F(VSyncDispatchTimerQueueTest, callbackReentrancy) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 900)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 1000)).InSequence(seq);

    VSyncDispatch::CallbackToken tmp;
    tmp = mDispatch.registerCallback([&](auto, auto) { mDispatch.schedule(tmp, 100, 2000); },
                                     "o.o");

    mDispatch.schedule(tmp, 100, 1000);
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, callbackReentrantWithPastWakeup) {
    VSyncDispatch::CallbackToken tmp;
    std::optional<nsecs_t> lastTarget;
    tmp = mDispatch.registerCallback(
            [&](auto timestamp, auto) {
                EXPECT_EQ(mDispatch.schedule(tmp, 400, timestamp - mVsyncMoveThreshold),
                          ScheduleResult::Scheduled);
                EXPECT_EQ(mDispatch.schedule(tmp, 400, timestamp), ScheduleResult::Scheduled);
                EXPECT_EQ(mDispatch.schedule(tmp, 400, timestamp + mVsyncMoveThreshold),
                          ScheduleResult::Scheduled);
                lastTarget = timestamp;
            },
            "oo");

    mDispatch.schedule(tmp, 999, 1000);
    advanceToNextCallback();
    EXPECT_THAT(lastTarget, Eq(1000));

    advanceToNextCallback();
    EXPECT_THAT(lastTarget, Eq(2000));
}

TEST_F(VSyncDispatchTimerQueueTest, modificationsAroundVsyncTime) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 1000)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 200)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 1000)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 150)).InSequence(seq);

    CountingCallback cb(mDispatch);
    mDispatch.schedule(cb, 0, 1000);

    mMockClock.advanceBy(750);
    mDispatch.schedule(cb, 50, 1000);

    advanceToNextCallback();
    mDispatch.schedule(cb, 50, 2000);

    mMockClock.advanceBy(800);
    mDispatch.schedule(cb, 100, 2000);
}

TEST_F(VSyncDispatchTimerQueueTest, lateModifications) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 400)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 350)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 950)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);

    mDispatch.schedule(cb0, 500, 1000);
    mDispatch.schedule(cb1, 100, 1000);

    advanceToNextCallback();
    mDispatch.schedule(cb0, 200, 2000);
    mDispatch.schedule(cb1, 150, 1000);

    advanceToNextCallback();
    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, doesntCancelPriorValidTimerForFutureMod) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    CountingCallback cb1(mDispatch);
    mDispatch.schedule(cb0, 500, 1000);
    mDispatch.schedule(cb1, 500, 20000);
}

TEST_F(VSyncDispatchTimerQueueTest, setsTimerAfterCancellation) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 900)).InSequence(seq);

    CountingCallback cb0(mDispatch);
    mDispatch.schedule(cb0, 500, 1000);
    mDispatch.cancel(cb0);
    mDispatch.schedule(cb0, 100, 1000);
}

TEST_F(VSyncDispatchTimerQueueTest, makingUpIdsError) {
    VSyncDispatch::CallbackToken token(100);
    EXPECT_THAT(mDispatch.schedule(token, 100, 1000), Eq(ScheduleResult::Error));
    EXPECT_THAT(mDispatch.cancel(token), Eq(CancelResult::Error));
}

TEST_F(VSyncDispatchTimerQueueTest, canMoveCallbackBackwardsInTime) {
    CountingCallback cb0(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb0, 500, 1000), ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb0, 100, 1000), ScheduleResult::Scheduled);
}

// b/1450138150
TEST_F(VSyncDispatchTimerQueueTest, doesNotMoveCallbackBackwardsAndSkipAScheduledTargetVSync) {
    EXPECT_CALL(mMockClock, alarmIn(_, 500));
    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, 500, 1000), ScheduleResult::Scheduled);
    mMockClock.advanceBy(400);

    EXPECT_EQ(mDispatch.schedule(cb, 800, 1000), ScheduleResult::Scheduled);
    advanceToNextCallback();
    ASSERT_THAT(cb.mCalls.size(), Eq(1));
}

TEST_F(VSyncDispatchTimerQueueTest, targetOffsetMovingBackALittleCanStillSchedule) {
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000))
            .Times(2)
            .WillOnce(Return(1000))
            .WillOnce(Return(1002));
    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, 500, 1000), ScheduleResult::Scheduled);
    mMockClock.advanceBy(400);
    EXPECT_EQ(mDispatch.schedule(cb, 400, 1000), ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, canScheduleNegativeOffsetAgainstDifferentPeriods) {
    CountingCallback cb0(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb0, 500, 1000), ScheduleResult::Scheduled);
    advanceToNextCallback();
    EXPECT_EQ(mDispatch.schedule(cb0, 1100, 2000), ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, canScheduleLargeNegativeOffset) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    CountingCallback cb0(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb0, 500, 1000), ScheduleResult::Scheduled);
    advanceToNextCallback();
    EXPECT_EQ(mDispatch.schedule(cb0, 1900, 2000), ScheduleResult::Scheduled);
}

TEST_F(VSyncDispatchTimerQueueTest, scheduleUpdatesDoesNotAffectSchedulingState) {
    EXPECT_CALL(mMockClock, alarmIn(_, 600));

    CountingCallback cb(mDispatch);
    EXPECT_EQ(mDispatch.schedule(cb, 400, 1000), ScheduleResult::Scheduled);

    EXPECT_EQ(mDispatch.schedule(cb, 1400, 1000), ScheduleResult::Scheduled);

    advanceToNextCallback();
}

TEST_F(VSyncDispatchTimerQueueTest, helperMove) {
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).Times(1);
    EXPECT_CALL(mMockClock, alarmCancel()).Times(1);

    VSyncCallbackRegistration cb(
            mDispatch, [](auto, auto) {}, "");
    VSyncCallbackRegistration cb1(std::move(cb));
    cb.schedule(100, 1000);
    cb.cancel();

    cb1.schedule(500, 1000);
    cb1.cancel();
}

TEST_F(VSyncDispatchTimerQueueTest, helperMoveAssign) {
    EXPECT_CALL(mMockClock, alarmIn(_, 500)).Times(1);
    EXPECT_CALL(mMockClock, alarmCancel()).Times(1);

    VSyncCallbackRegistration cb(
            mDispatch, [](auto, auto) {}, "");
    VSyncCallbackRegistration cb1(
            mDispatch, [](auto, auto) {}, "");
    cb1 = std::move(cb);
    cb.schedule(100, 1000);
    cb.cancel();

    cb1.schedule(500, 1000);
    cb1.cancel();
}

// b/154303580
TEST_F(VSyncDispatchTimerQueueTest, skipsSchedulingIfTimerReschedulingIsImminent) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 1200)).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb1, 400, 1000), ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.schedule(cb2, 100, 2000), ScheduleResult::Scheduled);
    mMockClock.advanceBy(80);

    EXPECT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb2.mCalls.size(), Eq(0));
}

// b/154303580.
// If the same callback tries to reschedule itself after it's too late, timer opts to apply the
// update later, as opposed to blocking the calling thread.
TEST_F(VSyncDispatchTimerQueueTest, skipsSchedulingIfTimerReschedulingIsImminentSameCallback) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 930)).InSequence(seq);
    CountingCallback cb(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb, 400, 1000), ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.schedule(cb, 370, 2000), ScheduleResult::Scheduled);
    mMockClock.advanceBy(80);

    EXPECT_THAT(cb.mCalls.size(), Eq(1));
}

// b/154303580.
TEST_F(VSyncDispatchTimerQueueTest, skipsRearmingWhenNotNextScheduled) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb1, 400, 1000), ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb2, 100, 2000), ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(620);

    EXPECT_EQ(mDispatch.cancel(cb2), CancelResult::Cancelled);

    mMockClock.advanceBy(80);

    EXPECT_THAT(cb1.mCalls.size(), Eq(1));
    EXPECT_THAT(cb2.mCalls.size(), Eq(0));
}

TEST_F(VSyncDispatchTimerQueueTest, rearmsWhenCancelledAndIsNextScheduled) {
    Sequence seq;
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmIn(_, 1280)).InSequence(seq);
    EXPECT_CALL(mMockClock, alarmCancel()).InSequence(seq);
    CountingCallback cb1(mDispatch);
    CountingCallback cb2(mDispatch);

    EXPECT_EQ(mDispatch.schedule(cb1, 400, 1000), ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb2, 100, 2000), ScheduleResult::Scheduled);

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
    EXPECT_CALL(mMockClock, alarmIn(_, 600)).InSequence(seq);
    EXPECT_CALL(mStubTracker, nextAnticipatedVSyncTimeFrom(1000))
            .InSequence(seq)
            .WillOnce(Return(1000));

    EXPECT_EQ(mDispatch.schedule(cb1, 400, 1000), ScheduleResult::Scheduled);
    EXPECT_EQ(mDispatch.schedule(cb2, 390, 1000), ScheduleResult::Scheduled);

    mMockClock.setLag(100);
    mMockClock.advanceBy(700);

    ASSERT_THAT(cb1.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb1.mWakeupTime[0], Eq(600));
    ASSERT_THAT(cb2.mWakeupTime.size(), Eq(1));
    EXPECT_THAT(cb2.mWakeupTime[0], Eq(610));
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
            name, [](auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.name(), Eq(name));
    EXPECT_FALSE(entry.lastExecutedVsyncTarget());
    EXPECT_FALSE(entry.wakeupTime());
}

TEST_F(VSyncDispatchTimerQueueEntryTest, stateScheduling) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
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
            "test", [](auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    EXPECT_THAT(entry.schedule(500, 994, mStubTracker, now), Eq(ScheduleResult::Scheduled));
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(9500));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, runCallback) {
    auto callCount = 0;
    auto vsyncCalledTime = 0;
    auto wakeupCalledTime = 0;
    VSyncDispatchTimerQueueEntry entry(
            "test",
            [&](auto vsyncTime, auto wakeupTime) {
                callCount++;
                vsyncCalledTime = vsyncTime;
                wakeupCalledTime = wakeupTime;
            },
            mVsyncMoveThreshold);

    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(900));

    entry.callback(entry.executing(), *wakeup);

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
            "test", [](auto, auto) {}, mVsyncMoveThreshold);

    EXPECT_FALSE(entry.wakeupTime());
    entry.update(mStubTracker, 0);
    EXPECT_FALSE(entry.wakeupTime());

    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
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
            "test", [](auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    entry.update(mStubTracker, 0);

    auto const wakeup = entry.wakeupTime();
    ASSERT_TRUE(wakeup);
    EXPECT_THAT(*wakeup, Eq(wakeup));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, willSnapToNextTargettableVSync) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    entry.executing(); // 1000 is executing
    // had 1000 not been executing, this could have been scheduled for time 800.
    EXPECT_THAT(entry.schedule(200, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(*entry.wakeupTime(), Eq(1800));

    EXPECT_THAT(entry.schedule(50, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(*entry.wakeupTime(), Eq(1950));

    EXPECT_THAT(entry.schedule(200, 1001, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(*entry.wakeupTime(), Eq(1800));
}

TEST_F(VSyncDispatchTimerQueueEntryTest,
       willRequestNextEstimateWhenSnappingToNextTargettableVSync) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto) {}, mVsyncMoveThreshold);

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

    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));

    entry.executing(); // 1000 is executing

    EXPECT_THAT(entry.schedule(200, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, reportsScheduledIfStillTime) {
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_THAT(entry.schedule(100, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(entry.schedule(200, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(entry.schedule(50, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
    EXPECT_THAT(entry.schedule(1200, 500, mStubTracker, 0), Eq(ScheduleResult::Scheduled));
}

TEST_F(VSyncDispatchTimerQueueEntryTest, storesPendingUpdatesUntilUpdate) {
    static constexpr auto effectualOffset = 200;
    VSyncDispatchTimerQueueEntry entry(
            "test", [](auto, auto) {}, mVsyncMoveThreshold);
    EXPECT_FALSE(entry.hasPendingWorkloadUpdate());
    entry.addPendingWorkloadUpdate(100, 400);
    entry.addPendingWorkloadUpdate(effectualOffset, 700);
    EXPECT_TRUE(entry.hasPendingWorkloadUpdate());
    entry.update(mStubTracker, 0);
    EXPECT_FALSE(entry.hasPendingWorkloadUpdate());
    EXPECT_THAT(*entry.wakeupTime(), Eq(mPeriod - effectualOffset));
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
