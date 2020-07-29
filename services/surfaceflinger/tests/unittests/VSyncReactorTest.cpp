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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"
#define LOG_NDEBUG 0

#include "Scheduler/TimeKeeper.h"
#include "Scheduler/VSyncDispatch.h"
#include "Scheduler/VSyncReactor.h"
#include "Scheduler/VSyncTracker.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ui/Fence.h>
#include <ui/FenceTime.h>
#include <array>

using namespace testing;
using namespace std::literals;
namespace android::scheduler {

class MockVSyncTracker : public VSyncTracker {
public:
    MockVSyncTracker() { ON_CALL(*this, addVsyncTimestamp(_)).WillByDefault(Return(true)); }
    MOCK_METHOD1(addVsyncTimestamp, bool(nsecs_t));
    MOCK_CONST_METHOD1(nextAnticipatedVSyncTimeFrom, nsecs_t(nsecs_t));
    MOCK_CONST_METHOD0(currentPeriod, nsecs_t());
    MOCK_METHOD1(setPeriod, void(nsecs_t));
    MOCK_METHOD0(resetModel, void());
    MOCK_CONST_METHOD0(needsMoreSamples, bool());
    MOCK_CONST_METHOD1(dump, void(std::string&));
};

class VSyncTrackerWrapper : public VSyncTracker {
public:
    VSyncTrackerWrapper(std::shared_ptr<VSyncTracker> const& tracker) : mTracker(tracker) {}

    bool addVsyncTimestamp(nsecs_t timestamp) final {
        return mTracker->addVsyncTimestamp(timestamp);
    }
    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t timePoint) const final {
        return mTracker->nextAnticipatedVSyncTimeFrom(timePoint);
    }
    nsecs_t currentPeriod() const final { return mTracker->currentPeriod(); }
    void setPeriod(nsecs_t period) final { mTracker->setPeriod(period); }
    void resetModel() final { mTracker->resetModel(); }
    bool needsMoreSamples() const final { return mTracker->needsMoreSamples(); }
    void dump(std::string& result) const final { mTracker->dump(result); }

private:
    std::shared_ptr<VSyncTracker> const mTracker;
};

class MockClock : public Clock {
public:
    MOCK_CONST_METHOD0(now, nsecs_t());
};

class ClockWrapper : public Clock {
public:
    ClockWrapper(std::shared_ptr<Clock> const& clock) : mClock(clock) {}

    nsecs_t now() const { return mClock->now(); }

private:
    std::shared_ptr<Clock> const mClock;
};

class MockVSyncDispatch : public VSyncDispatch {
public:
    MOCK_METHOD2(registerCallback,
                 CallbackToken(std::function<void(nsecs_t, nsecs_t)> const&, std::string));
    MOCK_METHOD1(unregisterCallback, void(CallbackToken));
    MOCK_METHOD3(schedule, ScheduleResult(CallbackToken, nsecs_t, nsecs_t));
    MOCK_METHOD1(cancel, CancelResult(CallbackToken token));
    MOCK_CONST_METHOD1(dump, void(std::string&));
};

class VSyncDispatchWrapper : public VSyncDispatch {
public:
    VSyncDispatchWrapper(std::shared_ptr<VSyncDispatch> const& dispatch) : mDispatch(dispatch) {}
    CallbackToken registerCallback(std::function<void(nsecs_t, nsecs_t)> const& callbackFn,
                                   std::string callbackName) final {
        return mDispatch->registerCallback(callbackFn, callbackName);
    }

    void unregisterCallback(CallbackToken token) final { mDispatch->unregisterCallback(token); }

    ScheduleResult schedule(CallbackToken token, nsecs_t workDuration,
                            nsecs_t earliestVsync) final {
        return mDispatch->schedule(token, workDuration, earliestVsync);
    }

    CancelResult cancel(CallbackToken token) final { return mDispatch->cancel(token); }

    void dump(std::string& result) const final { return mDispatch->dump(result); }

private:
    std::shared_ptr<VSyncDispatch> const mDispatch;
};

std::shared_ptr<FenceTime> generateInvalidFence() {
    sp<Fence> fence = new Fence();
    return std::make_shared<FenceTime>(fence);
}

std::shared_ptr<FenceTime> generatePendingFence() {
    sp<Fence> fence = new Fence(dup(fileno(tmpfile())));
    return std::make_shared<FenceTime>(fence);
}

void signalFenceWithTime(std::shared_ptr<FenceTime> const& fence, nsecs_t time) {
    FenceTime::Snapshot snap(time);
    fence->applyTrustedSnapshot(snap);
}

std::shared_ptr<FenceTime> generateSignalledFenceWithTime(nsecs_t time) {
    sp<Fence> fence = new Fence(dup(fileno(tmpfile())));
    std::shared_ptr<FenceTime> ft = std::make_shared<FenceTime>(fence);
    signalFenceWithTime(ft, time);
    return ft;
}

class StubCallback : public DispSync::Callback {
public:
    void onDispSyncEvent(nsecs_t when, nsecs_t /*expectedVSyncTimestamp*/) final {
        std::lock_guard<std::mutex> lk(mMutex);
        mLastCallTime = when;
    }
    std::optional<nsecs_t> lastCallTime() const {
        std::lock_guard<std::mutex> lk(mMutex);
        return mLastCallTime;
    }

private:
    std::mutex mutable mMutex;
    std::optional<nsecs_t> mLastCallTime GUARDED_BY(mMutex);
};

class VSyncReactorTest : public testing::Test {
protected:
    VSyncReactorTest()
          : mMockDispatch(std::make_shared<NiceMock<MockVSyncDispatch>>()),
            mMockTracker(std::make_shared<NiceMock<MockVSyncTracker>>()),
            mMockClock(std::make_shared<NiceMock<MockClock>>()),
            mReactor(std::make_unique<ClockWrapper>(mMockClock),
                     std::make_unique<VSyncDispatchWrapper>(mMockDispatch),
                     std::make_unique<VSyncTrackerWrapper>(mMockTracker), kPendingLimit,
                     false /* supportKernelIdleTimer */) {
        ON_CALL(*mMockClock, now()).WillByDefault(Return(mFakeNow));
        ON_CALL(*mMockTracker, currentPeriod()).WillByDefault(Return(period));
    }

    std::shared_ptr<MockVSyncDispatch> mMockDispatch;
    std::shared_ptr<MockVSyncTracker> mMockTracker;
    std::shared_ptr<MockClock> mMockClock;
    static constexpr size_t kPendingLimit = 3;
    static constexpr nsecs_t mDummyTime = 47;
    static constexpr nsecs_t mPhase = 3000;
    static constexpr nsecs_t mAnotherPhase = 5200;
    static constexpr nsecs_t period = 10000;
    static constexpr nsecs_t mFakeVSyncTime = 2093;
    static constexpr nsecs_t mFakeWakeupTime = 1892;
    static constexpr nsecs_t mFakeNow = 2214;
    static constexpr const char mName[] = "callbacky";
    VSyncDispatch::CallbackToken const mFakeToken{2398};

    nsecs_t lastCallbackTime = 0;
    StubCallback outerCb;
    std::function<void(nsecs_t, nsecs_t)> innerCb;

    VSyncReactor mReactor;
};

TEST_F(VSyncReactorTest, addingNullFenceCheck) {
    EXPECT_FALSE(mReactor.addPresentFence(nullptr));
}

TEST_F(VSyncReactorTest, addingInvalidFenceSignalsNeedsMoreInfo) {
    EXPECT_TRUE(mReactor.addPresentFence(generateInvalidFence()));
}

TEST_F(VSyncReactorTest, addingSignalledFenceAddsToTracker) {
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(mDummyTime));
    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(mDummyTime)));
}

TEST_F(VSyncReactorTest, addingPendingFenceAddsSignalled) {
    nsecs_t anotherDummyTime = 2919019201;

    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(0);
    auto pendingFence = generatePendingFence();
    EXPECT_FALSE(mReactor.addPresentFence(pendingFence));
    Mock::VerifyAndClearExpectations(mMockTracker.get());

    signalFenceWithTime(pendingFence, mDummyTime);

    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(mDummyTime));
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(anotherDummyTime));
    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(anotherDummyTime)));
}

TEST_F(VSyncReactorTest, limitsPendingFences) {
    std::array<std::shared_ptr<FenceTime>, kPendingLimit * 2> fences;
    std::array<nsecs_t, fences.size()> fakeTimes;
    std::generate(fences.begin(), fences.end(), [] { return generatePendingFence(); });
    std::generate(fakeTimes.begin(), fakeTimes.end(), [i = 10]() mutable {
        i++;
        return i * i;
    });

    for (auto const& fence : fences) {
        mReactor.addPresentFence(fence);
    }

    for (auto i = fences.size() - kPendingLimit; i < fences.size(); i++) {
        EXPECT_CALL(*mMockTracker, addVsyncTimestamp(fakeTimes[i]));
    }

    for (auto i = 0u; i < fences.size(); i++) {
        signalFenceWithTime(fences[i], fakeTimes[i]);
    }
    mReactor.addPresentFence(generatePendingFence());
}

TEST_F(VSyncReactorTest, ignoresPresentFencesWhenToldTo) {
    static constexpr size_t aFewTimes = 8;
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(mDummyTime)).Times(1);

    mReactor.setIgnorePresentFences(true);
    for (auto i = 0; i < aFewTimes; i++) {
        mReactor.addPresentFence(generateSignalledFenceWithTime(mDummyTime));
    }

    mReactor.setIgnorePresentFences(false);
    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(mDummyTime)));
}

TEST_F(VSyncReactorTest, ignoresProperlyAfterAPeriodConfirmation) {
    bool periodFlushed = true;
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(2);
    mReactor.setIgnorePresentFences(true);

    nsecs_t const newPeriod = 5000;
    mReactor.setPeriod(newPeriod);

    EXPECT_TRUE(mReactor.addResyncSample(0, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addResyncSample(newPeriod, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, queriesTrackerForNextRefreshNow) {
    nsecs_t const fakeTimestamp = 4839;
    EXPECT_CALL(*mMockTracker, currentPeriod()).Times(0);
    EXPECT_CALL(*mMockTracker, nextAnticipatedVSyncTimeFrom(_))
            .Times(1)
            .WillOnce(Return(fakeTimestamp));

    EXPECT_THAT(mReactor.computeNextRefresh(0, mMockClock->now()), Eq(fakeTimestamp));
}

TEST_F(VSyncReactorTest, queriesTrackerForExpectedPresentTime) {
    nsecs_t const fakeTimestamp = 4839;
    EXPECT_CALL(*mMockTracker, currentPeriod()).Times(0);
    EXPECT_CALL(*mMockTracker, nextAnticipatedVSyncTimeFrom(_))
            .Times(1)
            .WillOnce(Return(fakeTimestamp));

    EXPECT_THAT(mReactor.expectedPresentTime(mMockClock->now()), Eq(fakeTimestamp));
}

TEST_F(VSyncReactorTest, queriesTrackerForNextRefreshFuture) {
    nsecs_t const fakeTimestamp = 4839;
    nsecs_t const fakePeriod = 1010;
    nsecs_t const mFakeNow = 2214;
    int const numPeriodsOut = 3;
    EXPECT_CALL(*mMockClock, now()).WillOnce(Return(mFakeNow));
    EXPECT_CALL(*mMockTracker, currentPeriod()).WillOnce(Return(fakePeriod));
    EXPECT_CALL(*mMockTracker, nextAnticipatedVSyncTimeFrom(mFakeNow + numPeriodsOut * fakePeriod))
            .WillOnce(Return(fakeTimestamp));
    EXPECT_THAT(mReactor.computeNextRefresh(numPeriodsOut, mMockClock->now()), Eq(fakeTimestamp));
}

TEST_F(VSyncReactorTest, getPeriod) {
    nsecs_t const fakePeriod = 1010;
    EXPECT_CALL(*mMockTracker, currentPeriod()).WillOnce(Return(fakePeriod));
    EXPECT_THAT(mReactor.getPeriod(), Eq(fakePeriod));
}

TEST_F(VSyncReactorTest, setPeriodCalledOnceConfirmedChange) {
    nsecs_t const newPeriod = 5000;
    EXPECT_CALL(*mMockTracker, setPeriod(_)).Times(0);
    mReactor.setPeriod(newPeriod);

    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addResyncSample(10000, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    EXPECT_TRUE(mReactor.addResyncSample(20000, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    Mock::VerifyAndClearExpectations(mMockTracker.get());
    EXPECT_CALL(*mMockTracker, setPeriod(newPeriod)).Times(1);

    EXPECT_FALSE(mReactor.addResyncSample(25000, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);
}

TEST_F(VSyncReactorTest, changingPeriodBackAbortsConfirmationProcess) {
    nsecs_t sampleTime = 0;
    nsecs_t const newPeriod = 5000;
    mReactor.setPeriod(newPeriod);
    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addResyncSample(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    EXPECT_TRUE(mReactor.addResyncSample(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    mReactor.setPeriod(period);
    EXPECT_FALSE(mReactor.addResyncSample(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
}

TEST_F(VSyncReactorTest, changingToAThirdPeriodWillWaitForLastPeriod) {
    nsecs_t sampleTime = 0;
    nsecs_t const secondPeriod = 5000;
    nsecs_t const thirdPeriod = 2000;

    mReactor.setPeriod(secondPeriod);
    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addResyncSample(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_TRUE(mReactor.addResyncSample(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    mReactor.setPeriod(thirdPeriod);
    EXPECT_TRUE(mReactor.addResyncSample(sampleTime += secondPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addResyncSample(sampleTime += thirdPeriod, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);
}

TEST_F(VSyncReactorTest, reportedBadTimestampFromPredictorWillReactivateHwVSync) {
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_))
            .WillOnce(Return(false))
            .WillOnce(Return(true))
            .WillOnce(Return(true));
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));

    nsecs_t skewyPeriod = period >> 1;
    bool periodFlushed = false;
    nsecs_t sampleTime = 0;
    EXPECT_TRUE(mReactor.addResyncSample(sampleTime += skewyPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addResyncSample(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
}

TEST_F(VSyncReactorTest, reportedBadTimestampFromPredictorWillReactivateHwVSyncPendingFence) {
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_))
            .Times(2)
            .WillOnce(Return(false))
            .WillOnce(Return(true));

    auto fence = generatePendingFence();
    EXPECT_FALSE(mReactor.addPresentFence(fence));
    signalFenceWithTime(fence, period >> 1);
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, presentFenceAdditionDoesNotInterruptConfirmationProcess) {
    nsecs_t const newPeriod = 5000;
    mReactor.setPeriod(newPeriod);
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, setPeriodCalledFirstTwoEventsNewPeriod) {
    nsecs_t const newPeriod = 5000;
    EXPECT_CALL(*mMockTracker, setPeriod(_)).Times(0);
    mReactor.setPeriod(newPeriod);

    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addResyncSample(5000, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    Mock::VerifyAndClearExpectations(mMockTracker.get());

    EXPECT_CALL(*mMockTracker, setPeriod(newPeriod)).Times(1);
    EXPECT_FALSE(mReactor.addResyncSample(10000, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);
}

TEST_F(VSyncReactorTest, addResyncSampleTypical) {
    nsecs_t const fakeTimestamp = 3032;
    bool periodFlushed = false;

    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(fakeTimestamp));
    EXPECT_FALSE(mReactor.addResyncSample(fakeTimestamp, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
}

TEST_F(VSyncReactorTest, addResyncSamplePeriodChanges) {
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;

    mReactor.setPeriod(newPeriod);

    auto time = 0;
    auto constexpr numTimestampSubmissions = 10;
    for (auto i = 0; i < numTimestampSubmissions; i++) {
        time += period;
        EXPECT_TRUE(mReactor.addResyncSample(time, std::nullopt, &periodFlushed));
        EXPECT_FALSE(periodFlushed);
    }

    time += newPeriod;
    EXPECT_FALSE(mReactor.addResyncSample(time, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    for (auto i = 0; i < numTimestampSubmissions; i++) {
        time += newPeriod;
        EXPECT_FALSE(mReactor.addResyncSample(time, std::nullopt, &periodFlushed));
        EXPECT_FALSE(periodFlushed);
    }
}

TEST_F(VSyncReactorTest, addPresentFenceWhileAwaitingPeriodConfirmationRequestsHwVsync) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;
    mReactor.setPeriod(newPeriod);

    time += period;
    mReactor.addResyncSample(time, std::nullopt, &periodFlushed);
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));

    time += newPeriod;
    mReactor.addResyncSample(time, std::nullopt, &periodFlushed);

    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, hwVsyncIsRequestedForTracker) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;
    mReactor.setPeriod(newPeriod);

    static auto constexpr numSamplesWithNewPeriod = 4;
    Sequence seq;
    EXPECT_CALL(*mMockTracker, needsMoreSamples())
            .Times(numSamplesWithNewPeriod - 2)
            .InSequence(seq)
            .WillRepeatedly(Return(true));
    EXPECT_CALL(*mMockTracker, needsMoreSamples())
            .Times(1)
            .InSequence(seq)
            .WillRepeatedly(Return(false));
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(numSamplesWithNewPeriod);

    EXPECT_TRUE(mReactor.addResyncSample(time += period, std::nullopt, &periodFlushed));

    EXPECT_TRUE(mReactor.addResyncSample(time += period, std::nullopt, &periodFlushed));
    // confirmed period, but predictor wants numRequest samples. This one and prior are valid.
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addResyncSample(time += newPeriod, std::nullopt, &periodFlushed));
}

TEST_F(VSyncReactorTest, hwVsyncturnsOffOnConfirmationWhenTrackerDoesntRequest) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;
    mReactor.setPeriod(newPeriod);

    Sequence seq;
    EXPECT_CALL(*mMockTracker, needsMoreSamples())
            .Times(1)
            .InSequence(seq)
            .WillRepeatedly(Return(false));
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(2);

    EXPECT_TRUE(mReactor.addResyncSample(time += period, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addResyncSample(time += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addResyncSample(time += newPeriod, std::nullopt, &periodFlushed));
}

TEST_F(VSyncReactorTest, hwVsyncIsRequestedForTrackerMultiplePeriodChanges) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod1 = 4000;
    nsecs_t const newPeriod2 = 7000;

    mReactor.setPeriod(newPeriod1);

    Sequence seq;
    EXPECT_CALL(*mMockTracker, needsMoreSamples())
            .Times(4)
            .InSequence(seq)
            .WillRepeatedly(Return(true));
    EXPECT_CALL(*mMockTracker, needsMoreSamples())
            .Times(1)
            .InSequence(seq)
            .WillRepeatedly(Return(false));
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(7);

    EXPECT_TRUE(mReactor.addResyncSample(time += period, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addResyncSample(time += period, std::nullopt, &periodFlushed));
    // confirmed period, but predictor wants numRequest samples. This one and prior are valid.
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod1, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod1, std::nullopt, &periodFlushed));

    mReactor.setPeriod(newPeriod2);
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod1, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod2, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addResyncSample(time += newPeriod2, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addResyncSample(time += newPeriod2, std::nullopt, &periodFlushed));
}

static nsecs_t computeWorkload(nsecs_t period, nsecs_t phase) {
    return period - phase;
}

TEST_F(VSyncReactorTest, addEventListener) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch, cancel(mFakeToken)).Times(2).InSequence(seq);
    EXPECT_CALL(*mMockDispatch, unregisterCallback(mFakeToken)).InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    mReactor.removeEventListener(&outerCb, &lastCallbackTime);
}

TEST_F(VSyncReactorTest, addEventListenerTwiceChangesPhase) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch,
                schedule(mFakeToken, computeWorkload(period, mAnotherPhase), _)) // mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch, cancel(mFakeToken)).InSequence(seq);
    EXPECT_CALL(*mMockDispatch, unregisterCallback(mFakeToken)).InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    mReactor.addEventListener(mName, mAnotherPhase, &outerCb, lastCallbackTime);
}

TEST_F(VSyncReactorTest, eventListenerGetsACallbackAndReschedules) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(DoAll(SaveArg<0>(&innerCb), Return(mFakeToken)));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch,
                schedule(mFakeToken, computeWorkload(period, mPhase), mFakeVSyncTime))
            .Times(2)
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch, cancel(mFakeToken)).InSequence(seq);
    EXPECT_CALL(*mMockDispatch, unregisterCallback(mFakeToken)).InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    ASSERT_TRUE(innerCb);
    innerCb(mFakeVSyncTime, mFakeWakeupTime);
    innerCb(mFakeVSyncTime, mFakeWakeupTime);
}

TEST_F(VSyncReactorTest, callbackTimestampDistributedIsWakeupTime) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, _))
            .InSequence(seq)
            .WillOnce(DoAll(SaveArg<0>(&innerCb), Return(mFakeToken)));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch,
                schedule(mFakeToken, computeWorkload(period, mPhase), mFakeVSyncTime))
            .InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    ASSERT_TRUE(innerCb);
    innerCb(mFakeVSyncTime, mFakeWakeupTime);
    EXPECT_THAT(outerCb.lastCallTime(), Optional(mFakeWakeupTime));
}

TEST_F(VSyncReactorTest, eventListenersRemovedOnDestruction) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch, cancel(mFakeToken)).InSequence(seq);
    EXPECT_CALL(*mMockDispatch, unregisterCallback(mFakeToken)).InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
}

// b/149221293
TEST_F(VSyncReactorTest, selfRemovingEventListenerStopsCallbacks) {
    class SelfRemovingCallback : public DispSync::Callback {
    public:
        SelfRemovingCallback(VSyncReactor& vsr) : mVsr(vsr) {}
        void onDispSyncEvent(nsecs_t when, nsecs_t /*expectedVSyncTimestamp*/) final {
            mVsr.removeEventListener(this, &when);
        }

    private:
        VSyncReactor& mVsr;
    } selfRemover(mReactor);

    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(DoAll(SaveArg<0>(&innerCb), Return(mFakeToken)));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch, cancel(mFakeToken)).Times(2).InSequence(seq);
    EXPECT_CALL(*mMockDispatch, unregisterCallback(mFakeToken)).InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &selfRemover, lastCallbackTime);
    innerCb(0, 0);
}

TEST_F(VSyncReactorTest, addEventListenerChangePeriod) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch,
                schedule(mFakeToken, computeWorkload(period, mAnotherPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockDispatch, cancel(mFakeToken)).InSequence(seq);
    EXPECT_CALL(*mMockDispatch, unregisterCallback(mFakeToken)).InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    mReactor.addEventListener(mName, mAnotherPhase, &outerCb, lastCallbackTime);
}

TEST_F(VSyncReactorTest, changingPeriodChangesOffsetsOnNextCb) {
    static constexpr nsecs_t anotherPeriod = 23333;
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), mFakeNow))
            .InSequence(seq);
    EXPECT_CALL(*mMockTracker, setPeriod(anotherPeriod));
    EXPECT_CALL(*mMockDispatch,
                schedule(mFakeToken, computeWorkload(anotherPeriod, mPhase), mFakeNow))
            .InSequence(seq);

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);

    bool periodFlushed = false;
    mReactor.setPeriod(anotherPeriod);
    EXPECT_TRUE(mReactor.addResyncSample(anotherPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addResyncSample(anotherPeriod * 2, std::nullopt, &periodFlushed));

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
}

TEST_F(VSyncReactorTest, offsetsAppliedOnNextOpportunity) {
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(DoAll(SaveArg<0>(&innerCb), Return(mFakeToken)));
    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mPhase), _))
            .InSequence(seq)
            .WillOnce(Return(ScheduleResult::Scheduled));

    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mAnotherPhase), _))
            .InSequence(seq)
            .WillOnce(Return(ScheduleResult::Scheduled));

    EXPECT_CALL(*mMockDispatch, schedule(mFakeToken, computeWorkload(period, mAnotherPhase), _))
            .InSequence(seq)
            .WillOnce(Return(ScheduleResult::Scheduled));

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    mReactor.changePhaseOffset(&outerCb, mAnotherPhase);
    ASSERT_TRUE(innerCb);
    innerCb(mFakeVSyncTime, mFakeWakeupTime);
}

TEST_F(VSyncReactorTest, negativeOffsetsApplied) {
    nsecs_t const negativePhase = -4000;
    Sequence seq;
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .InSequence(seq)
            .WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mMockDispatch,
                schedule(mFakeToken, computeWorkload(period, negativePhase), mFakeNow))
            .InSequence(seq);
    mReactor.addEventListener(mName, negativePhase, &outerCb, lastCallbackTime);
}

TEST_F(VSyncReactorTest, beginResyncResetsModel) {
    EXPECT_CALL(*mMockTracker, resetModel());
    mReactor.beginResync();
}

TEST_F(VSyncReactorTest, periodChangeWithGivenVsyncPeriod) {
    bool periodFlushed = true;
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(2);
    mReactor.setIgnorePresentFences(true);

    nsecs_t const newPeriod = 5000;
    mReactor.setPeriod(newPeriod);

    EXPECT_TRUE(mReactor.addResyncSample(0, 0, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_TRUE(mReactor.addResyncSample(newPeriod, 0, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addResyncSample(newPeriod, newPeriod, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, periodIsMeasuredIfIgnoringComposer) {
    // Create a reactor which supports the kernel idle timer
    auto idleReactor = VSyncReactor(std::make_unique<ClockWrapper>(mMockClock),
                                    std::make_unique<VSyncDispatchWrapper>(mMockDispatch),
                                    std::make_unique<VSyncTrackerWrapper>(mMockTracker),
                                    kPendingLimit, true /* supportKernelIdleTimer */);

    bool periodFlushed = true;
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(4);
    idleReactor.setIgnorePresentFences(true);

    // First, set the same period, which should only be confirmed when we receive two
    // matching callbacks
    idleReactor.setPeriod(10000);
    EXPECT_TRUE(idleReactor.addResyncSample(0, 0, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    // Correct period but incorrect timestamp delta
    EXPECT_TRUE(idleReactor.addResyncSample(0, 10000, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    // Correct period and correct timestamp delta
    EXPECT_FALSE(idleReactor.addResyncSample(10000, 10000, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    // Then, set a new period, which should be confirmed as soon as we receive a callback
    // reporting the new period
    nsecs_t const newPeriod = 5000;
    idleReactor.setPeriod(newPeriod);
    // Incorrect timestamp delta and period
    EXPECT_TRUE(idleReactor.addResyncSample(20000, 10000, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    // Incorrect timestamp delta but correct period
    EXPECT_FALSE(idleReactor.addResyncSample(20000, 5000, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    EXPECT_TRUE(idleReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

using VSyncReactorDeathTest = VSyncReactorTest;
TEST_F(VSyncReactorDeathTest, invalidRemoval) {
    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    mReactor.removeEventListener(&outerCb, &lastCallbackTime);
    EXPECT_DEATH(mReactor.removeEventListener(&outerCb, &lastCallbackTime), ".*");
}

TEST_F(VSyncReactorDeathTest, invalidChange) {
    EXPECT_DEATH(mReactor.changePhaseOffset(&outerCb, mPhase), ".*");

    // the current DispSync-interface usage pattern has evolved around an implementation quirk,
    // which is a callback is assumed to always exist, and it is valid api usage to change the
    // offset of an object that is in the removed state.
    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    mReactor.removeEventListener(&outerCb, &lastCallbackTime);
    mReactor.changePhaseOffset(&outerCb, mPhase);
}

TEST_F(VSyncReactorDeathTest, cannotScheduleOnRegistration) {
    ON_CALL(*mMockDispatch, schedule(_, _, _))
            .WillByDefault(Return(ScheduleResult::CannotSchedule));
    EXPECT_DEATH(mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime), ".*");
}

TEST_F(VSyncReactorDeathTest, cannotScheduleOnCallback) {
    EXPECT_CALL(*mMockDispatch, registerCallback(_, std::string(mName)))
            .WillOnce(DoAll(SaveArg<0>(&innerCb), Return(mFakeToken)));
    EXPECT_CALL(*mMockDispatch, schedule(_, _, _)).WillOnce(Return(ScheduleResult::Scheduled));

    mReactor.addEventListener(mName, mPhase, &outerCb, lastCallbackTime);
    ASSERT_TRUE(innerCb);
    Mock::VerifyAndClearExpectations(mMockDispatch.get());

    ON_CALL(*mMockDispatch, schedule(_, _, _))
            .WillByDefault(Return(ScheduleResult::CannotSchedule));
    EXPECT_DEATH(innerCb(mFakeVSyncTime, mFakeWakeupTime), ".*");
}

} // namespace android::scheduler
