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
    MOCK_METHOD1(addVsyncTimestamp, void(nsecs_t));
    MOCK_CONST_METHOD1(nextAnticipatedVSyncTimeFrom, nsecs_t(nsecs_t));
    MOCK_CONST_METHOD0(currentPeriod, nsecs_t());
};

class VSyncTrackerWrapper : public VSyncTracker {
public:
    VSyncTrackerWrapper(std::shared_ptr<VSyncTracker> const& tracker) : mTracker(tracker) {}

    void addVsyncTimestamp(nsecs_t timestamp) final { mTracker->addVsyncTimestamp(timestamp); }
    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t timePoint) const final {
        return mTracker->nextAnticipatedVSyncTimeFrom(timePoint);
    }
    nsecs_t currentPeriod() const final { return mTracker->currentPeriod(); }

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
    MOCK_METHOD2(registerCallback, CallbackToken(std::function<void(nsecs_t)> const&, std::string));
    MOCK_METHOD1(unregisterCallback, void(CallbackToken));
    MOCK_METHOD3(schedule, ScheduleResult(CallbackToken, nsecs_t, nsecs_t));
    MOCK_METHOD1(cancel, CancelResult(CallbackToken token));
};

class VSyncDispatchWrapper : public VSyncDispatch {
public:
    VSyncDispatchWrapper(std::shared_ptr<VSyncDispatch> const& dispatch) : mDispatch(dispatch) {}
    CallbackToken registerCallback(std::function<void(nsecs_t)> const& callbackFn,
                                   std::string callbackName) final {
        return mDispatch->registerCallback(callbackFn, callbackName);
    }

    void unregisterCallback(CallbackToken token) final { mDispatch->unregisterCallback(token); }

    ScheduleResult schedule(CallbackToken token, nsecs_t workDuration,
                            nsecs_t earliestVsync) final {
        return mDispatch->schedule(token, workDuration, earliestVsync);
    }

    CancelResult cancel(CallbackToken token) final { return mDispatch->cancel(token); }

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

class VSyncReactorTest : public testing::Test {
protected:
    VSyncReactorTest()
          : mMockDispatch(std::make_shared<MockVSyncDispatch>()),
            mMockTracker(std::make_shared<MockVSyncTracker>()),
            mMockClock(std::make_shared<NiceMock<MockClock>>()),
            mReactor(std::make_unique<ClockWrapper>(mMockClock),
                     std::make_unique<VSyncDispatchWrapper>(mMockDispatch),
                     std::make_unique<VSyncTrackerWrapper>(mMockTracker), kPendingLimit) {}

    std::shared_ptr<MockVSyncDispatch> mMockDispatch;
    std::shared_ptr<MockVSyncTracker> mMockTracker;
    std::shared_ptr<MockClock> mMockClock;
    static constexpr size_t kPendingLimit = 3;
    static constexpr nsecs_t dummyTime = 47;
    VSyncReactor mReactor;
};

TEST_F(VSyncReactorTest, addingNullFenceCheck) {
    EXPECT_FALSE(mReactor.addPresentFence(nullptr));
}

TEST_F(VSyncReactorTest, addingInvalidFenceSignalsNeedsMoreInfo) {
    EXPECT_TRUE(mReactor.addPresentFence(generateInvalidFence()));
}

TEST_F(VSyncReactorTest, addingSignalledFenceAddsToTracker) {
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(dummyTime));
    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(dummyTime)));
}

TEST_F(VSyncReactorTest, addingPendingFenceAddsSignalled) {
    nsecs_t anotherDummyTime = 2919019201;

    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(0);
    auto pendingFence = generatePendingFence();
    EXPECT_FALSE(mReactor.addPresentFence(pendingFence));
    Mock::VerifyAndClearExpectations(mMockTracker.get());

    signalFenceWithTime(pendingFence, dummyTime);

    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(dummyTime));
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
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(dummyTime)).Times(1);

    mReactor.setIgnorePresentFences(true);
    for (auto i = 0; i < aFewTimes; i++) {
        mReactor.addPresentFence(generateSignalledFenceWithTime(dummyTime));
    }

    mReactor.setIgnorePresentFences(false);
    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(dummyTime)));
}

TEST_F(VSyncReactorTest, queriesTrackerForNextRefreshNow) {
    nsecs_t const fakeTimestamp = 4839;
    EXPECT_CALL(*mMockTracker, currentPeriod()).Times(0);
    EXPECT_CALL(*mMockTracker, nextAnticipatedVSyncTimeFrom(_))
            .Times(1)
            .WillOnce(Return(fakeTimestamp));

    EXPECT_THAT(mReactor.computeNextRefresh(0), Eq(fakeTimestamp));
}

TEST_F(VSyncReactorTest, queriesTrackerForExpectedPresentTime) {
    nsecs_t const fakeTimestamp = 4839;
    EXPECT_CALL(*mMockTracker, currentPeriod()).Times(0);
    EXPECT_CALL(*mMockTracker, nextAnticipatedVSyncTimeFrom(_))
            .Times(1)
            .WillOnce(Return(fakeTimestamp));

    EXPECT_THAT(mReactor.expectedPresentTime(), Eq(fakeTimestamp));
}

TEST_F(VSyncReactorTest, queriesTrackerForNextRefreshFuture) {
    nsecs_t const fakeTimestamp = 4839;
    nsecs_t const fakePeriod = 1010;
    nsecs_t const fakeNow = 2214;
    int const numPeriodsOut = 3;
    EXPECT_CALL(*mMockClock, now()).WillOnce(Return(fakeNow));
    EXPECT_CALL(*mMockTracker, currentPeriod()).WillOnce(Return(fakePeriod));
    EXPECT_CALL(*mMockTracker, nextAnticipatedVSyncTimeFrom(fakeNow + numPeriodsOut * fakePeriod))
            .WillOnce(Return(fakeTimestamp));
    EXPECT_THAT(mReactor.computeNextRefresh(numPeriodsOut), Eq(fakeTimestamp));
}

} // namespace android::scheduler
