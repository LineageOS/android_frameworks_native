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
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"
#define LOG_NDEBUG 0

#include <array>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ui/Fence.h>
#include <ui/FenceTime.h>

#include <scheduler/TimeKeeper.h>

#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockVSyncTracker.h"

#include "Scheduler/VSyncDispatch.h"
#include "Scheduler/VSyncReactor.h"
#include "Scheduler/VSyncTracker.h"

using namespace testing;
using namespace std::literals;

namespace android::scheduler {

namespace {
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

std::shared_ptr<android::FenceTime> generateInvalidFence() {
    sp<Fence> fence = sp<Fence>::make();
    return std::make_shared<android::FenceTime>(fence);
}

std::shared_ptr<android::FenceTime> generatePendingFence() {
    sp<Fence> fence = sp<Fence>::make(dup(fileno(tmpfile())));
    return std::make_shared<android::FenceTime>(fence);
}

void signalFenceWithTime(std::shared_ptr<android::FenceTime> const& fence, nsecs_t time) {
    android::FenceTime::Snapshot snap(time);
    fence->applyTrustedSnapshot(snap);
}

std::shared_ptr<android::FenceTime> generateSignalledFenceWithTime(nsecs_t time) {
    sp<Fence> fence = sp<Fence>::make(dup(fileno(tmpfile())));
    std::shared_ptr<android::FenceTime> ft = std::make_shared<android::FenceTime>(fence);
    signalFenceWithTime(ft, time);
    return ft;
}

constexpr PhysicalDisplayId DEFAULT_DISPLAY_ID = PhysicalDisplayId::fromPort(42u);

ftl::NonNull<DisplayModePtr> displayMode(nsecs_t vsyncPeriod) {
    const int32_t kGroup = 0;
    const auto kResolution = ui::Size(1920, 1080);
    const auto refreshRate = Fps::fromPeriodNsecs(vsyncPeriod);
    return ftl::as_non_null(mock::createDisplayMode(DisplayModeId(0), refreshRate, kGroup,
                                                    kResolution, DEFAULT_DISPLAY_ID));
}

MATCHER_P(DisplayModeMatcher, value, "display mode equals") {
    return arg->getId() == value->getId() && equalsExceptDisplayModeId(*arg, *value);
}

} // namespace

class VSyncReactorTest : public testing::Test {
protected:
    VSyncReactorTest()
          : mMockTracker(std::make_shared<NiceMock<mock::VSyncTracker>>()),
            mMockClock(std::make_shared<NiceMock<MockClock>>()),
            mReactor(DEFAULT_DISPLAY_ID, std::make_unique<ClockWrapper>(mMockClock), *mMockTracker,
                     kPendingLimit, false /* supportKernelIdleTimer */) {
        ON_CALL(*mMockClock, now()).WillByDefault(Return(mFakeNow));
        ON_CALL(*mMockTracker, currentPeriod()).WillByDefault(Return(period));
        ON_CALL(*mMockTracker, addVsyncTimestamp(_)).WillByDefault(Return(true));
    }

    std::shared_ptr<mock::VSyncTracker> mMockTracker;
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
    // StubCallback outerCb;
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
    std::array<std::shared_ptr<android::FenceTime>, kPendingLimit * 2> fences;
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
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(3);
    nsecs_t const newPeriod = 5000;

    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(0, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(newPeriod, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, setPeriodCalledOnceConfirmedChange) {
    nsecs_t const newPeriod = 5000;
    EXPECT_CALL(*mMockTracker, setDisplayModePtr(_)).Times(0);
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(10000, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(20000, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    Mock::VerifyAndClearExpectations(mMockTracker.get());
    EXPECT_CALL(*mMockTracker, setDisplayModePtr(/*displayMode(newPeriod)*/ _)).Times(1);

    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(25000, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);
}

TEST_F(VSyncReactorTest, changingPeriodBackAbortsConfirmationProcess) {
    nsecs_t sampleTime = 0;
    nsecs_t const newPeriod = 5000;
    auto modePtr = displayMode(newPeriod);
    mReactor.onDisplayModeChanged(modePtr, false);
    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    modePtr = displayMode(period);
    EXPECT_CALL(*mMockTracker, isCurrentMode(modePtr)).WillOnce(Return(true));
    mReactor.onDisplayModeChanged(modePtr, false);
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
}

TEST_F(VSyncReactorTest, changingToAThirdPeriodWillWaitForLastPeriod) {
    nsecs_t sampleTime = 0;
    nsecs_t const secondPeriod = 5000;
    nsecs_t const thirdPeriod = 2000;

    mReactor.onDisplayModeChanged(displayMode(secondPeriod), false);
    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(sampleTime += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    mReactor.onDisplayModeChanged(displayMode(thirdPeriod), false);
    EXPECT_TRUE(
            mReactor.addHwVsyncTimestamp(sampleTime += secondPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(
            mReactor.addHwVsyncTimestamp(sampleTime += thirdPeriod, std::nullopt, &periodFlushed));
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
    EXPECT_TRUE(
            mReactor.addHwVsyncTimestamp(sampleTime += skewyPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(sampleTime += period, std::nullopt, &periodFlushed));
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
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, setPeriodCalledFirstTwoEventsNewPeriod) {
    nsecs_t const newPeriod = 5000;
    EXPECT_CALL(*mMockTracker, setDisplayModePtr(_)).Times(0);
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    bool periodFlushed = true;
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(5000, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    Mock::VerifyAndClearExpectations(mMockTracker.get());

    EXPECT_CALL(*mMockTracker, setDisplayModePtr(DisplayModeMatcher(displayMode(newPeriod))))
            .Times(1);
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(10000, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);
}

TEST_F(VSyncReactorTest, addResyncSampleTypical) {
    nsecs_t const fakeTimestamp = 3032;
    bool periodFlushed = false;

    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(fakeTimestamp));
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(fakeTimestamp, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
}

TEST_F(VSyncReactorTest, addResyncSamplePeriodChanges) {
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;

    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    auto time = 0;
    auto constexpr numTimestampSubmissions = 10;
    for (auto i = 0; i < numTimestampSubmissions; i++) {
        time += period;
        EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed));
        EXPECT_FALSE(periodFlushed);
    }

    time += newPeriod;
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    for (auto i = 0; i < numTimestampSubmissions; i++) {
        time += newPeriod;
        EXPECT_FALSE(mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed));
        EXPECT_FALSE(periodFlushed);
    }
}

TEST_F(VSyncReactorTest, addHwVsyncTimestampDozePreempt) {
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;

    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    auto time = 0;
    // If the power mode is not DOZE or DOZE_SUSPEND, it is still collecting timestamps.
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed));
    EXPECT_FALSE(periodFlushed);

    // Set power mode to DOZE to trigger period flushing.
    mReactor.setDisplayPowerMode(hal::PowerMode::DOZE);
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed));
    EXPECT_TRUE(periodFlushed);
}

TEST_F(VSyncReactorTest, addPresentFenceWhileAwaitingPeriodConfirmationRequestsHwVsync) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    time += period;
    mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed);
    EXPECT_TRUE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));

    time += newPeriod;
    mReactor.addHwVsyncTimestamp(time, std::nullopt, &periodFlushed);

    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, hwVsyncIsRequestedForTracker) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

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

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += period, std::nullopt, &periodFlushed));

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += period, std::nullopt, &periodFlushed));
    // confirmed period, but predictor wants numRequest samples. This one and prior are valid.
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(time += newPeriod, std::nullopt, &periodFlushed));
}

TEST_F(VSyncReactorTest, hwVsyncturnsOffOnConfirmationWhenTrackerDoesntRequest) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod = 4000;
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    Sequence seq;
    EXPECT_CALL(*mMockTracker, needsMoreSamples())
            .Times(1)
            .InSequence(seq)
            .WillRepeatedly(Return(false));
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(2);

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += period, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += period, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(time += newPeriod, std::nullopt, &periodFlushed));
}

TEST_F(VSyncReactorTest, hwVsyncIsRequestedForTrackerMultiplePeriodChanges) {
    auto time = 0;
    bool periodFlushed = false;
    nsecs_t const newPeriod1 = 4000;
    nsecs_t const newPeriod2 = 7000;

    mReactor.onDisplayModeChanged(displayMode(newPeriod1), false);

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

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += period, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += period, std::nullopt, &periodFlushed));
    // confirmed period, but predictor wants numRequest samples. This one and prior are valid.
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod1, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod1, std::nullopt, &periodFlushed));

    mReactor.onDisplayModeChanged(displayMode(newPeriod2), false);
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod1, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod2, std::nullopt, &periodFlushed));
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(time += newPeriod2, std::nullopt, &periodFlushed));
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(time += newPeriod2, std::nullopt, &periodFlushed));
}

TEST_F(VSyncReactorTest, periodChangeWithGivenVsyncPeriod) {
    bool periodFlushed = true;
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(3);

    nsecs_t const newPeriod = 5000;
    mReactor.onDisplayModeChanged(displayMode(newPeriod), false);

    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(0, 0, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_TRUE(mReactor.addHwVsyncTimestamp(newPeriod, 0, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    EXPECT_FALSE(mReactor.addHwVsyncTimestamp(newPeriod, newPeriod, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    EXPECT_FALSE(mReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

TEST_F(VSyncReactorTest, periodIsMeasuredIfIgnoringComposer) {
    // Create a reactor which supports the kernel idle timer
    auto idleReactor =
            VSyncReactor(DEFAULT_DISPLAY_ID, std::make_unique<ClockWrapper>(mMockClock),
                         *mMockTracker, kPendingLimit, true /* supportKernelIdleTimer */);

    bool periodFlushed = true;
    EXPECT_CALL(*mMockTracker, addVsyncTimestamp(_)).Times(5);

    // First, set the same period, which should only be confirmed when we receive two
    // matching callbacks
    idleReactor.onDisplayModeChanged(displayMode(10000), false);
    EXPECT_TRUE(idleReactor.addHwVsyncTimestamp(0, 0, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    // Correct period but incorrect timestamp delta
    EXPECT_TRUE(idleReactor.addHwVsyncTimestamp(0, 10000, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    // Correct period and correct timestamp delta
    EXPECT_FALSE(idleReactor.addHwVsyncTimestamp(10000, 10000, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    // Then, set a new period, which should be confirmed as soon as we receive a callback
    // reporting the new period
    nsecs_t const newPeriod = 5000;
    idleReactor.onDisplayModeChanged(displayMode(newPeriod), false);
    // Incorrect timestamp delta and period
    EXPECT_TRUE(idleReactor.addHwVsyncTimestamp(20000, 10000, &periodFlushed));
    EXPECT_FALSE(periodFlushed);
    // Incorrect timestamp delta but correct period
    EXPECT_FALSE(idleReactor.addHwVsyncTimestamp(20000, 5000, &periodFlushed));
    EXPECT_TRUE(periodFlushed);

    EXPECT_FALSE(idleReactor.addPresentFence(generateSignalledFenceWithTime(0)));
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
