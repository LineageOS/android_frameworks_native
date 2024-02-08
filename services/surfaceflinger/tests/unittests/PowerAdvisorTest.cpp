/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "PowerAdvisorTest"

#include <DisplayHardware/PowerAdvisor.h>
#include <binder/Status.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <powermanager/PowerHalWrapper.h>
#include <ui/DisplayId.h>
#include <chrono>
#include <future>
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockIPowerHintSession.h"
#include "mock/DisplayHardware/MockPowerHalController.h"

using namespace android;
using namespace android::Hwc2::mock;
using namespace android::hardware::power;
using namespace std::chrono_literals;
using namespace testing;
using namespace android::power;

namespace android::Hwc2::impl {

class PowerAdvisorTest : public testing::Test {
public:
    void SetUp() override;
    void startPowerHintSession(bool returnValidSession = true);
    void fakeBasicFrameTiming(TimePoint startTime, Duration vsyncPeriod);
    void setExpectedTiming(Duration totalFrameTargetDuration, TimePoint expectedPresentTime);
    Duration getFenceWaitDelayDuration(bool skipValidate);
    Duration getErrorMargin();
    void setTimingTestingMode(bool testinMode);
    void allowReportActualToAcquireMutex();
    bool sessionExists();

protected:
    TestableSurfaceFlinger mFlinger;
    std::unique_ptr<PowerAdvisor> mPowerAdvisor;
    MockPowerHalController* mMockPowerHalController;
    std::shared_ptr<MockIPowerHintSession> mMockPowerHintSession;
};

bool PowerAdvisorTest::sessionExists() {
    std::scoped_lock lock(mPowerAdvisor->mHintSessionMutex);
    return mPowerAdvisor->mHintSession != nullptr;
}

void PowerAdvisorTest::SetUp() {
    mPowerAdvisor = std::make_unique<impl::PowerAdvisor>(*mFlinger.flinger());
    mPowerAdvisor->mPowerHal = std::make_unique<NiceMock<MockPowerHalController>>();
    mMockPowerHalController =
            reinterpret_cast<MockPowerHalController*>(mPowerAdvisor->mPowerHal.get());
    ON_CALL(*mMockPowerHalController, getHintSessionPreferredRate)
            .WillByDefault(Return(HalResult<int64_t>::fromStatus(binder::Status::ok(), 16000)));
}

void PowerAdvisorTest::startPowerHintSession(bool returnValidSession) {
    mMockPowerHintSession = ndk::SharedRefBase::make<NiceMock<MockIPowerHintSession>>();
    if (returnValidSession) {
        ON_CALL(*mMockPowerHalController, createHintSession)
                .WillByDefault(
                        Return(HalResult<std::shared_ptr<IPowerHintSession>>::
                                       fromStatus(binder::Status::ok(), mMockPowerHintSession)));
    } else {
        ON_CALL(*mMockPowerHalController, createHintSession)
                .WillByDefault(Return(HalResult<std::shared_ptr<IPowerHintSession>>::
                                              fromStatus(binder::Status::ok(), nullptr)));
    }
    mPowerAdvisor->enablePowerHintSession(true);
    mPowerAdvisor->startPowerHintSession({1, 2, 3});
    ON_CALL(*mMockPowerHintSession, updateTargetWorkDuration)
            .WillByDefault(Return(testing::ByMove(ndk::ScopedAStatus::ok())));
}

void PowerAdvisorTest::setExpectedTiming(Duration totalFrameTargetDuration,
                                         TimePoint expectedPresentTime) {
    mPowerAdvisor->setTotalFrameTargetWorkDuration(totalFrameTargetDuration);
    mPowerAdvisor->setExpectedPresentTime(expectedPresentTime);
}

void PowerAdvisorTest::fakeBasicFrameTiming(TimePoint startTime, Duration vsyncPeriod) {
    mPowerAdvisor->setCommitStart(startTime);
    mPowerAdvisor->setFrameDelay(0ns);
    mPowerAdvisor->updateTargetWorkDuration(vsyncPeriod);
}

void PowerAdvisorTest::setTimingTestingMode(bool testingMode) {
    mPowerAdvisor->mTimingTestingMode = testingMode;
}

void PowerAdvisorTest::allowReportActualToAcquireMutex() {
    mPowerAdvisor->mDelayReportActualMutexAcquisitonPromise.set_value(true);
}

Duration PowerAdvisorTest::getFenceWaitDelayDuration(bool skipValidate) {
    return (skipValidate ? PowerAdvisor::kFenceWaitStartDelaySkippedValidate
                         : PowerAdvisor::kFenceWaitStartDelayValidated);
}

Duration PowerAdvisorTest::getErrorMargin() {
    return mPowerAdvisor->sTargetSafetyMargin;
}

namespace {

TEST_F(PowerAdvisorTest, hintSessionUseHwcDisplay) {
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u)};

    // 60hz
    const Duration vsyncPeriod{std::chrono::nanoseconds(1s) / 60};
    const Duration presentDuration = 5ms;
    const Duration postCompDuration = 1ms;

    TimePoint startTime{100ns};

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const Duration expectedDuration = getErrorMargin() + presentDuration + postCompDuration;
    EXPECT_CALL(*mMockPowerHintSession,
                reportActualWorkDuration(ElementsAre(
                        Field(&WorkDuration::durationNanos, Eq(expectedDuration.ns())))))
            .Times(1)
            .WillOnce(Return(testing::ByMove(ndk::ScopedAStatus::ok())));
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 2500us);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->reportActualWorkDuration();
}

TEST_F(PowerAdvisorTest, hintSessionSubtractsHwcFenceTime) {
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u)};

    // 60hz
    const Duration vsyncPeriod{std::chrono::nanoseconds(1s) / 60};
    const Duration presentDuration = 5ms;
    const Duration postCompDuration = 1ms;
    const Duration hwcBlockedDuration = 500us;

    TimePoint startTime{100ns};

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const Duration expectedDuration = getErrorMargin() + presentDuration +
            getFenceWaitDelayDuration(false) - hwcBlockedDuration + postCompDuration;
    EXPECT_CALL(*mMockPowerHintSession,
                reportActualWorkDuration(ElementsAre(
                        Field(&WorkDuration::durationNanos, Eq(expectedDuration.ns())))))
            .Times(1)
            .WillOnce(Return(testing::ByMove(ndk::ScopedAStatus::ok())));

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 3ms);
    // now report the fence as having fired during the display HWC time
    mPowerAdvisor->setSfPresentTiming(startTime + 2ms + hwcBlockedDuration,
                                      startTime + presentDuration);
    mPowerAdvisor->reportActualWorkDuration();
}

TEST_F(PowerAdvisorTest, hintSessionUsingSecondaryVirtualDisplays) {
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u), GpuVirtualDisplayId(0),
                                      GpuVirtualDisplayId(1)};

    // 60hz
    const Duration vsyncPeriod{std::chrono::nanoseconds(1s) / 60};
    // make present duration much later than the hwc display by itself will account for
    const Duration presentDuration{10ms};
    const Duration postCompDuration{1ms};

    TimePoint startTime{100ns};

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const Duration expectedDuration = getErrorMargin() + presentDuration + postCompDuration;
    EXPECT_CALL(*mMockPowerHintSession,
                reportActualWorkDuration(ElementsAre(
                        Field(&WorkDuration::durationNanos, Eq(expectedDuration.ns())))))
            .Times(1)
            .WillOnce(Return(testing::ByMove(ndk::ScopedAStatus::ok())));

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);

    // don't report timing for the gpu displays since they don't use hwc
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 2500us);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->reportActualWorkDuration();
}

TEST_F(PowerAdvisorTest, hintSessionValidWhenNullFromPowerHAL) {
    mPowerAdvisor->onBootFinished();

    startPowerHintSession(false);

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u)};

    // 60hz
    const Duration vsyncPeriod{std::chrono::nanoseconds(1s) / 60};
    const Duration presentDuration = 5ms;
    const Duration postCompDuration = 1ms;

    TimePoint startTime{100ns};

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const Duration expectedDuration = getErrorMargin() + presentDuration + postCompDuration;
    EXPECT_CALL(*mMockPowerHintSession,
                reportActualWorkDuration(ElementsAre(
                        Field(&WorkDuration::durationNanos, Eq(expectedDuration.ns())))))
            .Times(0);
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 2500us);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->reportActualWorkDuration();
}

TEST_F(PowerAdvisorTest, hintSessionOnlyCreatedOnce) {
    EXPECT_CALL(*mMockPowerHalController, createHintSession(_, _, _, _)).Times(1);
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();
    mPowerAdvisor->startPowerHintSession({1, 2, 3});
}

TEST_F(PowerAdvisorTest, hintSessionTestNotifyReportRace) {
    // notifyDisplayUpdateImminentAndCpuReset or notifyCpuLoadUp gets called in background
    // reportActual gets called during callback and sees true session, passes ensure
    // first notify finishes, setting value to true. Another async method gets called, acquires the
    // lock between reportactual finishing ensure and acquiring the lock itself, and sets session to
    // nullptr. reportActual acquires the lock, and the session is now null, so it does nullptr
    // deref

    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    // --- fake a bunch of timing data
    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u)};
    // 60hz
    const Duration vsyncPeriod{std::chrono::nanoseconds(1s) / 60};
    const Duration presentDuration = 5ms;
    const Duration postCompDuration = 1ms;
    TimePoint startTime{100ns};
    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);
    // increment the frame
    startTime += vsyncPeriod;
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 2500us);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    // --- Done faking timing data

    setTimingTestingMode(true);
    std::promise<bool> letSendHintFinish;

    ON_CALL(*mMockPowerHintSession, sendHint).WillByDefault([&letSendHintFinish] {
        letSendHintFinish.get_future().wait();
        return ndk::ScopedAStatus::fromExceptionCode(-127);
    });

    ON_CALL(*mMockPowerHintSession, reportActualWorkDuration).WillByDefault([] {
        return ndk::ScopedAStatus::fromExceptionCode(-127);
    });

    ON_CALL(*mMockPowerHalController, createHintSession)
            .WillByDefault(Return(
                    HalResult<std::shared_ptr<IPowerHintSession>>::
                            fromStatus(ndk::ScopedAStatus::fromExceptionCode(-127), nullptr)));

    // First background call, to notice the session is down
    auto firstHint = std::async(std::launch::async, [this] {
        mPowerAdvisor->notifyCpuLoadUp();
        return true;
    });
    std::this_thread::sleep_for(10ms);

    // Call reportActual while callback is resolving to try and sneak past ensure
    auto reportActual =
            std::async(std::launch::async, [this] { mPowerAdvisor->reportActualWorkDuration(); });

    std::this_thread::sleep_for(10ms);
    // Let the first call finish
    letSendHintFinish.set_value(true);
    letSendHintFinish = std::promise<bool>{};
    firstHint.wait();

    // Do the second notify call, to ensure the session is nullptr
    auto secondHint = std::async(std::launch::async, [this] {
        mPowerAdvisor->notifyCpuLoadUp();
        return true;
    });
    letSendHintFinish.set_value(true);
    secondHint.wait();
    // Let report finish, potentially dereferencing
    allowReportActualToAcquireMutex();
    reportActual.wait();
    EXPECT_EQ(sessionExists(), false);
}

} // namespace
} // namespace android::Hwc2::impl
