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
#include <compositionengine/Display.h>
#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ui/DisplayId.h>
#include <chrono>
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockAidlPowerHalWrapper.h"

using namespace android;
using namespace android::Hwc2::mock;
using namespace android::hardware::power;
using namespace std::chrono_literals;
using namespace testing;

namespace android::Hwc2::impl {

class PowerAdvisorTest : public testing::Test {
public:
    void SetUp() override;
    void startPowerHintSession();
    void fakeBasicFrameTiming(TimePoint startTime, Duration vsyncPeriod);
    void setExpectedTiming(Duration totalFrameTargetDuration, TimePoint expectedPresentTime);
    Duration getFenceWaitDelayDuration(bool skipValidate);
    Duration getErrorMargin();

protected:
    TestableSurfaceFlinger mFlinger;
    std::unique_ptr<PowerAdvisor> mPowerAdvisor;
    NiceMock<MockAidlPowerHalWrapper>* mMockAidlWrapper;
};

void PowerAdvisorTest::SetUp() FTL_FAKE_GUARD(mPowerAdvisor->mPowerHalMutex) {
    std::unique_ptr<MockAidlPowerHalWrapper> mockAidlWrapper =
            std::make_unique<NiceMock<MockAidlPowerHalWrapper>>();
    mPowerAdvisor = std::make_unique<PowerAdvisor>(*mFlinger.flinger());
    ON_CALL(*mockAidlWrapper.get(), supportsPowerHintSession()).WillByDefault(Return(true));
    ON_CALL(*mockAidlWrapper.get(), startPowerHintSession()).WillByDefault(Return(true));
    mPowerAdvisor->mHalWrapper = std::move(mockAidlWrapper);
    mMockAidlWrapper =
            reinterpret_cast<NiceMock<MockAidlPowerHalWrapper>*>(mPowerAdvisor->mHalWrapper.get());
}

void PowerAdvisorTest::startPowerHintSession() {
    const std::vector<int32_t> threadIds = {1, 2, 3};
    mPowerAdvisor->enablePowerHint(true);
    mPowerAdvisor->startPowerHintSession(threadIds);
}

void PowerAdvisorTest::setExpectedTiming(Duration totalFrameTargetDuration,
                                         TimePoint expectedPresentTime) {
    mPowerAdvisor->setTotalFrameTargetWorkDuration(totalFrameTargetDuration);
    mPowerAdvisor->setExpectedPresentTime(expectedPresentTime);
}

void PowerAdvisorTest::fakeBasicFrameTiming(TimePoint startTime, Duration vsyncPeriod) {
    mPowerAdvisor->setCommitStart(startTime);
    mPowerAdvisor->setFrameDelay(0ns);
    mPowerAdvisor->setTargetWorkDuration(vsyncPeriod);
    ON_CALL(*mMockAidlWrapper, getTargetWorkDuration())
            .WillByDefault(Return(std::make_optional(vsyncPeriod)));
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
    EXPECT_CALL(*mMockAidlWrapper, sendActualWorkDuration(Eq(expectedDuration), _)).Times(1);

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 2500us);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->sendActualWorkDuration();
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
    EXPECT_CALL(*mMockAidlWrapper, sendActualWorkDuration(Eq(expectedDuration), _)).Times(1);

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 3ms);
    // now report the fence as having fired during the display HWC time
    mPowerAdvisor->setSfPresentTiming(startTime + 2ms + hwcBlockedDuration,
                                      startTime + presentDuration);
    mPowerAdvisor->sendActualWorkDuration();
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
    EXPECT_CALL(*mMockAidlWrapper, sendActualWorkDuration(Eq(expectedDuration), _)).Times(1);

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);

    // don't report timing for the gpu displays since they don't use hwc
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1ms, startTime + 1500us);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2ms, startTime + 2500us);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->sendActualWorkDuration();
}

} // namespace
} // namespace android::Hwc2::impl
