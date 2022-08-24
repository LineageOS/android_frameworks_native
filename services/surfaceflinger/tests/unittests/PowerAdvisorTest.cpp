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
    void fakeBasicFrameTiming(nsecs_t startTime, nsecs_t vsyncPeriod);
    void setExpectedTiming(nsecs_t startTime, nsecs_t vsyncPeriod);
    nsecs_t getFenceWaitDelayDuration(bool skipValidate);

protected:
    TestableSurfaceFlinger mFlinger;
    std::unique_ptr<PowerAdvisor> mPowerAdvisor;
    NiceMock<MockAidlPowerHalWrapper>* mMockAidlWrapper;
    nsecs_t kErrorMargin = std::chrono::nanoseconds(1ms).count();
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

void PowerAdvisorTest::setExpectedTiming(nsecs_t totalFrameTarget, nsecs_t expectedPresentTime) {
    mPowerAdvisor->setTotalFrameTargetWorkDuration(totalFrameTarget);
    mPowerAdvisor->setExpectedPresentTime(expectedPresentTime);
}

void PowerAdvisorTest::fakeBasicFrameTiming(nsecs_t startTime, nsecs_t vsyncPeriod) {
    mPowerAdvisor->setCommitStart(startTime);
    mPowerAdvisor->setFrameDelay(0);
    mPowerAdvisor->setTargetWorkDuration(vsyncPeriod);
}

nsecs_t PowerAdvisorTest::getFenceWaitDelayDuration(bool skipValidate) {
    return (skipValidate ? PowerAdvisor::kFenceWaitStartDelaySkippedValidate
                         : PowerAdvisor::kFenceWaitStartDelayValidated)
            .count();
}

namespace {

TEST_F(PowerAdvisorTest, hintSessionUseHwcDisplay) {
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u)};

    // 60hz
    const nsecs_t vsyncPeriod = std::chrono::nanoseconds(1s).count() / 60;
    const nsecs_t presentDuration = std::chrono::nanoseconds(5ms).count();
    const nsecs_t postCompDuration = std::chrono::nanoseconds(1ms).count();

    nsecs_t startTime = 100;

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const nsecs_t expectedDuration = kErrorMargin + presentDuration + postCompDuration;
    EXPECT_CALL(*mMockAidlWrapper, sendActualWorkDuration(Eq(expectedDuration), _)).Times(1);

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1000000, startTime + 1500000);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2000000, startTime + 2500000);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->sendActualWorkDuration();
}

TEST_F(PowerAdvisorTest, hintSessionSubtractsHwcFenceTime) {
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u)};

    // 60hz
    const nsecs_t vsyncPeriod = std::chrono::nanoseconds(1s).count() / 60;
    const nsecs_t presentDuration = std::chrono::nanoseconds(5ms).count();
    const nsecs_t postCompDuration = std::chrono::nanoseconds(1ms).count();
    const nsecs_t hwcBlockedDuration = std::chrono::nanoseconds(500us).count();

    nsecs_t startTime = 100;

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const nsecs_t expectedDuration = kErrorMargin + presentDuration +
            getFenceWaitDelayDuration(false) - hwcBlockedDuration + postCompDuration;
    EXPECT_CALL(*mMockAidlWrapper, sendActualWorkDuration(Eq(expectedDuration), _)).Times(1);

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1000000, startTime + 1500000);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2000000, startTime + 3000000);
    // now report the fence as having fired during the display HWC time
    mPowerAdvisor->setSfPresentTiming(startTime + 2000000 + hwcBlockedDuration,
                                      startTime + presentDuration);
    mPowerAdvisor->sendActualWorkDuration();
}

TEST_F(PowerAdvisorTest, hintSessionUsingSecondaryVirtualDisplays) {
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u), GpuVirtualDisplayId(0),
                                      GpuVirtualDisplayId(1)};

    // 60hz
    const nsecs_t vsyncPeriod = std::chrono::nanoseconds(1s).count() / 60;
    // make present duration much later than the hwc display by itself will account for
    const nsecs_t presentDuration = std::chrono::nanoseconds(10ms).count();
    const nsecs_t postCompDuration = std::chrono::nanoseconds(1ms).count();

    nsecs_t startTime = 100;

    // advisor only starts on frame 2 so do an initial no-op frame
    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + presentDuration + postCompDuration);

    // increment the frame
    startTime += vsyncPeriod;

    const nsecs_t expectedDuration = kErrorMargin + presentDuration + postCompDuration;
    EXPECT_CALL(*mMockAidlWrapper, sendActualWorkDuration(Eq(expectedDuration), _)).Times(1);

    fakeBasicFrameTiming(startTime, vsyncPeriod);
    setExpectedTiming(vsyncPeriod, startTime + vsyncPeriod);
    mPowerAdvisor->setDisplays(displayIds);

    // don't report timing for the gpu displays since they don't use hwc
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime + 1000000, startTime + 1500000);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime + 2000000, startTime + 2500000);
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + presentDuration);
    mPowerAdvisor->sendActualWorkDuration();
}

} // namespace
} // namespace android::Hwc2::impl
