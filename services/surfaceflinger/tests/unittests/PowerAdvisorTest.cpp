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
#include <android_os.h>
#include <binder/Status.h>
#include <com_android_graphics_surfaceflinger_flags.h>
#include <common/FlagManager.h>
#include <common/test/FlagUtils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <powermanager/PowerHalWrapper.h>
#include <ui/DisplayId.h>
#include <chrono>
#include <future>
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockPowerHalController.h"
#include "mock/DisplayHardware/MockPowerHintSessionWrapper.h"

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
    int64_t toNanos(Duration d);

    struct GpuTestConfig {
        bool adpfGpuFlagOn;
        Duration frame1GpuFenceDuration;
        Duration frame2GpuFenceDuration;
        Duration vsyncPeriod;
        Duration presentDuration = 0ms;
        Duration postCompDuration = 0ms;
        bool frame1RequiresRenderEngine;
        bool frame2RequiresRenderEngine;
    };

    WorkDuration testGpuScenario(GpuTestConfig& config);

protected:
    TestableSurfaceFlinger mFlinger;
    std::unique_ptr<PowerAdvisor> mPowerAdvisor;
    MockPowerHalController* mMockPowerHalController;
    std::shared_ptr<MockPowerHintSessionWrapper> mMockPowerHintSession;
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel, true);
};

bool PowerAdvisorTest::sessionExists() {
    std::scoped_lock lock(mPowerAdvisor->mHintSessionMutex);
    return mPowerAdvisor->mHintSession != nullptr;
}

int64_t PowerAdvisorTest::toNanos(Duration d) {
    return std::chrono::nanoseconds(d).count();
}

void PowerAdvisorTest::SetUp() {
    mPowerAdvisor = std::make_unique<impl::PowerAdvisor>(*mFlinger.flinger());
    mPowerAdvisor->mPowerHal = std::make_unique<NiceMock<MockPowerHalController>>();
    mMockPowerHalController =
            reinterpret_cast<MockPowerHalController*>(mPowerAdvisor->mPowerHal.get());
    ON_CALL(*mMockPowerHalController, getHintSessionPreferredRate)
            .WillByDefault(Return(
                    ByMove(HalResult<int64_t>::fromStatus(ndk::ScopedAStatus::ok(), 16000))));
}

void PowerAdvisorTest::startPowerHintSession(bool returnValidSession) {
    mMockPowerHintSession = std::make_shared<NiceMock<MockPowerHintSessionWrapper>>();
    if (returnValidSession) {
        ON_CALL(*mMockPowerHalController, createHintSessionWithConfig)
                .WillByDefault(DoAll(SetArgPointee<5>(aidl::android::hardware::power::SessionConfig{
                                             .id = 12}),
                                     Return(HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
                                                    fromStatus(binder::Status::ok(),
                                                               mMockPowerHintSession))));
    } else {
        ON_CALL(*mMockPowerHalController, createHintSessionWithConfig).WillByDefault([] {
            return HalResult<
                    std::shared_ptr<PowerHintSessionWrapper>>::fromStatus(ndk::ScopedAStatus::ok(),
                                                                          nullptr);
        });
    }
    mPowerAdvisor->enablePowerHintSession(true);
    mPowerAdvisor->startPowerHintSession({1, 2, 3});
    ON_CALL(*mMockPowerHintSession, updateTargetWorkDuration)
            .WillByDefault(Return(testing::ByMove(HalResult<void>::ok())));
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

WorkDuration PowerAdvisorTest::testGpuScenario(GpuTestConfig& config) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::adpf_gpu_sf,
                      config.adpfGpuFlagOn);
    mPowerAdvisor->onBootFinished();
    startPowerHintSession();

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u), GpuVirtualDisplayId(0),
                                      GpuVirtualDisplayId(1)};
    mPowerAdvisor->setDisplays(displayIds);
    auto display1 = displayIds[0];
    // 60hz

    TimePoint startTime = TimePoint::now();
    // advisor only starts on frame 2 so do an initial frame
    fakeBasicFrameTiming(startTime, config.vsyncPeriod);
    setExpectedTiming(config.vsyncPeriod, startTime + config.vsyncPeriod);

    // report GPU
    mPowerAdvisor->setRequiresRenderEngine(display1, config.frame1RequiresRenderEngine);
    if (config.adpfGpuFlagOn) {
        mPowerAdvisor->setGpuStartTime(display1, startTime);
    }
    if (config.frame1GpuFenceDuration.count() == Fence::SIGNAL_TIME_PENDING) {
        mPowerAdvisor->setGpuFenceTime(display1,
                                       std::make_unique<FenceTime>(Fence::SIGNAL_TIME_PENDING));
    } else {
        TimePoint end = startTime + config.frame1GpuFenceDuration;
        mPowerAdvisor->setGpuFenceTime(display1, std::make_unique<FenceTime>(end.ns()));
    }

    // increment the frame
    std::this_thread::sleep_for(config.vsyncPeriod);
    startTime = TimePoint::now();
    fakeBasicFrameTiming(startTime, config.vsyncPeriod);
    setExpectedTiming(config.vsyncPeriod, startTime + config.vsyncPeriod);

    // report GPU
    mPowerAdvisor->setRequiresRenderEngine(display1, config.frame2RequiresRenderEngine);
    if (config.adpfGpuFlagOn) {
        mPowerAdvisor->setGpuStartTime(display1, startTime);
    }
    if (config.frame2GpuFenceDuration.count() == Fence::SIGNAL_TIME_PENDING) {
        mPowerAdvisor->setGpuFenceTime(display1,
                                       std::make_unique<FenceTime>(Fence::SIGNAL_TIME_PENDING));
    } else {
        TimePoint end = startTime + config.frame2GpuFenceDuration;
        mPowerAdvisor->setGpuFenceTime(display1, std::make_unique<FenceTime>(end.ns()));
    }
    mPowerAdvisor->setSfPresentTiming(startTime, startTime + config.presentDuration);
    mPowerAdvisor->setCompositeEnd(startTime + config.presentDuration + config.postCompDuration);

    // don't report timing for the HWC
    mPowerAdvisor->setHwcValidateTiming(displayIds[0], startTime, startTime);
    mPowerAdvisor->setHwcPresentTiming(displayIds[0], startTime, startTime);

    std::vector<aidl::android::hardware::power::WorkDuration> durationReq;
    EXPECT_CALL(*mMockPowerHintSession, reportActualWorkDuration(_))
            .Times(1)
            .WillOnce(DoAll(testing::SaveArg<0>(&durationReq),
                            testing::Return(testing::ByMove(HalResult<void>::ok()))));
    mPowerAdvisor->reportActualWorkDuration();
    EXPECT_EQ(durationReq.size(), 1u);
    return durationReq[0];
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
            .WillOnce(Return(testing::ByMove(HalResult<void>::ok())));
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
            .WillOnce(Return(testing::ByMove(HalResult<void>::ok())));

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
            .WillOnce(Return(testing::ByMove(HalResult<void>::ok())));

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
    EXPECT_CALL(*mMockPowerHalController, createHintSessionWithConfig(_, _, _, _, _, _)).Times(1);
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
        return HalResult<void>::fromStatus(ndk::ScopedAStatus::fromExceptionCode(-127));
    });

    ON_CALL(*mMockPowerHintSession, reportActualWorkDuration).WillByDefault([] {
        return HalResult<void>::fromStatus(ndk::ScopedAStatus::fromExceptionCode(-127));
    });

    ON_CALL(*mMockPowerHalController, createHintSessionWithConfig).WillByDefault([] {
        return HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
                fromStatus(ndk::ScopedAStatus::fromExceptionCode(-127), nullptr);
    });

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

TEST_F(PowerAdvisorTest, legacyHintSessionCreationStillWorks) {
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel, false);
    mPowerAdvisor->onBootFinished();
    mMockPowerHintSession = std::make_shared<NiceMock<MockPowerHintSessionWrapper>>();
    EXPECT_CALL(*mMockPowerHalController, createHintSession)
            .Times(1)
            .WillOnce(Return(HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
                                     fromStatus(binder::Status::ok(), mMockPowerHintSession)));
    mPowerAdvisor->enablePowerHintSession(true);
    mPowerAdvisor->startPowerHintSession({1, 2, 3});
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_cpuThenGpuFrames) {
    GpuTestConfig config{
            .adpfGpuFlagOn = false,
            // faked buffer fence time for testing
            .frame1GpuFenceDuration = 41ms,
            .frame2GpuFenceDuration = 31ms,
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = false,
            .frame2RequiresRenderEngine = true,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, 0L);
    EXPECT_EQ(res.cpuDurationNanos, 0L);
    EXPECT_GE(res.durationNanos, toNanos(30ms + getErrorMargin()));
    EXPECT_LE(res.durationNanos, toNanos(31ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_cpuThenGpuFrames_flagOn) {
    GpuTestConfig config{
            .adpfGpuFlagOn = true,
            .frame1GpuFenceDuration = 40ms,
            .frame2GpuFenceDuration = 30ms,
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = false,
            .frame2RequiresRenderEngine = true,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(30ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(10ms));
    EXPECT_EQ(res.durationNanos, toNanos(30ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_gpuThenCpuFrames) {
    GpuTestConfig config{
            .adpfGpuFlagOn = false,
            // faked fence time for testing
            .frame1GpuFenceDuration = 41ms,
            .frame2GpuFenceDuration = 31ms,
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = false,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, 0L);
    EXPECT_EQ(res.cpuDurationNanos, 0L);
    EXPECT_EQ(res.durationNanos, toNanos(10ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_gpuThenCpuFrames_flagOn) {
    GpuTestConfig config{
            .adpfGpuFlagOn = true,
            .frame1GpuFenceDuration = 40ms,
            .frame2GpuFenceDuration = 30ms,
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = false,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, 0L);
    EXPECT_EQ(res.cpuDurationNanos, toNanos(10ms));
    EXPECT_EQ(res.durationNanos, toNanos(10ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_twoSignaledGpuFrames) {
    GpuTestConfig config{
            .adpfGpuFlagOn = false,
            // added a margin as a workaround since we set GPU start time at the time of fence set
            // call
            .frame1GpuFenceDuration = 31ms,
            .frame2GpuFenceDuration = 51ms,
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = true,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, 0L);
    EXPECT_EQ(res.cpuDurationNanos, 0L);
    EXPECT_GE(res.durationNanos, toNanos(50ms + getErrorMargin()));
    EXPECT_LE(res.durationNanos, toNanos(51ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_twoSignaledGpuFenceFrames_flagOn) {
    GpuTestConfig config{
            .adpfGpuFlagOn = true,
            .frame1GpuFenceDuration = 30ms,
            .frame2GpuFenceDuration = 50ms,
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = true,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(50ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(10ms));
    EXPECT_EQ(res.durationNanos, toNanos(50ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_UnsingaledGpuFenceFrameUsingPreviousFrame) {
    GpuTestConfig config{
            .adpfGpuFlagOn = false,
            .frame1GpuFenceDuration = 31ms,
            .frame2GpuFenceDuration = Duration::fromNs(Fence::SIGNAL_TIME_PENDING),
            .vsyncPeriod = 10ms,
            .presentDuration = 2ms,
            .postCompDuration = 8ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = true,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, 0L);
    EXPECT_EQ(res.cpuDurationNanos, 0L);
    EXPECT_GE(res.durationNanos, toNanos(30ms + getErrorMargin()));
    EXPECT_LE(res.durationNanos, toNanos(31ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, setGpuFenceTime_UnsingaledGpuFenceFrameUsingPreviousFrame_flagOn) {
    GpuTestConfig config{
            .adpfGpuFlagOn = true,
            .frame1GpuFenceDuration = 30ms,
            .frame2GpuFenceDuration = Duration::fromNs(Fence::SIGNAL_TIME_PENDING),
            .vsyncPeriod = 10ms,
            .presentDuration = 22ms,
            .postCompDuration = 88ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = true,
    };
    WorkDuration res = testGpuScenario(config);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(30ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(110ms));
    EXPECT_EQ(res.durationNanos, toNanos(110ms + getErrorMargin()));
}

} // namespace
} // namespace android::Hwc2::impl
