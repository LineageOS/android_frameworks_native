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
    void SetUpFmq(bool usesSharedEventFlag, bool isQueueFull);
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
        bool usesFmq = false;
        bool usesSharedFmqFlag = true;
        bool fmqFull = false;
    };

    void testGpuScenario(GpuTestConfig& config, WorkDuration& ret);

protected:
    TestableSurfaceFlinger mFlinger;
    std::unique_ptr<PowerAdvisor> mPowerAdvisor;
    MockPowerHalController* mMockPowerHalController;
    std::shared_ptr<MockPowerHintSessionWrapper> mMockPowerHintSession;
    std::shared_ptr<AidlMessageQueue<ChannelMessage, SynchronizedReadWrite>> mBackendFmq;
    std::shared_ptr<AidlMessageQueue<int8_t, SynchronizedReadWrite>> mBackendFlagQueue;
    android::hardware::EventFlag* mEventFlag;
    uint32_t mWriteFlagBitmask = 2;
    uint32_t mReadFlagBitmask = 1;
    int64_t mSessionId = 123;
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel, true);
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel_fixed, false);
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

void PowerAdvisorTest::SetUpFmq(bool usesSharedEventFlag, bool isQueueFull) {
    mBackendFmq = std::make_shared<
            AidlMessageQueue<ChannelMessage, SynchronizedReadWrite>>(2, !usesSharedEventFlag);
    ChannelConfig config;
    config.channelDescriptor = mBackendFmq->dupeDesc();
    if (usesSharedEventFlag) {
        mBackendFlagQueue =
                std::make_shared<AidlMessageQueue<int8_t, SynchronizedReadWrite>>(1, true);
        config.eventFlagDescriptor = mBackendFlagQueue->dupeDesc();
        ASSERT_EQ(android::hardware::EventFlag::createEventFlag(mBackendFlagQueue
                                                                        ->getEventFlagWord(),
                                                                &mEventFlag),
                  android::NO_ERROR);
    } else {
        ASSERT_EQ(android::hardware::EventFlag::createEventFlag(mBackendFmq->getEventFlagWord(),
                                                                &mEventFlag),
                  android::NO_ERROR);
    }
    config.writeFlagBitmask = static_cast<int32_t>(mWriteFlagBitmask);
    config.readFlagBitmask = static_cast<int32_t>(mReadFlagBitmask);
    ON_CALL(*mMockPowerHalController, getSessionChannel)
            .WillByDefault(Return(
                    ByMove(HalResult<ChannelConfig>::fromStatus(Status::ok(), std::move(config)))));
    startPowerHintSession();
    if (isQueueFull) {
        std::vector<ChannelMessage> msgs;
        msgs.resize(2);
        mBackendFmq->writeBlocking(msgs.data(), 2, mReadFlagBitmask, mWriteFlagBitmask,
                                   std::chrono::nanoseconds(1ms).count(), mEventFlag);
    }
}

void PowerAdvisorTest::startPowerHintSession(bool returnValidSession) {
    mMockPowerHintSession = std::make_shared<NiceMock<MockPowerHintSessionWrapper>>();
    if (returnValidSession) {
        ON_CALL(*mMockPowerHalController, createHintSessionWithConfig)
                .WillByDefault(DoAll(SetArgPointee<5>(aidl::android::hardware::power::SessionConfig{
                                             .id = mSessionId}),
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

void PowerAdvisorTest::testGpuScenario(GpuTestConfig& config, WorkDuration& ret) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::adpf_gpu_sf,
                      config.adpfGpuFlagOn);
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel_fixed, config.usesFmq);
    mPowerAdvisor->onBootFinished();
    bool expectsFmqSuccess = config.usesSharedFmqFlag && !config.fmqFull;
    if (config.usesFmq) {
        SetUpFmq(config.usesSharedFmqFlag, config.fmqFull);
    } else {
        startPowerHintSession();
    }

    std::vector<DisplayId> displayIds{PhysicalDisplayId::fromPort(42u), GpuVirtualDisplayId(0),
                                      GpuVirtualDisplayId(1)};
    mPowerAdvisor->setDisplays(displayIds);
    auto display1 = displayIds[0];
    // 60hz

    TimePoint startTime = TimePoint::now();
    int64_t target;
    SessionHint hint;
    if (!config.usesFmq || !expectsFmqSuccess) {
        EXPECT_CALL(*mMockPowerHintSession, updateTargetWorkDuration(_))
                .Times(1)
                .WillOnce(DoAll(testing::SaveArg<0>(&target),
                                testing::Return(testing::ByMove(HalResult<void>::ok()))));
        EXPECT_CALL(*mMockPowerHintSession, sendHint(_))
                .Times(1)
                .WillOnce(DoAll(testing::SaveArg<0>(&hint),
                                testing::Return(testing::ByMove(HalResult<void>::ok()))));
    }
    // advisor only starts on frame 2 so do an initial frame
    fakeBasicFrameTiming(startTime, config.vsyncPeriod);
    // send a load hint
    mPowerAdvisor->notifyCpuLoadUp();
    if (config.usesFmq && expectsFmqSuccess) {
        std::vector<ChannelMessage> msgs;
        ASSERT_EQ(mBackendFmq->availableToRead(), 2uL);
        msgs.resize(2);
        ASSERT_TRUE(mBackendFmq->readBlocking(msgs.data(), 2, mReadFlagBitmask, mWriteFlagBitmask,
                                              std::chrono::nanoseconds(1ms).count(), mEventFlag));
        ASSERT_EQ(msgs[0].sessionID, mSessionId);
        ASSERT_GE(msgs[0].timeStampNanos, startTime.ns());
        ASSERT_EQ(msgs[0].data.getTag(),
                  ChannelMessage::ChannelMessageContents::Tag::targetDuration);
        target = msgs[0].data.get<ChannelMessage::ChannelMessageContents::Tag::targetDuration>();
        ASSERT_EQ(msgs[1].sessionID, mSessionId);
        ASSERT_GE(msgs[1].timeStampNanos, startTime.ns());
        ASSERT_EQ(msgs[1].data.getTag(), ChannelMessage::ChannelMessageContents::Tag::hint);
        hint = msgs[1].data.get<ChannelMessage::ChannelMessageContents::Tag::hint>();
    }
    ASSERT_EQ(target, config.vsyncPeriod.ns());
    ASSERT_EQ(hint, SessionHint::CPU_LOAD_UP);

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
    if (config.usesFmq && expectsFmqSuccess) {
        // same target update will not trigger FMQ write
        ASSERT_EQ(mBackendFmq->availableToRead(), 0uL);
    }
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

    if (config.usesFmq && expectsFmqSuccess) {
        mPowerAdvisor->reportActualWorkDuration();
        ASSERT_EQ(mBackendFmq->availableToRead(), 1uL);
        std::vector<ChannelMessage> msgs;
        msgs.resize(1);
        ASSERT_TRUE(mBackendFmq->readBlocking(msgs.data(), 1, mReadFlagBitmask, mWriteFlagBitmask,
                                              std::chrono::nanoseconds(1ms).count(), mEventFlag));
        ASSERT_EQ(msgs[0].sessionID, mSessionId);
        ASSERT_GE(msgs[0].timeStampNanos, startTime.ns());
        ASSERT_EQ(msgs[0].data.getTag(), ChannelMessage::ChannelMessageContents::Tag::workDuration);
        auto actual = msgs[0].data.get<ChannelMessage::ChannelMessageContents::Tag::workDuration>();
        ret.workPeriodStartTimestampNanos = actual.workPeriodStartTimestampNanos;
        ret.cpuDurationNanos = actual.cpuDurationNanos;
        ret.gpuDurationNanos = actual.gpuDurationNanos;
        ret.durationNanos = actual.durationNanos;
    } else {
        std::vector<aidl::android::hardware::power::WorkDuration> durationReq;
        EXPECT_CALL(*mMockPowerHintSession, reportActualWorkDuration(_))
                .Times(1)
                .WillOnce(DoAll(testing::SaveArg<0>(&durationReq),
                                testing::Return(testing::ByMove(HalResult<void>::ok()))));
        mPowerAdvisor->reportActualWorkDuration();
        ASSERT_EQ(durationReq.size(), 1u);
        ret = std::move(durationReq[0]);
    }
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
    mPowerAdvisor->onBootFinished();
    mMockPowerHintSession = std::make_shared<NiceMock<MockPowerHintSessionWrapper>>();
    EXPECT_CALL(*mMockPowerHalController, createHintSessionWithConfig)
            .Times(1)
            .WillOnce(Return(HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
                                     fromStatus(ndk::ScopedAStatus::fromExceptionCode(
                                                        EX_UNSUPPORTED_OPERATION),
                                                nullptr)));

    EXPECT_CALL(*mMockPowerHalController, createHintSession)
            .Times(1)
            .WillOnce(Return(HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
                                     fromStatus(binder::Status::ok(), mMockPowerHintSession)));
    mPowerAdvisor->enablePowerHintSession(true);
    ASSERT_TRUE(mPowerAdvisor->startPowerHintSession({1, 2, 3}));
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
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
    WorkDuration res;
    testGpuScenario(config, res);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(30ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(110ms));
    EXPECT_EQ(res.durationNanos, toNanos(110ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, fmq_sendTargetAndActualDuration) {
    GpuTestConfig config{
            .adpfGpuFlagOn = true,
            .frame1GpuFenceDuration = 30ms,
            .frame2GpuFenceDuration = Duration::fromNs(Fence::SIGNAL_TIME_PENDING),
            .vsyncPeriod = 10ms,
            .presentDuration = 22ms,
            .postCompDuration = 88ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = true,
            .usesFmq = true,
            .usesSharedFmqFlag = true,
    };
    WorkDuration res;
    testGpuScenario(config, res);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(30ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(110ms));
    EXPECT_EQ(res.durationNanos, toNanos(110ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, fmq_sendTargetAndActualDuration_noSharedFlag) {
    GpuTestConfig config{
            .adpfGpuFlagOn = true,
            .frame1GpuFenceDuration = 30ms,
            .frame2GpuFenceDuration = Duration::fromNs(Fence::SIGNAL_TIME_PENDING),
            .vsyncPeriod = 10ms,
            .presentDuration = 22ms,
            .postCompDuration = 88ms,
            .frame1RequiresRenderEngine = true,
            .frame2RequiresRenderEngine = true,
            .usesFmq = true,
            .usesSharedFmqFlag = false,
    };
    WorkDuration res;
    testGpuScenario(config, res);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(30ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(110ms));
    EXPECT_EQ(res.durationNanos, toNanos(110ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, fmq_sendTargetAndActualDuration_queueFull) {
    GpuTestConfig config{.adpfGpuFlagOn = true,
                         .frame1GpuFenceDuration = 30ms,
                         .frame2GpuFenceDuration = Duration::fromNs(Fence::SIGNAL_TIME_PENDING),
                         .vsyncPeriod = 10ms,
                         .presentDuration = 22ms,
                         .postCompDuration = 88ms,
                         .frame1RequiresRenderEngine = true,
                         .frame2RequiresRenderEngine = true,
                         .usesFmq = true,
                         .usesSharedFmqFlag = true,
                         .fmqFull = true};
    WorkDuration res;
    testGpuScenario(config, res);
    EXPECT_EQ(res.gpuDurationNanos, toNanos(30ms));
    EXPECT_EQ(res.cpuDurationNanos, toNanos(110ms));
    EXPECT_EQ(res.durationNanos, toNanos(110ms + getErrorMargin()));
}

TEST_F(PowerAdvisorTest, fmq_sendHint) {
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel_fixed, true);
    mPowerAdvisor->onBootFinished();
    SetUpFmq(true, false);
    auto startTime = uptimeNanos();
    mPowerAdvisor->notifyCpuLoadUp();
    std::vector<ChannelMessage> msgs;
    ASSERT_EQ(mBackendFmq->availableToRead(), 1uL);
    msgs.resize(1);
    ASSERT_TRUE(mBackendFmq->readBlocking(msgs.data(), 1, mReadFlagBitmask, mWriteFlagBitmask,
                                          std::chrono::nanoseconds(1ms).count(), mEventFlag));
    ASSERT_EQ(msgs[0].sessionID, mSessionId);
    ASSERT_GE(msgs[0].timeStampNanos, startTime);
    ASSERT_EQ(msgs[0].data.getTag(), ChannelMessage::ChannelMessageContents::Tag::hint);
    auto hint = msgs[0].data.get<ChannelMessage::ChannelMessageContents::Tag::hint>();
    ASSERT_EQ(hint, SessionHint::CPU_LOAD_UP);
}

TEST_F(PowerAdvisorTest, fmq_sendHint_noSharedFlag) {
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel_fixed, true);
    mPowerAdvisor->onBootFinished();
    SetUpFmq(false, false);
    SessionHint hint;
    EXPECT_CALL(*mMockPowerHintSession, sendHint(_))
            .Times(1)
            .WillOnce(DoAll(testing::SaveArg<0>(&hint),
                            testing::Return(testing::ByMove(HalResult<void>::ok()))));
    mPowerAdvisor->notifyCpuLoadUp();
    ASSERT_EQ(mBackendFmq->availableToRead(), 0uL);
    ASSERT_EQ(hint, SessionHint::CPU_LOAD_UP);
}

TEST_F(PowerAdvisorTest, fmq_sendHint_queueFull) {
    SET_FLAG_FOR_TEST(android::os::adpf_use_fmq_channel_fixed, true);
    mPowerAdvisor->onBootFinished();
    SetUpFmq(true, true);
    ASSERT_EQ(mBackendFmq->availableToRead(), 2uL);
    SessionHint hint;
    EXPECT_CALL(*mMockPowerHintSession, sendHint(_))
            .Times(1)
            .WillOnce(DoAll(testing::SaveArg<0>(&hint),
                            testing::Return(testing::ByMove(HalResult<void>::ok()))));
    std::vector<ChannelMessage> msgs;
    msgs.resize(1);
    mBackendFmq->writeBlocking(msgs.data(), 1, mReadFlagBitmask, mWriteFlagBitmask,
                               std::chrono::nanoseconds(1ms).count(), mEventFlag);
    mPowerAdvisor->notifyCpuLoadUp();
    ASSERT_EQ(mBackendFmq->availableToRead(), 2uL);
    ASSERT_EQ(hint, SessionHint::CPU_LOAD_UP);
}

} // namespace
} // namespace android::Hwc2::impl
