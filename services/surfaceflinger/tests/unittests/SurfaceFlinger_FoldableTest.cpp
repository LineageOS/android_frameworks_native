/*
 * Copyright 2023 The Android Open Source Project
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

#include <com_android_graphics_surfaceflinger_flags.h>
#include <common/test/FlagUtils.h>
#include "DualDisplayTransactionTest.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace com::android::graphics::surfaceflinger;

namespace android {
namespace {

constexpr bool kExpectSetPowerModeOnce = false;
struct FoldableTest : DualDisplayTransactionTest<hal::PowerMode::OFF, hal::PowerMode::OFF,
                                                 kExpectSetPowerModeOnce> {};

TEST_F(FoldableTest, promotesPacesetterOnBoot) {
    // When the device boots, the inner display should be the pacesetter.
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);

    // ...and should still be after powering on.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);
}

TEST_F(FoldableTest, promotesPacesetterOnFoldUnfold) {
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);

    // The outer display should become the pacesetter after folding.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::OFF);
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kOuterDisplayId);

    // The inner display should become the pacesetter after unfolding.
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::OFF);
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);
}

TEST_F(FoldableTest, promotesPacesetterOnConcurrentPowerOn) {
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);

    // The inner display should stay the pacesetter if both are powered on.
    // TODO(b/255635821): The pacesetter should depend on the displays' refresh rates.
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);

    // The outer display should become the pacesetter if designated.
    mFlinger.scheduler()->setPacesetterDisplay(kOuterDisplayId);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kOuterDisplayId);

    // The inner display should become the pacesetter if designated.
    mFlinger.scheduler()->setPacesetterDisplay(kInnerDisplayId);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);
}

TEST_F(FoldableTest, promotesPacesetterOnConcurrentPowerOff) {
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);

    // The outer display should become the pacesetter if the inner display powers off.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::OFF);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kOuterDisplayId);

    // The outer display should stay the pacesetter if both are powered on.
    // TODO(b/255635821): The pacesetter should depend on the displays' refresh rates.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kOuterDisplayId);

    // The inner display should become the pacesetter if the outer display powers off.
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::OFF);
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);
}

TEST_F(FoldableTest, doesNotRequestHardwareVsyncIfPoweredOff) {
    // Both displays are powered off.
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kInnerDisplayId, _))
            .Times(0);
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kOuterDisplayId, _))
            .Times(0);

    EXPECT_FALSE(mInnerDisplay->isPoweredOn());
    EXPECT_FALSE(mOuterDisplay->isPoweredOn());

    auto& scheduler = *mFlinger.scheduler();
    scheduler.onHardwareVsyncRequest(kInnerDisplayId, true);
    scheduler.onHardwareVsyncRequest(kOuterDisplayId, true);
}

TEST_F(FoldableTest, requestsHardwareVsyncForInnerDisplay) {
    // Only inner display is powered on.
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kInnerDisplayId, true))
            .Times(1);
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kOuterDisplayId, _))
            .Times(0);

    // The injected VsyncSchedule uses TestableScheduler::mockRequestHardwareVsync, so no calls to
    // ISchedulerCallback::requestHardwareVsync are expected during setPowerModeInternal.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);

    EXPECT_TRUE(mInnerDisplay->isPoweredOn());
    EXPECT_FALSE(mOuterDisplay->isPoweredOn());

    auto& scheduler = *mFlinger.scheduler();
    scheduler.onHardwareVsyncRequest(kInnerDisplayId, true);
    scheduler.onHardwareVsyncRequest(kOuterDisplayId, true);
}

TEST_F(FoldableTest, requestsHardwareVsyncForOuterDisplay) {
    // Only outer display is powered on.
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kInnerDisplayId, _))
            .Times(0);
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kOuterDisplayId, true))
            .Times(1);

    // The injected VsyncSchedule uses TestableScheduler::mockRequestHardwareVsync, so no calls to
    // ISchedulerCallback::requestHardwareVsync are expected during setPowerModeInternal.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::OFF);
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);

    EXPECT_FALSE(mInnerDisplay->isPoweredOn());
    EXPECT_TRUE(mOuterDisplay->isPoweredOn());

    auto& scheduler = *mFlinger.scheduler();
    scheduler.onHardwareVsyncRequest(kInnerDisplayId, true);
    scheduler.onHardwareVsyncRequest(kOuterDisplayId, true);
}

TEST_F(FoldableTest, requestsHardwareVsyncForBothDisplays) {
    // Both displays are powered on.
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kInnerDisplayId, true))
            .Times(1);
    EXPECT_CALL(mFlinger.mockSchedulerCallback(), requestHardwareVsync(kOuterDisplayId, true))
            .Times(1);

    // The injected VsyncSchedule uses TestableScheduler::mockRequestHardwareVsync, so no calls to
    // ISchedulerCallback::requestHardwareVsync are expected during setPowerModeInternal.
    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);

    EXPECT_TRUE(mInnerDisplay->isPoweredOn());
    EXPECT_TRUE(mOuterDisplay->isPoweredOn());

    auto& scheduler = *mFlinger.scheduler();
    scheduler.onHardwareVsyncRequest(mInnerDisplay->getPhysicalId(), true);
    scheduler.onHardwareVsyncRequest(mOuterDisplay->getPhysicalId(), true);
}

TEST_F(FoldableTest, requestVsyncOnPowerOn) {
    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    EXPECT_CALL(mFlinger.scheduler()->mockRequestHardwareVsync, Call(kInnerDisplayId, true))
            .Times(1);
    EXPECT_CALL(mFlinger.scheduler()->mockRequestHardwareVsync, Call(kOuterDisplayId, true))
            .Times(1);

    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);
}

TEST_F(FoldableTest, disableVsyncOnPowerOffPacesetter) {
    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    // When the device boots, the inner display should be the pacesetter.
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kInnerDisplayId);

    testing::InSequence seq;
    EXPECT_CALL(mFlinger.scheduler()->mockRequestHardwareVsync, Call(kInnerDisplayId, true))
            .Times(1);
    EXPECT_CALL(mFlinger.scheduler()->mockRequestHardwareVsync, Call(kOuterDisplayId, true))
            .Times(1);

    // Turning off the pacesetter will result in disabling VSYNC.
    EXPECT_CALL(mFlinger.scheduler()->mockRequestHardwareVsync, Call(kInnerDisplayId, false))
            .Times(1);

    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::ON);
    mFlinger.setPowerModeInternal(mOuterDisplay, PowerMode::ON);

    mFlinger.setPowerModeInternal(mInnerDisplay, PowerMode::OFF);

    // Other display is now the pacesetter.
    ASSERT_EQ(mFlinger.scheduler()->pacesetterDisplayId(), kOuterDisplayId);
}

} // namespace
} // namespace android
