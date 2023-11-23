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

#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include <scheduler/Fps.h>
#include "Scheduler/VsyncSchedule.h"
#include "ThreadContext.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockVSyncDispatch.h"
#include "mock/MockVSyncTracker.h"
#include "mock/MockVsyncController.h"

using android::mock::createDisplayMode;
using testing::_;

namespace android {

constexpr PhysicalDisplayId kDisplayId = PhysicalDisplayId::fromPort(42u);

class VsyncScheduleTest : public testing::Test {
protected:
    VsyncScheduleTest();
    ~VsyncScheduleTest() override;

    testing::MockFunction<void(PhysicalDisplayId, bool)> mRequestHardwareVsync;

    const std::unique_ptr<scheduler::VsyncSchedule> mVsyncSchedule =
            std::unique_ptr<scheduler::VsyncSchedule>(
                    new scheduler::VsyncSchedule(kDisplayId, std::make_shared<mock::VSyncTracker>(),
                                                 std::make_shared<mock::VSyncDispatch>(),
                                                 std::make_unique<mock::VsyncController>(),
                                                 mRequestHardwareVsync.AsStdFunction()));

    mock::VsyncController& getController() {
        return *static_cast<mock::VsyncController*>(&mVsyncSchedule->getController());
    }
};

VsyncScheduleTest::VsyncScheduleTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

VsyncScheduleTest::~VsyncScheduleTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

namespace {

using namespace testing;

TEST_F(VsyncScheduleTest, InitiallyDisallowed) {
    ASSERT_FALSE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, EnableDoesNothingWhenDisallowed) {
    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);

    mVsyncSchedule->enableHardwareVsync();
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisallowed) {
    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(false /* disallow */);
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisallowed2) {
    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(true /* disallow */);
}

TEST_F(VsyncScheduleTest, MakeAllowed) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(false /* disallow */);
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisabled2) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(true /* disallow */);
}

TEST_F(VsyncScheduleTest, EnableWorksWhenDisabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, true));

    mVsyncSchedule->enableHardwareVsync();
}

TEST_F(VsyncScheduleTest, EnableWorksOnce) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, true));

    mVsyncSchedule->enableHardwareVsync();

    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);
    mVsyncSchedule->enableHardwareVsync();
}

TEST_F(VsyncScheduleTest, AllowedIsSticky) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, EnableDisable) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, true));

    mVsyncSchedule->enableHardwareVsync();

    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, false));
    mVsyncSchedule->disableHardwareVsync(false /* disallow */);
}

TEST_F(VsyncScheduleTest, EnableDisable2) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, true));

    mVsyncSchedule->enableHardwareVsync();

    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, false));
    mVsyncSchedule->disableHardwareVsync(true /* disallow */);
}

TEST_F(VsyncScheduleTest, StartPeriodTransition) {
    // Note: startPeriodTransition is only called when hardware vsyncs are
    // allowed.
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));

    const auto mode = ftl::as_non_null(createDisplayMode(DisplayModeId(0), 60_Hz));

    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, true));
    EXPECT_CALL(getController(), onDisplayModeChanged(mode, false));

    mVsyncSchedule->onDisplayModeChanged(mode, false);
}

TEST_F(VsyncScheduleTest, StartPeriodTransitionAlreadyEnabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->enableHardwareVsync();

    const auto mode = ftl::as_non_null(createDisplayMode(DisplayModeId(0), 60_Hz));

    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);
    EXPECT_CALL(getController(), onDisplayModeChanged(mode, false));

    mVsyncSchedule->onDisplayModeChanged(mode, false);
}

TEST_F(VsyncScheduleTest, StartPeriodTransitionForce) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));

    const auto mode = ftl::as_non_null(createDisplayMode(DisplayModeId(0), 60_Hz));

    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, true));
    EXPECT_CALL(getController(), onDisplayModeChanged(mode, true));

    mVsyncSchedule->onDisplayModeChanged(mode, true);
}

TEST_F(VsyncScheduleTest, AddResyncSampleDisallowed) {
    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);
    EXPECT_CALL(getController(), addHwVsyncTimestamp(_, _, _)).Times(0);

    mVsyncSchedule->addResyncSample(timestamp, period);
}

TEST_F(VsyncScheduleTest, AddResyncSampleDisabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);
    EXPECT_CALL(getController(), addHwVsyncTimestamp(_, _, _)).Times(0);

    mVsyncSchedule->addResyncSample(timestamp, period);
}

TEST_F(VsyncScheduleTest, AddResyncSampleReturnsTrue) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->enableHardwareVsync();

    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mRequestHardwareVsync, Call(_, _)).Times(0);
    EXPECT_CALL(getController(),
                addHwVsyncTimestamp(timestamp.ns(), std::optional<nsecs_t>(period.ns()), _))
            .WillOnce(Return(true));

    mVsyncSchedule->addResyncSample(timestamp, period);
}

TEST_F(VsyncScheduleTest, AddResyncSampleReturnsFalse) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->enableHardwareVsync();

    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mRequestHardwareVsync, Call(kDisplayId, false));
    EXPECT_CALL(getController(),
                addHwVsyncTimestamp(timestamp.ns(), std::optional<nsecs_t>(period.ns()), _))
            .WillOnce(Return(false));

    mVsyncSchedule->addResyncSample(timestamp, period);
}

TEST_F(VsyncScheduleTest, PendingState) FTL_FAKE_GUARD(kMainThreadContext) {
    ASSERT_FALSE(mVsyncSchedule->getPendingHardwareVsyncState());
    mVsyncSchedule->setPendingHardwareVsyncState(true);
    ASSERT_TRUE(mVsyncSchedule->getPendingHardwareVsyncState());

    mVsyncSchedule->setPendingHardwareVsyncState(false);
    ASSERT_FALSE(mVsyncSchedule->getPendingHardwareVsyncState());
}

TEST_F(VsyncScheduleTest, DisableDoesNotMakeAllowed) {
    ASSERT_FALSE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
    mVsyncSchedule->disableHardwareVsync(false /* disallow */);
    ASSERT_FALSE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, DisallowMakesNotAllowed) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->disableHardwareVsync(true /* disallow */);
    ASSERT_FALSE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, StillAllowedAfterDisable) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->disableHardwareVsync(false /* disallow */);
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

} // namespace
} // namespace android
