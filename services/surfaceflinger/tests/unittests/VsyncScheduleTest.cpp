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
#include "mock/MockSchedulerCallback.h"
#include "mock/MockVSyncDispatch.h"
#include "mock/MockVSyncTracker.h"
#include "mock/MockVsyncController.h"

using testing::_;

namespace android {

constexpr PhysicalDisplayId DEFAULT_DISPLAY_ID = PhysicalDisplayId::fromPort(42u);

class VsyncScheduleTest : public testing::Test {
protected:
    VsyncScheduleTest();
    ~VsyncScheduleTest() override;

    scheduler::mock::SchedulerCallback mCallback;
    const std::unique_ptr<scheduler::VsyncSchedule> mVsyncSchedule =
            std::unique_ptr<scheduler::VsyncSchedule>(
                    new scheduler::VsyncSchedule(DEFAULT_DISPLAY_ID,
                                                 std::make_shared<mock::VSyncTracker>(),
                                                 std::make_shared<mock::VSyncDispatch>(),
                                                 std::make_unique<mock::VsyncController>()));

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
    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);

    mVsyncSchedule->enableHardwareVsync(mCallback);
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisallowed) {
    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(mCallback, false /* disallow */);
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisallowed2) {
    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(mCallback, true /* disallow */);
}

TEST_F(VsyncScheduleTest, MakeAllowed) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(mCallback, false /* disallow */);
}

TEST_F(VsyncScheduleTest, DisableDoesNothingWhenDisabled2) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);

    mVsyncSchedule->disableHardwareVsync(mCallback, true /* disallow */);
}

TEST_F(VsyncScheduleTest, EnableWorksWhenDisabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, true));

    mVsyncSchedule->enableHardwareVsync(mCallback);
}

TEST_F(VsyncScheduleTest, EnableWorksOnce) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, true));

    mVsyncSchedule->enableHardwareVsync(mCallback);

    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);
    mVsyncSchedule->enableHardwareVsync(mCallback);
}

TEST_F(VsyncScheduleTest, AllowedIsSticky) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, EnableDisable) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, true));

    mVsyncSchedule->enableHardwareVsync(mCallback);

    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, false));
    mVsyncSchedule->disableHardwareVsync(mCallback, false /* disallow */);
}

TEST_F(VsyncScheduleTest, EnableDisable2) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, true));

    mVsyncSchedule->enableHardwareVsync(mCallback);

    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, false));
    mVsyncSchedule->disableHardwareVsync(mCallback, true /* disallow */);
}

TEST_F(VsyncScheduleTest, StartPeriodTransition) {
    // Note: startPeriodTransition is only called when hardware vsyncs are
    // allowed.
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));

    const Period period = (60_Hz).getPeriod();

    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, true));
    EXPECT_CALL(getController(), startPeriodTransition(period.ns(), false));

    mVsyncSchedule->startPeriodTransition(mCallback, period, false);
}

TEST_F(VsyncScheduleTest, StartPeriodTransitionAlreadyEnabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->enableHardwareVsync(mCallback);

    const Period period = (60_Hz).getPeriod();

    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);
    EXPECT_CALL(getController(), startPeriodTransition(period.ns(), false));

    mVsyncSchedule->startPeriodTransition(mCallback, period, false);
}

TEST_F(VsyncScheduleTest, StartPeriodTransitionForce) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));

    const Period period = (60_Hz).getPeriod();

    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, true));
    EXPECT_CALL(getController(), startPeriodTransition(period.ns(), true));

    mVsyncSchedule->startPeriodTransition(mCallback, period, true);
}

TEST_F(VsyncScheduleTest, AddResyncSampleDisallowed) {
    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);
    EXPECT_CALL(getController(), addHwVsyncTimestamp(_, _, _)).Times(0);

    mVsyncSchedule->addResyncSample(mCallback, timestamp, period);
}

TEST_F(VsyncScheduleTest, AddResyncSampleDisabled) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);
    EXPECT_CALL(getController(), addHwVsyncTimestamp(_, _, _)).Times(0);

    mVsyncSchedule->addResyncSample(mCallback, timestamp, period);
}

TEST_F(VsyncScheduleTest, AddResyncSampleReturnsTrue) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->enableHardwareVsync(mCallback);

    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mCallback, setVsyncEnabled(_, _)).Times(0);
    EXPECT_CALL(getController(),
                addHwVsyncTimestamp(timestamp.ns(), std::optional<nsecs_t>(period.ns()), _))
            .WillOnce(Return(true));

    mVsyncSchedule->addResyncSample(mCallback, timestamp, period);
}

TEST_F(VsyncScheduleTest, AddResyncSampleReturnsFalse) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->enableHardwareVsync(mCallback);

    const Period period = (60_Hz).getPeriod();
    const auto timestamp = TimePoint::now();

    EXPECT_CALL(mCallback, setVsyncEnabled(DEFAULT_DISPLAY_ID, false));
    EXPECT_CALL(getController(),
                addHwVsyncTimestamp(timestamp.ns(), std::optional<nsecs_t>(period.ns()), _))
            .WillOnce(Return(false));

    mVsyncSchedule->addResyncSample(mCallback, timestamp, period);
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
    mVsyncSchedule->disableHardwareVsync(mCallback, false /* disallow */);
    ASSERT_FALSE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, DisallowMakesNotAllowed) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->disableHardwareVsync(mCallback, true /* disallow */);
    ASSERT_FALSE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

TEST_F(VsyncScheduleTest, StillAllowedAfterDisable) {
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(true /* makeAllowed */));
    mVsyncSchedule->disableHardwareVsync(mCallback, false /* disallow */);
    ASSERT_TRUE(mVsyncSchedule->isHardwareVsyncAllowed(false /* makeAllowed */));
}

} // namespace
} // namespace android
