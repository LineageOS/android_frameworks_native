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
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include <mutex>

#include "Scheduler/EventControlThread.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "TestableScheduler.h"
#include "mock/DisplayHardware/MockDisplay.h"
#include "mock/MockEventThread.h"

using testing::_;
using testing::Return;

namespace android {

constexpr PhysicalDisplayId PHYSICAL_DISPLAY_ID = 999;

class SchedulerTest : public testing::Test {
protected:
    class MockEventThreadConnection : public android::EventThreadConnection {
    public:
        explicit MockEventThreadConnection(EventThread* eventThread)
              : EventThreadConnection(eventThread, ResyncCallback(),
                                      ISurfaceComposer::eConfigChangedSuppress) {}
        ~MockEventThreadConnection() = default;

        MOCK_METHOD1(stealReceiveChannel, status_t(gui::BitTube* outChannel));
        MOCK_METHOD1(setVsyncRate, status_t(uint32_t count));
        MOCK_METHOD0(requestNextVsync, void());
    };

    SchedulerTest();
    ~SchedulerTest() override;

    std::unique_ptr<scheduler::RefreshRateConfigs> mRefreshRateConfigs;
    std::unique_ptr<TestableScheduler> mScheduler;

    Scheduler::ConnectionHandle mConnectionHandle;
    mock::EventThread* mEventThread;
    sp<MockEventThreadConnection> mEventThreadConnection;
    Hwc2::mock::Display mDisplay;
};

SchedulerTest::SchedulerTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    std::vector<std::shared_ptr<const HWC2::Display::Config>> configs{
            HWC2::Display::Config::Builder(mDisplay, 0)
                    .setVsyncPeriod(int32_t(16666667))
                    .setConfigGroup(0)
                    .build()};
    mRefreshRateConfigs = std::make_unique<
            scheduler::RefreshRateConfigs>(configs, /*currentConfig=*/HwcConfigIndexType(0));

    mScheduler = std::make_unique<TestableScheduler>(*mRefreshRateConfigs, false);

    auto eventThread = std::make_unique<mock::EventThread>();
    mEventThread = eventThread.get();
    EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_)).WillOnce(Return(0));

    mEventThreadConnection = new MockEventThreadConnection(mEventThread);

    // createConnection call to scheduler makes a createEventConnection call to EventThread. Make
    // sure that call gets executed and returns an EventThread::Connection object.
    EXPECT_CALL(*mEventThread, createEventConnection(_, _))
            .WillRepeatedly(Return(mEventThreadConnection));

    mConnectionHandle = mScheduler->createConnection(std::move(eventThread));
    EXPECT_TRUE(mConnectionHandle);
}

SchedulerTest::~SchedulerTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

namespace {
/* ------------------------------------------------------------------------
 * Test cases
 */

TEST_F(SchedulerTest, invalidConnectionHandle) {
    Scheduler::ConnectionHandle handle;

    sp<IDisplayEventConnection> connection;
    ASSERT_NO_FATAL_FAILURE(
            connection = mScheduler->createDisplayEventConnection(handle,
                                                                  ISurfaceComposer::
                                                                          eConfigChangedSuppress));
    EXPECT_FALSE(connection);
    EXPECT_FALSE(mScheduler->getEventConnection(handle));

    // The EXPECT_CALLS make sure we don't call the functions on the subsequent event threads.
    EXPECT_CALL(*mEventThread, onHotplugReceived(_, _)).Times(0);
    ASSERT_NO_FATAL_FAILURE(mScheduler->onHotplugReceived(handle, PHYSICAL_DISPLAY_ID, false));

    EXPECT_CALL(*mEventThread, onScreenAcquired()).Times(0);
    ASSERT_NO_FATAL_FAILURE(mScheduler->onScreenAcquired(handle));

    EXPECT_CALL(*mEventThread, onScreenReleased()).Times(0);
    ASSERT_NO_FATAL_FAILURE(mScheduler->onScreenReleased(handle));

    std::string output;
    EXPECT_CALL(*mEventThread, dump(_)).Times(0);
    ASSERT_NO_FATAL_FAILURE(mScheduler->dump(handle, output));
    EXPECT_TRUE(output.empty());

    EXPECT_CALL(*mEventThread, setPhaseOffset(_)).Times(0);
    ASSERT_NO_FATAL_FAILURE(mScheduler->setPhaseOffset(handle, 10));
}

TEST_F(SchedulerTest, validConnectionHandle) {
    sp<IDisplayEventConnection> connection;
    ASSERT_NO_FATAL_FAILURE(
            connection = mScheduler->createDisplayEventConnection(mConnectionHandle,
                                                                  ISurfaceComposer::
                                                                          eConfigChangedSuppress));
    ASSERT_EQ(mEventThreadConnection, connection);
    EXPECT_TRUE(mScheduler->getEventConnection(mConnectionHandle));

    EXPECT_CALL(*mEventThread, onHotplugReceived(PHYSICAL_DISPLAY_ID, false)).Times(1);
    ASSERT_NO_FATAL_FAILURE(
            mScheduler->onHotplugReceived(mConnectionHandle, PHYSICAL_DISPLAY_ID, false));

    EXPECT_CALL(*mEventThread, onScreenAcquired()).Times(1);
    ASSERT_NO_FATAL_FAILURE(mScheduler->onScreenAcquired(mConnectionHandle));

    EXPECT_CALL(*mEventThread, onScreenReleased()).Times(1);
    ASSERT_NO_FATAL_FAILURE(mScheduler->onScreenReleased(mConnectionHandle));

    std::string output("dump");
    EXPECT_CALL(*mEventThread, dump(output)).Times(1);
    ASSERT_NO_FATAL_FAILURE(mScheduler->dump(mConnectionHandle, output));
    EXPECT_FALSE(output.empty());

    EXPECT_CALL(*mEventThread, setPhaseOffset(10)).Times(1);
    ASSERT_NO_FATAL_FAILURE(mScheduler->setPhaseOffset(mConnectionHandle, 10));

    static constexpr size_t kEventConnections = 5;
    ON_CALL(*mEventThread, getEventThreadConnectionCount())
            .WillByDefault(Return(kEventConnections));
    EXPECT_EQ(kEventConnections, mScheduler->getEventThreadConnectionCount(mConnectionHandle));
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
