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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include <mutex>

#include "Scheduler/EventThread.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockEventThread.h"
#include "mock/MockLayer.h"
#include "mock/MockSchedulerCallback.h"

namespace android::scheduler {

using android::mock::createDisplayMode;

using testing::_;
using testing::Return;

namespace {

using MockEventThread = android::mock::EventThread;
using MockLayer = android::mock::MockLayer;

constexpr PhysicalDisplayId PHYSICAL_DISPLAY_ID = PhysicalDisplayId::fromPort(255u);

class SchedulerTest : public testing::Test {
protected:
    class MockEventThreadConnection : public android::EventThreadConnection {
    public:
        explicit MockEventThreadConnection(EventThread* eventThread)
              : EventThreadConnection(eventThread, /*callingUid=*/0, ResyncCallback()) {}
        ~MockEventThreadConnection() = default;

        MOCK_METHOD1(stealReceiveChannel, binder::Status(gui::BitTube* outChannel));
        MOCK_METHOD1(setVsyncRate, binder::Status(int count));
        MOCK_METHOD0(requestNextVsync, binder::Status());
    };

    SchedulerTest();

    static inline const DisplayModePtr kMode60 = createDisplayMode(DisplayModeId(0), 60_Hz);
    static inline const DisplayModePtr kMode120 = createDisplayMode(DisplayModeId(1), 120_Hz);

    std::shared_ptr<RefreshRateConfigs> mConfigs =
            std::make_shared<RefreshRateConfigs>(makeModes(kMode60), kMode60->getId());

    mock::SchedulerCallback mSchedulerCallback;
    TestableScheduler* mScheduler = new TestableScheduler{mConfigs, mSchedulerCallback};

    ConnectionHandle mConnectionHandle;
    MockEventThread* mEventThread;
    sp<MockEventThreadConnection> mEventThreadConnection;

    TestableSurfaceFlinger mFlinger;
};

SchedulerTest::SchedulerTest() {
    auto eventThread = std::make_unique<MockEventThread>();
    mEventThread = eventThread.get();
    EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_)).WillOnce(Return(0));

    mEventThreadConnection = new MockEventThreadConnection(mEventThread);

    // createConnection call to scheduler makes a createEventConnection call to EventThread. Make
    // sure that call gets executed and returns an EventThread::Connection object.
    EXPECT_CALL(*mEventThread, createEventConnection(_, _))
            .WillRepeatedly(Return(mEventThreadConnection));

    mConnectionHandle = mScheduler->createConnection(std::move(eventThread));
    EXPECT_TRUE(mConnectionHandle);

    mFlinger.resetScheduler(mScheduler);
}

} // namespace

TEST_F(SchedulerTest, invalidConnectionHandle) {
    ConnectionHandle handle;

    const sp<IDisplayEventConnection> connection = mScheduler->createDisplayEventConnection(handle);

    EXPECT_FALSE(connection);
    EXPECT_FALSE(mScheduler->getEventConnection(handle));

    // The EXPECT_CALLS make sure we don't call the functions on the subsequent event threads.
    EXPECT_CALL(*mEventThread, onHotplugReceived(_, _)).Times(0);
    mScheduler->onHotplugReceived(handle, PHYSICAL_DISPLAY_ID, false);

    EXPECT_CALL(*mEventThread, onScreenAcquired()).Times(0);
    mScheduler->onScreenAcquired(handle);

    EXPECT_CALL(*mEventThread, onScreenReleased()).Times(0);
    mScheduler->onScreenReleased(handle);

    std::string output;
    EXPECT_CALL(*mEventThread, dump(_)).Times(0);
    mScheduler->dump(handle, output);
    EXPECT_TRUE(output.empty());

    EXPECT_CALL(*mEventThread, setDuration(10ns, 20ns)).Times(0);
    mScheduler->setDuration(handle, 10ns, 20ns);
}

TEST_F(SchedulerTest, validConnectionHandle) {
    const sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(mConnectionHandle);

    ASSERT_EQ(mEventThreadConnection, connection);
    EXPECT_TRUE(mScheduler->getEventConnection(mConnectionHandle));

    EXPECT_CALL(*mEventThread, onHotplugReceived(PHYSICAL_DISPLAY_ID, false)).Times(1);
    mScheduler->onHotplugReceived(mConnectionHandle, PHYSICAL_DISPLAY_ID, false);

    EXPECT_CALL(*mEventThread, onScreenAcquired()).Times(1);
    mScheduler->onScreenAcquired(mConnectionHandle);

    EXPECT_CALL(*mEventThread, onScreenReleased()).Times(1);
    mScheduler->onScreenReleased(mConnectionHandle);

    std::string output("dump");
    EXPECT_CALL(*mEventThread, dump(output)).Times(1);
    mScheduler->dump(mConnectionHandle, output);
    EXPECT_FALSE(output.empty());

    EXPECT_CALL(*mEventThread, setDuration(10ns, 20ns)).Times(1);
    mScheduler->setDuration(mConnectionHandle, 10ns, 20ns);

    static constexpr size_t kEventConnections = 5;
    EXPECT_CALL(*mEventThread, getEventThreadConnectionCount()).WillOnce(Return(kEventConnections));
    EXPECT_EQ(kEventConnections, mScheduler->getEventThreadConnectionCount(mConnectionHandle));
}

TEST_F(SchedulerTest, chooseRefreshRateForContentIsNoopWhenModeSwitchingIsNotSupported) {
    // The layer is registered at creation time and deregistered at destruction time.
    sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());

    // recordLayerHistory should be a noop
    ASSERT_EQ(0u, mScheduler->getNumActiveLayers());
    mScheduler->recordLayerHistory(layer.get(), 0, LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(0u, mScheduler->getNumActiveLayers());

    constexpr hal::PowerMode kPowerModeOn = hal::PowerMode::ON;
    mScheduler->setDisplayPowerMode(kPowerModeOn);

    constexpr uint32_t kDisplayArea = 999'999;
    mScheduler->onActiveDisplayAreaChanged(kDisplayArea);

    EXPECT_CALL(mSchedulerCallback, requestDisplayMode(_, _)).Times(0);
    mScheduler->chooseRefreshRateForContent();
}

TEST_F(SchedulerTest, updateDisplayModes) {
    ASSERT_EQ(0u, mScheduler->layerHistorySize());
    sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    ASSERT_EQ(1u, mScheduler->layerHistorySize());

    mScheduler->setRefreshRateConfigs(
            std::make_shared<RefreshRateConfigs>(makeModes(kMode60, kMode120), kMode60->getId()));

    ASSERT_EQ(0u, mScheduler->getNumActiveLayers());
    mScheduler->recordLayerHistory(layer.get(), 0, LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(1u, mScheduler->getNumActiveLayers());
}

TEST_F(SchedulerTest, dispatchCachedReportedMode) {
    mScheduler->clearCachedReportedMode();

    EXPECT_CALL(*mEventThread, onModeChanged(_)).Times(0);
    EXPECT_NO_FATAL_FAILURE(mScheduler->dispatchCachedReportedMode());
}

TEST_F(SchedulerTest, onNonPrimaryDisplayModeChanged_invalidParameters) {
    const auto mode = DisplayMode::Builder(hal::HWConfigId(0))
                              .setId(DisplayModeId(111))
                              .setPhysicalDisplayId(PHYSICAL_DISPLAY_ID)
                              .setVsyncPeriod(111111)
                              .build();

    // If the handle is incorrect, the function should return before
    // onModeChange is called.
    ConnectionHandle invalidHandle = {.id = 123};
    EXPECT_NO_FATAL_FAILURE(mScheduler->onNonPrimaryDisplayModeChanged(invalidHandle, mode));
    EXPECT_CALL(*mEventThread, onModeChanged(_)).Times(0);
}

TEST_F(SchedulerTest, calculateMaxAcquiredBufferCount) {
    EXPECT_EQ(1, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 30ms));
    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(90_Hz, 30ms));
    EXPECT_EQ(3, mFlinger.calculateMaxAcquiredBufferCount(120_Hz, 30ms));

    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 40ms));

    EXPECT_EQ(1, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 10ms));
}

MATCHER(Is120Hz, "") {
    return isApproxEqual(arg->getFps(), 120_Hz);
}

TEST_F(SchedulerTest, chooseRefreshRateForContentSelectsMaxRefreshRate) {
    mScheduler->setRefreshRateConfigs(
            std::make_shared<RefreshRateConfigs>(makeModes(kMode60, kMode120), kMode60->getId()));

    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    EXPECT_CALL(*layer, isVisible()).WillOnce(Return(true));

    mScheduler->recordLayerHistory(layer.get(), 0, LayerHistory::LayerUpdateType::Buffer);

    constexpr hal::PowerMode kPowerModeOn = hal::PowerMode::ON;
    mScheduler->setDisplayPowerMode(kPowerModeOn);

    constexpr uint32_t kDisplayArea = 999'999;
    mScheduler->onActiveDisplayAreaChanged(kDisplayArea);

    EXPECT_CALL(mSchedulerCallback, requestDisplayMode(Is120Hz(), _)).Times(1);
    mScheduler->chooseRefreshRateForContent();

    // No-op if layer requirements have not changed.
    EXPECT_CALL(mSchedulerCallback, requestDisplayMode(_, _)).Times(0);
    mScheduler->chooseRefreshRateForContent();
}

} // namespace android::scheduler
