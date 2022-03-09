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
#include "mock/MockEventThread.h"
#include "mock/MockLayer.h"
#include "mock/MockSchedulerCallback.h"

using testing::_;
using testing::Return;

namespace android {
namespace {

constexpr PhysicalDisplayId PHYSICAL_DISPLAY_ID(999);

class SchedulerTest : public testing::Test {
protected:
    class MockEventThreadConnection : public android::EventThreadConnection {
    public:
        explicit MockEventThreadConnection(EventThread* eventThread)
              : EventThreadConnection(eventThread, /*callingUid=*/0, ResyncCallback()) {}
        ~MockEventThreadConnection() = default;

        MOCK_METHOD1(stealReceiveChannel, status_t(gui::BitTube* outChannel));
        MOCK_METHOD1(setVsyncRate, status_t(uint32_t count));
        MOCK_METHOD0(requestNextVsync, void());
    };

    SchedulerTest();

    const DisplayModePtr mode60 = DisplayMode::Builder(0)
                                          .setId(DisplayModeId(0))
                                          .setPhysicalDisplayId(PhysicalDisplayId(0))
                                          .setVsyncPeriod(Fps(60.f).getPeriodNsecs())
                                          .setGroup(0)
                                          .build();
    const DisplayModePtr mode120 = DisplayMode::Builder(1)
                                           .setId(DisplayModeId(1))
                                           .setPhysicalDisplayId(PhysicalDisplayId(0))
                                           .setVsyncPeriod(Fps(120.f).getPeriodNsecs())
                                           .setGroup(0)
                                           .build();

    std::shared_ptr<scheduler::RefreshRateConfigs> mConfigs =
            std::make_shared<scheduler::RefreshRateConfigs>(DisplayModes{mode60}, mode60->getId());

    mock::SchedulerCallback mSchedulerCallback;

    // The scheduler should initially disable VSYNC.
    struct ExpectDisableVsync {
        ExpectDisableVsync(mock::SchedulerCallback& callback) {
            EXPECT_CALL(callback, setVsyncEnabled(false)).Times(1);
        }
    } mExpectDisableVsync{mSchedulerCallback};

    TestableScheduler* mScheduler = new TestableScheduler{mConfigs, mSchedulerCallback};

    Scheduler::ConnectionHandle mConnectionHandle;
    mock::EventThread* mEventThread;
    sp<MockEventThreadConnection> mEventThreadConnection;

    TestableSurfaceFlinger mFlinger;
};

SchedulerTest::SchedulerTest() {
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

    mFlinger.resetScheduler(mScheduler);
}

} // namespace

TEST_F(SchedulerTest, invalidConnectionHandle) {
    Scheduler::ConnectionHandle handle;

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
    sp<mock::MockLayer> layer = sp<mock::MockLayer>::make(mFlinger.flinger());

    // recordLayerHistory should be a noop
    ASSERT_EQ(static_cast<size_t>(0), mScheduler->getNumActiveLayers());
    mScheduler->recordLayerHistory(layer.get(), 0, LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(static_cast<size_t>(0), mScheduler->getNumActiveLayers());

    constexpr bool kPowerStateNormal = true;
    mScheduler->setDisplayPowerState(kPowerStateNormal);

    constexpr uint32_t kDisplayArea = 999'999;
    mScheduler->onActiveDisplayAreaChanged(kDisplayArea);

    EXPECT_CALL(mSchedulerCallback, changeRefreshRate(_, _)).Times(0);
    mScheduler->chooseRefreshRateForContent();
}

TEST_F(SchedulerTest, updateDisplayModes) {
    ASSERT_EQ(static_cast<size_t>(0), mScheduler->layerHistorySize());
    sp<mock::MockLayer> layer = sp<mock::MockLayer>::make(mFlinger.flinger());
    ASSERT_EQ(static_cast<size_t>(1), mScheduler->layerHistorySize());

    mScheduler->setRefreshRateConfigs(
            std::make_shared<scheduler::RefreshRateConfigs>(DisplayModes{mode60, mode120},
                                                            mode60->getId()));

    ASSERT_EQ(static_cast<size_t>(0), mScheduler->getNumActiveLayers());
    mScheduler->recordLayerHistory(layer.get(), 0, LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(static_cast<size_t>(1), mScheduler->getNumActiveLayers());
}

TEST_F(SchedulerTest, testDispatchCachedReportedMode) {
    // If the optional fields are cleared, the function should return before
    // onModeChange is called.
    mScheduler->clearOptionalFieldsInFeatures();
    EXPECT_NO_FATAL_FAILURE(mScheduler->dispatchCachedReportedMode());
    EXPECT_CALL(*mEventThread, onModeChanged(_)).Times(0);
}

TEST_F(SchedulerTest, onNonPrimaryDisplayModeChanged_invalidParameters) {
    const auto mode = DisplayMode::Builder(hal::HWConfigId(0))
                              .setId(DisplayModeId(111))
                              .setPhysicalDisplayId(PHYSICAL_DISPLAY_ID)
                              .setVsyncPeriod(111111)
                              .build();

    // If the handle is incorrect, the function should return before
    // onModeChange is called.
    Scheduler::ConnectionHandle invalidHandle = {.id = 123};
    EXPECT_NO_FATAL_FAILURE(mScheduler->onNonPrimaryDisplayModeChanged(invalidHandle, mode));
    EXPECT_CALL(*mEventThread, onModeChanged(_)).Times(0);
}

TEST_F(SchedulerTest, calculateMaxAcquiredBufferCount) {
    EXPECT_EQ(1, mFlinger.calculateMaxAcquiredBufferCount(Fps(60), 30ms));
    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(Fps(90), 30ms));
    EXPECT_EQ(3, mFlinger.calculateMaxAcquiredBufferCount(Fps(120), 30ms));

    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(Fps(60), 40ms));

    EXPECT_EQ(1, mFlinger.calculateMaxAcquiredBufferCount(Fps(60), 10ms));
}

MATCHER(Is120Hz, "") {
    return arg.getFps().equalsWithMargin(Fps(120.f));
}

TEST_F(SchedulerTest, chooseRefreshRateForContentSelectsMaxRefreshRate) {
    mScheduler->setRefreshRateConfigs(
            std::make_shared<scheduler::RefreshRateConfigs>(DisplayModes{mode60, mode120},
                                                            mode60->getId()));

    sp<mock::MockLayer> layer = sp<mock::MockLayer>::make(mFlinger.flinger());

    mScheduler->recordLayerHistory(layer.get(), 0, LayerHistory::LayerUpdateType::Buffer);

    constexpr bool kPowerStateNormal = true;
    mScheduler->setDisplayPowerState(kPowerStateNormal);

    constexpr uint32_t kDisplayArea = 999'999;
    mScheduler->onActiveDisplayAreaChanged(kDisplayArea);

    EXPECT_CALL(mSchedulerCallback, changeRefreshRate(Is120Hz(), _)).Times(1);
    mScheduler->chooseRefreshRateForContent();
}

} // namespace android
