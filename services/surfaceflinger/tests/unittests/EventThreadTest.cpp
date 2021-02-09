/*
 * Copyright (C) 2018 The Android Open Source Project
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
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <utils/Errors.h>

#include "AsyncCallRecorder.h"
#include "DisplayHardware/DisplayMode.h"
#include "Scheduler/EventThread.h"

using namespace std::chrono_literals;
using namespace std::placeholders;

using namespace android::flag_operators;
using testing::_;
using testing::Invoke;

namespace android {

namespace {

constexpr PhysicalDisplayId INTERNAL_DISPLAY_ID(111);
constexpr PhysicalDisplayId EXTERNAL_DISPLAY_ID(222);
constexpr PhysicalDisplayId DISPLAY_ID_64BIT(0xabcd12349876fedcULL);

class MockVSyncSource : public VSyncSource {
public:
    const char* getName() const override { return "test"; }

    MOCK_METHOD1(setVSyncEnabled, void(bool));
    MOCK_METHOD1(setCallback, void(VSyncSource::Callback*));
    MOCK_METHOD2(setDuration,
                 void(std::chrono::nanoseconds workDuration,
                      std::chrono::nanoseconds readyDuration));
    MOCK_METHOD1(pauseVsyncCallback, void(bool));
    MOCK_CONST_METHOD1(dump, void(std::string&));
};

} // namespace

class EventThreadTest : public testing::Test {
protected:
    class MockEventThreadConnection : public EventThreadConnection {
    public:
        MockEventThreadConnection(impl::EventThread* eventThread, uid_t callingUid,
                                  ResyncCallback&& resyncCallback,
                                  ISurfaceComposer::EventRegistrationFlags eventRegistration)
              : EventThreadConnection(eventThread, callingUid, std::move(resyncCallback),
                                      eventRegistration) {}
        MOCK_METHOD1(postEvent, status_t(const DisplayEventReceiver::Event& event));
    };

    using ConnectionEventRecorder =
            AsyncCallRecorderWithCannedReturn<status_t (*)(const DisplayEventReceiver::Event&)>;

    EventThreadTest();
    ~EventThreadTest() override;

    void createThread(std::unique_ptr<VSyncSource>);
    sp<MockEventThreadConnection> createConnection(
            ConnectionEventRecorder& recorder,
            ISurfaceComposer::EventRegistrationFlags eventRegistration = {},
            uid_t ownerUid = mConnectionUid);

    void expectVSyncSetEnabledCallReceived(bool expectedState);
    void expectVSyncSetDurationCallReceived(std::chrono::nanoseconds expectedDuration,
                                            std::chrono::nanoseconds expectedReadyDuration);
    VSyncSource::Callback* expectVSyncSetCallbackCallReceived();
    void expectInterceptCallReceived(nsecs_t expectedTimestamp);
    void expectVsyncEventReceivedByConnection(const char* name,
                                              ConnectionEventRecorder& connectionEventRecorder,
                                              nsecs_t expectedTimestamp, unsigned expectedCount);
    void expectVsyncEventReceivedByConnection(nsecs_t expectedTimestamp, unsigned expectedCount);
    void expectHotplugEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                bool expectedConnected);
    void expectConfigChangedEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                      int32_t expectedConfigId,
                                                      nsecs_t expectedVsyncPeriod);
    void expectThrottleVsyncReceived(nsecs_t expectedTimestamp, uid_t);
    void expectUidFrameRateMappingEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                            std::vector<FrameRateOverride>);

    AsyncCallRecorder<void (*)(bool)> mVSyncSetEnabledCallRecorder;
    AsyncCallRecorder<void (*)(VSyncSource::Callback*)> mVSyncSetCallbackCallRecorder;
    AsyncCallRecorder<void (*)(std::chrono::nanoseconds, std::chrono::nanoseconds)>
            mVSyncSetDurationCallRecorder;
    AsyncCallRecorder<void (*)()> mResyncCallRecorder;
    AsyncCallRecorder<void (*)(nsecs_t)> mInterceptVSyncCallRecorder;
    AsyncCallRecorder<void (*)(nsecs_t, uid_t)> mThrottleVsyncCallRecorder;
    ConnectionEventRecorder mConnectionEventCallRecorder{0};
    ConnectionEventRecorder mThrottledConnectionEventCallRecorder{0};

    MockVSyncSource* mVSyncSource;
    VSyncSource::Callback* mCallback = nullptr;
    std::unique_ptr<impl::EventThread> mThread;
    sp<MockEventThreadConnection> mConnection;
    sp<MockEventThreadConnection> mThrottledConnection;

    static constexpr uid_t mConnectionUid = 443;
    static constexpr uid_t mThrottledConnectionUid = 177;
};

EventThreadTest::EventThreadTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    auto vsyncSource = std::make_unique<MockVSyncSource>();
    mVSyncSource = vsyncSource.get();

    EXPECT_CALL(*mVSyncSource, setVSyncEnabled(_))
            .WillRepeatedly(Invoke(mVSyncSetEnabledCallRecorder.getInvocable()));

    EXPECT_CALL(*mVSyncSource, setCallback(_))
            .WillRepeatedly(Invoke(mVSyncSetCallbackCallRecorder.getInvocable()));

    EXPECT_CALL(*mVSyncSource, setDuration(_, _))
            .WillRepeatedly(Invoke(mVSyncSetDurationCallRecorder.getInvocable()));

    createThread(std::move(vsyncSource));
    mConnection = createConnection(mConnectionEventCallRecorder,
                                   ISurfaceComposer::EventRegistration::modeChanged |
                                           ISurfaceComposer::EventRegistration::frameRateOverride);
    mThrottledConnection = createConnection(mThrottledConnectionEventCallRecorder,
                                            ISurfaceComposer::EventRegistration::modeChanged,
                                            mThrottledConnectionUid);

    // A display must be connected for VSYNC events to be delivered.
    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, true);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, true);
}

EventThreadTest::~EventThreadTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());

    // EventThread should unregister itself as VSyncSource callback.
    EXPECT_TRUE(!mVSyncSetCallbackCallRecorder.waitForUnexpectedCall().has_value());
}

void EventThreadTest::createThread(std::unique_ptr<VSyncSource> source) {
    const auto throttleVsync = [&](nsecs_t expectedVsyncTimestamp, uid_t uid) {
        mThrottleVsyncCallRecorder.getInvocable()(expectedVsyncTimestamp, uid);
        return (uid == mThrottledConnectionUid);
    };

    mThread = std::make_unique<impl::EventThread>(std::move(source),
                                                  /*tokenManager=*/nullptr,
                                                  mInterceptVSyncCallRecorder.getInvocable(),
                                                  throttleVsync);

    // EventThread should register itself as VSyncSource callback.
    mCallback = expectVSyncSetCallbackCallReceived();
    ASSERT_TRUE(mCallback);
}

sp<EventThreadTest::MockEventThreadConnection> EventThreadTest::createConnection(
        ConnectionEventRecorder& recorder,
        ISurfaceComposer::EventRegistrationFlags eventRegistration, uid_t ownerUid) {
    sp<MockEventThreadConnection> connection =
            new MockEventThreadConnection(mThread.get(), ownerUid,
                                          mResyncCallRecorder.getInvocable(), eventRegistration);
    EXPECT_CALL(*connection, postEvent(_)).WillRepeatedly(Invoke(recorder.getInvocable()));
    return connection;
}

void EventThreadTest::expectVSyncSetEnabledCallReceived(bool expectedState) {
    auto args = mVSyncSetEnabledCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedState, std::get<0>(args.value()));
}

void EventThreadTest::expectVSyncSetDurationCallReceived(
        std::chrono::nanoseconds expectedDuration, std::chrono::nanoseconds expectedReadyDuration) {
    auto args = mVSyncSetDurationCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedDuration, std::get<0>(args.value()));
    EXPECT_EQ(expectedReadyDuration, std::get<1>(args.value()));
}

VSyncSource::Callback* EventThreadTest::expectVSyncSetCallbackCallReceived() {
    auto callbackSet = mVSyncSetCallbackCallRecorder.waitForCall();
    return callbackSet.has_value() ? std::get<0>(callbackSet.value()) : nullptr;
}

void EventThreadTest::expectInterceptCallReceived(nsecs_t expectedTimestamp) {
    auto args = mInterceptVSyncCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedTimestamp, std::get<0>(args.value()));
}

void EventThreadTest::expectThrottleVsyncReceived(nsecs_t expectedTimestamp, uid_t uid) {
    auto args = mThrottleVsyncCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedTimestamp, std::get<0>(args.value()));
    EXPECT_EQ(uid, std::get<1>(args.value()));
}

void EventThreadTest::expectVsyncEventReceivedByConnection(
        const char* name, ConnectionEventRecorder& connectionEventRecorder,
        nsecs_t expectedTimestamp, unsigned expectedCount) {
    auto args = connectionEventRecorder.waitForCall();
    ASSERT_TRUE(args.has_value()) << name << " did not receive an event for timestamp "
                                  << expectedTimestamp;
    const auto& event = std::get<0>(args.value());
    EXPECT_EQ(DisplayEventReceiver::DISPLAY_EVENT_VSYNC, event.header.type)
            << name << " did not get the correct event for timestamp " << expectedTimestamp;
    EXPECT_EQ(expectedTimestamp, event.header.timestamp)
            << name << " did not get the expected timestamp for timestamp " << expectedTimestamp;
    EXPECT_EQ(expectedCount, event.vsync.count)
            << name << " did not get the expected count for timestamp " << expectedTimestamp;
}

void EventThreadTest::expectVsyncEventReceivedByConnection(nsecs_t expectedTimestamp,
                                                           unsigned expectedCount) {
    expectVsyncEventReceivedByConnection("mConnectionEventCallRecorder",
                                         mConnectionEventCallRecorder, expectedTimestamp,
                                         expectedCount);
}

void EventThreadTest::expectHotplugEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                             bool expectedConnected) {
    auto args = mConnectionEventCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    const auto& event = std::get<0>(args.value());
    EXPECT_EQ(DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG, event.header.type);
    EXPECT_EQ(expectedDisplayId, event.header.displayId);
    EXPECT_EQ(expectedConnected, event.hotplug.connected);
}

void EventThreadTest::expectConfigChangedEventReceivedByConnection(
        PhysicalDisplayId expectedDisplayId, int32_t expectedConfigId,
        nsecs_t expectedVsyncPeriod) {
    auto args = mConnectionEventCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    const auto& event = std::get<0>(args.value());
    EXPECT_EQ(DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE, event.header.type);
    EXPECT_EQ(expectedDisplayId, event.header.displayId);
    EXPECT_EQ(expectedConfigId, event.modeChange.modeId);
    EXPECT_EQ(expectedVsyncPeriod, event.modeChange.vsyncPeriod);
}

void EventThreadTest::expectUidFrameRateMappingEventReceivedByConnection(
        PhysicalDisplayId expectedDisplayId, std::vector<FrameRateOverride> expectedOverrides) {
    for (const auto [uid, frameRateHz] : expectedOverrides) {
        auto args = mConnectionEventCallRecorder.waitForCall();
        ASSERT_TRUE(args.has_value());
        const auto& event = std::get<0>(args.value());
        EXPECT_EQ(DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE, event.header.type);
        EXPECT_EQ(expectedDisplayId, event.header.displayId);
        EXPECT_EQ(uid, event.frameRateOverride.uid);
        EXPECT_EQ(frameRateHz, event.frameRateOverride.frameRateHz);
    }

    auto args = mConnectionEventCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    const auto& event = std::get<0>(args.value());
    EXPECT_EQ(DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH, event.header.type);
    EXPECT_EQ(expectedDisplayId, event.header.displayId);
}

namespace {

/* ------------------------------------------------------------------------
 * Test cases
 */

TEST_F(EventThreadTest, canCreateAndDestroyThreadWithNoEventsSent) {
    EXPECT_FALSE(mVSyncSetEnabledCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mVSyncSetCallbackCallRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mVSyncSetDurationCallRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mResyncCallRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mInterceptVSyncCallRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForCall(0us).has_value());
}

TEST_F(EventThreadTest, vsyncRequestIsIgnoredIfDisplayIsDisconnected) {
    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, false);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, false);

    // Signal that we want the next vsync event to be posted to the connection.
    mThread->requestNextVsync(mConnection);

    // EventThread should not enable vsync callbacks.
    EXPECT_FALSE(mVSyncSetEnabledCallRecorder.waitForUnexpectedCall().has_value());
}

TEST_F(EventThreadTest, requestNextVsyncPostsASingleVSyncEventToTheConnection) {
    // Signal that we want the next vsync event to be posted to the connection
    mThread->requestNextVsync(mConnection);

    // EventThread should immediately request a resync.
    EXPECT_TRUE(mResyncCallRecorder.waitForCall().has_value());

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // Use the received callback to signal a first vsync event.
    // The interceptor should receive the event, as well as the connection.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    expectThrottleVsyncReceived(456, mConnectionUid);
    expectVsyncEventReceivedByConnection(123, 1u);

    // Use the received callback to signal a second vsync event.
    // The interceptor should receive the event, but the connection should
    // not as it was only interested in the first.
    mCallback->onVSyncEvent(456, 123, 0);
    expectInterceptCallReceived(456);
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());

    // EventThread should also detect that at this point that it does not need
    // any more vsync events, and should disable their generation.
    expectVSyncSetEnabledCallReceived(false);
}

TEST_F(EventThreadTest, setVsyncRateZeroPostsNoVSyncEventsToThatConnection) {
    // Create a first connection, register it, and request a vsync rate of zero.
    ConnectionEventRecorder firstConnectionEventRecorder{0};
    sp<MockEventThreadConnection> firstConnection = createConnection(firstConnectionEventRecorder);
    mThread->setVsyncRate(0, firstConnection);

    // By itself, this should not enable vsync events
    EXPECT_FALSE(mVSyncSetEnabledCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mVSyncSetCallbackCallRecorder.waitForCall(0us).has_value());

    // However if there is another connection which wants events at a nonzero rate.....
    ConnectionEventRecorder secondConnectionEventRecorder{0};
    sp<MockEventThreadConnection> secondConnection =
            createConnection(secondConnectionEventRecorder);
    mThread->setVsyncRate(1, secondConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // Send a vsync event. EventThread should then make a call to the
    // interceptor, and the second connection. The first connection should not
    // get the event.
    mCallback->onVSyncEvent(123, 456, 0);
    expectInterceptCallReceived(123);
    EXPECT_FALSE(firstConnectionEventRecorder.waitForUnexpectedCall().has_value());
    expectVsyncEventReceivedByConnection("secondConnection", secondConnectionEventRecorder, 123,
                                         1u);
}

TEST_F(EventThreadTest, setVsyncRateOnePostsAllEventsToThatConnection) {
    mThread->setVsyncRate(1, mConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // Send a vsync event. EventThread should then make a call to the
    // interceptor, and the connection.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    expectThrottleVsyncReceived(456, mConnectionUid);
    expectVsyncEventReceivedByConnection(123, 1u);

    // A second event should go to the same places.
    mCallback->onVSyncEvent(456, 123, 0);
    expectInterceptCallReceived(456);
    expectThrottleVsyncReceived(123, mConnectionUid);
    expectVsyncEventReceivedByConnection(456, 2u);

    // A third event should go to the same places.
    mCallback->onVSyncEvent(789, 777, 111);
    expectInterceptCallReceived(789);
    expectThrottleVsyncReceived(777, mConnectionUid);
    expectVsyncEventReceivedByConnection(789, 3u);
}

TEST_F(EventThreadTest, setVsyncRateTwoPostsEveryOtherEventToThatConnection) {
    mThread->setVsyncRate(2, mConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // The first event will be seen by the interceptor, and not the connection.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());

    // The second event will be seen by the interceptor and the connection.
    mCallback->onVSyncEvent(456, 123, 0);
    expectInterceptCallReceived(456);
    expectVsyncEventReceivedByConnection(456, 2u);
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());

    // The third event will be seen by the interceptor, and not the connection.
    mCallback->onVSyncEvent(789, 777, 744);
    expectInterceptCallReceived(789);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());

    // The fourth event will be seen by the interceptor and the connection.
    mCallback->onVSyncEvent(101112, 7847, 86);
    expectInterceptCallReceived(101112);
    expectVsyncEventReceivedByConnection(101112, 4u);
}

TEST_F(EventThreadTest, connectionsRemovedIfInstanceDestroyed) {
    mThread->setVsyncRate(1, mConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // Destroy the only (strong) reference to the connection.
    mConnection = nullptr;

    // The first event will be seen by the interceptor, and not the connection.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());

    // EventThread should disable vsync callbacks
    expectVSyncSetEnabledCallReceived(false);
}

TEST_F(EventThreadTest, connectionsRemovedIfEventDeliveryError) {
    ConnectionEventRecorder errorConnectionEventRecorder{NO_MEMORY};
    sp<MockEventThreadConnection> errorConnection = createConnection(errorConnectionEventRecorder);
    mThread->setVsyncRate(1, errorConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // The first event will be seen by the interceptor, and by the connection,
    // which then returns an error.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 123, 1u);

    // A subsequent event will be seen by the interceptor and not by the
    // connection.
    mCallback->onVSyncEvent(456, 123, 0);
    expectInterceptCallReceived(456);
    EXPECT_FALSE(errorConnectionEventRecorder.waitForUnexpectedCall().has_value());

    // EventThread should disable vsync callbacks with the second event
    expectVSyncSetEnabledCallReceived(false);
}

TEST_F(EventThreadTest, tracksEventConnections) {
    EXPECT_EQ(2, mThread->getEventThreadConnectionCount());
    ConnectionEventRecorder errorConnectionEventRecorder{NO_MEMORY};
    sp<MockEventThreadConnection> errorConnection = createConnection(errorConnectionEventRecorder);
    mThread->setVsyncRate(1, errorConnection);
    EXPECT_EQ(3, mThread->getEventThreadConnectionCount());
    ConnectionEventRecorder secondConnectionEventRecorder{0};
    sp<MockEventThreadConnection> secondConnection =
            createConnection(secondConnectionEventRecorder);
    mThread->setVsyncRate(1, secondConnection);
    EXPECT_EQ(4, mThread->getEventThreadConnectionCount());

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // The first event will be seen by the interceptor, and by the connection,
    // which then returns an error.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 123, 1u);
    expectVsyncEventReceivedByConnection("successConnection", secondConnectionEventRecorder, 123,
                                         1u);
    EXPECT_EQ(3, mThread->getEventThreadConnectionCount());
}

TEST_F(EventThreadTest, eventsDroppedIfNonfatalEventDeliveryError) {
    ConnectionEventRecorder errorConnectionEventRecorder{WOULD_BLOCK};
    sp<MockEventThreadConnection> errorConnection = createConnection(errorConnectionEventRecorder);
    mThread->setVsyncRate(1, errorConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // The first event will be seen by the interceptor, and by the connection,
    // which then returns an non-fatal error.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 123, 1u);

    // A subsequent event will be seen by the interceptor, and by the connection,
    // which still then returns an non-fatal error.
    mCallback->onVSyncEvent(456, 123, 0);
    expectInterceptCallReceived(456);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 456, 2u);

    // EventThread will not disable vsync callbacks as the errors are non-fatal.
    EXPECT_FALSE(mVSyncSetEnabledCallRecorder.waitForUnexpectedCall().has_value());
}

TEST_F(EventThreadTest, setPhaseOffsetForwardsToVSyncSource) {
    mThread->setDuration(321ns, 456ns);
    expectVSyncSetDurationCallReceived(321ns, 456ns);
}

TEST_F(EventThreadTest, postHotplugInternalDisconnect) {
    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, false);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, false);
}

TEST_F(EventThreadTest, postHotplugInternalConnect) {
    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, true);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, true);
}

TEST_F(EventThreadTest, postHotplugExternalDisconnect) {
    mThread->onHotplugReceived(EXTERNAL_DISPLAY_ID, false);
    expectHotplugEventReceivedByConnection(EXTERNAL_DISPLAY_ID, false);
}

TEST_F(EventThreadTest, postHotplugExternalConnect) {
    mThread->onHotplugReceived(EXTERNAL_DISPLAY_ID, true);
    expectHotplugEventReceivedByConnection(EXTERNAL_DISPLAY_ID, true);
}

TEST_F(EventThreadTest, postConfigChangedPrimary) {
    mThread->onModeChanged(INTERNAL_DISPLAY_ID, DisplayModeId(7), 16666666);
    expectConfigChangedEventReceivedByConnection(INTERNAL_DISPLAY_ID, 7, 16666666);
}

TEST_F(EventThreadTest, postConfigChangedExternal) {
    mThread->onModeChanged(EXTERNAL_DISPLAY_ID, DisplayModeId(5), 16666666);
    expectConfigChangedEventReceivedByConnection(EXTERNAL_DISPLAY_ID, 5, 16666666);
}

TEST_F(EventThreadTest, postConfigChangedPrimary64bit) {
    mThread->onModeChanged(DISPLAY_ID_64BIT, DisplayModeId(7), 16666666);
    expectConfigChangedEventReceivedByConnection(DISPLAY_ID_64BIT, 7, 16666666);
}

TEST_F(EventThreadTest, suppressConfigChanged) {
    ConnectionEventRecorder suppressConnectionEventRecorder{0};
    sp<MockEventThreadConnection> suppressConnection =
            createConnection(suppressConnectionEventRecorder);

    mThread->onModeChanged(INTERNAL_DISPLAY_ID, DisplayModeId(9), 16666666);
    expectConfigChangedEventReceivedByConnection(INTERNAL_DISPLAY_ID, 9, 16666666);

    auto args = suppressConnectionEventRecorder.waitForCall();
    ASSERT_FALSE(args.has_value());
}

TEST_F(EventThreadTest, postUidFrameRateMapping) {
    const std::vector<FrameRateOverride> overrides = {
            {.uid = 1, .frameRateHz = 20},
            {.uid = 3, .frameRateHz = 40},
            {.uid = 5, .frameRateHz = 60},
    };

    mThread->onFrameRateOverridesChanged(INTERNAL_DISPLAY_ID, overrides);
    expectUidFrameRateMappingEventReceivedByConnection(INTERNAL_DISPLAY_ID, overrides);
}

TEST_F(EventThreadTest, suppressUidFrameRateMapping) {
    const std::vector<FrameRateOverride> overrides = {
            {.uid = 1, .frameRateHz = 20},
            {.uid = 3, .frameRateHz = 40},
            {.uid = 5, .frameRateHz = 60},
    };

    ConnectionEventRecorder suppressConnectionEventRecorder{0};
    sp<MockEventThreadConnection> suppressConnection =
            createConnection(suppressConnectionEventRecorder);

    mThread->onFrameRateOverridesChanged(INTERNAL_DISPLAY_ID, overrides);
    expectUidFrameRateMappingEventReceivedByConnection(INTERNAL_DISPLAY_ID, overrides);

    auto args = suppressConnectionEventRecorder.waitForCall();
    ASSERT_FALSE(args.has_value());
}

TEST_F(EventThreadTest, requestNextVsyncWithThrottleVsyncDoesntPostVSync) {
    // Signal that we want the next vsync event to be posted to the throttled connection
    mThread->requestNextVsync(mThrottledConnection);

    // EventThread should immediately request a resync.
    EXPECT_TRUE(mResyncCallRecorder.waitForCall().has_value());

    // EventThread should enable vsync callbacks.
    expectVSyncSetEnabledCallReceived(true);

    // Use the received callback to signal a first vsync event.
    // The interceptor should receive the event, but not the connection.
    mCallback->onVSyncEvent(123, 456, 789);
    expectInterceptCallReceived(123);
    expectThrottleVsyncReceived(456, mThrottledConnectionUid);
    mThrottledConnectionEventCallRecorder.waitForUnexpectedCall();

    // Use the received callback to signal a second vsync event.
    // The interceptor should receive the event, but the connection should
    // not as it was only interested in the first.
    mCallback->onVSyncEvent(456, 123, 0);
    expectInterceptCallReceived(456);
    expectThrottleVsyncReceived(123, mThrottledConnectionUid);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());

    // EventThread should not change the vsync state as it didn't send the event
    // yet
    EXPECT_FALSE(mVSyncSetEnabledCallRecorder.waitForUnexpectedCall().has_value());
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
