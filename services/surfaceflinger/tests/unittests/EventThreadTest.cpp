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
#include <scheduler/VsyncConfig.h>
#include <utils/Errors.h>

#include "AsyncCallRecorder.h"
#include "DisplayHardware/DisplayMode.h"
#include "FrameTimeline.h"
#include "Scheduler/EventThread.h"
#include "mock/MockVSyncDispatch.h"
#include "mock/MockVSyncTracker.h"
#include "mock/MockVsyncController.h"

using namespace std::chrono_literals;
using namespace std::placeholders;

using testing::_;
using testing::Invoke;
using testing::Return;

namespace android {

using namespace ftl::flag_operators;

namespace {

constexpr PhysicalDisplayId INTERNAL_DISPLAY_ID = PhysicalDisplayId::fromPort(111u);
constexpr PhysicalDisplayId EXTERNAL_DISPLAY_ID = PhysicalDisplayId::fromPort(222u);
constexpr PhysicalDisplayId DISPLAY_ID_64BIT =
        PhysicalDisplayId::fromEdid(0xffu, 0xffffu, 0xffff'ffffu);

constexpr std::chrono::duration VSYNC_PERIOD(16ms);

constexpr int HDCP_V1 = 2;
constexpr int HDCP_V2 = 3;

} // namespace

class EventThreadTest : public testing::Test, public IEventThreadCallback {
protected:
    static constexpr std::chrono::nanoseconds kWorkDuration = 0ms;
    static constexpr std::chrono::nanoseconds kReadyDuration = 3ms;

    class MockEventThreadConnection : public EventThreadConnection {
    public:
        MockEventThreadConnection(impl::EventThread* eventThread, uid_t callingUid,
                                  EventRegistrationFlags eventRegistration)
              : EventThreadConnection(eventThread, callingUid, eventRegistration) {}
        MOCK_METHOD1(postEvent, status_t(const DisplayEventReceiver::Event& event));
    };

    using ConnectionEventRecorder =
            AsyncCallRecorderWithCannedReturn<status_t (*)(const DisplayEventReceiver::Event&)>;

    EventThreadTest();
    ~EventThreadTest() override;

    void SetUp() override { mVsyncPeriod = VSYNC_PERIOD; }

    // IEventThreadCallback overrides
    bool throttleVsync(TimePoint, uid_t) override;
    Period getVsyncPeriod(uid_t) override;
    void resync() override;
    void onExpectedPresentTimePosted(TimePoint) override;

    void setupEventThread();
    sp<MockEventThreadConnection> createConnection(ConnectionEventRecorder& recorder,
                                                   EventRegistrationFlags eventRegistration = {},
                                                   uid_t ownerUid = mConnectionUid);

    void expectVSyncCallbackScheduleReceived(bool expectState);
    void expectVSyncSetDurationCallReceived(std::chrono::nanoseconds expectedDuration,
                                            std::chrono::nanoseconds expectedReadyDuration);
    void expectVsyncEventReceivedByConnection(const char* name,
                                              ConnectionEventRecorder& connectionEventRecorder,
                                              nsecs_t expectedTimestamp, unsigned expectedCount);
    void expectVsyncEventReceivedByConnection(nsecs_t expectedTimestamp, unsigned expectedCount);
    void expectVsyncEventFrameTimelinesCorrect(
            nsecs_t expectedTimestamp, gui::VsyncEventData::FrameTimeline preferredVsyncData);
    void expectVsyncEventDataFrameTimelinesValidLength(VsyncEventData vsyncEventData);
    void expectHotplugEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                bool expectedConnected);
    void expectConfigChangedEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                      int32_t expectedConfigId,
                                                      nsecs_t expectedVsyncPeriod);
    void expectThrottleVsyncReceived(nsecs_t expectedTimestamp, uid_t);
    void expectOnExpectedPresentTimePosted(nsecs_t expectedPresentTime);
    void expectUidFrameRateMappingEventReceivedByConnection(PhysicalDisplayId expectedDisplayId,
                                                            std::vector<FrameRateOverride>);

    void onVSyncEvent(nsecs_t timestamp, nsecs_t expectedPresentationTime,
                      nsecs_t deadlineTimestamp) {
        mThread->onVsync(expectedPresentationTime, timestamp, deadlineTimestamp);
    }

    static constexpr scheduler::ScheduleResult kScheduleResult{TimePoint::fromNs(0),
                                                               TimePoint::fromNs(0)};
    AsyncCallRecorderWithCannedReturn<
            scheduler::ScheduleResult (*)(scheduler::VSyncDispatch::CallbackToken,
                                          scheduler::VSyncDispatch::ScheduleTiming)>
            mVSyncCallbackScheduleRecorder{kScheduleResult};
    AsyncCallRecorderWithCannedReturn<
            scheduler::ScheduleResult (*)(scheduler::VSyncDispatch::CallbackToken,
                                          scheduler::VSyncDispatch::ScheduleTiming)>
            mVSyncCallbackUpdateRecorder{kScheduleResult};
    AsyncCallRecorderWithCannedReturn<
            scheduler::VSyncDispatch::CallbackToken (*)(scheduler::VSyncDispatch::Callback,
                                                        std::string)>
            mVSyncCallbackRegisterRecorder{scheduler::VSyncDispatch::CallbackToken(0)};
    AsyncCallRecorder<void (*)(scheduler::VSyncDispatch::CallbackToken)>
            mVSyncCallbackUnregisterRecorder;
    AsyncCallRecorder<void (*)()> mResyncCallRecorder;
    AsyncCallRecorder<void (*)(nsecs_t, uid_t)> mThrottleVsyncCallRecorder;
    AsyncCallRecorder<void (*)(nsecs_t)> mOnExpectedPresentTimePostedRecorder;
    ConnectionEventRecorder mConnectionEventCallRecorder{0};
    ConnectionEventRecorder mThrottledConnectionEventCallRecorder{0};

    std::shared_ptr<scheduler::VsyncSchedule> mVsyncSchedule;
    std::unique_ptr<impl::EventThread> mThread;
    sp<MockEventThreadConnection> mConnection;
    sp<MockEventThreadConnection> mThrottledConnection;
    std::unique_ptr<frametimeline::impl::TokenManager> mTokenManager;

    std::chrono::nanoseconds mVsyncPeriod;

    static constexpr uid_t mConnectionUid = 443;
    static constexpr uid_t mThrottledConnectionUid = 177;
};

EventThreadTest::EventThreadTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    auto mockDispatchPtr = std::make_shared<mock::VSyncDispatch>();
    mVsyncSchedule = std::shared_ptr<scheduler::VsyncSchedule>(
            new scheduler::VsyncSchedule(INTERNAL_DISPLAY_ID,
                                         std::make_shared<mock::VSyncTracker>(), mockDispatchPtr,
                                         nullptr));
    mock::VSyncDispatch& mockDispatch = *mockDispatchPtr;
    EXPECT_CALL(mockDispatch, registerCallback(_, _))
            .WillRepeatedly(Invoke(mVSyncCallbackRegisterRecorder.getInvocable()));
    EXPECT_CALL(mockDispatch, schedule(_, _))
            .WillRepeatedly(Invoke(mVSyncCallbackScheduleRecorder.getInvocable()));
    EXPECT_CALL(mockDispatch, update(_, _))
            .WillRepeatedly(Invoke(mVSyncCallbackUpdateRecorder.getInvocable()));
    EXPECT_CALL(mockDispatch, unregisterCallback(_))
            .WillRepeatedly(Invoke(mVSyncCallbackUnregisterRecorder.getInvocable()));
}

EventThreadTest::~EventThreadTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());

    mThread.reset();
    // EventThread should unregister itself as VSyncSource callback.
    EXPECT_TRUE(mVSyncCallbackUnregisterRecorder.waitForCall().has_value());
}

bool EventThreadTest::throttleVsync(android::TimePoint expectedVsyncTimestamp, uid_t uid) {
    mThrottleVsyncCallRecorder.recordCall(expectedVsyncTimestamp.ns(), uid);
    return (uid == mThrottledConnectionUid);
}

Period EventThreadTest::getVsyncPeriod(uid_t) {
    return mVsyncPeriod;
}

void EventThreadTest::resync() {
    mResyncCallRecorder.recordCall();
}

void EventThreadTest::onExpectedPresentTimePosted(TimePoint expectedPresentTime) {
    mOnExpectedPresentTimePostedRecorder.recordCall(expectedPresentTime.ns());
}

void EventThreadTest::setupEventThread() {
    mTokenManager = std::make_unique<frametimeline::impl::TokenManager>();
    mThread = std::make_unique<impl::EventThread>("EventThreadTest", mVsyncSchedule,
                                                  mTokenManager.get(), *this, kWorkDuration,
                                                  kReadyDuration);

    // EventThread should register itself as VSyncSource callback.
    EXPECT_TRUE(mVSyncCallbackRegisterRecorder.waitForCall().has_value());

    mConnection =
            createConnection(mConnectionEventCallRecorder,
                             gui::ISurfaceComposer::EventRegistration::modeChanged |
                                     gui::ISurfaceComposer::EventRegistration::frameRateOverride);
    mThrottledConnection = createConnection(mThrottledConnectionEventCallRecorder,
                                            gui::ISurfaceComposer::EventRegistration::modeChanged,
                                            mThrottledConnectionUid);

    // A display must be connected for VSYNC events to be delivered.
    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, true);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, true);
}

sp<EventThreadTest::MockEventThreadConnection> EventThreadTest::createConnection(
        ConnectionEventRecorder& recorder, EventRegistrationFlags eventRegistration,
        uid_t ownerUid) {
    sp<MockEventThreadConnection> connection =
            sp<MockEventThreadConnection>::make(mThread.get(), ownerUid, eventRegistration);
    EXPECT_CALL(*connection, postEvent(_)).WillRepeatedly(Invoke(recorder.getInvocable()));
    return connection;
}

void EventThreadTest::expectVSyncCallbackScheduleReceived(bool expectState) {
    if (expectState) {
        ASSERT_TRUE(mVSyncCallbackScheduleRecorder.waitForCall().has_value());
    } else {
        ASSERT_FALSE(mVSyncCallbackScheduleRecorder.waitForUnexpectedCall().has_value());
    }
}

void EventThreadTest::expectVSyncSetDurationCallReceived(
        std::chrono::nanoseconds expectedDuration, std::chrono::nanoseconds expectedReadyDuration) {
    auto args = mVSyncCallbackUpdateRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedDuration.count(), std::get<1>(args.value()).workDuration);
    EXPECT_EQ(expectedReadyDuration.count(), std::get<1>(args.value()).readyDuration);
}

void EventThreadTest::expectThrottleVsyncReceived(nsecs_t expectedTimestamp, uid_t uid) {
    auto args = mThrottleVsyncCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedTimestamp, std::get<0>(args.value()));
    EXPECT_EQ(uid, std::get<1>(args.value()));
}

void EventThreadTest::expectOnExpectedPresentTimePosted(nsecs_t expectedPresentTime) {
    auto args = mOnExpectedPresentTimePostedRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    EXPECT_EQ(expectedPresentTime, std::get<0>(args.value()));
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

void EventThreadTest::expectVsyncEventFrameTimelinesCorrect(
        nsecs_t expectedTimestamp, VsyncEventData::FrameTimeline preferredVsyncData) {
    auto args = mConnectionEventCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value()) << " did not receive an event for timestamp "
                                  << expectedTimestamp;
    const auto& event = std::get<0>(args.value());
    for (int i = 0; i < event.vsync.vsyncData.frameTimelinesLength; i++) {
        auto prediction = mTokenManager->getPredictionsForToken(
                event.vsync.vsyncData.frameTimelines[i].vsyncId);
        EXPECT_TRUE(prediction.has_value());
        EXPECT_EQ(prediction.value().endTime,
                  event.vsync.vsyncData.frameTimelines[i].deadlineTimestamp)
                << "Deadline timestamp does not match cached value";
        EXPECT_EQ(prediction.value().presentTime,
                  event.vsync.vsyncData.frameTimelines[i].expectedPresentationTime)
                << "Expected vsync.vsyncData timestamp does not match cached value";

        if (i > 0) {
            EXPECT_GT(event.vsync.vsyncData.frameTimelines[i].deadlineTimestamp,
                      event.vsync.vsyncData.frameTimelines[i - 1].deadlineTimestamp)
                    << "Deadline timestamp out of order for frame timeline " << i;
            EXPECT_GT(event.vsync.vsyncData.frameTimelines[i].expectedPresentationTime,
                      event.vsync.vsyncData.frameTimelines[i - 1].expectedPresentationTime)
                    << "Expected vsync.vsyncData timestamp out of order for frame timeline " << i;
        }

        // Vsync ID order lines up with registration into test token manager.
        EXPECT_EQ(i, event.vsync.vsyncData.frameTimelines[i].vsyncId)
                << "Vsync ID incorrect for frame timeline " << i;
        if (i == event.vsync.vsyncData.preferredFrameTimelineIndex) {
            EXPECT_EQ(event.vsync.vsyncData.frameTimelines[i].deadlineTimestamp,
                      preferredVsyncData.deadlineTimestamp)
                    << "Preferred deadline timestamp incorrect" << i;
            EXPECT_EQ(event.vsync.vsyncData.frameTimelines[i].expectedPresentationTime,
                      preferredVsyncData.expectedPresentationTime)
                    << "Preferred expected vsync.vsyncData timestamp incorrect" << i;
        }
    }
}

void EventThreadTest::expectVsyncEventDataFrameTimelinesValidLength(VsyncEventData vsyncEventData) {
    float nonPreferredTimelinesAmount =
            scheduler::VsyncConfig::kEarlyLatchMaxThreshold / mVsyncPeriod;
    EXPECT_LE(vsyncEventData.frameTimelinesLength, nonPreferredTimelinesAmount + 1)
            << "Amount of non-preferred frame timelines too many;"
            << " expected presentation time will be over threshold";
    EXPECT_LT(nonPreferredTimelinesAmount, VsyncEventData::kFrameTimelinesCapacity)
            << "Amount of non-preferred frame timelines should be less than max capacity";
    EXPECT_GT(static_cast<int64_t>(vsyncEventData.frameTimelinesLength), 0)
            << "Frame timelines length should be greater than 0";
    EXPECT_LT(vsyncEventData.preferredFrameTimelineIndex, vsyncEventData.frameTimelinesLength)
            << "Preferred frame timeline index should be less than frame timelines length";
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

using namespace testing;

/* ------------------------------------------------------------------------
 * Test cases
 */

TEST_F(EventThreadTest, canCreateAndDestroyThreadWithNoEventsSent) {
    setupEventThread();

    EXPECT_FALSE(mVSyncCallbackRegisterRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mVSyncCallbackScheduleRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mVSyncCallbackUpdateRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mVSyncCallbackUnregisterRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mResyncCallRecorder.waitForCall(0us).has_value());
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForCall(0us).has_value());
}

TEST_F(EventThreadTest, vsyncRequestIsIgnoredIfDisplayIsDisconnected) {
    setupEventThread();

    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, false);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, false);

    // Signal that we want the next vsync event to be posted to the connection.
    mThread->requestNextVsync(mConnection);

    // EventThread should not enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(false);
}

TEST_F(EventThreadTest, requestNextVsyncPostsASingleVSyncEventToTheConnection) {
    setupEventThread();

    // Signal that we want the next vsync event to be posted to the connection
    mThread->requestNextVsync(mConnection);

    // EventThread should immediately request a resync.
    EXPECT_TRUE(mResyncCallRecorder.waitForCall().has_value());

    // EventThread should enable schedule a vsync callback
    expectVSyncCallbackScheduleReceived(true);

    // Use the received callback to signal a first vsync event.
    // The throttler should receive the event, as well as the connection.
    onVSyncEvent(123, 456, 789);
    expectThrottleVsyncReceived(456, mConnectionUid);
    expectVsyncEventReceivedByConnection(123, 1u);
    expectOnExpectedPresentTimePosted(456);

    // EventThread is requesting one more callback due to VsyncRequest::SingleSuppressCallback
    expectVSyncCallbackScheduleReceived(true);

    // Use the received callback to signal a second vsync event.
    // The throttler should receive the event, but the connection should
    // not as it was only interested in the first.
    onVSyncEvent(456, 123, 0);
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());

    // EventThread should also detect that at this point that it does not need
    // any more vsync events, and should disable their generation.
    expectVSyncCallbackScheduleReceived(false);
}

TEST_F(EventThreadTest, requestNextVsyncEventFrameTimelinesCorrect) {
    setupEventThread();

    // Signal that we want the next vsync event to be posted to the connection
    mThread->requestNextVsync(mConnection);

    expectVSyncCallbackScheduleReceived(true);

    // Use the received callback to signal a vsync event.
    // The throttler should receive the event, as well as the connection.
    onVSyncEvent(123, 456, 789);
    expectVsyncEventFrameTimelinesCorrect(123, {-1, 789, 456});
}

TEST_F(EventThreadTest, requestNextVsyncEventFrameTimelinesValidLength) {
    setupEventThread();
    // The VsyncEventData should not have kFrameTimelinesCapacity amount of valid frame timelines,
    // due to longer vsync period and kEarlyLatchMaxThreshold. Use length-2 to avoid decimal
    // truncation (e.g. 60Hz has 16.6... ms vsync period).
    mVsyncPeriod = (scheduler::VsyncConfig::kEarlyLatchMaxThreshold /
                    (VsyncEventData::kFrameTimelinesCapacity - 2));

    // Signal that we want the next vsync event to be posted to the connection
    mThread->requestNextVsync(mConnection);

    expectVSyncCallbackScheduleReceived(true);

    // Use the received callback to signal a vsync event.
    // The throttler should receive the event, as well as the connection.
    nsecs_t expectedTimestamp = 123;
    onVSyncEvent(expectedTimestamp, 456, 789);

    auto args = mConnectionEventCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value()) << " did not receive an event for timestamp "
                                  << expectedTimestamp;
    const VsyncEventData vsyncEventData = std::get<0>(args.value()).vsync.vsyncData;
    expectVsyncEventDataFrameTimelinesValidLength(vsyncEventData);
}

TEST_F(EventThreadTest, getLatestVsyncEventData) {
    setupEventThread();

    const nsecs_t now = systemTime();
    const nsecs_t preferredExpectedPresentationTime = now + 20000000;
    const nsecs_t preferredDeadline = preferredExpectedPresentationTime - kReadyDuration.count();

    mock::VSyncTracker& mockTracker =
            *static_cast<mock::VSyncTracker*>(&mVsyncSchedule->getTracker());
    EXPECT_CALL(mockTracker, nextAnticipatedVSyncTimeFrom(_, _))
            .WillOnce(Return(preferredExpectedPresentationTime));

    VsyncEventData vsyncEventData = mThread->getLatestVsyncEventData(mConnection, now);

    // Check EventThread immediately requested a resync.
    EXPECT_TRUE(mResyncCallRecorder.waitForCall().has_value());

    expectVsyncEventDataFrameTimelinesValidLength(vsyncEventData);
    EXPECT_GT(vsyncEventData.frameTimelines[0].deadlineTimestamp, now)
            << "Deadline timestamp should be greater than frame time";
    for (size_t i = 0; i < vsyncEventData.frameTimelinesLength; i++) {
        auto prediction =
                mTokenManager->getPredictionsForToken(vsyncEventData.frameTimelines[i].vsyncId);
        EXPECT_TRUE(prediction.has_value());
        EXPECT_EQ(prediction.value().endTime, vsyncEventData.frameTimelines[i].deadlineTimestamp)
                << "Deadline timestamp does not match cached value";
        EXPECT_EQ(prediction.value().presentTime,
                  vsyncEventData.frameTimelines[i].expectedPresentationTime)
                << "Expected vsync timestamp does not match cached value";
        EXPECT_GT(vsyncEventData.frameTimelines[i].expectedPresentationTime,
                  vsyncEventData.frameTimelines[i].deadlineTimestamp)
                << "Expected vsync timestamp should be greater than deadline";

        if (i > 0) {
            EXPECT_GT(vsyncEventData.frameTimelines[i].deadlineTimestamp,
                      vsyncEventData.frameTimelines[i - 1].deadlineTimestamp)
                    << "Deadline timestamp out of order for frame timeline " << i;
            EXPECT_GT(vsyncEventData.frameTimelines[i].expectedPresentationTime,
                      vsyncEventData.frameTimelines[i - 1].expectedPresentationTime)
                    << "Expected vsync timestamp out of order for frame timeline " << i;
        }

        // Vsync ID order lines up with registration into test token manager.
        EXPECT_EQ(i, vsyncEventData.frameTimelines[i].vsyncId)
                << "Vsync ID incorrect for frame timeline " << i;
        if (i == vsyncEventData.preferredFrameTimelineIndex) {
            EXPECT_EQ(vsyncEventData.frameTimelines[i].deadlineTimestamp, preferredDeadline)
                    << "Preferred deadline timestamp incorrect" << i;
            EXPECT_EQ(vsyncEventData.frameTimelines[i].expectedPresentationTime,
                      preferredExpectedPresentationTime)
                    << "Preferred expected vsync timestamp incorrect" << i;
        }
    }
}

TEST_F(EventThreadTest, setVsyncRateZeroPostsNoVSyncEventsToThatConnection) {
    setupEventThread();

    // Create a first connection, register it, and request a vsync rate of zero.
    ConnectionEventRecorder firstConnectionEventRecorder{0};
    sp<MockEventThreadConnection> firstConnection = createConnection(firstConnectionEventRecorder);
    mThread->setVsyncRate(0, firstConnection);

    // By itself, this should not enable vsync events
    expectVSyncCallbackScheduleReceived(false);

    // However if there is another connection which wants events at a nonzero rate.....
    ConnectionEventRecorder secondConnectionEventRecorder{0};
    sp<MockEventThreadConnection> secondConnection =
            createConnection(secondConnectionEventRecorder);
    mThread->setVsyncRate(1, secondConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // Send a vsync event. EventThread should then make a call to the
    // the second connection. The first connection should not
    // get the event.
    onVSyncEvent(123, 0456, 0);
    EXPECT_FALSE(firstConnectionEventRecorder.waitForUnexpectedCall().has_value());
    expectVsyncEventReceivedByConnection("secondConnection", secondConnectionEventRecorder, 123,
                                         1u);
}

TEST_F(EventThreadTest, setVsyncRateOnePostsAllEventsToThatConnection) {
    setupEventThread();

    mThread->setVsyncRate(1, mConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // Send a vsync event. EventThread should then make a call to the
    // throttler, and the connection.
    onVSyncEvent(123, 456, 789);
    expectThrottleVsyncReceived(456, mConnectionUid);
    expectVsyncEventReceivedByConnection(123, 1u);
    expectOnExpectedPresentTimePosted(456);

    // A second event should go to the same places.
    onVSyncEvent(456, 123, 0);
    expectThrottleVsyncReceived(123, mConnectionUid);
    expectVsyncEventReceivedByConnection(456, 2u);
    expectOnExpectedPresentTimePosted(123);

    // A third event should go to the same places.
    onVSyncEvent(789, 777, 111);
    expectThrottleVsyncReceived(777, mConnectionUid);
    expectVsyncEventReceivedByConnection(789, 3u);
    expectOnExpectedPresentTimePosted(777);
}

TEST_F(EventThreadTest, setVsyncRateTwoPostsEveryOtherEventToThatConnection) {
    setupEventThread();

    mThread->setVsyncRate(2, mConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // The first event will not be seen by the connection.
    onVSyncEvent(123, 456, 789);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());

    // The second event will be seen by the connection.
    onVSyncEvent(456, 123, 0);
    expectVsyncEventReceivedByConnection(456, 2u);
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());

    // The third event will not be seen by the connection.
    onVSyncEvent(789, 777, 744);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());
    EXPECT_FALSE(mThrottleVsyncCallRecorder.waitForUnexpectedCall().has_value());

    // The fourth event will be seen by the connection.
    onVSyncEvent(101112, 7847, 86);
    expectVsyncEventReceivedByConnection(101112, 4u);
}

TEST_F(EventThreadTest, connectionsRemovedIfInstanceDestroyed) {
    setupEventThread();

    mThread->setVsyncRate(1, mConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // Destroy the only (strong) reference to the connection.
    mConnection = nullptr;

    // The first event will not be seen by the connection.
    onVSyncEvent(123, 56, 789);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());

    // EventThread should disable vsync callbacks
    expectVSyncCallbackScheduleReceived(false);
}

TEST_F(EventThreadTest, connectionsRemovedIfEventDeliveryError) {
    setupEventThread();

    ConnectionEventRecorder errorConnectionEventRecorder{NO_MEMORY};
    sp<MockEventThreadConnection> errorConnection = createConnection(errorConnectionEventRecorder);
    mThread->setVsyncRate(1, errorConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // The first event will be seen by the connection, which then returns an error.
    onVSyncEvent(123, 456, 789);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 123, 1u);

    // Another schedule is expected, since the connection is removed only after
    // the next vsync is requested.
    expectVSyncCallbackScheduleReceived(true);

    // A subsequent event will not be seen by the connection.
    onVSyncEvent(456, 123, 0);
    EXPECT_FALSE(errorConnectionEventRecorder.waitForUnexpectedCall().has_value());

    // EventThread should disable vsync callbacks with the second event
    expectVSyncCallbackScheduleReceived(false);
}

TEST_F(EventThreadTest, eventsDroppedIfNonfatalEventDeliveryError) {
    setupEventThread();

    ConnectionEventRecorder errorConnectionEventRecorder{WOULD_BLOCK};
    sp<MockEventThreadConnection> errorConnection = createConnection(errorConnectionEventRecorder);
    mThread->setVsyncRate(1, errorConnection);

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // The first event will be seen by the connection, which then returns a non-fatal error.
    onVSyncEvent(123, 456, 789);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 123, 1u);
    expectVSyncCallbackScheduleReceived(true);

    // A subsequent event will be seen by the connection, which still then returns a non-fatal
    // error.
    onVSyncEvent(456, 123, 0);
    expectVsyncEventReceivedByConnection("errorConnection", errorConnectionEventRecorder, 456, 2u);
    expectVSyncCallbackScheduleReceived(true);

    // EventThread will not disable vsync callbacks as the errors are non-fatal.
    onVSyncEvent(456, 123, 0);
    expectVSyncCallbackScheduleReceived(true);
}

TEST_F(EventThreadTest, setPhaseOffsetForwardsToVSyncSource) {
    setupEventThread();

    mThread->setDuration(321ns, 456ns);
    expectVSyncSetDurationCallReceived(321ns, 456ns);
}

TEST_F(EventThreadTest, postHotplugInternalDisconnect) {
    setupEventThread();

    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, false);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, false);
}

TEST_F(EventThreadTest, postHotplugInternalConnect) {
    setupEventThread();

    mThread->onHotplugReceived(INTERNAL_DISPLAY_ID, true);
    expectHotplugEventReceivedByConnection(INTERNAL_DISPLAY_ID, true);
}

TEST_F(EventThreadTest, postHotplugExternalDisconnect) {
    setupEventThread();

    mThread->onHotplugReceived(EXTERNAL_DISPLAY_ID, false);
    expectHotplugEventReceivedByConnection(EXTERNAL_DISPLAY_ID, false);
}

TEST_F(EventThreadTest, postHotplugExternalConnect) {
    setupEventThread();

    mThread->onHotplugReceived(EXTERNAL_DISPLAY_ID, true);
    expectHotplugEventReceivedByConnection(EXTERNAL_DISPLAY_ID, true);
}

TEST_F(EventThreadTest, postConfigChangedPrimary) {
    setupEventThread();

    const auto mode = DisplayMode::Builder(hal::HWConfigId(0))
                              .setPhysicalDisplayId(INTERNAL_DISPLAY_ID)
                              .setId(DisplayModeId(7))
                              .setVsyncPeriod(16666666)
                              .build();
    const Fps fps = mode->getPeakFps() / 2;

    mThread->onModeChanged({fps, ftl::as_non_null(mode)});
    expectConfigChangedEventReceivedByConnection(INTERNAL_DISPLAY_ID, 7, fps.getPeriodNsecs());
}

TEST_F(EventThreadTest, postConfigChangedExternal) {
    setupEventThread();

    const auto mode = DisplayMode::Builder(hal::HWConfigId(0))
                              .setPhysicalDisplayId(EXTERNAL_DISPLAY_ID)
                              .setId(DisplayModeId(5))
                              .setVsyncPeriod(16666666)
                              .build();
    const Fps fps = mode->getPeakFps() / 2;

    mThread->onModeChanged({fps, ftl::as_non_null(mode)});
    expectConfigChangedEventReceivedByConnection(EXTERNAL_DISPLAY_ID, 5, fps.getPeriodNsecs());
}

TEST_F(EventThreadTest, postConfigChangedPrimary64bit) {
    setupEventThread();

    const auto mode = DisplayMode::Builder(hal::HWConfigId(0))
                              .setPhysicalDisplayId(DISPLAY_ID_64BIT)
                              .setId(DisplayModeId(7))
                              .setVsyncPeriod(16666666)
                              .build();
    const Fps fps = mode->getPeakFps() / 2;
    mThread->onModeChanged({fps, ftl::as_non_null(mode)});
    expectConfigChangedEventReceivedByConnection(DISPLAY_ID_64BIT, 7, fps.getPeriodNsecs());
}

TEST_F(EventThreadTest, suppressConfigChanged) {
    setupEventThread();

    ConnectionEventRecorder suppressConnectionEventRecorder{0};
    sp<MockEventThreadConnection> suppressConnection =
            createConnection(suppressConnectionEventRecorder);

    const auto mode = DisplayMode::Builder(hal::HWConfigId(0))
                              .setPhysicalDisplayId(INTERNAL_DISPLAY_ID)
                              .setId(DisplayModeId(9))
                              .setVsyncPeriod(16666666)
                              .build();
    const Fps fps = mode->getPeakFps() / 2;

    mThread->onModeChanged({fps, ftl::as_non_null(mode)});
    expectConfigChangedEventReceivedByConnection(INTERNAL_DISPLAY_ID, 9, fps.getPeriodNsecs());

    auto args = suppressConnectionEventRecorder.waitForCall();
    ASSERT_FALSE(args.has_value());
}

TEST_F(EventThreadTest, postUidFrameRateMapping) {
    setupEventThread();

    const std::vector<FrameRateOverride> overrides = {
            {.uid = 1, .frameRateHz = 20},
            {.uid = 3, .frameRateHz = 40},
            {.uid = 5, .frameRateHz = 60},
    };

    mThread->onFrameRateOverridesChanged(INTERNAL_DISPLAY_ID, overrides);
    expectUidFrameRateMappingEventReceivedByConnection(INTERNAL_DISPLAY_ID, overrides);
}

TEST_F(EventThreadTest, suppressUidFrameRateMapping) {
    setupEventThread();

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
    setupEventThread();

    // Signal that we want the next vsync event to be posted to the throttled connection
    mThread->requestNextVsync(mThrottledConnection);

    // EventThread should immediately request a resync.
    EXPECT_TRUE(mResyncCallRecorder.waitForCall().has_value());

    // EventThread should enable vsync callbacks.
    expectVSyncCallbackScheduleReceived(true);

    // Use the received callback to signal a first vsync event.
    // The throttler should receive the event, but not the connection.
    onVSyncEvent(123, 456, 789);
    expectThrottleVsyncReceived(456, mThrottledConnectionUid);
    mThrottledConnectionEventCallRecorder.waitForUnexpectedCall();
    expectVSyncCallbackScheduleReceived(true);

    // Use the received callback to signal a second vsync event.
    // The throttler should receive the event, but the connection should
    // not as it was only interested in the first.
    onVSyncEvent(456, 123, 0);
    expectThrottleVsyncReceived(123, mThrottledConnectionUid);
    EXPECT_FALSE(mConnectionEventCallRecorder.waitForUnexpectedCall().has_value());
    expectVSyncCallbackScheduleReceived(true);

    // EventThread should not change the vsync state as it didn't send the event
    // yet
    onVSyncEvent(456, 123, 0);
    expectVSyncCallbackScheduleReceived(true);
}

TEST_F(EventThreadTest, postHcpLevelsChanged) {
    setupEventThread();

    mThread->onHdcpLevelsChanged(EXTERNAL_DISPLAY_ID, HDCP_V1, HDCP_V2);
    auto args = mConnectionEventCallRecorder.waitForCall();
    ASSERT_TRUE(args.has_value());
    const auto& event = std::get<0>(args.value());
    EXPECT_EQ(DisplayEventReceiver::DISPLAY_EVENT_HDCP_LEVELS_CHANGE, event.header.type);
    EXPECT_EQ(EXTERNAL_DISPLAY_ID, event.header.displayId);
    EXPECT_EQ(HDCP_V1, event.hdcpLevelsChange.connectedLevel);
    EXPECT_EQ(HDCP_V2, event.hdcpLevelsChange.maxLevel);
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
