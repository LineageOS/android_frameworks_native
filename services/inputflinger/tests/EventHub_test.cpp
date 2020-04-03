/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "EventHub.h"

#include "UinputDevice.h"

#include <gtest/gtest.h>
#include <inttypes.h>
#include <linux/uinput.h>
#include <log/log.h>
#include <chrono>

#define TAG "EventHub_test"

using android::createUinputDevice;
using android::EventHub;
using android::EventHubInterface;
using android::InputDeviceIdentifier;
using android::RawEvent;
using android::sp;
using android::UinputHomeKey;
using std::chrono_literals::operator""ms;
using std::chrono_literals::operator""s;

static constexpr bool DEBUG = false;

static void dumpEvents(const std::vector<RawEvent>& events) {
    for (const RawEvent& event : events) {
        if (event.type >= EventHubInterface::FIRST_SYNTHETIC_EVENT) {
            switch (event.type) {
                case EventHubInterface::DEVICE_ADDED:
                    ALOGI("Device added: %i", event.deviceId);
                    break;
                case EventHubInterface::DEVICE_REMOVED:
                    ALOGI("Device removed: %i", event.deviceId);
                    break;
                case EventHubInterface::FINISHED_DEVICE_SCAN:
                    ALOGI("Finished device scan.");
                    break;
            }
        } else {
            ALOGI("Device %" PRId32 " : time = %" PRId64 ", type %i, code %i, value %i",
                  event.deviceId, event.when, event.type, event.code, event.value);
        }
    }
}

// --- EventHubTest ---
class EventHubTest : public testing::Test {
protected:
    std::unique_ptr<EventHubInterface> mEventHub;
    // We are only going to emulate a single input device currently.
    std::unique_ptr<UinputHomeKey> mKeyboard;
    int32_t mDeviceId;

    virtual void SetUp() override {
        mEventHub = std::make_unique<EventHub>();
        consumeInitialDeviceAddedEvents();
        mKeyboard = createUinputDevice<UinputHomeKey>();
        ASSERT_NO_FATAL_FAILURE(mDeviceId = waitForDeviceCreation());
    }
    virtual void TearDown() override {
        mKeyboard.reset();
        waitForDeviceClose(mDeviceId);
        assertNoMoreEvents();
    }

    /**
     * Return the device id of the created device.
     */
    int32_t waitForDeviceCreation();
    void waitForDeviceClose(int32_t deviceId);
    void consumeInitialDeviceAddedEvents();
    void assertNoMoreEvents();
    /**
     * Read events from the EventHub.
     *
     * If expectedEvents is set, wait for a significant period of time to try and ensure that
     * the expected number of events has been read. The number of returned events
     * may be smaller (if timeout has been reached) or larger than expectedEvents.
     *
     * If expectedEvents is not set, return all of the immediately available events.
     */
    std::vector<RawEvent> getEvents(std::optional<size_t> expectedEvents = std::nullopt);
};

std::vector<RawEvent> EventHubTest::getEvents(std::optional<size_t> expectedEvents) {
    static constexpr size_t EVENT_BUFFER_SIZE = 256;
    std::array<RawEvent, EVENT_BUFFER_SIZE> eventBuffer;
    std::vector<RawEvent> events;

    while (true) {
        std::chrono::milliseconds timeout = 0s;
        if (expectedEvents) {
            timeout = 2s;
        }
        const size_t count =
                mEventHub->getEvents(timeout.count(), eventBuffer.data(), eventBuffer.size());
        if (count == 0) {
            break;
        }
        events.insert(events.end(), eventBuffer.begin(), eventBuffer.begin() + count);
        if (expectedEvents && events.size() >= *expectedEvents) {
            break;
        }
    }
    if (DEBUG) {
        dumpEvents(events);
    }
    return events;
}

/**
 * Since the test runs on a real platform, there will be existing devices
 * in addition to the test devices being added. Therefore, when EventHub is first created,
 * it will return a lot of "device added" type of events.
 */
void EventHubTest::consumeInitialDeviceAddedEvents() {
    std::vector<RawEvent> events = getEvents();
    std::set<int32_t /*deviceId*/> existingDevices;
    // All of the events should be DEVICE_ADDED type, except the last one.
    for (size_t i = 0; i < events.size() - 1; i++) {
        const RawEvent& event = events[i];
        EXPECT_EQ(EventHubInterface::DEVICE_ADDED, event.type);
        existingDevices.insert(event.deviceId);
    }
    // None of the existing system devices should be changing while this test is run.
    // Check that the returned device ids are unique for all of the existing devices.
    EXPECT_EQ(existingDevices.size(), events.size() - 1);
    // The last event should be "finished device scan"
    EXPECT_EQ(EventHubInterface::FINISHED_DEVICE_SCAN, events[events.size() - 1].type);
}

int32_t EventHubTest::waitForDeviceCreation() {
    // Wait a little longer than usual, to ensure input device has time to be created
    std::vector<RawEvent> events = getEvents(2);
    if (events.size() != 2) {
        ADD_FAILURE() << "Instead of 2 events, received " << events.size();
        return 0; // this value is unused
    }
    const RawEvent& deviceAddedEvent = events[0];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::DEVICE_ADDED), deviceAddedEvent.type);
    InputDeviceIdentifier identifier = mEventHub->getDeviceIdentifier(deviceAddedEvent.deviceId);
    const int32_t deviceId = deviceAddedEvent.deviceId;
    EXPECT_EQ(identifier.name, mKeyboard->getName());
    const RawEvent& finishedDeviceScanEvent = events[1];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::FINISHED_DEVICE_SCAN),
              finishedDeviceScanEvent.type);
    return deviceId;
}

void EventHubTest::waitForDeviceClose(int32_t deviceId) {
    std::vector<RawEvent> events = getEvents(2);
    ASSERT_EQ(2U, events.size());
    const RawEvent& deviceRemovedEvent = events[0];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::DEVICE_REMOVED), deviceRemovedEvent.type);
    EXPECT_EQ(deviceId, deviceRemovedEvent.deviceId);
    const RawEvent& finishedDeviceScanEvent = events[1];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::FINISHED_DEVICE_SCAN),
              finishedDeviceScanEvent.type);
}

void EventHubTest::assertNoMoreEvents() {
    std::vector<RawEvent> events = getEvents();
    ASSERT_TRUE(events.empty());
}

/**
 * Ensure that input_events are generated with monotonic clock.
 * That means input_event should receive a timestamp that is in the future of the time
 * before the event was sent.
 * Input system uses CLOCK_MONOTONIC everywhere in the code base.
 */
TEST_F(EventHubTest, InputEvent_TimestampIsMonotonic) {
    nsecs_t lastEventTime = systemTime(SYSTEM_TIME_MONOTONIC);
    ASSERT_NO_FATAL_FAILURE(mKeyboard->pressAndReleaseHomeKey());

    std::vector<RawEvent> events = getEvents(4);
    ASSERT_EQ(4U, events.size()) << "Expected to receive 2 keys and 2 syncs, total of 4 events";
    for (const RawEvent& event : events) {
        // Cannot use strict comparison because the events may happen too quickly
        ASSERT_LE(lastEventTime, event.when) << "Event must have occurred after the key was sent";
        ASSERT_LT(std::chrono::nanoseconds(event.when - lastEventTime), 100ms)
                << "Event times are too far apart";
        lastEventTime = event.when; // Ensure all returned events are monotonic
    }
}
