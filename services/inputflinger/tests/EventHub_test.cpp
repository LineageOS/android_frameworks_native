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

#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <linux/uinput.h>
#include <log/log.h>
#include <chrono>

#define TAG "EventHub_test"

using android::EventHub;
using android::EventHubInterface;
using android::InputDeviceIdentifier;
using android::RawEvent;
using android::sp;
using android::base::StringPrintf;
using std::chrono_literals::operator""ms;

static constexpr bool DEBUG = false;
static const char* DEVICE_NAME = "EventHub Test Device";

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
    android::base::unique_fd mDeviceFd;
    int32_t mDeviceId;
    virtual void SetUp() override {
        mEventHub = std::make_unique<EventHub>();
        consumeInitialDeviceAddedEvents();
        createDevice();
        mDeviceId = waitForDeviceCreation();
    }
    virtual void TearDown() override {
        mDeviceFd.reset();
        waitForDeviceClose(mDeviceId);
    }

    void createDevice();
    /**
     * Return the device id of the created device.
     */
    int32_t waitForDeviceCreation();
    void waitForDeviceClose(int32_t deviceId);
    void consumeInitialDeviceAddedEvents();
    void sendEvent(uint16_t type, uint16_t code, int32_t value);
    std::vector<RawEvent> getEvents(std::chrono::milliseconds timeout = 5ms);
};

std::vector<RawEvent> EventHubTest::getEvents(std::chrono::milliseconds timeout) {
    static constexpr size_t EVENT_BUFFER_SIZE = 256;
    std::array<RawEvent, EVENT_BUFFER_SIZE> eventBuffer;
    std::vector<RawEvent> events;

    while (true) {
        size_t count =
                mEventHub->getEvents(timeout.count(), eventBuffer.data(), eventBuffer.size());
        if (count == 0) {
            break;
        }
        events.insert(events.end(), eventBuffer.begin(), eventBuffer.begin() + count);
    }
    if (DEBUG) {
        dumpEvents(events);
    }
    return events;
}

void EventHubTest::createDevice() {
    mDeviceFd = android::base::unique_fd(open("/dev/uinput", O_WRONLY | O_NONBLOCK));
    if (mDeviceFd < 0) {
        FAIL() << "Can't open /dev/uinput :" << strerror(errno);
    }

    /**
     * Signal which type of events this input device supports.
     * We will emulate a keyboard here.
     */
    // enable key press/release event
    if (ioctl(mDeviceFd, UI_SET_EVBIT, EV_KEY)) {
        ADD_FAILURE() << "Error in ioctl : UI_SET_EVBIT : EV_KEY: " << strerror(errno);
    }

    // enable set of KEY events
    if (ioctl(mDeviceFd, UI_SET_KEYBIT, KEY_HOME)) {
        ADD_FAILURE() << "Error in ioctl : UI_SET_KEYBIT : KEY_HOME: " << strerror(errno);
    }

    // enable synchronization event
    if (ioctl(mDeviceFd, UI_SET_EVBIT, EV_SYN)) {
        ADD_FAILURE() << "Error in ioctl : UI_SET_EVBIT : EV_SYN: " << strerror(errno);
    }

    struct uinput_user_dev keyboard = {};
    strlcpy(keyboard.name, DEVICE_NAME, UINPUT_MAX_NAME_SIZE);
    keyboard.id.bustype = BUS_USB;
    keyboard.id.vendor = 0x01;
    keyboard.id.product = 0x01;
    keyboard.id.version = 1;

    if (write(mDeviceFd, &keyboard, sizeof(keyboard)) < 0) {
        FAIL() << "Could not write uinput_user_dev struct into uinput file descriptor: "
               << strerror(errno);
    }

    if (ioctl(mDeviceFd, UI_DEV_CREATE)) {
        FAIL() << "Error in ioctl : UI_DEV_CREATE: " << strerror(errno);
    }
}

/**
 * Since the test runs on a real platform, there will be existing devices
 * in addition to the test devices being added. Therefore, when EventHub is first created,
 * it will return a lot of "device added" type of events.
 */
void EventHubTest::consumeInitialDeviceAddedEvents() {
    std::vector<RawEvent> events = getEvents(0ms);
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
    std::vector<RawEvent> events = getEvents(20ms);
    EXPECT_EQ(2U, events.size()); // Using "expect" because the function is non-void.
    const RawEvent& deviceAddedEvent = events[0];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::DEVICE_ADDED), deviceAddedEvent.type);
    InputDeviceIdentifier identifier = mEventHub->getDeviceIdentifier(deviceAddedEvent.deviceId);
    const int32_t deviceId = deviceAddedEvent.deviceId;
    EXPECT_EQ(identifier.name, DEVICE_NAME);
    const RawEvent& finishedDeviceScanEvent = events[1];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::FINISHED_DEVICE_SCAN),
              finishedDeviceScanEvent.type);
    return deviceId;
}

void EventHubTest::waitForDeviceClose(int32_t deviceId) {
    std::vector<RawEvent> events = getEvents(20ms);
    ASSERT_EQ(2U, events.size());
    const RawEvent& deviceRemovedEvent = events[0];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::DEVICE_REMOVED), deviceRemovedEvent.type);
    EXPECT_EQ(deviceId, deviceRemovedEvent.deviceId);
    const RawEvent& finishedDeviceScanEvent = events[1];
    EXPECT_EQ(static_cast<int32_t>(EventHubInterface::FINISHED_DEVICE_SCAN),
              finishedDeviceScanEvent.type);
}

void EventHubTest::sendEvent(uint16_t type, uint16_t code, int32_t value) {
    struct input_event event = {};
    event.type = type;
    event.code = code;
    event.value = value;
    event.time = {}; // uinput ignores the timestamp

    if (write(mDeviceFd, &event, sizeof(input_event)) < 0) {
        std::string msg = StringPrintf("Could not write event %" PRIu16 " %" PRIu16
                                       " with value %" PRId32 " : %s",
                                       type, code, value, strerror(errno));
        ALOGE("%s", msg.c_str());
        ADD_FAILURE() << msg.c_str();
    }
}

/**
 * Ensure that input_events are generated with monotonic clock.
 * That means input_event should receive a timestamp that is in the future of the time
 * before the event was sent.
 * Input system uses CLOCK_MONOTONIC everywhere in the code base.
 */
TEST_F(EventHubTest, InputEvent_TimestampIsMonotonic) {
    nsecs_t lastEventTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // key press
    sendEvent(EV_KEY, KEY_HOME, 1);
    sendEvent(EV_SYN, SYN_REPORT, 0);

    // key release
    sendEvent(EV_KEY, KEY_HOME, 0);
    sendEvent(EV_SYN, SYN_REPORT, 0);

    std::vector<RawEvent> events = getEvents();
    ASSERT_EQ(4U, events.size()) << "Expected to receive 2 keys and 2 syncs, total of 4 events";
    for (const RawEvent& event : events) {
        // Cannot use strict comparison because the events may happen too quickly
        ASSERT_LE(lastEventTime, event.when) << "Event must have occurred after the key was sent";
        ASSERT_LT(std::chrono::nanoseconds(event.when - lastEventTime), 100ms)
                << "Event times are too far apart";
        lastEventTime = event.when; // Ensure all returned events are monotonic
    }
}
