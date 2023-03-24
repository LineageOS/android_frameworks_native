/*
 * Copyright 2022 The Android Open Source Project
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

#include <EventHub.h>
#include <gestures/HardwareStateConverter.h>
#include <gtest/gtest.h>
#include <linux/input-event-codes.h>

#include "FakeEventHub.h"
#include "FakeInputReaderPolicy.h"
#include "InstrumentedInputReader.h"
#include "TestConstants.h"
#include "TestInputListener.h"

namespace android {

class HardwareStateConverterTest : public testing::Test {
protected:
    static constexpr int32_t DEVICE_ID = END_RESERVED_ID + 1000;
    static constexpr int32_t EVENTHUB_ID = 1;

    void SetUp() {
        mFakeEventHub = std::make_unique<FakeEventHub>();
        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        mFakeListener = std::make_unique<TestInputListener>();
        mReader = std::make_unique<InstrumentedInputReader>(mFakeEventHub, mFakePolicy,
                                                            *mFakeListener);
        mDevice = newDevice();

        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_SLOT, 0, 7, 0, 0, 0);
    }

    std::shared_ptr<InputDevice> newDevice() {
        InputDeviceIdentifier identifier;
        identifier.name = "device";
        identifier.location = "USB1";
        identifier.bus = 0;
        std::shared_ptr<InputDevice> device =
                std::make_shared<InputDevice>(mReader->getContext(), DEVICE_ID, /* generation= */ 2,
                                              identifier);
        mReader->pushNextDevice(device);
        mFakeEventHub->addDevice(EVENTHUB_ID, identifier.name, InputDeviceClass::TOUCHPAD,
                                 identifier.bus);
        mReader->loopOnce();
        return device;
    }

    void processAxis(HardwareStateConverter& conv, nsecs_t when, int32_t type, int32_t code,
                     int32_t value) {
        RawEvent event;
        event.when = when;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = type;
        event.code = code;
        event.value = value;
        std::optional<SelfContainedHardwareState> schs = conv.processRawEvent(&event);
        EXPECT_FALSE(schs.has_value());
    }

    std::optional<SelfContainedHardwareState> processSync(HardwareStateConverter& conv,
                                                          nsecs_t when) {
        RawEvent event;
        event.when = when;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = EV_SYN;
        event.code = SYN_REPORT;
        event.value = 0;
        return conv.processRawEvent(&event);
    }

    std::shared_ptr<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    std::unique_ptr<TestInputListener> mFakeListener;
    std::unique_ptr<InstrumentedInputReader> mReader;
    std::shared_ptr<InputDevice> mDevice;
};

TEST_F(HardwareStateConverterTest, OneFinger) {
    const nsecs_t time = 1500000000;
    InputDeviceContext deviceContext(*mDevice, EVENTHUB_ID);
    HardwareStateConverter conv(deviceContext);

    processAxis(conv, time, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, time, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, time, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    processAxis(conv, time, EV_ABS, ABS_MT_TOUCH_MINOR, 4);
    processAxis(conv, time, EV_ABS, ABS_MT_PRESSURE, 42);
    processAxis(conv, time, EV_ABS, ABS_MT_ORIENTATION, 2);

    processAxis(conv, time, EV_ABS, ABS_X, 50);
    processAxis(conv, time, EV_ABS, ABS_Y, 100);
    processAxis(conv, time, EV_ABS, ABS_PRESSURE, 42);

    processAxis(conv, time, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, time, EV_KEY, BTN_TOOL_FINGER, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(conv, time);

    ASSERT_TRUE(schs.has_value());
    const HardwareState& state = schs->state;
    EXPECT_NEAR(1.5, state.timestamp, EPSILON);
    EXPECT_EQ(0, state.buttons_down);
    EXPECT_EQ(1, state.touch_cnt);

    ASSERT_EQ(1, state.finger_cnt);
    const FingerState& finger = state.fingers[0];
    EXPECT_EQ(123, finger.tracking_id);
    EXPECT_NEAR(50, finger.position_x, EPSILON);
    EXPECT_NEAR(100, finger.position_y, EPSILON);
    EXPECT_NEAR(5, finger.touch_major, EPSILON);
    EXPECT_NEAR(4, finger.touch_minor, EPSILON);
    EXPECT_NEAR(42, finger.pressure, EPSILON);
    EXPECT_NEAR(2, finger.orientation, EPSILON);
    EXPECT_EQ(0u, finger.flags);

    EXPECT_EQ(0, state.rel_x);
    EXPECT_EQ(0, state.rel_y);
    EXPECT_EQ(0, state.rel_wheel);
    EXPECT_EQ(0, state.rel_wheel_hi_res);
    EXPECT_EQ(0, state.rel_hwheel);
    EXPECT_NEAR(0.0, state.msc_timestamp, EPSILON);
}

TEST_F(HardwareStateConverterTest, TwoFingers) {
    const nsecs_t time = ARBITRARY_TIME;
    InputDeviceContext deviceContext(*mDevice, EVENTHUB_ID);
    HardwareStateConverter conv(deviceContext);

    processAxis(conv, time, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, time, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, time, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    processAxis(conv, time, EV_ABS, ABS_MT_TOUCH_MINOR, 4);
    processAxis(conv, time, EV_ABS, ABS_MT_PRESSURE, 42);
    processAxis(conv, time, EV_ABS, ABS_MT_ORIENTATION, 2);

    processAxis(conv, time, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, time, EV_ABS, ABS_MT_TRACKING_ID, 456);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, -20);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 40);
    processAxis(conv, time, EV_ABS, ABS_MT_TOUCH_MAJOR, 8);
    processAxis(conv, time, EV_ABS, ABS_MT_TOUCH_MINOR, 7);
    processAxis(conv, time, EV_ABS, ABS_MT_PRESSURE, 21);
    processAxis(conv, time, EV_ABS, ABS_MT_ORIENTATION, 1);

    processAxis(conv, time, EV_ABS, ABS_X, 50);
    processAxis(conv, time, EV_ABS, ABS_Y, 100);
    processAxis(conv, time, EV_ABS, ABS_PRESSURE, 42);

    processAxis(conv, time, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, time, EV_KEY, BTN_TOOL_DOUBLETAP, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(conv, time);

    ASSERT_TRUE(schs.has_value());
    ASSERT_EQ(2, schs->state.finger_cnt);
    const FingerState& finger1 = schs->state.fingers[0];
    EXPECT_EQ(123, finger1.tracking_id);
    EXPECT_NEAR(50, finger1.position_x, EPSILON);
    EXPECT_NEAR(100, finger1.position_y, EPSILON);
    EXPECT_NEAR(5, finger1.touch_major, EPSILON);
    EXPECT_NEAR(4, finger1.touch_minor, EPSILON);
    EXPECT_NEAR(42, finger1.pressure, EPSILON);
    EXPECT_NEAR(2, finger1.orientation, EPSILON);
    EXPECT_EQ(0u, finger1.flags);

    const FingerState& finger2 = schs->state.fingers[1];
    EXPECT_EQ(456, finger2.tracking_id);
    EXPECT_NEAR(-20, finger2.position_x, EPSILON);
    EXPECT_NEAR(40, finger2.position_y, EPSILON);
    EXPECT_NEAR(8, finger2.touch_major, EPSILON);
    EXPECT_NEAR(7, finger2.touch_minor, EPSILON);
    EXPECT_NEAR(21, finger2.pressure, EPSILON);
    EXPECT_NEAR(1, finger2.orientation, EPSILON);
    EXPECT_EQ(0u, finger2.flags);
}

TEST_F(HardwareStateConverterTest, OnePalm) {
    const nsecs_t time = ARBITRARY_TIME;
    InputDeviceContext deviceContext(*mDevice, EVENTHUB_ID);
    HardwareStateConverter conv(deviceContext);

    processAxis(conv, time, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, time, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(conv, time, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(conv, time, EV_KEY, BTN_TOUCH, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(conv, time);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(0, schs->state.finger_cnt);
}

TEST_F(HardwareStateConverterTest, OneFingerTurningIntoAPalm) {
    const nsecs_t time = ARBITRARY_TIME;
    InputDeviceContext deviceContext(*mDevice, EVENTHUB_ID);
    HardwareStateConverter conv(deviceContext);

    processAxis(conv, time, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, time, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(conv, time, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(conv, time, EV_KEY, BTN_TOUCH, 1);

    std::optional<SelfContainedHardwareState> schs = processSync(conv, time);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.finger_cnt);

    processAxis(conv, time, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 51);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 99);

    schs = processSync(conv, time);
    ASSERT_TRUE(schs.has_value());
    ASSERT_EQ(0, schs->state.finger_cnt);

    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 53);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 97);

    schs = processSync(conv, time);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(0, schs->state.finger_cnt);

    processAxis(conv, time, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_X, 55);
    processAxis(conv, time, EV_ABS, ABS_MT_POSITION_Y, 95);
    schs = processSync(conv, time);
    ASSERT_TRUE(schs.has_value());
    ASSERT_EQ(1, schs->state.finger_cnt);
    const FingerState& newFinger = schs->state.fingers[0];
    EXPECT_EQ(123, newFinger.tracking_id);
    EXPECT_NEAR(55, newFinger.position_x, EPSILON);
    EXPECT_NEAR(95, newFinger.position_y, EPSILON);
}

TEST_F(HardwareStateConverterTest, ButtonPressed) {
    const nsecs_t time = ARBITRARY_TIME;
    InputDeviceContext deviceContext(*mDevice, EVENTHUB_ID);
    HardwareStateConverter conv(deviceContext);

    processAxis(conv, time, EV_KEY, BTN_LEFT, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(conv, time);

    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(GESTURES_BUTTON_LEFT, schs->state.buttons_down);
}

TEST_F(HardwareStateConverterTest, MscTimestamp) {
    const nsecs_t time = ARBITRARY_TIME;
    mFakeEventHub->setMscEvent(EVENTHUB_ID, MSC_TIMESTAMP);
    InputDeviceContext deviceContext(*mDevice, EVENTHUB_ID);
    HardwareStateConverter conv(deviceContext);

    processAxis(conv, time, EV_MSC, MSC_TIMESTAMP, 1200000);
    std::optional<SelfContainedHardwareState> schs = processSync(conv, time);

    ASSERT_TRUE(schs.has_value());
    EXPECT_NEAR(1.2, schs->state.msc_timestamp, EPSILON);
}

} // namespace android
