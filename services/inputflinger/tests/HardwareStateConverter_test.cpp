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
#include <gestures/HardwareStateConverter.h>

#include <memory>

#include <EventHub.h>
#include <com_android_input_flags.h>
#include <flag_macros.h>
#include <gtest/gtest.h>
#include <linux/input-event-codes.h>
#include <utils/StrongPointer.h>

#include "FakeEventHub.h"
#include "FakeInputReaderPolicy.h"
#include "InstrumentedInputReader.h"
#include "MultiTouchMotionAccumulator.h"
#include "TestConstants.h"
#include "TestInputListener.h"

namespace android {

namespace {

const auto REPORT_PALMS =
        ACONFIG_FLAG(com::android::input::flags, report_palms_to_gestures_library);

} // namespace

class HardwareStateConverterTest : public testing::Test {
public:
    HardwareStateConverterTest()
          : mFakeEventHub(std::make_shared<FakeEventHub>()),
            mFakePolicy(sp<FakeInputReaderPolicy>::make()),
            mReader(mFakeEventHub, mFakePolicy, mFakeListener),
            mDevice(newDevice()),
            mDeviceContext(*mDevice, EVENTHUB_ID) {
        const size_t slotCount = 8;
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_SLOT, 0, slotCount - 1, 0, 0, 0);
        mAccumulator.configure(mDeviceContext, slotCount, /*usingSlotsProtocol=*/true);
        mConverter = std::make_unique<HardwareStateConverter>(mDeviceContext, mAccumulator);
    }

protected:
    static constexpr int32_t DEVICE_ID = END_RESERVED_ID + 1000;
    static constexpr int32_t EVENTHUB_ID = 1;

    std::shared_ptr<InputDevice> newDevice() {
        InputDeviceIdentifier identifier;
        identifier.name = "device";
        identifier.location = "USB1";
        identifier.bus = 0;
        std::shared_ptr<InputDevice> device =
                std::make_shared<InputDevice>(mReader.getContext(), DEVICE_ID, /*generation=*/2,
                                              identifier);
        mReader.pushNextDevice(device);
        mFakeEventHub->addDevice(EVENTHUB_ID, identifier.name, InputDeviceClass::TOUCHPAD,
                                 identifier.bus);
        mReader.loopOnce();
        return device;
    }

    void processAxis(nsecs_t when, int32_t type, int32_t code, int32_t value) {
        RawEvent event;
        event.when = when;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = type;
        event.code = code;
        event.value = value;
        std::optional<SelfContainedHardwareState> schs = mConverter->processRawEvent(event);
        EXPECT_FALSE(schs.has_value());
    }

    std::optional<SelfContainedHardwareState> processSync(nsecs_t when) {
        RawEvent event;
        event.when = when;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = EV_SYN;
        event.code = SYN_REPORT;
        event.value = 0;
        return mConverter->processRawEvent(event);
    }

    std::shared_ptr<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    TestInputListener mFakeListener;
    InstrumentedInputReader mReader;
    std::shared_ptr<InputDevice> mDevice;
    InputDeviceContext mDeviceContext;
    MultiTouchMotionAccumulator mAccumulator;
    std::unique_ptr<HardwareStateConverter> mConverter;
};

TEST_F(HardwareStateConverterTest, OneFinger) {
    const nsecs_t time = 1500000000;

    processAxis(time, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(time, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(time, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(time, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(time, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    processAxis(time, EV_ABS, ABS_MT_TOUCH_MINOR, 4);
    processAxis(time, EV_ABS, ABS_MT_PRESSURE, 42);
    processAxis(time, EV_ABS, ABS_MT_ORIENTATION, 2);

    processAxis(time, EV_ABS, ABS_X, 50);
    processAxis(time, EV_ABS, ABS_Y, 100);
    processAxis(time, EV_ABS, ABS_PRESSURE, 42);

    processAxis(time, EV_KEY, BTN_TOUCH, 1);
    processAxis(time, EV_KEY, BTN_TOOL_FINGER, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(time);

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
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MINOR, 4);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_PRESSURE, 42);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_ORIENTATION, 2);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, 456);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, -20);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 40);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MAJOR, 8);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOUCH_MINOR, 7);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_PRESSURE, 21);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_ORIENTATION, 1);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_X, 50);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_Y, 100);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_PRESSURE, 42);

    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOUCH, 1);
    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOOL_DOUBLETAP, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);

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

TEST_F_WITH_FLAGS(HardwareStateConverterTest, OnePalmDisableReportPalms,
                  REQUIRES_FLAGS_DISABLED(REPORT_PALMS)) {
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOUCH, 1);
    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOOL_FINGER, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(0, schs->state.touch_cnt);
    EXPECT_EQ(0, schs->state.finger_cnt);
}

TEST_F_WITH_FLAGS(HardwareStateConverterTest, OnePalmEnableReportPalms,
                  REQUIRES_FLAGS_ENABLED(REPORT_PALMS)) {
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOUCH, 1);
    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOOL_FINGER, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    EXPECT_EQ(1, schs->state.finger_cnt);
    EXPECT_EQ(FingerState::ToolType::kPalm, schs->state.fingers[0].tool_type);
}

TEST_F_WITH_FLAGS(HardwareStateConverterTest, OneFingerTurningIntoAPalmDisableReportPalms,
                  REQUIRES_FLAGS_DISABLED(REPORT_PALMS)) {
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOUCH, 1);
    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOOL_FINGER, 1);

    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    EXPECT_EQ(1, schs->state.finger_cnt);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 51);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 99);

    schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(0, schs->state.touch_cnt);
    ASSERT_EQ(0, schs->state.finger_cnt);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 53);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 97);

    schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(0, schs->state.touch_cnt);
    EXPECT_EQ(0, schs->state.finger_cnt);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 55);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 95);
    schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    ASSERT_EQ(1, schs->state.finger_cnt);
    const FingerState& newFinger = schs->state.fingers[0];
    EXPECT_EQ(123, newFinger.tracking_id);
    EXPECT_NEAR(55, newFinger.position_x, EPSILON);
    EXPECT_NEAR(95, newFinger.position_y, EPSILON);
}

TEST_F_WITH_FLAGS(HardwareStateConverterTest, OneFingerTurningIntoAPalmEnableReportPalms,
                  REQUIRES_FLAGS_ENABLED(REPORT_PALMS)) {
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TRACKING_ID, 123);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOUCH, 1);
    processAxis(ARBITRARY_TIME, EV_KEY, BTN_TOOL_FINGER, 1);

    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    EXPECT_EQ(1, schs->state.finger_cnt);
    EXPECT_EQ(FingerState::ToolType::kFinger, schs->state.fingers[0].tool_type);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 51);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 99);

    schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    ASSERT_EQ(1, schs->state.finger_cnt);
    EXPECT_EQ(FingerState::ToolType::kPalm, schs->state.fingers[0].tool_type);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 53);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 97);

    schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    EXPECT_EQ(1, schs->state.finger_cnt);
    EXPECT_EQ(FingerState::ToolType::kPalm, schs->state.fingers[0].tool_type);

    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_X, 55);
    processAxis(ARBITRARY_TIME, EV_ABS, ABS_MT_POSITION_Y, 95);
    schs = processSync(ARBITRARY_TIME);
    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(1, schs->state.touch_cnt);
    ASSERT_EQ(1, schs->state.finger_cnt);
    const FingerState& newFinger = schs->state.fingers[0];
    EXPECT_EQ(FingerState::ToolType::kFinger, newFinger.tool_type);
    EXPECT_EQ(123, newFinger.tracking_id);
    EXPECT_NEAR(55, newFinger.position_x, EPSILON);
    EXPECT_NEAR(95, newFinger.position_y, EPSILON);
}

TEST_F(HardwareStateConverterTest, ButtonPressed) {
    processAxis(ARBITRARY_TIME, EV_KEY, BTN_LEFT, 1);
    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);

    ASSERT_TRUE(schs.has_value());
    EXPECT_EQ(GESTURES_BUTTON_LEFT, schs->state.buttons_down);
}

TEST_F(HardwareStateConverterTest, MscTimestamp) {
    processAxis(ARBITRARY_TIME, EV_MSC, MSC_TIMESTAMP, 1200000);
    std::optional<SelfContainedHardwareState> schs = processSync(ARBITRARY_TIME);

    ASSERT_TRUE(schs.has_value());
    EXPECT_NEAR(1.2, schs->state.msc_timestamp, EPSILON);
}

} // namespace android
