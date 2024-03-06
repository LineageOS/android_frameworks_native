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
#include <gestures/HardwareProperties.h>

#include <memory>
#include <set>

#include <gtest/gtest.h>
#include <linux/input-event-codes.h>

#include "EventHub.h"
#include "InputDevice.h"
#include "InterfaceMocks.h"
#include "TestConstants.h"
#include "include/gestures.h"

namespace android {

using testing::Return;

class HardwarePropertiesTest : public testing::Test {
public:
    HardwarePropertiesTest() {
        EXPECT_CALL(mMockInputReaderContext, getEventHub()).WillRepeatedly(Return(&mMockEventHub));
        InputDeviceIdentifier identifier;
        identifier.name = "device";
        identifier.location = "USB1";
        mDevice = std::make_unique<InputDevice>(&mMockInputReaderContext, DEVICE_ID,
                                                /*generation=*/2, identifier);
        mDeviceContext = std::make_unique<InputDeviceContext>(*mDevice, EVENTHUB_ID);
    }

protected:
    static constexpr int32_t DEVICE_ID = END_RESERVED_ID + 1000;
    static constexpr int32_t EVENTHUB_ID = 1;

    void setupValidAxis(int axis, int32_t min, int32_t max, int32_t resolution) {
        EXPECT_CALL(mMockEventHub, getAbsoluteAxisInfo(EVENTHUB_ID, axis, testing::_))
                .WillRepeatedly([=](int32_t, int32_t, RawAbsoluteAxisInfo* outAxisInfo) {
                    outAxisInfo->valid = true;
                    outAxisInfo->minValue = min;
                    outAxisInfo->maxValue = max;
                    outAxisInfo->flat = 0;
                    outAxisInfo->fuzz = 0;
                    outAxisInfo->resolution = resolution;
                    return OK;
                });
    }

    void setupInvalidAxis(int axis) {
        EXPECT_CALL(mMockEventHub, getAbsoluteAxisInfo(EVENTHUB_ID, axis, testing::_))
                .WillRepeatedly([=](int32_t, int32_t, RawAbsoluteAxisInfo* outAxisInfo) {
                    outAxisInfo->valid = false;
                    return -1;
                });
    }

    void setProperty(int property, bool value) {
        EXPECT_CALL(mMockEventHub, hasInputProperty(EVENTHUB_ID, property))
                .WillRepeatedly(Return(value));
    }

    void setButtonsPresent(std::set<int> buttonCodes, bool present) {
        for (const auto& buttonCode : buttonCodes) {
            EXPECT_CALL(mMockEventHub, hasScanCode(EVENTHUB_ID, buttonCode))
                    .WillRepeatedly(Return(present));
        }
    }

    MockEventHubInterface mMockEventHub;
    MockInputReaderContext mMockInputReaderContext;
    std::unique_ptr<InputDevice> mDevice;
    std::unique_ptr<InputDeviceContext> mDeviceContext;
};

TEST_F(HardwarePropertiesTest, FancyTouchpad) {
    setupValidAxis(ABS_MT_POSITION_X, 0, 2048, 27);
    setupValidAxis(ABS_MT_POSITION_Y, 0, 1500, 30);
    setupValidAxis(ABS_MT_ORIENTATION, -3, 4, 0);
    setupValidAxis(ABS_MT_SLOT, 0, 15, 0);
    setupValidAxis(ABS_MT_PRESSURE, 0, 256, 0);

    setProperty(INPUT_PROP_SEMI_MT, false);
    setProperty(INPUT_PROP_BUTTONPAD, true);

    setButtonsPresent({BTN_TOOL_FINGER, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP,
                       BTN_TOOL_QUINTTAP},
                      true);

    HardwareProperties hwprops = createHardwareProperties(*mDeviceContext);
    EXPECT_NEAR(0, hwprops.left, EPSILON);
    EXPECT_NEAR(0, hwprops.top, EPSILON);
    EXPECT_NEAR(2048, hwprops.right, EPSILON);
    EXPECT_NEAR(1500, hwprops.bottom, EPSILON);

    EXPECT_NEAR(27, hwprops.res_x, EPSILON);
    EXPECT_NEAR(30, hwprops.res_y, EPSILON);

    EXPECT_NEAR(-3, hwprops.orientation_minimum, EPSILON);
    EXPECT_NEAR(4, hwprops.orientation_maximum, EPSILON);

    EXPECT_EQ(16, hwprops.max_finger_cnt);
    EXPECT_EQ(5, hwprops.max_touch_cnt);

    EXPECT_FALSE(hwprops.supports_t5r2);
    EXPECT_FALSE(hwprops.support_semi_mt);
    EXPECT_TRUE(hwprops.is_button_pad);
    EXPECT_FALSE(hwprops.has_wheel);
    EXPECT_FALSE(hwprops.wheel_is_hi_res);
    EXPECT_FALSE(hwprops.is_haptic_pad);
    EXPECT_TRUE(hwprops.reports_pressure);
}

TEST_F(HardwarePropertiesTest, BasicTouchpad) {
    setupValidAxis(ABS_MT_POSITION_X, 0, 1024, 0);
    setupValidAxis(ABS_MT_POSITION_Y, 0, 768, 0);
    setupValidAxis(ABS_MT_SLOT, 0, 7, 0);

    setupInvalidAxis(ABS_MT_ORIENTATION);
    setupInvalidAxis(ABS_MT_PRESSURE);

    setProperty(INPUT_PROP_SEMI_MT, false);
    setProperty(INPUT_PROP_BUTTONPAD, false);

    setButtonsPresent({BTN_TOOL_FINGER, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP}, true);
    setButtonsPresent({BTN_TOOL_QUADTAP, BTN_TOOL_QUINTTAP}, false);

    HardwareProperties hwprops = createHardwareProperties(*mDeviceContext);
    EXPECT_NEAR(0, hwprops.left, EPSILON);
    EXPECT_NEAR(0, hwprops.top, EPSILON);
    EXPECT_NEAR(1024, hwprops.right, EPSILON);
    EXPECT_NEAR(768, hwprops.bottom, EPSILON);

    EXPECT_NEAR(0, hwprops.res_x, EPSILON);
    EXPECT_NEAR(0, hwprops.res_y, EPSILON);

    EXPECT_NEAR(0, hwprops.orientation_minimum, EPSILON);
    EXPECT_NEAR(0, hwprops.orientation_maximum, EPSILON);

    EXPECT_EQ(8, hwprops.max_finger_cnt);
    EXPECT_EQ(3, hwprops.max_touch_cnt);

    EXPECT_FALSE(hwprops.supports_t5r2);
    EXPECT_FALSE(hwprops.support_semi_mt);
    EXPECT_FALSE(hwprops.is_button_pad);
    EXPECT_FALSE(hwprops.has_wheel);
    EXPECT_FALSE(hwprops.wheel_is_hi_res);
    EXPECT_FALSE(hwprops.is_haptic_pad);
    EXPECT_FALSE(hwprops.reports_pressure);
}

} // namespace android
