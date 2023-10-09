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

#include <CapturedTouchpadEventConverter.h>

#include <list>
#include <memory>

#include <EventHub.h>
#include <gtest/gtest.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <utils/StrongPointer.h>

#include "FakeEventHub.h"
#include "FakeInputReaderPolicy.h"
#include "InstrumentedInputReader.h"
#include "TestConstants.h"
#include "TestEventMatchers.h"
#include "TestInputListener.h"

namespace android {

using testing::AllOf;

class CapturedTouchpadEventConverterTest : public testing::Test {
public:
    CapturedTouchpadEventConverterTest()
          : mFakeEventHub(std::make_unique<FakeEventHub>()),
            mFakePolicy(sp<FakeInputReaderPolicy>::make()),
            mReader(mFakeEventHub, mFakePolicy, mFakeListener),
            mDevice(newDevice()),
            mDeviceContext(*mDevice, EVENTHUB_ID) {
        const size_t slotCount = 8;
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_SLOT, 0, slotCount - 1, 0, 0, 0);
        mAccumulator.configure(mDeviceContext, slotCount, /*usingSlotsProtocol=*/true);
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

    void addBasicAxesToEventHub() {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_PRESSURE, 0, 256, 0, 0, 0);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MAJOR, 0, 1000, 0, 0, 0);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MINOR, 0, 1000, 0, 0, 0);
    }

    CapturedTouchpadEventConverter createConverter() {
        addBasicAxesToEventHub();
        return CapturedTouchpadEventConverter(*mReader.getContext(), mDeviceContext, mAccumulator,
                                              DEVICE_ID);
    }

    void processAxis(CapturedTouchpadEventConverter& conv, int32_t type, int32_t code,
                     int32_t value) {
        RawEvent event;
        event.when = ARBITRARY_TIME;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = type;
        event.code = code;
        event.value = value;
        std::list<NotifyArgs> out = conv.process(event);
        EXPECT_TRUE(out.empty());
    }

    std::list<NotifyArgs> processSync(CapturedTouchpadEventConverter& conv) {
        RawEvent event;
        event.when = ARBITRARY_TIME;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = EV_SYN;
        event.code = SYN_REPORT;
        event.value = 0;
        return conv.process(event);
    }

    NotifyMotionArgs processSyncAndExpectSingleMotionArg(CapturedTouchpadEventConverter& conv) {
        std::list<NotifyArgs> args = processSync(conv);
        EXPECT_EQ(1u, args.size());
        return std::get<NotifyMotionArgs>(args.front());
    }

    std::shared_ptr<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    TestInputListener mFakeListener;
    InstrumentedInputReader mReader;
    std::shared_ptr<InputDevice> mDevice;
    InputDeviceContext mDeviceContext;
    MultiTouchMotionAccumulator mAccumulator;
};

TEST_F(CapturedTouchpadEventConverterTest, MotionRanges_allAxesPresent_populatedCorrectly) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MAJOR, 0, 1100, 0, 0, 35);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MINOR, 0, 1000, 0, 0, 30);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, 0, 900, 0, 0, 25);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MINOR, 0, 800, 0, 0, 20);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_ORIENTATION, -3, 4, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_PRESSURE, 0, 256, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    InputDeviceInfo info;
    conv.populateMotionRanges(info);

    // Most axes should have min, max, and resolution matching the evdev axes.
    const InputDeviceInfo::MotionRange* posX =
            info.getMotionRange(AMOTION_EVENT_AXIS_X, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, posX);
    EXPECT_NEAR(0, posX->min, EPSILON);
    EXPECT_NEAR(4000, posX->max, EPSILON);
    EXPECT_NEAR(45, posX->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* posY =
            info.getMotionRange(AMOTION_EVENT_AXIS_Y, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, posY);
    EXPECT_NEAR(0, posY->min, EPSILON);
    EXPECT_NEAR(2500, posY->max, EPSILON);
    EXPECT_NEAR(40, posY->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* touchMajor =
            info.getMotionRange(AMOTION_EVENT_AXIS_TOUCH_MAJOR, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, touchMajor);
    EXPECT_NEAR(0, touchMajor->min, EPSILON);
    EXPECT_NEAR(1100, touchMajor->max, EPSILON);
    EXPECT_NEAR(35, touchMajor->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* touchMinor =
            info.getMotionRange(AMOTION_EVENT_AXIS_TOUCH_MINOR, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, touchMinor);
    EXPECT_NEAR(0, touchMinor->min, EPSILON);
    EXPECT_NEAR(1000, touchMinor->max, EPSILON);
    EXPECT_NEAR(30, touchMinor->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* toolMajor =
            info.getMotionRange(AMOTION_EVENT_AXIS_TOOL_MAJOR, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, toolMajor);
    EXPECT_NEAR(0, toolMajor->min, EPSILON);
    EXPECT_NEAR(900, toolMajor->max, EPSILON);
    EXPECT_NEAR(25, toolMajor->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* toolMinor =
            info.getMotionRange(AMOTION_EVENT_AXIS_TOOL_MINOR, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, toolMinor);
    EXPECT_NEAR(0, toolMinor->min, EPSILON);
    EXPECT_NEAR(800, toolMinor->max, EPSILON);
    EXPECT_NEAR(20, toolMinor->resolution, EPSILON);

    // ...except orientation and pressure, which get scaled, and size, which is generated from other
    // values.
    const InputDeviceInfo::MotionRange* orientation =
            info.getMotionRange(AMOTION_EVENT_AXIS_ORIENTATION, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, orientation);
    EXPECT_NEAR(-M_PI_2, orientation->min, EPSILON);
    EXPECT_NEAR(M_PI_2, orientation->max, EPSILON);
    EXPECT_NEAR(0, orientation->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* pressure =
            info.getMotionRange(AMOTION_EVENT_AXIS_PRESSURE, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, pressure);
    EXPECT_NEAR(0, pressure->min, EPSILON);
    EXPECT_NEAR(1, pressure->max, EPSILON);
    EXPECT_NEAR(0, pressure->resolution, EPSILON);

    const InputDeviceInfo::MotionRange* size =
            info.getMotionRange(AMOTION_EVENT_AXIS_SIZE, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(nullptr, size);
    EXPECT_NEAR(0, size->min, EPSILON);
    EXPECT_NEAR(1, size->max, EPSILON);
    EXPECT_NEAR(0, size->resolution, EPSILON);
}

TEST_F(CapturedTouchpadEventConverterTest, MotionRanges_bareMinimumAxesPresent_populatedCorrectly) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    InputDeviceInfo info;
    conv.populateMotionRanges(info);

    // Only the bare minimum motion ranges should be reported, and no others (e.g. size shouldn't be
    // present, since it's generated from axes that aren't provided by this device).
    EXPECT_NE(nullptr, info.getMotionRange(AMOTION_EVENT_AXIS_X, AINPUT_SOURCE_TOUCHPAD));
    EXPECT_NE(nullptr, info.getMotionRange(AMOTION_EVENT_AXIS_Y, AINPUT_SOURCE_TOUCHPAD));
    EXPECT_EQ(2u, info.getMotionRanges().size());
}

TEST_F(CapturedTouchpadEventConverterTest, OneFinger_motionReportedCorrectly) {
    CapturedTouchpadEventConverter conv = createConverter();

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithCoords(50, 100), WithToolType(ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 52);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 99);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u),
                      WithCoords(52, 99), WithToolType(ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_KEY, BTN_TOUCH, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u),
                      WithCoords(52, 99), WithToolType(ToolType::FINGER)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithPointerCount(1u),
                      WithCoords(52, 99), WithToolType(ToolType::FINGER)));
}

TEST_F(CapturedTouchpadEventConverterTest, OneFinger_touchDimensionsPassedThrough) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, 0, 1000, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MINOR, 0, 1000, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_TOUCH_MAJOR, 250);
    processAxis(conv, EV_ABS, ABS_MT_TOUCH_MINOR, 120);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MAJOR, 400);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MINOR, 200);

    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithTouchDimensions(250, 120), WithToolDimensions(400, 200)));
}

TEST_F(CapturedTouchpadEventConverterTest, OneFinger_orientationCalculatedCorrectly) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_ORIENTATION, -3, 4, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_ORIENTATION, -3);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_NEAR(-3 * M_PI / 8,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_ORIENTATION),
                EPSILON);

    processAxis(conv, EV_ABS, ABS_MT_ORIENTATION, 0);

    EXPECT_NEAR(0,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_ORIENTATION),
                EPSILON);

    processAxis(conv, EV_ABS, ABS_MT_ORIENTATION, 4);

    EXPECT_NEAR(M_PI / 2,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_ORIENTATION),
                EPSILON);
}

TEST_F(CapturedTouchpadEventConverterTest, OneFinger_pressureScaledCorrectly) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_PRESSURE, 0, 256, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_PRESSURE, 128);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv), WithPressure(0.5));
}

TEST_F(CapturedTouchpadEventConverterTest,
       OneFinger_withAllSizeAxes_sizeCalculatedFromTouchMajorMinorAverage) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MAJOR, 0, 256, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MINOR, 0, 256, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, 0, 256, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MINOR, 0, 256, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_TOUCH_MAJOR, 138);
    processAxis(conv, EV_ABS, ABS_MT_TOUCH_MINOR, 118);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MAJOR, 200);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MINOR, 210);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_NEAR(0.5,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_SIZE),
                EPSILON);
}

TEST_F(CapturedTouchpadEventConverterTest,
       OneFinger_withMajorDimensionsOnly_sizeCalculatedFromTouchMajor) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MAJOR, 0, 256, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, 0, 256, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_TOUCH_MAJOR, 128);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MAJOR, 200);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_NEAR(0.5,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_SIZE),
                EPSILON);
}

TEST_F(CapturedTouchpadEventConverterTest,
       OneFinger_withToolDimensionsOnly_sizeCalculatedFromToolMajorMinorAverage) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, 0, 256, 0, 0, 0);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MINOR, 0, 256, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MAJOR, 138);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MINOR, 118);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_NEAR(0.5,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_SIZE),
                EPSILON);
}

TEST_F(CapturedTouchpadEventConverterTest,
       OneFinger_withToolMajorOnly_sizeCalculatedFromTouchMajor) {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, 0, 4000, 0, 0, 45);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, 0, 2500, 0, 0, 40);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, 0, 256, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_WIDTH_MAJOR, 128);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_NEAR(0.5,
                processSyncAndExpectSingleMotionArg(conv).pointerCoords[0].getAxisValue(
                        AMOTION_EVENT_AXIS_SIZE),
                EPSILON);
}

TEST_F(CapturedTouchpadEventConverterTest, OnePalm_neverReported) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_PALM, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_EQ(0u, processSync(conv).size());

    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 51);

    EXPECT_EQ(0u, processSync(conv).size());

    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_KEY, BTN_TOUCH, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);

    EXPECT_EQ(0u, processSync(conv).size());
}

TEST_F(CapturedTouchpadEventConverterTest, FingerTurningIntoPalm_cancelled) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_PALM, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithToolType(ToolType::FINGER),
                      WithPointerCount(1u)));

    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 51);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL), WithPointerCount(1u)));

    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 52);

    EXPECT_EQ(0u, processSync(conv).size());

    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_KEY, BTN_TOUCH, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);

    EXPECT_EQ(0u, processSync(conv).size());
}

TEST_F(CapturedTouchpadEventConverterTest, PalmTurningIntoFinger_reported) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_PALM, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_EQ(0u, processSync(conv).size());

    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 51);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithCoords(51, 100)));

    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 52);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u),
                      WithCoords(52, 100)));
}

TEST_F(CapturedTouchpadEventConverterTest, FingerArrivingAfterPalm_onlyFingerReported) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_PALM, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_EQ(0u, processSync(conv).size());

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 2);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 100);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 150);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_DOUBLETAP, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithCoords(100, 150)));

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 52);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 102);
    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 98);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 148);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u),
                      WithCoords(98, 148)));
}

TEST_F(CapturedTouchpadEventConverterTest, FingerAndFingerTurningIntoPalm_partiallyCancelled) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_PALM, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 2);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 250);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);

    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_DOUBLETAP, 1);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithToolType(ToolType::FINGER)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u), WithPointerToolType(0, ToolType::FINGER),
                      WithPointerToolType(1, ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 51);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 251);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);

    args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(2u)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_UP |
                                       1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithFlags(AMOTION_EVENT_FLAG_CANCELED), WithPointerCount(2u)));
}

TEST_F(CapturedTouchpadEventConverterTest, FingerAndPalmTurningIntoFinger_reported) {
    addBasicAxesToEventHub();
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_PALM, 0, 0, 0);
    CapturedTouchpadEventConverter conv(*mReader.getContext(), mDeviceContext, mAccumulator,
                                        DEVICE_ID);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 2);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 250);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_PALM);

    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_DOUBLETAP, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithToolType(ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 51);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 251);
    processAxis(conv, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u)));
}

TEST_F(CapturedTouchpadEventConverterTest, TwoFingers_motionReportedCorrectly) {
    CapturedTouchpadEventConverter conv = createConverter();

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);

    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithCoords(50, 100), WithToolType(ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 52);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 99);

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 2);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 250);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 200);

    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_DOUBLETAP, 1);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u),
                      WithCoords(52, 99), WithToolType(ToolType::FINGER)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u), WithPointerCoords(0, 52, 99),
                      WithPointerCoords(1, 250, 200), WithPointerToolType(0, ToolType::FINGER),
                      WithPointerToolType(1, ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 255);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 202);

    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_DOUBLETAP, 0);

    args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(2u),
                      WithPointerCoords(0, 52, 99), WithPointerCoords(1, 255, 202),
                      WithPointerToolType(1, ToolType::FINGER),
                      WithPointerToolType(0, ToolType::FINGER)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_UP |
                                       0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u), WithPointerCoords(0, 52, 99),
                      WithPointerCoords(1, 255, 202), WithPointerToolType(0, ToolType::FINGER),
                      WithPointerToolType(1, ToolType::FINGER)));

    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);
    processAxis(conv, EV_KEY, BTN_TOUCH, 0);

    args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(1u),
                      WithCoords(255, 202), WithToolType(ToolType::FINGER)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithPointerCount(1u),
                      WithCoords(255, 202), WithToolType(ToolType::FINGER)));
}

// Pointer IDs max out at 31, and so must be reused once a touch is lifted to avoid running out.
TEST_F(CapturedTouchpadEventConverterTest, PointerIdsReusedAfterLift) {
    CapturedTouchpadEventConverter conv = createConverter();

    // Put down two fingers, which should get IDs 0 and 1.
    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 10);
    processAxis(conv, EV_ABS, ABS_MT_SLOT, 1);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 2);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 20);

    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_DOUBLETAP, 1);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPointerCount(1u),
                      WithPointerId(/*index=*/0, /*id=*/0)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u), WithPointerId(/*index=*/0, /*id=*/0),
                      WithPointerId(/*index=*/1, /*id=*/1)));

    // Lift the finger in slot 0, freeing up pointer ID 0...
    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);

    // ...and simultaneously add a finger in slot 2.
    processAxis(conv, EV_ABS, ABS_MT_SLOT, 2);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 3);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 30);

    args = processSync(conv);
    ASSERT_EQ(3u, args.size());
    // Slot 1 being present will result in a MOVE event, even though it hasn't actually moved (see
    // comments in CapturedTouchpadEventConverter::sync).
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithPointerCount(2u),
                      WithPointerId(/*index=*/0, /*id=*/0), WithPointerId(/*index=*/1, /*id=*/1)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_UP |
                                       0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u), WithPointerId(/*index=*/0, /*id=*/0),
                      WithPointerId(/*index=*/1, /*id=*/1)));
    args.pop_front();
    // Slot 0 being lifted causes the finger from slot 1 to move up to index 0, but keep its
    // previous ID. The new finger in slot 2 should take ID 0, which was just freed up.
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                      WithPointerCount(2u), WithPointerId(/*index=*/0, /*id=*/1),
                      WithPointerId(/*index=*/1, /*id=*/0)));
}

// Motion events without any pointers are invalid, so when a button press is reported in the same
// frame as a touch down, the button press must be reported second. Similarly with a button release
// and a touch lift.
TEST_F(CapturedTouchpadEventConverterTest,
       ButtonPressedAndReleasedInSameFrameAsTouch_ReportedWithPointers) {
    CapturedTouchpadEventConverter conv = createConverter();

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    processAxis(conv, EV_KEY, BTN_LEFT, 1);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS), WithPointerCount(1u),
                      WithCoords(50, 100), WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY)));

    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_KEY, BTN_TOUCH, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);

    processAxis(conv, EV_KEY, BTN_LEFT, 0);
    args = processSync(conv);
    ASSERT_EQ(3u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_MOVE));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE), WithPointerCount(1u),
                      WithCoords(50, 100), WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(0)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_UP));
}

// Some touchpads sometimes report a button press before they report the finger touching the pad. In
// that case we need to wait until the touch comes to report the button press.
TEST_F(CapturedTouchpadEventConverterTest, ButtonPressedBeforeTouch_ReportedOnceTouchOccurs) {
    CapturedTouchpadEventConverter conv = createConverter();

    processAxis(conv, EV_KEY, BTN_LEFT, 1);
    ASSERT_EQ(0u, processSync(conv).size());

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS), WithPointerCount(1u),
                      WithCoords(50, 100), WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY)));
}

// When all fingers are lifted from a touchpad, we should release any buttons that are down, since
// we won't be able to report them being lifted later if no pointers are present.
TEST_F(CapturedTouchpadEventConverterTest, ButtonReleasedAfterTouchLifts_ReportedWithLift) {
    CapturedTouchpadEventConverter conv = createConverter();

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    processAxis(conv, EV_KEY, BTN_LEFT, 1);

    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, -1);
    processAxis(conv, EV_KEY, BTN_TOUCH, 0);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 0);
    args = processSync(conv);
    ASSERT_EQ(3u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_MOVE));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE), WithPointerCount(1u),
                      WithCoords(50, 100), WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(0)));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_UP));

    processAxis(conv, EV_KEY, BTN_LEFT, 0);
    ASSERT_EQ(0u, processSync(conv).size());
}

TEST_F(CapturedTouchpadEventConverterTest, MultipleButtonsPressedDuringTouch_ReportedCorrectly) {
    CapturedTouchpadEventConverter conv = createConverter();

    processAxis(conv, EV_ABS, ABS_MT_SLOT, 0);
    processAxis(conv, EV_ABS, ABS_MT_TRACKING_ID, 1);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_X, 50);
    processAxis(conv, EV_ABS, ABS_MT_POSITION_Y, 100);
    processAxis(conv, EV_KEY, BTN_TOUCH, 1);
    processAxis(conv, EV_KEY, BTN_TOOL_FINGER, 1);

    EXPECT_THAT(processSyncAndExpectSingleMotionArg(conv),
                WithMotionAction(AMOTION_EVENT_ACTION_DOWN));

    processAxis(conv, EV_KEY, BTN_LEFT, 1);
    std::list<NotifyArgs> args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_MOVE));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                      WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY)));

    processAxis(conv, EV_KEY, BTN_RIGHT, 1);
    args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_MOVE));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                      WithActionButton(AMOTION_EVENT_BUTTON_SECONDARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY |
                                      AMOTION_EVENT_BUTTON_SECONDARY)));

    processAxis(conv, EV_KEY, BTN_LEFT, 0);
    args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_MOVE));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                      WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_SECONDARY)));

    processAxis(conv, EV_KEY, BTN_RIGHT, 0);
    args = processSync(conv);
    ASSERT_EQ(2u, args.size());
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                WithMotionAction(AMOTION_EVENT_ACTION_MOVE));
    args.pop_front();
    EXPECT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                      WithActionButton(AMOTION_EVENT_BUTTON_SECONDARY), WithButtonState(0)));
}

} // namespace android
