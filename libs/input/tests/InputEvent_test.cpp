/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <array>
#include <math.h>

#include <android-base/properties.h>
#include <attestation/HmacKeyManager.h>
#include <binder/Parcel.h>
#include <gtest/gtest.h>
#include <gui/constants.h>
#include <input/Input.h>

namespace android {

// Default display id.
static constexpr int32_t DISPLAY_ID = ADISPLAY_ID_DEFAULT;

class BaseTest : public testing::Test {
protected:
    static constexpr std::array<uint8_t, 32> HMAC = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                                     11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                                     22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
};

// --- PointerCoordsTest ---

class PointerCoordsTest : public BaseTest {
};

TEST_F(PointerCoordsTest, ClearSetsBitsToZero) {
    PointerCoords coords;
    coords.clear();

    ASSERT_EQ(0ULL, coords.bits);
}

TEST_F(PointerCoordsTest, AxisValues) {
    PointerCoords coords;
    coords.clear();

    // Check invariants when no axes are present.
    ASSERT_EQ(0, coords.getAxisValue(0))
            << "getAxisValue should return zero because axis is not present";
    ASSERT_EQ(0, coords.getAxisValue(1))
            << "getAxisValue should return zero because axis is not present";

    // Set first axis.
    ASSERT_EQ(OK, coords.setAxisValue(1, 5));
    ASSERT_EQ(5, coords.values[0]);
    ASSERT_EQ(0x4000000000000000ULL, coords.bits);

    ASSERT_EQ(0, coords.getAxisValue(0))
            << "getAxisValue should return zero because axis is not present";
    ASSERT_EQ(5, coords.getAxisValue(1))
            << "getAxisValue should return value of axis";

    // Set an axis with a higher id than all others.  (appending value at the end)
    ASSERT_EQ(OK, coords.setAxisValue(3, 2));
    ASSERT_EQ(0x5000000000000000ULL, coords.bits);
    ASSERT_EQ(5, coords.values[0]);
    ASSERT_EQ(2, coords.values[1]);

    ASSERT_EQ(0, coords.getAxisValue(0))
            << "getAxisValue should return zero because axis is not present";
    ASSERT_EQ(5, coords.getAxisValue(1))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(0, coords.getAxisValue(2))
            << "getAxisValue should return zero because axis is not present";
    ASSERT_EQ(2, coords.getAxisValue(3))
            << "getAxisValue should return value of axis";

    // Set an axis with an id lower than all others.  (prepending value at beginning)
    ASSERT_EQ(OK, coords.setAxisValue(0, 4));
    ASSERT_EQ(0xd000000000000000ULL, coords.bits);
    ASSERT_EQ(4, coords.values[0]);
    ASSERT_EQ(5, coords.values[1]);
    ASSERT_EQ(2, coords.values[2]);

    ASSERT_EQ(4, coords.getAxisValue(0))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(5, coords.getAxisValue(1))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(0, coords.getAxisValue(2))
            << "getAxisValue should return zero because axis is not present";
    ASSERT_EQ(2, coords.getAxisValue(3))
            << "getAxisValue should return value of axis";

    // Set an axis with an id between the others.  (inserting value in the middle)
    ASSERT_EQ(OK, coords.setAxisValue(2, 1));
    ASSERT_EQ(0xf000000000000000ULL, coords.bits);
    ASSERT_EQ(4, coords.values[0]);
    ASSERT_EQ(5, coords.values[1]);
    ASSERT_EQ(1, coords.values[2]);
    ASSERT_EQ(2, coords.values[3]);

    ASSERT_EQ(4, coords.getAxisValue(0))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(5, coords.getAxisValue(1))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(1, coords.getAxisValue(2))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(2, coords.getAxisValue(3))
            << "getAxisValue should return value of axis";

    // Set an existing axis value in place.
    ASSERT_EQ(OK, coords.setAxisValue(1, 6));
    ASSERT_EQ(0xf000000000000000ULL, coords.bits);
    ASSERT_EQ(4, coords.values[0]);
    ASSERT_EQ(6, coords.values[1]);
    ASSERT_EQ(1, coords.values[2]);
    ASSERT_EQ(2, coords.values[3]);

    ASSERT_EQ(4, coords.getAxisValue(0))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(6, coords.getAxisValue(1))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(1, coords.getAxisValue(2))
            << "getAxisValue should return value of axis";
    ASSERT_EQ(2, coords.getAxisValue(3))
            << "getAxisValue should return value of axis";

    // Set maximum number of axes.
    for (size_t axis = 4; axis < PointerCoords::MAX_AXES; axis++) {
        ASSERT_EQ(OK, coords.setAxisValue(axis, axis));
    }
    ASSERT_EQ(PointerCoords::MAX_AXES, __builtin_popcountll(coords.bits));

    // Try to set one more axis beyond maximum number.
    // Ensure bits are unchanged.
    ASSERT_EQ(NO_MEMORY, coords.setAxisValue(PointerCoords::MAX_AXES, 100));
    ASSERT_EQ(PointerCoords::MAX_AXES, __builtin_popcountll(coords.bits));
}

TEST_F(PointerCoordsTest, Parcel) {
    Parcel parcel;

    PointerCoords inCoords;
    inCoords.clear();
    PointerCoords outCoords;

    // Round trip with empty coords.
    inCoords.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    outCoords.readFromParcel(&parcel);

    ASSERT_EQ(0ULL, outCoords.bits);

    // Round trip with some values.
    parcel.freeData();
    inCoords.setAxisValue(2, 5);
    inCoords.setAxisValue(5, 8);

    inCoords.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    outCoords.readFromParcel(&parcel);

    ASSERT_EQ(outCoords.bits, inCoords.bits);
    ASSERT_EQ(outCoords.values[0], inCoords.values[0]);
    ASSERT_EQ(outCoords.values[1], inCoords.values[1]);
}


// --- KeyEventTest ---

class KeyEventTest : public BaseTest {
};

TEST_F(KeyEventTest, Properties) {
    KeyEvent event;

    // Initialize and get properties.
    constexpr nsecs_t ARBITRARY_DOWN_TIME = 1;
    constexpr nsecs_t ARBITRARY_EVENT_TIME = 2;
    const int32_t id = InputEvent::nextId();
    event.initialize(id, 2, AINPUT_SOURCE_GAMEPAD, DISPLAY_ID, HMAC, AKEY_EVENT_ACTION_DOWN,
                     AKEY_EVENT_FLAG_FROM_SYSTEM, AKEYCODE_BUTTON_X, 121, AMETA_ALT_ON, 1,
                     ARBITRARY_DOWN_TIME, ARBITRARY_EVENT_TIME);

    ASSERT_EQ(id, event.getId());
    ASSERT_EQ(AINPUT_EVENT_TYPE_KEY, event.getType());
    ASSERT_EQ(2, event.getDeviceId());
    ASSERT_EQ(AINPUT_SOURCE_GAMEPAD, event.getSource());
    ASSERT_EQ(DISPLAY_ID, event.getDisplayId());
    EXPECT_EQ(HMAC, event.getHmac());
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, event.getAction());
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, event.getFlags());
    ASSERT_EQ(AKEYCODE_BUTTON_X, event.getKeyCode());
    ASSERT_EQ(121, event.getScanCode());
    ASSERT_EQ(AMETA_ALT_ON, event.getMetaState());
    ASSERT_EQ(1, event.getRepeatCount());
    ASSERT_EQ(ARBITRARY_DOWN_TIME, event.getDownTime());
    ASSERT_EQ(ARBITRARY_EVENT_TIME, event.getEventTime());

    // Set source.
    event.setSource(AINPUT_SOURCE_JOYSTICK);
    ASSERT_EQ(AINPUT_SOURCE_JOYSTICK, event.getSource());

    // Set display id.
    constexpr int32_t newDisplayId = 2;
    event.setDisplayId(newDisplayId);
    ASSERT_EQ(newDisplayId, event.getDisplayId());
}


// --- MotionEventTest ---

class MotionEventTest : public BaseTest {
protected:
    static constexpr nsecs_t ARBITRARY_DOWN_TIME = 1;
    static constexpr nsecs_t ARBITRARY_EVENT_TIME = 2;
    static constexpr float X_SCALE = 2.0;
    static constexpr float Y_SCALE = 3.0;
    static constexpr float X_OFFSET = 1;
    static constexpr float Y_OFFSET = 1.1;
    static constexpr float RAW_X_SCALE = 4.0;
    static constexpr float RAW_Y_SCALE = -5.0;
    static constexpr float RAW_X_OFFSET = 12;
    static constexpr float RAW_Y_OFFSET = -41.1;

    int32_t mId;
    ui::Transform mTransform;
    ui::Transform mRawTransform;

    void initializeEventWithHistory(MotionEvent* event);
    void assertEqualsEventWithHistory(const MotionEvent* event);
};

void MotionEventTest::initializeEventWithHistory(MotionEvent* event) {
    mId = InputEvent::nextId();
    mTransform.set({X_SCALE, 0, X_OFFSET, 0, Y_SCALE, Y_OFFSET, 0, 0, 1});
    mRawTransform.set({RAW_X_SCALE, 0, RAW_X_OFFSET, 0, RAW_Y_SCALE, RAW_Y_OFFSET, 0, 0, 1});

    PointerProperties pointerProperties[2];
    pointerProperties[0].clear();
    pointerProperties[0].id = 1;
    pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
    pointerProperties[1].clear();
    pointerProperties[1].id = 2;
    pointerProperties[1].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;

    PointerCoords pointerCoords[2];
    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 10);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 11);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 12);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 13);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 14);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 15);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 16);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, 17);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 18);
    pointerCoords[1].clear();
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_X, 20);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_Y, 21);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 22);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 23);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 24);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 25);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 26);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, 27);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 28);
    event->initialize(mId, 2, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID, HMAC,
                      AMOTION_EVENT_ACTION_MOVE, 0, AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED,
                      AMOTION_EVENT_EDGE_FLAG_TOP, AMETA_ALT_ON, AMOTION_EVENT_BUTTON_PRIMARY,
                      MotionClassification::NONE, mTransform, 2.0f, 2.1f,
                      AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                      mRawTransform, ARBITRARY_DOWN_TIME, ARBITRARY_EVENT_TIME, 2,
                      pointerProperties, pointerCoords);

    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 110);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 111);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 112);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 113);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 114);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 115);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 116);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, 117);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 118);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_X, 120);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_Y, 121);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 122);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 123);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 124);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 125);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 126);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, 127);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 128);
    event->addSample(ARBITRARY_EVENT_TIME + 1, pointerCoords);

    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 210);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 211);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 212);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 213);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 214);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 215);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 216);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, 217);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 218);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_X, 220);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_Y, 221);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 222);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 223);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 224);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 225);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 226);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, 227);
    pointerCoords[1].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 228);
    event->addSample(ARBITRARY_EVENT_TIME + 2, pointerCoords);
}

void MotionEventTest::assertEqualsEventWithHistory(const MotionEvent* event) {
    // Check properties.
    ASSERT_EQ(mId, event->getId());
    ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, event->getType());
    ASSERT_EQ(2, event->getDeviceId());
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, event->getSource());
    ASSERT_EQ(DISPLAY_ID, event->getDisplayId());
    EXPECT_EQ(HMAC, event->getHmac());
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, event->getAction());
    ASSERT_EQ(AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED, event->getFlags());
    ASSERT_EQ(AMOTION_EVENT_EDGE_FLAG_TOP, event->getEdgeFlags());
    ASSERT_EQ(AMETA_ALT_ON, event->getMetaState());
    ASSERT_EQ(AMOTION_EVENT_BUTTON_PRIMARY, event->getButtonState());
    ASSERT_EQ(MotionClassification::NONE, event->getClassification());
    EXPECT_EQ(mTransform, event->getTransform());
    ASSERT_EQ(X_OFFSET, event->getXOffset());
    ASSERT_EQ(Y_OFFSET, event->getYOffset());
    ASSERT_EQ(2.0f, event->getXPrecision());
    ASSERT_EQ(2.1f, event->getYPrecision());
    ASSERT_EQ(ARBITRARY_DOWN_TIME, event->getDownTime());

    ASSERT_EQ(2U, event->getPointerCount());
    ASSERT_EQ(1, event->getPointerId(0));
    ASSERT_EQ(AMOTION_EVENT_TOOL_TYPE_FINGER, event->getToolType(0));
    ASSERT_EQ(2, event->getPointerId(1));
    ASSERT_EQ(AMOTION_EVENT_TOOL_TYPE_STYLUS, event->getToolType(1));

    ASSERT_EQ(2U, event->getHistorySize());

    // Check data.
    ASSERT_EQ(ARBITRARY_EVENT_TIME, event->getHistoricalEventTime(0));
    ASSERT_EQ(ARBITRARY_EVENT_TIME + 1, event->getHistoricalEventTime(1));
    ASSERT_EQ(ARBITRARY_EVENT_TIME + 2, event->getEventTime());

    ASSERT_EQ(11, event->getHistoricalRawPointerCoords(0, 0)->getAxisValue(AMOTION_EVENT_AXIS_Y));
    ASSERT_EQ(21, event->getHistoricalRawPointerCoords(1, 0)->getAxisValue(AMOTION_EVENT_AXIS_Y));
    ASSERT_EQ(111, event->getHistoricalRawPointerCoords(0, 1)->getAxisValue(AMOTION_EVENT_AXIS_Y));
    ASSERT_EQ(121, event->getHistoricalRawPointerCoords(1, 1)->getAxisValue(AMOTION_EVENT_AXIS_Y));
    ASSERT_EQ(211, event->getRawPointerCoords(0)->getAxisValue(AMOTION_EVENT_AXIS_Y));
    ASSERT_EQ(221, event->getRawPointerCoords(1)->getAxisValue(AMOTION_EVENT_AXIS_Y));

    ASSERT_EQ(RAW_Y_OFFSET + 11 * RAW_Y_SCALE,
              event->getHistoricalRawAxisValue(AMOTION_EVENT_AXIS_Y, 0, 0));
    ASSERT_EQ(RAW_Y_OFFSET + 21 * RAW_Y_SCALE,
              event->getHistoricalRawAxisValue(AMOTION_EVENT_AXIS_Y, 1, 0));
    ASSERT_EQ(RAW_Y_OFFSET + 111 * RAW_Y_SCALE,
              event->getHistoricalRawAxisValue(AMOTION_EVENT_AXIS_Y, 0, 1));
    ASSERT_EQ(RAW_Y_OFFSET + 121 * RAW_Y_SCALE,
              event->getHistoricalRawAxisValue(AMOTION_EVENT_AXIS_Y, 1, 1));
    ASSERT_EQ(RAW_Y_OFFSET + 211 * RAW_Y_SCALE, event->getRawAxisValue(AMOTION_EVENT_AXIS_Y, 0));
    ASSERT_EQ(RAW_Y_OFFSET + 221 * RAW_Y_SCALE, event->getRawAxisValue(AMOTION_EVENT_AXIS_Y, 1));

    ASSERT_EQ(RAW_X_OFFSET + 10 * RAW_X_SCALE, event->getHistoricalRawX(0, 0));
    ASSERT_EQ(RAW_X_OFFSET + 20 * RAW_X_SCALE, event->getHistoricalRawX(1, 0));
    ASSERT_EQ(RAW_X_OFFSET + 110 * RAW_X_SCALE, event->getHistoricalRawX(0, 1));
    ASSERT_EQ(RAW_X_OFFSET + 120 * RAW_X_SCALE, event->getHistoricalRawX(1, 1));
    ASSERT_EQ(RAW_X_OFFSET + 210 * RAW_X_SCALE, event->getRawX(0));
    ASSERT_EQ(RAW_X_OFFSET + 220 * RAW_X_SCALE, event->getRawX(1));

    ASSERT_EQ(RAW_Y_OFFSET + 11 * RAW_Y_SCALE, event->getHistoricalRawY(0, 0));
    ASSERT_EQ(RAW_Y_OFFSET + 21 * RAW_Y_SCALE, event->getHistoricalRawY(1, 0));
    ASSERT_EQ(RAW_Y_OFFSET + 111 * RAW_Y_SCALE, event->getHistoricalRawY(0, 1));
    ASSERT_EQ(RAW_Y_OFFSET + 121 * RAW_Y_SCALE, event->getHistoricalRawY(1, 1));
    ASSERT_EQ(RAW_Y_OFFSET + 211 * RAW_Y_SCALE, event->getRawY(0));
    ASSERT_EQ(RAW_Y_OFFSET + 221 * RAW_Y_SCALE, event->getRawY(1));

    ASSERT_EQ(X_OFFSET + 10 * X_SCALE, event->getHistoricalX(0, 0));
    ASSERT_EQ(X_OFFSET + 20 * X_SCALE, event->getHistoricalX(1, 0));
    ASSERT_EQ(X_OFFSET + 110 * X_SCALE, event->getHistoricalX(0, 1));
    ASSERT_EQ(X_OFFSET + 120 * X_SCALE, event->getHistoricalX(1, 1));
    ASSERT_EQ(X_OFFSET + 210 * X_SCALE, event->getX(0));
    ASSERT_EQ(X_OFFSET + 220 * X_SCALE, event->getX(1));

    ASSERT_EQ(Y_OFFSET + 11 * Y_SCALE, event->getHistoricalY(0, 0));
    ASSERT_EQ(Y_OFFSET + 21 * Y_SCALE, event->getHistoricalY(1, 0));
    ASSERT_EQ(Y_OFFSET + 111 * Y_SCALE, event->getHistoricalY(0, 1));
    ASSERT_EQ(Y_OFFSET + 121 * Y_SCALE, event->getHistoricalY(1, 1));
    ASSERT_EQ(Y_OFFSET + 211 * Y_SCALE, event->getY(0));
    ASSERT_EQ(Y_OFFSET + 221 * Y_SCALE, event->getY(1));

    ASSERT_EQ(12, event->getHistoricalPressure(0, 0));
    ASSERT_EQ(22, event->getHistoricalPressure(1, 0));
    ASSERT_EQ(112, event->getHistoricalPressure(0, 1));
    ASSERT_EQ(122, event->getHistoricalPressure(1, 1));
    ASSERT_EQ(212, event->getPressure(0));
    ASSERT_EQ(222, event->getPressure(1));

    ASSERT_EQ(13, event->getHistoricalSize(0, 0));
    ASSERT_EQ(23, event->getHistoricalSize(1, 0));
    ASSERT_EQ(113, event->getHistoricalSize(0, 1));
    ASSERT_EQ(123, event->getHistoricalSize(1, 1));
    ASSERT_EQ(213, event->getSize(0));
    ASSERT_EQ(223, event->getSize(1));

    ASSERT_EQ(14, event->getHistoricalTouchMajor(0, 0));
    ASSERT_EQ(24, event->getHistoricalTouchMajor(1, 0));
    ASSERT_EQ(114, event->getHistoricalTouchMajor(0, 1));
    ASSERT_EQ(124, event->getHistoricalTouchMajor(1, 1));
    ASSERT_EQ(214, event->getTouchMajor(0));
    ASSERT_EQ(224, event->getTouchMajor(1));

    ASSERT_EQ(15, event->getHistoricalTouchMinor(0, 0));
    ASSERT_EQ(25, event->getHistoricalTouchMinor(1, 0));
    ASSERT_EQ(115, event->getHistoricalTouchMinor(0, 1));
    ASSERT_EQ(125, event->getHistoricalTouchMinor(1, 1));
    ASSERT_EQ(215, event->getTouchMinor(0));
    ASSERT_EQ(225, event->getTouchMinor(1));

    ASSERT_EQ(16, event->getHistoricalToolMajor(0, 0));
    ASSERT_EQ(26, event->getHistoricalToolMajor(1, 0));
    ASSERT_EQ(116, event->getHistoricalToolMajor(0, 1));
    ASSERT_EQ(126, event->getHistoricalToolMajor(1, 1));
    ASSERT_EQ(216, event->getToolMajor(0));
    ASSERT_EQ(226, event->getToolMajor(1));

    ASSERT_EQ(17, event->getHistoricalToolMinor(0, 0));
    ASSERT_EQ(27, event->getHistoricalToolMinor(1, 0));
    ASSERT_EQ(117, event->getHistoricalToolMinor(0, 1));
    ASSERT_EQ(127, event->getHistoricalToolMinor(1, 1));
    ASSERT_EQ(217, event->getToolMinor(0));
    ASSERT_EQ(227, event->getToolMinor(1));

    // Calculate the orientation after scaling, keeping in mind that an orientation of 0 is "up",
    // and the positive y direction is "down".
    auto toScaledOrientation = [](float angle) {
        const float x = sinf(angle) * X_SCALE;
        const float y = -cosf(angle) * Y_SCALE;
        return atan2f(x, -y);
    };
    ASSERT_EQ(toScaledOrientation(18), event->getHistoricalOrientation(0, 0));
    ASSERT_EQ(toScaledOrientation(28), event->getHistoricalOrientation(1, 0));
    ASSERT_EQ(toScaledOrientation(118), event->getHistoricalOrientation(0, 1));
    ASSERT_EQ(toScaledOrientation(128), event->getHistoricalOrientation(1, 1));
    ASSERT_EQ(toScaledOrientation(218), event->getOrientation(0));
    ASSERT_EQ(toScaledOrientation(228), event->getOrientation(1));
}

TEST_F(MotionEventTest, Properties) {
    MotionEvent event;

    // Initialize, add samples and check properties.
    initializeEventWithHistory(&event);
    ASSERT_NO_FATAL_FAILURE(assertEqualsEventWithHistory(&event));

    // Set source.
    event.setSource(AINPUT_SOURCE_JOYSTICK);
    ASSERT_EQ(AINPUT_SOURCE_JOYSTICK, event.getSource());

    // Set displayId.
    constexpr int32_t newDisplayId = 2;
    event.setDisplayId(newDisplayId);
    ASSERT_EQ(newDisplayId, event.getDisplayId());

    // Set action.
    event.setAction(AMOTION_EVENT_ACTION_CANCEL);
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, event.getAction());

    // Set meta state.
    event.setMetaState(AMETA_CTRL_ON);
    ASSERT_EQ(AMETA_CTRL_ON, event.getMetaState());
}

TEST_F(MotionEventTest, CopyFrom_KeepHistory) {
    MotionEvent event;
    initializeEventWithHistory(&event);

    MotionEvent copy;
    copy.copyFrom(&event, true /*keepHistory*/);

    ASSERT_NO_FATAL_FAILURE(assertEqualsEventWithHistory(&event));
}

TEST_F(MotionEventTest, CopyFrom_DoNotKeepHistory) {
    MotionEvent event;
    initializeEventWithHistory(&event);

    MotionEvent copy;
    copy.copyFrom(&event, false /*keepHistory*/);

    ASSERT_EQ(event.getPointerCount(), copy.getPointerCount());
    ASSERT_EQ(0U, copy.getHistorySize());

    ASSERT_EQ(event.getPointerId(0), copy.getPointerId(0));
    ASSERT_EQ(event.getPointerId(1), copy.getPointerId(1));

    ASSERT_EQ(event.getEventTime(), copy.getEventTime());

    ASSERT_EQ(event.getX(0), copy.getX(0));
}

TEST_F(MotionEventTest, OffsetLocation) {
    MotionEvent event;
    initializeEventWithHistory(&event);

    event.offsetLocation(5.0f, -2.0f);

    ASSERT_EQ(X_OFFSET + 5.0f, event.getXOffset());
    ASSERT_EQ(Y_OFFSET - 2.0f, event.getYOffset());
}

TEST_F(MotionEventTest, Scale) {
    MotionEvent event;
    initializeEventWithHistory(&event);
    const float unscaledOrientation = event.getOrientation(0);

    event.scale(2.0f);

    ASSERT_EQ(X_OFFSET * 2, event.getXOffset());
    ASSERT_EQ(Y_OFFSET * 2, event.getYOffset());

    ASSERT_EQ((RAW_X_OFFSET + 210 * RAW_X_SCALE) * 2, event.getRawX(0));
    ASSERT_EQ((RAW_Y_OFFSET + 211 * RAW_Y_SCALE) * 2, event.getRawY(0));
    ASSERT_EQ((X_OFFSET + 210 * X_SCALE) * 2, event.getX(0));
    ASSERT_EQ((Y_OFFSET + 211 * Y_SCALE) * 2, event.getY(0));
    ASSERT_EQ(212, event.getPressure(0));
    ASSERT_EQ(213, event.getSize(0));
    ASSERT_EQ(214 * 2, event.getTouchMajor(0));
    ASSERT_EQ(215 * 2, event.getTouchMinor(0));
    ASSERT_EQ(216 * 2, event.getToolMajor(0));
    ASSERT_EQ(217 * 2, event.getToolMinor(0));
    ASSERT_EQ(unscaledOrientation, event.getOrientation(0));
}

TEST_F(MotionEventTest, Parcel) {
    Parcel parcel;

    MotionEvent inEvent;
    initializeEventWithHistory(&inEvent);
    MotionEvent outEvent;

    // Round trip.
    inEvent.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    outEvent.readFromParcel(&parcel);

    ASSERT_NO_FATAL_FAILURE(assertEqualsEventWithHistory(&outEvent));
}

static void setRotationMatrix(std::array<float, 9>& matrix, float angle) {
    float sin = sinf(angle);
    float cos = cosf(angle);
    matrix[0] = cos;
    matrix[1] = -sin;
    matrix[2] = 0;
    matrix[3] = sin;
    matrix[4] = cos;
    matrix[5] = 0;
    matrix[6] = 0;
    matrix[7] = 0;
    matrix[8] = 1.0f;
}

TEST_F(MotionEventTest, Transform) {
    // Generate some points on a circle.
    // Each point 'i' is a point on a circle of radius ROTATION centered at (3,2) at an angle
    // of ARC * i degrees clockwise relative to the Y axis.
    // The geometrical representation is irrelevant to the test, it's just easy to generate
    // and check rotation.  We set the orientation to the same angle.
    // Coordinate system: down is increasing Y, right is increasing X.
    static constexpr float PI_180 = float(M_PI / 180);
    static constexpr float RADIUS = 10;
    static constexpr float ARC = 36;
    static constexpr float ROTATION = ARC * 2;

    const size_t pointerCount = 11;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    for (size_t i = 0; i < pointerCount; i++) {
        float angle = float(i * ARC * PI_180);
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerCoords[i].clear();
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, sinf(angle) * RADIUS + 3);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, -cosf(angle) * RADIUS + 2);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, angle);
    }
    MotionEvent event;
    ui::Transform identityTransform;
    event.initialize(InputEvent::nextId(), 0 /*deviceId*/, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID,
                     INVALID_HMAC, AMOTION_EVENT_ACTION_MOVE, 0 /*actionButton*/, 0 /*flags*/,
                     AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE, 0 /*buttonState*/,
                     MotionClassification::NONE, identityTransform, 0 /*xPrecision*/,
                     0 /*yPrecision*/, 3 + RADIUS /*xCursorPosition*/, 2 /*yCursorPosition*/,
                     identityTransform, 0 /*downTime*/, 0 /*eventTime*/, pointerCount,
                     pointerProperties, pointerCoords);
    float originalRawX = 0 + 3;
    float originalRawY = -RADIUS + 2;

    // Check original raw X and Y assumption.
    ASSERT_NEAR(originalRawX, event.getRawX(0), 0.001);
    ASSERT_NEAR(originalRawY, event.getRawY(0), 0.001);

    // Now translate the motion event so the circle's origin is at (0,0).
    event.offsetLocation(-3, -2);

    // Offsetting the location should preserve the raw X and Y of the first point.
    ASSERT_NEAR(originalRawX, event.getRawX(0), 0.001);
    ASSERT_NEAR(originalRawY, event.getRawY(0), 0.001);

    // Apply a rotation about the origin by ROTATION degrees clockwise.
    std::array<float, 9> matrix;
    setRotationMatrix(matrix, ROTATION * PI_180);
    event.transform(matrix);

    // Check the points.
    for (size_t i = 0; i < pointerCount; i++) {
        float angle = float((i * ARC + ROTATION) * PI_180);
        ASSERT_NEAR(sinf(angle) * RADIUS, event.getX(i), 0.001);
        ASSERT_NEAR(-cosf(angle) * RADIUS, event.getY(i), 0.001);
        ASSERT_NEAR(tanf(angle), tanf(event.getOrientation(i)), 0.1);
    }

    // Check cursor positions. The original cursor position is at (3 + RADIUS, 2), where the center
    // of the circle is (3, 2), so the cursor position is to the right of the center of the circle.
    // The choice of triangular functions in this test defines the angle of rotation clockwise
    // relative to the y-axis. Therefore the cursor position's angle is 90 degrees. Here we swap the
    // triangular function so that we don't have to add the 90 degrees.
    ASSERT_NEAR(cosf(PI_180 * ROTATION) * RADIUS, event.getXCursorPosition(), 0.001);
    ASSERT_NEAR(sinf(PI_180 * ROTATION) * RADIUS, event.getYCursorPosition(), 0.001);

    // Applying the transformation should preserve the raw X and Y of the first point.
    ASSERT_NEAR(originalRawX, event.getRawX(0), 0.001);
    ASSERT_NEAR(originalRawY, event.getRawY(0), 0.001);
}

MotionEvent createMotionEvent(int32_t source, uint32_t action, float x, float y, float dx, float dy,
                              const ui::Transform& transform, const ui::Transform& rawTransform) {
    std::vector<PointerProperties> pointerProperties;
    pointerProperties.push_back(PointerProperties{/* id */ 0, AMOTION_EVENT_TOOL_TYPE_FINGER});
    std::vector<PointerCoords> pointerCoords;
    pointerCoords.emplace_back().clear();
    pointerCoords.back().setAxisValue(AMOTION_EVENT_AXIS_X, x);
    pointerCoords.back().setAxisValue(AMOTION_EVENT_AXIS_Y, y);
    pointerCoords.back().setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, dx);
    pointerCoords.back().setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, dy);
    nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
    MotionEvent event;
    event.initialize(InputEvent::nextId(), /* deviceId */ 1, source,
                     /* displayId */ 0, INVALID_HMAC, action,
                     /* actionButton */ 0, /* flags */ 0, /* edgeFlags */ 0, AMETA_NONE,
                     /* buttonState */ 0, MotionClassification::NONE, transform,
                     /* xPrecision */ 0, /* yPrecision */ 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, rawTransform, eventTime, eventTime,
                     pointerCoords.size(), pointerProperties.data(), pointerCoords.data());
    return event;
}

MotionEvent createTouchDownEvent(float x, float y, float dx, float dy,
                                 const ui::Transform& transform,
                                 const ui::Transform& rawTransform) {
    return createMotionEvent(AINPUT_SOURCE_TOUCHSCREEN, AMOTION_EVENT_ACTION_DOWN, x, y, dx, dy,
                             transform, rawTransform);
}

TEST_F(MotionEventTest, ApplyTransform) {
    // Create a rotate-90 transform with an offset (like a window which isn't fullscreen).
    ui::Transform identity;
    ui::Transform transform(ui::Transform::ROT_90, 800, 400);
    transform.set(transform.tx() + 20, transform.ty() + 40);
    ui::Transform rawTransform(ui::Transform::ROT_90, 800, 400);
    MotionEvent event = createTouchDownEvent(60, 100, 42, 96, transform, rawTransform);
    ASSERT_EQ(700, event.getRawX(0));
    ASSERT_EQ(60, event.getRawY(0));
    ASSERT_NE(event.getRawX(0), event.getX(0));
    ASSERT_NE(event.getRawY(0), event.getY(0));
    // Relative values should be rotated but not translated.
    ASSERT_EQ(-96, event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0));
    ASSERT_EQ(42, event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0));

    MotionEvent changedEvent = createTouchDownEvent(60, 100, 42, 96, identity, identity);
    const std::array<float, 9> rowMajor{transform[0][0], transform[1][0], transform[2][0],
                                        transform[0][1], transform[1][1], transform[2][1],
                                        transform[0][2], transform[1][2], transform[2][2]};
    changedEvent.applyTransform(rowMajor);

    // transformContent effectively rotates the raw coordinates, so those should now include
    // both rotation AND offset.
    ASSERT_EQ(720, changedEvent.getRawX(0));
    ASSERT_EQ(100, changedEvent.getRawY(0));
    // Relative values should be rotated but not translated.
    ASSERT_EQ(-96, event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0));
    ASSERT_EQ(42, event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0));

    // The transformed output should be the same then.
    ASSERT_NEAR(event.getX(0), changedEvent.getX(0), 0.001);
    ASSERT_NEAR(event.getY(0), changedEvent.getY(0), 0.001);
    ASSERT_NEAR(event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0),
                changedEvent.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0), 0.001);
    ASSERT_NEAR(event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0),
                changedEvent.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0), 0.001);
}

TEST_F(MotionEventTest, JoystickAndTouchpadAreNotTransformed) {
    constexpr static std::array kNonTransformedSources =
            {std::pair(AINPUT_SOURCE_TOUCHPAD, AMOTION_EVENT_ACTION_DOWN),
             std::pair(AINPUT_SOURCE_JOYSTICK, AMOTION_EVENT_ACTION_MOVE),
             std::pair(AINPUT_SOURCE_MOUSE_RELATIVE, AMOTION_EVENT_ACTION_MOVE)};
    // Create a rotate-90 transform with an offset (like a window which isn't fullscreen).
    ui::Transform transform(ui::Transform::ROT_90, 800, 400);
    transform.set(transform.tx() + 20, transform.ty() + 40);

    for (const auto& [source, action] : kNonTransformedSources) {
        const MotionEvent event =
                createMotionEvent(source, action, 60, 100, 0, 0, transform, transform);

        // These events should not be transformed in any way.
        ASSERT_EQ(60, event.getX(0));
        ASSERT_EQ(100, event.getY(0));
        ASSERT_EQ(event.getRawX(0), event.getX(0));
        ASSERT_EQ(event.getRawY(0), event.getY(0));
    }
}

TEST_F(MotionEventTest, NonPointerSourcesAreNotTranslated) {
    constexpr static std::array kNonPointerSources = {std::pair(AINPUT_SOURCE_TRACKBALL,
                                                                AMOTION_EVENT_ACTION_DOWN),
                                                      std::pair(AINPUT_SOURCE_TOUCH_NAVIGATION,
                                                                AMOTION_EVENT_ACTION_MOVE)};
    // Create a rotate-90 transform with an offset (like a window which isn't fullscreen).
    ui::Transform transform(ui::Transform::ROT_90, 800, 400);
    transform.set(transform.tx() + 20, transform.ty() + 40);

    for (const auto& [source, action] : kNonPointerSources) {
        const MotionEvent event =
                createMotionEvent(source, action, 60, 100, 42, 96, transform, transform);

        // Since this event comes from a non-pointer source, it should include rotation but not
        // translation/offset.
        ASSERT_EQ(-100, event.getX(0));
        ASSERT_EQ(60, event.getY(0));
        ASSERT_EQ(event.getRawX(0), event.getX(0));
        ASSERT_EQ(event.getRawY(0), event.getY(0));
    }
}

TEST_F(MotionEventTest, AxesAreCorrectlyTransformed) {
    const ui::Transform identity;
    ui::Transform transform;
    transform.set({1.1, -2.2, 3.3, -4.4, 5.5, -6.6, 0, 0, 1});
    ui::Transform rawTransform;
    rawTransform.set({-6.6, 5.5, -4.4, 3.3, -2.2, 1.1, 0, 0, 1});
    auto transformWithoutTranslation = [](const ui::Transform& t, float x, float y) {
        auto newPoint = t.transform(x, y);
        auto newOrigin = t.transform(0, 0);
        return newPoint - newOrigin;
    };

    const MotionEvent event = createTouchDownEvent(60, 100, 42, 96, transform, rawTransform);

    // The x and y axes should have the window transform applied.
    const auto newPoint = transform.transform(60, 100);
    ASSERT_EQ(newPoint.x, event.getX(0));
    ASSERT_EQ(newPoint.y, event.getY(0));

    // The raw values should have the display transform applied.
    const auto raw = rawTransform.transform(60, 100);
    ASSERT_EQ(raw.x, event.getRawX(0));
    ASSERT_EQ(raw.y, event.getRawY(0));

    // Relative values should have the window transform applied without any translation.
    const auto rel = transformWithoutTranslation(transform, 42, 96);
    ASSERT_EQ(rel.x, event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, 0));
    ASSERT_EQ(rel.y, event.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, 0));
}

TEST_F(MotionEventTest, Initialize_SetsClassification) {
    std::array<MotionClassification, 3> classifications = {
            MotionClassification::NONE,
            MotionClassification::AMBIGUOUS_GESTURE,
            MotionClassification::DEEP_PRESS,
    };

    MotionEvent event;
    constexpr size_t pointerCount = 1;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerCoords[i].clear();
    }

    ui::Transform identityTransform;
    for (MotionClassification classification : classifications) {
        event.initialize(InputEvent::nextId(), 0 /*deviceId*/, AINPUT_SOURCE_TOUCHSCREEN,
                         DISPLAY_ID, INVALID_HMAC, AMOTION_EVENT_ACTION_DOWN, 0, 0,
                         AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE, 0, classification,
                         identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                         AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, 0 /*downTime*/,
                         0 /*eventTime*/, pointerCount, pointerProperties, pointerCoords);
        ASSERT_EQ(classification, event.getClassification());
    }
}

TEST_F(MotionEventTest, Initialize_SetsCursorPosition) {
    MotionEvent event;
    constexpr size_t pointerCount = 1;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerCoords[i].clear();
    }

    ui::Transform identityTransform;
    event.initialize(InputEvent::nextId(), 0 /*deviceId*/, AINPUT_SOURCE_MOUSE, DISPLAY_ID,
                     INVALID_HMAC, AMOTION_EVENT_ACTION_DOWN, 0, 0, AMOTION_EVENT_EDGE_FLAG_NONE,
                     AMETA_NONE, 0, MotionClassification::NONE, identityTransform, 0, 0,
                     280 /*xCursorPosition*/, 540 /*yCursorPosition*/, identityTransform,
                     0 /*downTime*/, 0 /*eventTime*/, pointerCount, pointerProperties,
                     pointerCoords);
    event.offsetLocation(20, 60);
    ASSERT_EQ(280, event.getRawXCursorPosition());
    ASSERT_EQ(540, event.getRawYCursorPosition());
    ASSERT_EQ(300, event.getXCursorPosition());
    ASSERT_EQ(600, event.getYCursorPosition());
}

TEST_F(MotionEventTest, SetCursorPosition) {
    MotionEvent event;
    initializeEventWithHistory(&event);
    event.setSource(AINPUT_SOURCE_MOUSE);

    event.setCursorPosition(3, 4);
    ASSERT_EQ(3, event.getXCursorPosition());
    ASSERT_EQ(4, event.getYCursorPosition());
}

} // namespace android
