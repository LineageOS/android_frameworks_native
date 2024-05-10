/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <gtest/gtest.h>
#include "../PreferStylusOverTouchBlocker.h"

namespace android {

constexpr int32_t TOUCH_DEVICE_ID = 3;
constexpr int32_t SECOND_TOUCH_DEVICE_ID = 4;
constexpr int32_t STYLUS_DEVICE_ID = 5;
constexpr int32_t SECOND_STYLUS_DEVICE_ID = 6;

constexpr int DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr int MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr int UP = AMOTION_EVENT_ACTION_UP;
constexpr int CANCEL = AMOTION_EVENT_ACTION_CANCEL;
static constexpr int32_t POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int32_t TOUCHSCREEN = AINPUT_SOURCE_TOUCHSCREEN;
constexpr int32_t STYLUS = AINPUT_SOURCE_STYLUS;

static NotifyMotionArgs generateMotionArgs(nsecs_t downTime, nsecs_t eventTime, int32_t action,
                                           const std::vector<Point>& points, uint32_t source) {
    size_t pointerCount = points.size();
    if (action == DOWN || action == UP) {
        EXPECT_EQ(1U, pointerCount) << "Actions DOWN and UP can only contain a single pointer";
    }

    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    const int32_t deviceId = isFromSource(source, TOUCHSCREEN) ? TOUCH_DEVICE_ID : STYLUS_DEVICE_ID;
    const ToolType toolType =
            isFromSource(source, TOUCHSCREEN) ? ToolType::FINGER : ToolType::STYLUS;
    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerProperties[i].toolType = toolType;

        pointerCoords[i].clear();
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, points[i].x);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, points[i].y);
    }

    // Currently, can't have STYLUS source without it also being a TOUCH source. Update the source
    // accordingly.
    if (isFromSource(source, STYLUS)) {
        source |= TOUCHSCREEN;
    }

    // Define a valid motion event.
    NotifyMotionArgs args(/*id=*/0, eventTime, /*readTime=*/0, deviceId, source,
                          ui::LogicalDisplayId::DEFAULT, POLICY_FLAG_PASS_TO_USER, action,
                          /* actionButton */ 0,
                          /*flags=*/0, AMETA_NONE, /*buttonState=*/0, MotionClassification::NONE,
                          AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount, pointerProperties,
                          pointerCoords, /*xPrecision=*/0, /*yPrecision=*/0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, downTime, /*videoFrames=*/{});

    return args;
}

class PreferStylusOverTouchTest : public testing::Test {
protected:
    void assertNotBlocked(const NotifyMotionArgs& args) { assertResponse(args, {args}); }

    void assertDropped(const NotifyMotionArgs& args) { assertResponse(args, {}); }

    void assertResponse(const NotifyMotionArgs& args,
                        const std::vector<NotifyMotionArgs>& expected) {
        std::vector<NotifyMotionArgs> receivedArgs = mBlocker.processMotion(args);
        ASSERT_EQ(expected.size(), receivedArgs.size());
        for (size_t i = 0; i < expected.size(); i++) {
            // The 'eventTime' of CANCEL events is dynamically generated. Don't check this field.
            if (expected[i].action == CANCEL && receivedArgs[i].action == CANCEL) {
                receivedArgs[i].eventTime = expected[i].eventTime;
            }

            ASSERT_EQ(expected[i], receivedArgs[i])
                    << expected[i].dump() << " vs " << receivedArgs[i].dump();
        }
    }

    void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& devices) {
        mBlocker.notifyInputDevicesChanged(devices);
    }

    void dump() const { ALOGI("Blocker: \n%s\n", mBlocker.dump().c_str()); }

private:
    PreferStylusOverTouchBlocker mBlocker;
};

TEST_F(PreferStylusOverTouchTest, TouchGestureIsNotBlocked) {
    NotifyMotionArgs args;

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/0, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/1, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/2, UP, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);
}

TEST_F(PreferStylusOverTouchTest, StylusGestureIsNotBlocked) {
    NotifyMotionArgs args;

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/0, DOWN, {{1, 2}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/1, MOVE, {{1, 3}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/2, UP, {{1, 3}}, STYLUS);
    assertNotBlocked(args);
}

/**
 * Existing touch gesture should be canceled when stylus goes down. There should be an ACTION_CANCEL
 * event generated.
 */
TEST_F(PreferStylusOverTouchTest, TouchIsCanceledWhenStylusGoesDown) {
    NotifyMotionArgs args;

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/0, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/1, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/3, /*eventTime=*/3, DOWN, {{10, 30}}, STYLUS);
    NotifyMotionArgs cancelArgs =
            generateMotionArgs(/*downTime=*/0, /*eventTime=*/1, CANCEL, {{1, 3}}, TOUCHSCREEN);
    cancelArgs.flags |= AMOTION_EVENT_FLAG_CANCELED;
    assertResponse(args, {cancelArgs, args});

    // Both stylus and touch events continue. Stylus should be not blocked, and touch should be
    // blocked
    args = generateMotionArgs(/*downTime=*/3, /*eventTime=*/4, MOVE, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/5, MOVE, {{1, 4}}, TOUCHSCREEN);
    assertDropped(args);
}

/**
 * Stylus goes down after touch gesture.
 */
TEST_F(PreferStylusOverTouchTest, StylusDownAfterTouch) {
    NotifyMotionArgs args;

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/0, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/1, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/2, UP, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    // Stylus goes down
    args = generateMotionArgs(/*downTime=*/3, /*eventTime=*/3, DOWN, {{10, 30}}, STYLUS);
    assertNotBlocked(args);
}

/**
 * New touch events should be simply blocked (dropped) when stylus is down. No CANCEL event should
 * be generated.
 */
TEST_F(PreferStylusOverTouchTest, NewTouchIsBlockedWhenStylusIsDown) {
    NotifyMotionArgs args;
    constexpr nsecs_t stylusDownTime = 0;
    constexpr nsecs_t touchDownTime = 1;

    args = generateMotionArgs(stylusDownTime, /*eventTime=*/0, DOWN, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(touchDownTime, /*eventTime=*/1, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertDropped(args);

    // Stylus should continue to work
    args = generateMotionArgs(stylusDownTime, /*eventTime=*/2, MOVE, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    // Touch should continue to be blocked
    args = generateMotionArgs(touchDownTime, /*eventTime=*/1, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertDropped(args);

    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/5, MOVE, {{1, 4}}, TOUCHSCREEN);
    assertDropped(args);
}

/**
 * New touch events should be simply blocked (dropped) when stylus is down. No CANCEL event should
 * be generated.
 */
TEST_F(PreferStylusOverTouchTest, NewTouchWorksAfterStylusIsLifted) {
    NotifyMotionArgs args;
    constexpr nsecs_t stylusDownTime = 0;
    constexpr nsecs_t touchDownTime = 4;

    // Stylus goes down and up
    args = generateMotionArgs(stylusDownTime, /*eventTime=*/0, DOWN, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(stylusDownTime, /*eventTime=*/2, MOVE, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(stylusDownTime, /*eventTime=*/3, UP, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    // New touch goes down. It should not be blocked
    args = generateMotionArgs(touchDownTime, touchDownTime, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(touchDownTime, /*eventTime=*/5, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(touchDownTime, /*eventTime=*/6, UP, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);
}

/**
 * Once a touch gesture is canceled, it should continue to be canceled, even if the stylus has been
 * lifted.
 */
TEST_F(PreferStylusOverTouchTest, AfterStylusIsLiftedCurrentTouchIsBlocked) {
    NotifyMotionArgs args;
    constexpr nsecs_t stylusDownTime = 0;
    constexpr nsecs_t touchDownTime = 1;

    assertNotBlocked(generateMotionArgs(stylusDownTime, /*eventTime=*/0, DOWN, {{10, 30}}, STYLUS));

    args = generateMotionArgs(touchDownTime, /*eventTime=*/1, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertDropped(args);

    // Lift the stylus
    args = generateMotionArgs(stylusDownTime, /*eventTime=*/2, UP, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    // Touch should continue to be blocked
    args = generateMotionArgs(touchDownTime, /*eventTime=*/3, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertDropped(args);

    args = generateMotionArgs(touchDownTime, /*eventTime=*/4, UP, {{1, 3}}, TOUCHSCREEN);
    assertDropped(args);

    // New touch should go through, though.
    constexpr nsecs_t newTouchDownTime = 5;
    args = generateMotionArgs(newTouchDownTime, /*eventTime=*/5, DOWN, {{10, 20}}, TOUCHSCREEN);
    assertNotBlocked(args);
}

/**
 * If an event with mixed stylus and touch pointers is encountered, it should be ignored. Touches
 * from such should pass, even if stylus from the same device goes down.
 */
TEST_F(PreferStylusOverTouchTest, MixedStylusAndTouchPointersAreIgnored) {
    NotifyMotionArgs args;

    // Event from a stylus device, but with finger tool type
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/1, DOWN, {{1, 2}}, STYLUS);
    // Keep source stylus, but make the tool type touch
    args.pointerProperties[0].toolType = ToolType::FINGER;
    assertNotBlocked(args);

    // Second pointer (stylus pointer) goes down, from the same device
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/2, POINTER_1_DOWN, {{1, 2}, {10, 20}},
                              STYLUS);
    // Keep source stylus, but make the tool type touch
    args.pointerProperties[0].toolType = ToolType::STYLUS;
    assertNotBlocked(args);

    // Second pointer (stylus pointer) goes down, from the same device
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/3, MOVE, {{2, 3}, {11, 21}}, STYLUS);
    // Keep source stylus, but make the tool type touch
    args.pointerProperties[0].toolType = ToolType::FINGER;
    assertNotBlocked(args);
}

/**
 * When there are two touch devices, stylus down should cancel all current touch streams.
 */
TEST_F(PreferStylusOverTouchTest, TouchFromTwoDevicesAndStylus) {
    NotifyMotionArgs touch1Down =
            generateMotionArgs(/*downTime=*/1, /*eventTime=*/1, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(touch1Down);

    NotifyMotionArgs touch2Down =
            generateMotionArgs(/*downTime=*/2, /*eventTime=*/2, DOWN, {{3, 4}}, TOUCHSCREEN);
    touch2Down.deviceId = SECOND_TOUCH_DEVICE_ID;
    assertNotBlocked(touch2Down);

    NotifyMotionArgs stylusDown =
            generateMotionArgs(/*downTime=*/3, /*eventTime=*/3, DOWN, {{10, 30}}, STYLUS);
    NotifyMotionArgs cancelArgs1 = touch1Down;
    cancelArgs1.action = CANCEL;
    cancelArgs1.flags |= AMOTION_EVENT_FLAG_CANCELED;
    NotifyMotionArgs cancelArgs2 = touch2Down;
    cancelArgs2.action = CANCEL;
    cancelArgs2.flags |= AMOTION_EVENT_FLAG_CANCELED;
    assertResponse(stylusDown, {cancelArgs1, cancelArgs2, stylusDown});
}

/**
 * Touch should be canceled when stylus goes down. After the stylus lifts up, the touch from that
 * device should continue to be canceled.
 * If one of the devices is already canceled, it should remain canceled, but new touches from a
 * different device should go through.
 */
TEST_F(PreferStylusOverTouchTest, AllTouchMustLiftAfterCanceledByStylus) {
    // First device touches down
    NotifyMotionArgs touch1Down =
            generateMotionArgs(/*downTime=*/1, /*eventTime=*/1, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(touch1Down);

    // Stylus goes down - touch should be canceled
    NotifyMotionArgs stylusDown =
            generateMotionArgs(/*downTime=*/2, /*eventTime=*/2, DOWN, {{10, 30}}, STYLUS);
    NotifyMotionArgs cancelArgs1 = touch1Down;
    cancelArgs1.action = CANCEL;
    cancelArgs1.flags |= AMOTION_EVENT_FLAG_CANCELED;
    assertResponse(stylusDown, {cancelArgs1, stylusDown});

    // Stylus goes up
    NotifyMotionArgs stylusUp =
            generateMotionArgs(/*downTime=*/2, /*eventTime=*/3, UP, {{10, 30}}, STYLUS);
    assertNotBlocked(stylusUp);

    // Touch from the first device remains blocked
    NotifyMotionArgs touch1Move =
            generateMotionArgs(/*downTime=*/1, /*eventTime=*/4, MOVE, {{2, 3}}, TOUCHSCREEN);
    assertDropped(touch1Move);

    // Second touch goes down. It should not be blocked because stylus has already lifted.
    NotifyMotionArgs touch2Down =
            generateMotionArgs(/*downTime=*/5, /*eventTime=*/5, DOWN, {{31, 32}}, TOUCHSCREEN);
    touch2Down.deviceId = SECOND_TOUCH_DEVICE_ID;
    assertNotBlocked(touch2Down);

    // First device is lifted up. It's already been canceled, so the UP event should be dropped.
    NotifyMotionArgs touch1Up =
            generateMotionArgs(/*downTime=*/1, /*eventTime=*/6, UP, {{2, 3}}, TOUCHSCREEN);
    assertDropped(touch1Up);

    // Touch from second device touch should continue to work
    NotifyMotionArgs touch2Move =
            generateMotionArgs(/*downTime=*/5, /*eventTime=*/7, MOVE, {{32, 33}}, TOUCHSCREEN);
    touch2Move.deviceId = SECOND_TOUCH_DEVICE_ID;
    assertNotBlocked(touch2Move);

    // Second touch lifts up
    NotifyMotionArgs touch2Up =
            generateMotionArgs(/*downTime=*/5, /*eventTime=*/8, UP, {{32, 33}}, TOUCHSCREEN);
    touch2Up.deviceId = SECOND_TOUCH_DEVICE_ID;
    assertNotBlocked(touch2Up);

    // Now that all touch has been lifted, new touch from either first or second device should work
    NotifyMotionArgs touch3Down =
            generateMotionArgs(/*downTime=*/9, /*eventTime=*/9, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(touch3Down);

    NotifyMotionArgs touch4Down =
            generateMotionArgs(/*downTime=*/10, /*eventTime=*/10, DOWN, {{100, 200}}, TOUCHSCREEN);
    touch4Down.deviceId = SECOND_TOUCH_DEVICE_ID;
    assertNotBlocked(touch4Down);
}

/**
 * When we don't know that a specific device does both stylus and touch, and we only see touch
 * pointers from it, we should treat it as a touch device. That means, the device events should be
 * canceled when stylus from another device goes down. When we detect simultaneous touch and stylus
 * from this device though, we should just pass this device through without canceling anything.
 *
 * In this test:
 * 1. Start by touching down with device 1
 * 2. Device 2 has stylus going down
 * 3. Device 1 should be canceled.
 * 4. When we add stylus pointers to the device 1, they should continue to be canceled.
 * 5. Device 1 lifts up.
 * 6. Subsequent events from device 1 should not be canceled even if stylus is down.
 * 7. If a reset happens, and such device is no longer there, then we should
 * Therefore, the device 1 is "ignored" and does not participate into "prefer stylus over touch"
 * behaviour.
 */
TEST_F(PreferStylusOverTouchTest, MixedStylusAndTouchDeviceIsCanceledAtFirst) {
    // Touch from device 1 goes down
    NotifyMotionArgs touchDown =
            generateMotionArgs(/*downTime=*/1, /*eventTime=*/1, DOWN, {{1, 2}}, TOUCHSCREEN);
    touchDown.source = STYLUS;
    assertNotBlocked(touchDown);

    // Stylus from device 2 goes down. Touch should be canceled.
    NotifyMotionArgs args =
            generateMotionArgs(/*downTime=*/2, /*eventTime=*/2, DOWN, {{10, 20}}, STYLUS);
    NotifyMotionArgs cancelTouchArgs = touchDown;
    cancelTouchArgs.action = CANCEL;
    cancelTouchArgs.flags |= AMOTION_EVENT_FLAG_CANCELED;
    assertResponse(args, {cancelTouchArgs, args});

    // Introduce a stylus pointer into the device 1 stream. It should be ignored.
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/3, POINTER_1_DOWN, {{1, 2}, {3, 4}},
                              TOUCHSCREEN);
    args.pointerProperties[1].toolType = ToolType::STYLUS;
    args.source = STYLUS;
    assertDropped(args);

    // Lift up touch from the mixed touch/stylus device
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/4, CANCEL, {{1, 2}, {3, 4}},
                              TOUCHSCREEN);
    args.pointerProperties[1].toolType = ToolType::STYLUS;
    args.source = STYLUS;
    assertDropped(args);

    // Stylus from device 2 is still down. Since the device 1 is now identified as a mixed
    // touch/stylus device, its events should go through, even if they are touch.
    args = generateMotionArgs(/*downTime=*/5, /*eventTime=*/5, DOWN, {{21, 22}}, TOUCHSCREEN);
    touchDown.source = STYLUS;
    assertResponse(args, {args});

    // Reconfigure such that only the stylus device remains
    InputDeviceInfo stylusDevice;
    stylusDevice.initialize(STYLUS_DEVICE_ID, /*generation=*/1, /*controllerNumber=*/1,
                            /*identifier=*/{}, "stylus device", /*external=*/false,
                            /*hasMic=*/false, ui::LogicalDisplayId::INVALID);
    notifyInputDevicesChanged({stylusDevice});
    // The touchscreen device was removed, so we no longer remember anything about it. We should
    // again start blocking touch events from it.
    args = generateMotionArgs(/*downTime=*/6, /*eventTime=*/6, DOWN, {{1, 2}}, TOUCHSCREEN);
    args.source = STYLUS;
    assertDropped(args);
}

/**
 * If two styli are active at the same time, touch should be blocked until both of them are lifted.
 * If one of them lifts, touch should continue to be blocked.
 */
TEST_F(PreferStylusOverTouchTest, TouchIsBlockedWhenTwoStyliAreUsed) {
    NotifyMotionArgs args;

    // First stylus is down
    assertNotBlocked(generateMotionArgs(/*downTime=*/0, /*eventTime=*/0, DOWN, {{10, 30}}, STYLUS));

    // Second stylus is down
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/1, DOWN, {{20, 40}}, STYLUS);
    args.deviceId = SECOND_STYLUS_DEVICE_ID;
    assertNotBlocked(args);

    // Touch goes down. It should be ignored.
    args = generateMotionArgs(/*downTime=*/2, /*eventTime=*/2, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertDropped(args);

    // Lift the first stylus
    args = generateMotionArgs(/*downTime=*/0, /*eventTime=*/3, UP, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    // Touch should continue to be blocked
    args = generateMotionArgs(/*downTime=*/2, /*eventTime=*/4, UP, {{1, 2}}, TOUCHSCREEN);
    assertDropped(args);

    // New touch should be blocked because second stylus is still down
    args = generateMotionArgs(/*downTime=*/5, /*eventTime=*/5, DOWN, {{5, 6}}, TOUCHSCREEN);
    assertDropped(args);

    // Second stylus goes up
    args = generateMotionArgs(/*downTime=*/1, /*eventTime=*/6, UP, {{20, 40}}, STYLUS);
    args.deviceId = SECOND_STYLUS_DEVICE_ID;
    assertNotBlocked(args);

    // Current touch gesture should continue to be blocked
    // Touch should continue to be blocked
    args = generateMotionArgs(/*downTime=*/5, /*eventTime=*/7, UP, {{5, 6}}, TOUCHSCREEN);
    assertDropped(args);

    // Now that all styli were lifted, new touch should go through
    args = generateMotionArgs(/*downTime=*/8, /*eventTime=*/8, DOWN, {{7, 8}}, TOUCHSCREEN);
    assertNotBlocked(args);
}

} // namespace android
