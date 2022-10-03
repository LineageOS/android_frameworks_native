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

#include "../UnwantedInteractionBlocker.h"
#include <android-base/silent_death_test.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/constants.h>
#include <linux/input.h>
#include <thread>
#include "ui/events/ozone/evdev/touch_filter/neural_stylus_palm_detection_filter.h"

#include "TestInputListener.h"

using ::testing::AllOf;

namespace android {

constexpr int32_t DEVICE_ID = 3;
constexpr int32_t X_RESOLUTION = 11;
constexpr int32_t Y_RESOLUTION = 11;
constexpr int32_t MAJOR_RESOLUTION = 1;

const nsecs_t RESAMPLE_PERIOD = ::ui::kResamplePeriod.InNanoseconds();

constexpr int POINTER_0_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int POINTER_2_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int POINTER_0_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int POINTER_1_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int POINTER_2_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
constexpr int DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr int MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr int UP = AMOTION_EVENT_ACTION_UP;
constexpr int CANCEL = AMOTION_EVENT_ACTION_CANCEL;

constexpr int32_t FLAG_CANCELED = AMOTION_EVENT_FLAG_CANCELED;

MATCHER_P(WithAction, action, "MotionEvent with specified action") {
    bool result = true;
    if (action == CANCEL) {
        result &= (arg.flags & FLAG_CANCELED) != 0;
    }
    result &= arg.action == action;
    *result_listener << "expected to receive " << MotionEvent::actionToString(action)
                     << " but received " << MotionEvent::actionToString(arg.action) << " instead.";
    return result;
}

MATCHER_P(WithFlags, flags, "MotionEvent with specified flags") {
    return arg.flags == flags;
}

static nsecs_t toNs(std::chrono::nanoseconds duration) {
    return duration.count();
}

struct PointerData {
    float x;
    float y;
    float major;
};

static NotifyMotionArgs generateMotionArgs(nsecs_t downTime, nsecs_t eventTime, int32_t action,
                                           const std::vector<PointerData>& points) {
    size_t pointerCount = points.size();
    if (action == AMOTION_EVENT_ACTION_DOWN || action == AMOTION_EVENT_ACTION_UP) {
        EXPECT_EQ(1U, pointerCount) << "Actions DOWN and UP can only contain a single pointer";
    }

    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerProperties[i].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

        pointerCoords[i].clear();
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, points[i].x);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, points[i].y);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, points[i].major);
    }

    // Define a valid motion event.
    NotifyMotionArgs args(/* id */ 0, eventTime, 0 /*readTime*/, DEVICE_ID,
                          AINPUT_SOURCE_TOUCHSCREEN, 0 /*displayId*/, POLICY_FLAG_PASS_TO_USER,
                          action, /* actionButton */ 0,
                          /* flags */ 0, AMETA_NONE, /* buttonState */ 0,
                          MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount,
                          pointerProperties, pointerCoords, /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, downTime, /* videoFrames */ {});

    return args;
}

static InputDeviceInfo generateTestDeviceInfo() {
    InputDeviceIdentifier identifier;

    auto info = InputDeviceInfo();
    info.initialize(DEVICE_ID, /*generation*/ 1, /*controllerNumber*/ 1, identifier, "alias",
                    /*isExternal*/ false, /*hasMic*/ false);
    info.addSource(AINPUT_SOURCE_TOUCHSCREEN);
    info.addMotionRange(AMOTION_EVENT_AXIS_X, AINPUT_SOURCE_TOUCHSCREEN, 0, 1599, /*flat*/ 0,
                        /*fuzz*/ 0, X_RESOLUTION);
    info.addMotionRange(AMOTION_EVENT_AXIS_Y, AINPUT_SOURCE_TOUCHSCREEN, 0, 2559, /*flat*/ 0,
                        /*fuzz*/ 0, Y_RESOLUTION);
    info.addMotionRange(AMOTION_EVENT_AXIS_TOUCH_MAJOR, AINPUT_SOURCE_TOUCHSCREEN, 0, 255,
                        /*flat*/ 0, /*fuzz*/ 0, MAJOR_RESOLUTION);

    return info;
}

static AndroidPalmFilterDeviceInfo generatePalmFilterDeviceInfo() {
    InputDeviceInfo androidInfo = generateTestDeviceInfo();
    std::optional<AndroidPalmFilterDeviceInfo> info = createPalmFilterDeviceInfo(androidInfo);
    if (!info) {
        ADD_FAILURE() << "Could not convert android device info to ::ui version";
        return {};
    }
    return *info;
}

TEST(DeviceInfoConversionTest, TabletDeviceTest) {
    AndroidPalmFilterDeviceInfo info = generatePalmFilterDeviceInfo();
    ASSERT_EQ(X_RESOLUTION, info.x_res);
    ASSERT_EQ(Y_RESOLUTION, info.y_res);
    ASSERT_EQ(MAJOR_RESOLUTION, info.touch_major_res);
    ASSERT_EQ(1599, info.max_x);
    ASSERT_EQ(2559, info.max_y);
}

static void assertArgs(const NotifyMotionArgs& args, int32_t action,
                       const std::vector<std::pair<int32_t /*pointerId*/, PointerData>>& pointers) {
    ASSERT_EQ(action, args.action);
    ASSERT_EQ(pointers.size(), args.pointerCount);
    for (size_t i = 0; i < args.pointerCount; i++) {
        const auto& [pointerId, pointerData] = pointers[i];
        ASSERT_EQ(pointerId, args.pointerProperties[i].id);
        ASSERT_EQ(pointerData.x, args.pointerCoords[i].getX());
        ASSERT_EQ(pointerData.y, args.pointerCoords[i].getY());
        ASSERT_EQ(pointerData.major,
                  args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR));
    }
}

TEST(RemovePointerIdsTest, RemoveOnePointer) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0,
                                               AMOTION_EVENT_ACTION_MOVE, {{1, 2, 3}, {4, 5, 6}});

    NotifyMotionArgs pointer1Only = removePointerIds(args, {0});
    assertArgs(pointer1Only, AMOTION_EVENT_ACTION_MOVE, {{1, {4, 5, 6}}});

    NotifyMotionArgs pointer0Only = removePointerIds(args, {1});
    assertArgs(pointer0Only, AMOTION_EVENT_ACTION_MOVE, {{0, {1, 2, 3}}});
}

/**
 * Remove 2 out of 3 pointers during a MOVE event.
 */
TEST(RemovePointerIdsTest, RemoveTwoPointers) {
    NotifyMotionArgs args =
            generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, AMOTION_EVENT_ACTION_MOVE,
                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});

    NotifyMotionArgs pointer1Only = removePointerIds(args, {0, 2});
    assertArgs(pointer1Only, AMOTION_EVENT_ACTION_MOVE, {{1, {4, 5, 6}}});
}

/**
 * Remove an active pointer during a POINTER_DOWN event, and also remove a non-active
 * pointer during a POINTER_DOWN event.
 */
TEST(RemovePointerIdsTest, ActionPointerDown) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_1_DOWN,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});

    NotifyMotionArgs pointers0And2 = removePointerIds(args, {1});
    assertArgs(pointers0And2, ACTION_UNKNOWN, {{0, {1, 2, 3}}, {2, {7, 8, 9}}});

    NotifyMotionArgs pointers1And2 = removePointerIds(args, {0});
    assertArgs(pointers1And2, POINTER_0_DOWN, {{1, {4, 5, 6}}, {2, {7, 8, 9}}});
}

/**
 * Remove all pointers during a MOVE event.
 */
TEST(RemovePointerIdsTest, RemoveAllPointersDuringMove) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0,
                                               AMOTION_EVENT_ACTION_MOVE, {{1, 2, 3}, {4, 5, 6}});

    NotifyMotionArgs noPointers = removePointerIds(args, {0, 1});
    ASSERT_EQ(0u, noPointers.pointerCount);
}

/**
 * If we have ACTION_POINTER_DOWN, and we remove all pointers except for the active pointer,
 * then we should just have ACTION_DOWN. Likewise, a POINTER_UP event should become an UP event.
 */
TEST(RemovePointerIdsTest, PointerDownBecomesDown) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_1_DOWN,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});

    NotifyMotionArgs pointer1 = removePointerIds(args, {0, 2});
    assertArgs(pointer1, DOWN, {{1, {4, 5, 6}}});

    args.action = POINTER_1_UP;
    pointer1 = removePointerIds(args, {0, 2});
    assertArgs(pointer1, UP, {{1, {4, 5, 6}}});
}

/**
 * If a pointer that is now going down is canceled, then we can just drop the POINTER_DOWN event.
 */
TEST(CancelSuppressedPointersTest, CanceledPointerDownIsDropped) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_1_DOWN,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {},
                                     /*newSuppressedPointerIds*/ {1});
    ASSERT_TRUE(result.empty());
}

/**
 * If a pointer is already suppressed, the POINTER_UP event for this pointer should be dropped
 */
TEST(CancelSuppressedPointersTest, SuppressedPointerUpIsDropped) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_1_UP,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {1},
                                     /*newSuppressedPointerIds*/ {1});
    ASSERT_TRUE(result.empty());
}

/**
 * If a pointer is already suppressed, it should be removed from a MOVE event.
 */
TEST(CancelSuppressedPointersTest, SuppressedPointerIsRemovedDuringMove) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, MOVE,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {1},
                                     /*newSuppressedPointerIds*/ {1});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], MOVE, {{0, {1, 2, 3}}, {2, {7, 8, 9}}});
}

/**
 * If a pointer just got canceled during a MOVE event, we should see two events:
 * 1) ACTION_POINTER_UP with FLAG_CANCELED so that this pointer is lifted
 * 2) A MOVE event without this pointer
 */
TEST(CancelSuppressedPointersTest, NewlySuppressedPointerIsCanceled) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, MOVE,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {},
                                     /*newSuppressedPointerIds*/ {1});
    ASSERT_EQ(2u, result.size());
    assertArgs(result[0], POINTER_1_UP, {{0, {1, 2, 3}}, {1, {4, 5, 6}}, {2, {7, 8, 9}}});
    ASSERT_EQ(FLAG_CANCELED, result[0].flags);
    assertArgs(result[1], MOVE, {{0, {1, 2, 3}}, {2, {7, 8, 9}}});
}

/**
 * If we have a single pointer that gets canceled during a MOVE, the entire gesture
 * should be canceled with ACTION_CANCEL.
 */
TEST(CancelSuppressedPointersTest, SingleSuppressedPointerIsCanceled) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, MOVE, {{1, 2, 3}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {},
                                     /*newSuppressedPointerIds*/ {0});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], CANCEL, {{0, {1, 2, 3}}});
    ASSERT_EQ(FLAG_CANCELED, result[0].flags);
}

/**
 * If one of 3 pointers gets canceled during a POINTER_UP event, we should proceed with POINTER_UP,
 * but this event should also have FLAG_CANCELED to indicate that this pointer was unintentional.
 */
TEST(CancelSuppressedPointersTest, SuppressedPointer1GoingUpIsCanceled) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_1_UP,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {},
                                     /*newSuppressedPointerIds*/ {1});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], POINTER_1_UP, {{0, {1, 2, 3}}, {1, {4, 5, 6}}, {2, {7, 8, 9}}});
    ASSERT_EQ(FLAG_CANCELED, result[0].flags);
}

/**
 * Same test as above, but we change the pointer's index to 0 instead of 1. This helps detect
 * errors with handling pointer index inside the action.
 */
TEST(CancelSuppressedPointersTest, SuppressedPointer0GoingUpIsCanceled) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_0_UP,
                                               {{1, 2, 3}, {4, 5, 6}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {},
                                     /*newSuppressedPointerIds*/ {0});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], POINTER_0_UP, {{0, {1, 2, 3}}, {1, {4, 5, 6}}});
    ASSERT_EQ(FLAG_CANCELED, result[0].flags);
}

/**
 * If two pointers are canceled simultaneously during MOVE, we should see a single ACTION_CANCEL
 * event. This event would cancel the entire gesture.
 */
TEST(CancelSuppressedPointersTest, TwoNewlySuppressedPointersAreBothCanceled) {
    NotifyMotionArgs args =
            generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, MOVE, {{1, 2, 3}, {4, 5, 6}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {},
                                     /*newSuppressedPointerIds*/ {0, 1});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], CANCEL, {{0, {1, 2, 3}}, {1, {4, 5, 6}}});
    ASSERT_EQ(FLAG_CANCELED, result[0].flags);
}

/**
 * Similar test to above. During a POINTER_UP event, both pointers are detected as 'palm' and
 * therefore should be removed. In this case, we should send a single ACTION_CANCEL that
 * would undo the entire gesture.
 */
TEST(CancelSuppressedPointersTest, TwoPointersAreCanceledDuringPointerUp) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_1_UP,
                                               {{1, 2, 3}, {4, 5, 6}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {1},
                                     /*newSuppressedPointerIds*/ {0, 1});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], CANCEL, {{0, {1, 2, 3}}});
    ASSERT_EQ(FLAG_CANCELED, result[0].flags);
}

/**
 * When all pointers have been removed from the touch stream, and we have a new POINTER_DOWN,
 * this should become a regular DOWN event because it's the only pointer that will be valid now.
 */
TEST(CancelSuppressedPointersTest, NewPointerDownBecomesDown) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, POINTER_2_DOWN,
                                               {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}});
    std::vector<NotifyMotionArgs> result =
            cancelSuppressedPointers(args, /*oldSuppressedPointerIds*/ {0, 1},
                                     /*newSuppressedPointerIds*/ {0, 1});
    ASSERT_EQ(1u, result.size());
    assertArgs(result[0], DOWN, {{2, {7, 8, 9}}});
    ASSERT_EQ(0, result[0].flags);
}

/**
 * Call 'getTouches' for a DOWN event and check that the resulting 'InProgressTouchEvdev'
 * struct is populated as expected.
 */
TEST(GetTouchesTest, ConvertDownEvent) {
    NotifyMotionArgs args = generateMotionArgs(/*downTime*/ 0, /*eventTime*/ 0, DOWN, {{1, 2, 3}});
    AndroidPalmFilterDeviceInfo deviceInfo = generatePalmFilterDeviceInfo();
    SlotState slotState;
    SlotState oldSlotState = slotState;
    slotState.update(args);
    std::vector<::ui::InProgressTouchEvdev> touches =
            getTouches(args, deviceInfo, oldSlotState, slotState);
    ASSERT_EQ(1u, touches.size());
    ::ui::InProgressTouchEvdev expected;

    expected.major = 3;
    expected.minor = 0;
    expected.tool_type = MT_TOOL_FINGER;
    expected.altered = true;
    expected.was_cancelled = false;
    expected.cancelled = false;
    expected.delayed = false;
    expected.was_delayed = false;
    expected.held = false;
    expected.was_held = false;
    expected.was_touching = false;
    expected.touching = true;
    expected.x = 1;
    expected.y = 2;
    expected.tracking_id = 0;
    std::optional<size_t> slot = slotState.getSlotForPointerId(0);
    ASSERT_TRUE(slot);
    expected.slot = *slot;
    expected.pressure = 0;
    expected.tool_code = BTN_TOOL_FINGER;
    expected.reported_tool_type = ::ui::EventPointerType::kTouch;
    expected.stylus_button = false;

    ASSERT_EQ(expected, touches[0]) << touches[0];
}

// --- UnwantedInteractionBlockerTest ---

class UnwantedInteractionBlockerTest : public testing::Test {
protected:
    TestInputListener mTestListener;
    std::unique_ptr<UnwantedInteractionBlockerInterface> mBlocker;

    void SetUp() override {
        mBlocker = std::make_unique<UnwantedInteractionBlocker>(mTestListener,
                                                                /*enablePalmRejection*/ true);
    }
};

/**
 * Create a basic configuration change and send it to input classifier.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(UnwantedInteractionBlockerTest, ConfigurationChangedIsPassedToNextListener) {
    // Create a basic configuration change and send to classifier
    NotifyConfigurationChangedArgs args(1 /*sequenceNum*/, 2 /*eventTime*/);

    mBlocker->notifyConfigurationChanged(&args);
    NotifyConfigurationChangedArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyConfigurationChangedWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

/**
 * Keys are not handled in 'UnwantedInteractionBlocker' and should be passed
 * to next stage unmodified.
 */
TEST_F(UnwantedInteractionBlockerTest, KeyIsPassedToNextListener) {
    // Create a basic key event and send to classifier
    NotifyKeyArgs args(1 /*sequenceNum*/, 2 /*eventTime*/, 21 /*readTime*/, 3 /*deviceId*/,
                       AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_DEFAULT, 0 /*policyFlags*/,
                       AKEY_EVENT_ACTION_DOWN, 4 /*flags*/, AKEYCODE_HOME, 5 /*scanCode*/,
                       AMETA_NONE, 6 /*downTime*/);

    mBlocker->notifyKey(&args);
    NotifyKeyArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyKeyWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

/**
 * Create a basic motion event. Since it's just a DOWN event, it should not
 * be detected as palm and should be sent to the next listener stage
 * unmodified.
 */
TEST_F(UnwantedInteractionBlockerTest, DownEventIsPassedToNextListener) {
    NotifyMotionArgs motionArgs =
            generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2, 3}});
    mBlocker->notifyMotion(&motionArgs);
    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(motionArgs, args);
}

/**
 * Create a basic switch event and send it to the UnwantedInteractionBlocker.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(UnwantedInteractionBlockerTest, SwitchIsPassedToNextListener) {
    NotifySwitchArgs args(1 /*sequenceNum*/, 2 /*eventTime*/, 3 /*policyFlags*/, 4 /*switchValues*/,
                          5 /*switchMask*/);

    mBlocker->notifySwitch(&args);
    NotifySwitchArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifySwitchWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

/**
 * Create a basic device reset event and send it to UnwantedInteractionBlocker.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(UnwantedInteractionBlockerTest, DeviceResetIsPassedToNextListener) {
    NotifyDeviceResetArgs args(1 /*sequenceNum*/, 2 /*eventTime*/, DEVICE_ID);

    mBlocker->notifyDeviceReset(&args);
    NotifyDeviceResetArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyDeviceResetWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

/**
 * The state should be reset when device reset happens. That means, we can reset in the middle of a
 * gesture, and start a new stream. There should be no crash. If the state wasn't reset correctly,
 * a crash due to inconsistent event stream could have occurred.
 */
TEST_F(UnwantedInteractionBlockerTest, NoCrashWhenResetHappens) {
    NotifyMotionArgs args;
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, DOWN, {{1, 2, 3}})));
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, MOVE, {{4, 5, 6}})));
    NotifyDeviceResetArgs resetArgs(1 /*sequenceNum*/, 3 /*eventTime*/, DEVICE_ID);
    mBlocker->notifyDeviceReset(&resetArgs);
    // Start a new gesture with a DOWN event, even though the previous event stream was incomplete.
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 4 /*eventTime*/, DOWN, {{7, 8, 9}})));
}

TEST_F(UnwantedInteractionBlockerTest, NoCrashWhenStylusSourceWithFingerToolIsReceived) {
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    NotifyMotionArgs args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, DOWN, {{1, 2, 3}});
    args.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
    args.source = AINPUT_SOURCE_STYLUS;
    mBlocker->notifyMotion(&args);
}

/**
 * If input devices have changed, but the important device info that's used by the
 * UnwantedInteractionBlocker has not changed, there should not be a reset.
 */
TEST_F(UnwantedInteractionBlockerTest, NoResetIfDeviceInfoChanges) {
    NotifyMotionArgs args;
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, DOWN, {{1, 2, 3}})));
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, MOVE, {{4, 5, 6}})));

    // Now pretend the device changed, even though nothing is different for DEVICE_ID in practice.
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});

    // The MOVE event continues the gesture that started before 'devices changed', so it should not
    // cause a crash.
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 4 /*eventTime*/, MOVE, {{7, 8, 9}})));
}

/**
 * Send a touch event, and then a stylus event. Make sure that both work.
 */
TEST_F(UnwantedInteractionBlockerTest, StylusAfterTouchWorks) {
    NotifyMotionArgs args;
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    args = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2, 3}});
    mBlocker->notifyMotion(&args);
    args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, MOVE, {{4, 5, 6}});
    mBlocker->notifyMotion(&args);
    args = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, UP, {{4, 5, 6}});
    mBlocker->notifyMotion(&args);

    // Now touch down stylus
    args = generateMotionArgs(3 /*downTime*/, 3 /*eventTime*/, DOWN, {{10, 20, 30}});
    args.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    args.source |= AINPUT_SOURCE_STYLUS;
    mBlocker->notifyMotion(&args);
    args = generateMotionArgs(3 /*downTime*/, 4 /*eventTime*/, MOVE, {{40, 50, 60}});
    args.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    args.source |= AINPUT_SOURCE_STYLUS;
    mBlocker->notifyMotion(&args);
    args = generateMotionArgs(3 /*downTime*/, 5 /*eventTime*/, UP, {{40, 50, 60}});
    args.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    args.source |= AINPUT_SOURCE_STYLUS;
    mBlocker->notifyMotion(&args);
}

/**
 * Call dump, and on another thread, try to send some motions. The blocker should
 * not crash. On 2022 hardware, this test requires ~ 13K executions (about 20 seconds) to reproduce
 * the original bug. This is meant to be run with "--gtest_repeat=100000 --gtest_break_on_failure"
 * options
 */
TEST_F(UnwantedInteractionBlockerTest, DumpCanBeAccessedOnAnotherThread) {
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    NotifyMotionArgs args1 = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2, 3}});
    mBlocker->notifyMotion(&args1);
    std::thread dumpThread([this]() {
        std::string dump;
        mBlocker->dump(dump);
    });
    NotifyMotionArgs args2 = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, MOVE, {{4, 5, 6}});
    mBlocker->notifyMotion(&args2);
    NotifyMotionArgs args3 = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, UP, {{4, 5, 6}});
    mBlocker->notifyMotion(&args3);
    dumpThread.join();
}

/**
 * Heuristic filter that's present in the palm rejection model blocks touches early if the size
 * of the touch is large. This is an integration test that checks that this filter kicks in.
 */
TEST_F(UnwantedInteractionBlockerTest, HeuristicFilterWorks) {
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    // Small touch down
    NotifyMotionArgs args1 = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2, 3}});
    mBlocker->notifyMotion(&args1);
    mTestListener.assertNotifyMotionWasCalled(WithAction(DOWN));

    // Large touch oval on the next move
    NotifyMotionArgs args2 =
            generateMotionArgs(0 /*downTime*/, RESAMPLE_PERIOD, MOVE, {{4, 5, 200}});
    mBlocker->notifyMotion(&args2);
    mTestListener.assertNotifyMotionWasCalled(WithAction(MOVE));

    // Lift up the touch to force the model to decide on whether it's a palm
    NotifyMotionArgs args3 =
            generateMotionArgs(0 /*downTime*/, 2 * RESAMPLE_PERIOD, UP, {{4, 5, 200}});
    mBlocker->notifyMotion(&args3);
    mTestListener.assertNotifyMotionWasCalled(WithAction(CANCEL));
}

/**
 * Send a stylus event that would have triggered the heuristic palm detector if it were a touch
 * event. However, since it's a stylus event, it should propagate without being canceled through
 * the blocker.
 * This is similar to `HeuristicFilterWorks` test, but for stylus tool.
 */
TEST_F(UnwantedInteractionBlockerTest, StylusIsNotBlocked) {
    InputDeviceInfo info = generateTestDeviceInfo();
    info.addSource(AINPUT_SOURCE_STYLUS);
    mBlocker->notifyInputDevicesChanged({info});
    NotifyMotionArgs args1 = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2, 3}});
    args1.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args1);
    mTestListener.assertNotifyMotionWasCalled(WithAction(DOWN));

    // Move the stylus, setting large TOUCH_MAJOR/TOUCH_MINOR dimensions
    NotifyMotionArgs args2 =
            generateMotionArgs(0 /*downTime*/, RESAMPLE_PERIOD, MOVE, {{4, 5, 200}});
    args2.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args2);
    mTestListener.assertNotifyMotionWasCalled(WithAction(MOVE));

    // Lift up the stylus. If it were a touch event, this would force the model to decide on whether
    // it's a palm.
    NotifyMotionArgs args3 =
            generateMotionArgs(0 /*downTime*/, 2 * RESAMPLE_PERIOD, UP, {{4, 5, 200}});
    args3.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args3);
    mTestListener.assertNotifyMotionWasCalled(WithAction(UP));
}

/**
 * Send a mixed touch and stylus event.
 * The touch event goes first, and is a palm. The stylus event goes down after.
 * Stylus event should continue to work even after touch is detected as a palm.
 */
TEST_F(UnwantedInteractionBlockerTest, TouchIsBlockedWhenMixedWithStylus) {
    InputDeviceInfo info = generateTestDeviceInfo();
    info.addSource(AINPUT_SOURCE_STYLUS);
    mBlocker->notifyInputDevicesChanged({info});

    // Touch down
    NotifyMotionArgs args1 = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2, 3}});
    mBlocker->notifyMotion(&args1);
    mTestListener.assertNotifyMotionWasCalled(WithAction(DOWN));

    // Stylus pointer down
    NotifyMotionArgs args2 = generateMotionArgs(0 /*downTime*/, RESAMPLE_PERIOD, POINTER_1_DOWN,
                                                {{1, 2, 3}, {10, 20, 30}});
    args2.pointerProperties[1].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args2);
    mTestListener.assertNotifyMotionWasCalled(WithAction(POINTER_1_DOWN));

    // Large touch oval on the next finger move
    NotifyMotionArgs args3 = generateMotionArgs(0 /*downTime*/, 2 * RESAMPLE_PERIOD, MOVE,
                                                {{1, 2, 300}, {11, 21, 30}});
    args3.pointerProperties[1].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args3);
    mTestListener.assertNotifyMotionWasCalled(WithAction(MOVE));

    // Lift up the finger pointer. It should be canceled due to the heuristic filter.
    NotifyMotionArgs args4 = generateMotionArgs(0 /*downTime*/, 3 * RESAMPLE_PERIOD, POINTER_0_UP,
                                                {{1, 2, 300}, {11, 21, 30}});
    args4.pointerProperties[1].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args4);
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithAction(POINTER_0_UP), WithFlags(FLAG_CANCELED)));

    NotifyMotionArgs args5 =
            generateMotionArgs(0 /*downTime*/, 4 * RESAMPLE_PERIOD, MOVE, {{12, 22, 30}});
    args5.pointerProperties[0].id = args4.pointerProperties[1].id;
    args5.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args5);
    mTestListener.assertNotifyMotionWasCalled(WithAction(MOVE));

    // Lift up the stylus pointer
    NotifyMotionArgs args6 =
            generateMotionArgs(0 /*downTime*/, 5 * RESAMPLE_PERIOD, UP, {{4, 5, 200}});
    args6.pointerProperties[0].id = args4.pointerProperties[1].id;
    args6.pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    mBlocker->notifyMotion(&args6);
    mTestListener.assertNotifyMotionWasCalled(WithAction(UP));
}

using UnwantedInteractionBlockerTestDeathTest = UnwantedInteractionBlockerTest;

/**
 * The state should be reset when device reset happens. If we receive an inconsistent event after
 * the reset happens, crash should occur.
 */
TEST_F(UnwantedInteractionBlockerTestDeathTest, InconsistentEventAfterResetCausesACrash) {
    ScopedSilentDeath _silentDeath;
    NotifyMotionArgs args;
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, DOWN, {{1, 2, 3}})));
    mBlocker->notifyMotion(
            &(args = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, MOVE, {{4, 5, 6}})));
    NotifyDeviceResetArgs resetArgs(1 /*sequenceNum*/, 3 /*eventTime*/, DEVICE_ID);
    mBlocker->notifyDeviceReset(&resetArgs);
    // Sending MOVE without a DOWN -> should crash!
    ASSERT_DEATH(
            {
                mBlocker->notifyMotion(&(args = generateMotionArgs(0 /*downTime*/, 4 /*eventTime*/,
                                                                   MOVE, {{7, 8, 9}})));
            },
            "Could not find slot");
}

/**
 * There should be a crash when an inconsistent event is received.
 */
TEST_F(UnwantedInteractionBlockerTestDeathTest, WhenMoveWithoutDownCausesACrash) {
    ScopedSilentDeath _silentDeath;
    NotifyMotionArgs args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, MOVE, {{1, 2, 3}});
    mBlocker->notifyInputDevicesChanged({generateTestDeviceInfo()});
    ASSERT_DEATH({ mBlocker->notifyMotion(&args); }, "Could not find slot");
}

class PalmRejectorTest : public testing::Test {
protected:
    std::unique_ptr<PalmRejector> mPalmRejector;

    void SetUp() override {
        AndroidPalmFilterDeviceInfo info = generatePalmFilterDeviceInfo();
        mPalmRejector = std::make_unique<PalmRejector>(info);
    }
};

using PalmRejectorTestDeathTest = PalmRejectorTest;

TEST_F(PalmRejectorTestDeathTest, InconsistentEventCausesACrash) {
    ScopedSilentDeath _silentDeath;
    constexpr nsecs_t downTime = 0;
    NotifyMotionArgs args =
            generateMotionArgs(downTime, 2 /*eventTime*/, MOVE, {{1406.0, 650.0, 52.0}});
    ASSERT_DEATH({ mPalmRejector->processMotion(args); }, "Could not find slot");
}

/**
 * Use PalmRejector with actual touchscreen data and real model.
 * Two pointers that should both be classified as palms.
 */
TEST_F(PalmRejectorTest, TwoPointersAreCanceled) {
    std::vector<NotifyMotionArgs> argsList;
    const nsecs_t downTime = toNs(0ms);

    mPalmRejector->processMotion(
            generateMotionArgs(downTime, downTime, DOWN, {{1342.0, 613.0, 79.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(8ms), MOVE, {{1406.0, 650.0, 52.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(16ms), MOVE, {{1429.0, 672.0, 46.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(24ms), MOVE, {{1417.0, 685.0, 41.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(32ms), POINTER_1_DOWN,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(40ms), MOVE,
                               {{1414.0, 702.0, 41.0}, {1059.0, 731.0, 12.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(48ms), MOVE,
                               {{1415.0, 719.0, 44.0}, {1060.0, 760.0, 11.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(56ms), MOVE,
                               {{1421.0, 733.0, 42.0}, {1065.0, 769.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(64ms), MOVE,
                               {{1426.0, 742.0, 43.0}, {1068.0, 771.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(72ms), MOVE,
                               {{1430.0, 748.0, 45.0}, {1069.0, 772.0, 13.0}}));
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(80ms), MOVE,
                               {{1432.0, 750.0, 44.0}, {1069.0, 772.0, 13.0}}));
    ASSERT_EQ(1u, argsList.size());
    ASSERT_EQ(0 /* No FLAG_CANCELED */, argsList[0].flags);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(88ms), MOVE,
                               {{1433.0, 751.0, 44.0}, {1070.0, 771.0, 13.0}}));
    ASSERT_EQ(2u, argsList.size());
    ASSERT_EQ(POINTER_0_UP, argsList[0].action);
    ASSERT_EQ(FLAG_CANCELED, argsList[0].flags);
    ASSERT_EQ(MOVE, argsList[1].action);
    ASSERT_EQ(1u, argsList[1].pointerCount);
    ASSERT_EQ(0, argsList[1].flags);

    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(96ms), MOVE,
                               {{1433.0, 751.0, 42.0}, {1071.0, 770.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(104ms), MOVE,
                               {{1433.0, 751.0, 45.0}, {1072.0, 769.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(112ms), MOVE,
                               {{1433.0, 751.0, 43.0}, {1072.0, 768.0, 13.0}}));
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(120ms), MOVE,
                               {{1433.0, 751.0, 45.0}, {1072.0, 767.0, 13.0}}));
    ASSERT_EQ(1u, argsList.size());
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, argsList[0].action);
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(128ms), MOVE,
                               {{1433.0, 751.0, 43.0}, {1072.0, 766.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(136ms), MOVE,
                               {{1433.0, 750.0, 44.0}, {1072.0, 765.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(144ms), MOVE,
                               {{1433.0, 750.0, 42.0}, {1072.0, 763.0, 14.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(152ms), MOVE,
                               {{1434.0, 750.0, 44.0}, {1073.0, 761.0, 14.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(160ms), MOVE,
                               {{1435.0, 750.0, 43.0}, {1073.0, 759.0, 15.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(168ms), MOVE,
                               {{1436.0, 750.0, 45.0}, {1074.0, 757.0, 15.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(176ms), MOVE,
                               {{1436.0, 750.0, 44.0}, {1074.0, 755.0, 15.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(184ms), MOVE,
                               {{1436.0, 750.0, 45.0}, {1074.0, 753.0, 15.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(192ms), MOVE,
                               {{1436.0, 749.0, 44.0}, {1074.0, 751.0, 15.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(200ms), MOVE,
                               {{1435.0, 748.0, 45.0}, {1074.0, 749.0, 15.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(208ms), MOVE,
                               {{1434.0, 746.0, 44.0}, {1074.0, 747.0, 14.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(216ms), MOVE,
                               {{1433.0, 744.0, 44.0}, {1075.0, 745.0, 14.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(224ms), MOVE,
                               {{1431.0, 741.0, 43.0}, {1075.0, 742.0, 13.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(232ms), MOVE,
                               {{1428.0, 738.0, 43.0}, {1076.0, 739.0, 12.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(240ms), MOVE,
                               {{1400.0, 726.0, 54.0}, {1076.0, 739.0, 13.0}}));
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(248ms), POINTER_1_UP,
                               {{1362.0, 716.0, 55.0}, {1076.0, 739.0, 13.0}}));
    ASSERT_TRUE(argsList.empty());
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(256ms), MOVE, {{1362.0, 716.0, 55.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(264ms), MOVE, {{1347.0, 707.0, 54.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(272ms), MOVE, {{1340.0, 698.0, 54.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(280ms), MOVE, {{1338.0, 694.0, 55.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(288ms), MOVE, {{1336.0, 690.0, 53.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(296ms), MOVE, {{1334.0, 685.0, 47.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(304ms), MOVE, {{1333.0, 679.0, 46.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(312ms), MOVE, {{1332.0, 672.0, 45.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(320ms), MOVE, {{1333.0, 666.0, 40.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(328ms), MOVE, {{1336.0, 661.0, 24.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(336ms), MOVE, {{1338.0, 656.0, 16.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(344ms), MOVE, {{1341.0, 649.0, 1.0}}));
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, toNs(352ms), UP, {{1341.0, 649.0, 1.0}}));
    ASSERT_TRUE(argsList.empty());
}

/**
 * A test implementation of PalmDetectionFilter that allows you to specify which pointer you want
 * the model to consider 'suppressed'. The pointer is specified using its position (x, y).
 * Current limitation:
 *      Pointers may not cross each other in space during motion. Otherwise, any pointer with the
 *      position matching the suppressed position will be considered "palm".
 */
class TestFilter : public ::ui::PalmDetectionFilter {
public:
    TestFilter(::ui::SharedPalmDetectionFilterState* state,
               std::vector<std::pair<float, float>>& suppressedPointers)
          : ::ui::PalmDetectionFilter(state), mSuppressedPointers(suppressedPointers) {}

    void Filter(const std::vector<::ui::InProgressTouchEvdev>& touches, ::base::TimeTicks time,
                std::bitset<::ui::kNumTouchEvdevSlots>* slots_to_hold,
                std::bitset<::ui::kNumTouchEvdevSlots>* slots_to_suppress) override {
        updateSuppressedSlots(touches);
        *slots_to_suppress = mSuppressedSlots;
    }

    std::string FilterNameForTesting() const override { return "test filter"; }

private:
    void updateSuppressedSlots(const std::vector<::ui::InProgressTouchEvdev>& touches) {
        for (::ui::InProgressTouchEvdev touch : touches) {
            for (const auto& [x, y] : mSuppressedPointers) {
                const float dx = (touch.x - x);
                const float dy = (touch.y - y);
                const float distanceSquared = dx * dx + dy * dy;
                if (distanceSquared < 1) {
                    mSuppressedSlots.set(touch.slot, true);
                }
            }
        }
    }

    std::bitset<::ui::kNumTouchEvdevSlots> mSuppressedSlots;
    std::vector<std::pair<float, float>>& mSuppressedPointers;
};

class PalmRejectorFakeFilterTest : public testing::Test {
protected:
    std::unique_ptr<PalmRejector> mPalmRejector;

    void SetUp() override {
        std::unique_ptr<::ui::PalmDetectionFilter> filter =
                std::make_unique<TestFilter>(&mSharedPalmState, /*byref*/ mSuppressedPointers);
        mPalmRejector =
                std::make_unique<PalmRejector>(generatePalmFilterDeviceInfo(), std::move(filter));
    }

    void suppressPointerAtPosition(float x, float y) { mSuppressedPointers.push_back({x, y}); }

private:
    std::vector<std::pair<float, float>> mSuppressedPointers;
    ::ui::SharedPalmDetectionFilterState mSharedPalmState; // unused, but we must retain ownership
};

/**
 * When a MOVE event happens, the model identifies the pointer as palm. At that time, the palm
 * rejector should send a POINTER_UP event for this pointer with FLAG_CANCELED, and subsequent
 * events should have this pointer removed.
 */
TEST_F(PalmRejectorFakeFilterTest, OneOfTwoPointersIsCanceled) {
    std::vector<NotifyMotionArgs> argsList;
    constexpr nsecs_t downTime = 0;

    mPalmRejector->processMotion(
            generateMotionArgs(downTime, downTime, DOWN, {{1342.0, 613.0, 79.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, 1, POINTER_1_DOWN,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}}));
    // Cancel the second pointer
    suppressPointerAtPosition(1059, 731);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783039000, MOVE,
                               {{1414.0, 702.0, 41.0}, {1059.0, 731.0, 12.0}}));
    ASSERT_EQ(2u, argsList.size());
    // First event - cancel pointer 1
    ASSERT_EQ(POINTER_1_UP, argsList[0].action);
    ASSERT_EQ(FLAG_CANCELED, argsList[0].flags);
    // Second event - send MOVE for the remaining pointer
    ASSERT_EQ(MOVE, argsList[1].action);
    ASSERT_EQ(0, argsList[1].flags);

    // Future move events only contain 1 pointer, because the second pointer will continue
    // to be suppressed
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783039000, MOVE,
                               {{1433.0, 751.0, 43.0}, {1072.0, 766.0, 13.0}}));
    ASSERT_EQ(1u, argsList.size());
    ASSERT_EQ(MOVE, argsList[0].action);
    ASSERT_EQ(1u, argsList[0].pointerCount);
    ASSERT_EQ(1433, argsList[0].pointerCoords[0].getX());
    ASSERT_EQ(751, argsList[0].pointerCoords[0].getY());
}

/**
 * Send two pointers, and suppress both of them. Check that ACTION_CANCEL is generated.
 * Afterwards:
 *  1) Future MOVE events are ignored.
 *  2) When a new pointer goes down, ACTION_DOWN is generated
 */
TEST_F(PalmRejectorFakeFilterTest, NewDownEventAfterCancel) {
    std::vector<NotifyMotionArgs> argsList;
    constexpr nsecs_t downTime = 0;

    mPalmRejector->processMotion(
            generateMotionArgs(downTime, downTime, DOWN, {{1342.0, 613.0, 79.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, 1, POINTER_1_DOWN,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}}));
    // Cancel both pointers
    suppressPointerAtPosition(1059, 731);
    suppressPointerAtPosition(1400, 680);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 1, MOVE, {{1400, 680, 41}, {1059, 731, 10}}));
    ASSERT_EQ(1u, argsList.size());
    // Cancel all
    ASSERT_EQ(CANCEL, argsList[0].action);
    ASSERT_EQ(2u, argsList[0].pointerCount);
    ASSERT_EQ(FLAG_CANCELED, argsList[0].flags);

    // Future move events are ignored
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783039000, MOVE,
                               {{1433.0, 751.0, 43.0}, {1072.0, 766.0, 13.0}}));
    ASSERT_EQ(0u, argsList.size());

    // When a new pointer goes down, a new DOWN event is generated
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783039000, POINTER_2_DOWN,
                               {{1433.0, 751.0, 43.0}, {1072.0, 766.0, 13.0}, {1000, 700, 10}}));
    ASSERT_EQ(1u, argsList.size());
    ASSERT_EQ(DOWN, argsList[0].action);
    ASSERT_EQ(1u, argsList[0].pointerCount);
    ASSERT_EQ(2, argsList[0].pointerProperties[0].id);
}

/**
 * 2 pointers are classified as palm simultaneously. When they are later
 * released by Android, make sure that we drop both of these POINTER_UP events.
 * Since they are classified as palm at the same time, we just need to receive a single CANCEL
 * event. From MotionEvent docs: """A pointer id remains valid until the pointer eventually goes up
 * (indicated by ACTION_UP or ACTION_POINTER_UP) or when the gesture is canceled (indicated by
 *  ACTION_CANCEL)."""
 * This means that generating additional POINTER_UP events is not necessary.
 * The risk here is that "oldSuppressedPointerIds" will not be correct, because it will update after
 * each motion, but pointers are canceled one at a time by Android.
 */
TEST_F(PalmRejectorFakeFilterTest, TwoPointersCanceledWhenOnePointerGoesUp) {
    std::vector<NotifyMotionArgs> argsList;
    constexpr nsecs_t downTime = 0;

    mPalmRejector->processMotion(
            generateMotionArgs(downTime, downTime, DOWN, {{1342.0, 613.0, 79.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, /*eventTime*/ 1, POINTER_1_DOWN,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}}));
    // Suppress both pointers!!
    suppressPointerAtPosition(1414, 702);
    suppressPointerAtPosition(1059, 731);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783039000, POINTER_1_UP,
                               {{1414.0, 702.0, 41.0}, {1059.0, 731.0, 12.0}}));
    ASSERT_EQ(1u, argsList.size());
    ASSERT_EQ(CANCEL, argsList[0].action) << MotionEvent::actionToString(argsList[0].action);
    ASSERT_EQ(FLAG_CANCELED, argsList[0].flags);

    // Future move events should not go to the listener.
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783049000, MOVE, {{1435.0, 755.0, 43.0}}));
    ASSERT_EQ(0u, argsList.size());

    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, 255955783059000, UP, {{1436.0, 756.0, 43.0}}));
    ASSERT_EQ(0u, argsList.size());
}

/**
 * Send 3 pointers, and then cancel one of them during a MOVE event. We should see ACTION_POINTER_UP
 * generated for that. Next, another pointer is canceled during ACTION_POINTER_DOWN. For that
 * pointer, we simply shouldn't send the event.
 */
TEST_F(PalmRejectorFakeFilterTest, CancelTwoPointers) {
    std::vector<NotifyMotionArgs> argsList;
    constexpr nsecs_t downTime = 0;

    mPalmRejector->processMotion(
            generateMotionArgs(downTime, downTime, DOWN, {{1342.0, 613.0, 79.0}}));
    mPalmRejector->processMotion(
            generateMotionArgs(downTime, /*eventTime*/ 1, POINTER_1_DOWN,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}}));

    // Suppress second pointer (pointer 1)
    suppressPointerAtPosition(1060, 700);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, /*eventTime*/ 1, MOVE,
                               {{1417.0, 685.0, 41.0}, {1060, 700, 10.0}}));
    ASSERT_EQ(2u, argsList.size());
    ASSERT_EQ(POINTER_1_UP, argsList[0].action);
    ASSERT_EQ(FLAG_CANCELED, argsList[0].flags);

    ASSERT_EQ(MOVE, argsList[1].action) << MotionEvent::actionToString(argsList[1].action);
    ASSERT_EQ(0, argsList[1].flags);

    // A new pointer goes down and gets suppressed right away. It should just be dropped
    suppressPointerAtPosition(1001, 601);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, /*eventTime*/ 1, POINTER_2_DOWN,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}, {1001, 601, 5}}));

    ASSERT_EQ(0u, argsList.size());
    // Likewise, pointer that's already canceled should be ignored
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, /*eventTime*/ 1, POINTER_2_UP,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}, {1001, 601, 5}}));
    ASSERT_EQ(0u, argsList.size());

    // Cancel all pointers when pointer 1 goes up. Pointer 1 was already canceled earlier.
    suppressPointerAtPosition(1417, 685);
    argsList = mPalmRejector->processMotion(
            generateMotionArgs(downTime, /*eventTime*/ 1, POINTER_1_UP,
                               {{1417.0, 685.0, 41.0}, {1062.0, 697.0, 10.0}}));
    ASSERT_EQ(1u, argsList.size());
    ASSERT_EQ(CANCEL, argsList[0].action);
}

} // namespace android
