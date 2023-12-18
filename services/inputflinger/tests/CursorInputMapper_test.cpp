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

#include "CursorInputMapper.h"

#include <list>
#include <string>
#include <tuple>
#include <variant>

#include <android-base/logging.h>
#include <com_android_input_flags.h>
#include <gtest/gtest.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <utils/Timers.h>

#include "FakePointerController.h"
#include "InputMapperTest.h"
#include "InterfaceMocks.h"
#include "NotifyArgs.h"
#include "TestEventMatchers.h"
#include "ui/Rotation.h"

#define TAG "CursorInputMapper_test"

namespace android {

using testing::AllOf;
using testing::Return;
using testing::VariantWith;
constexpr auto ACTION_DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr auto ACTION_MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr auto ACTION_UP = AMOTION_EVENT_ACTION_UP;
constexpr auto BUTTON_PRESS = AMOTION_EVENT_ACTION_BUTTON_PRESS;
constexpr auto BUTTON_RELEASE = AMOTION_EVENT_ACTION_BUTTON_RELEASE;
constexpr auto HOVER_MOVE = AMOTION_EVENT_ACTION_HOVER_MOVE;
constexpr auto INVALID_CURSOR_POSITION = AMOTION_EVENT_INVALID_CURSOR_POSITION;
constexpr int32_t DISPLAY_ID = 0;
constexpr int32_t SECONDARY_DISPLAY_ID = DISPLAY_ID + 1;
constexpr int32_t DISPLAY_WIDTH = 480;
constexpr int32_t DISPLAY_HEIGHT = 800;
constexpr std::optional<uint8_t> NO_PORT = std::nullopt; // no physical port is specified

constexpr int32_t TRACKBALL_MOVEMENT_THRESHOLD = 6;

namespace input_flags = com::android::input::flags;

/**
 * Unit tests for CursorInputMapper.
 * These classes are named 'CursorInputMapperUnitTest...' to avoid name collision with the existing
 * 'CursorInputMapperTest...' classes. If all of the CursorInputMapper tests are migrated here, the
 * name can be simplified to 'CursorInputMapperTest'.
 *
 * TODO(b/283812079): move the remaining CursorInputMapper tests here. The ones that are left all
 *   depend on viewport association, for which we'll need to fake InputDeviceContext.
 */
class CursorInputMapperUnitTestBase : public InputMapperUnitTest {
protected:
    void SetUp() override { SetUpWithBus(BUS_USB); }
    void SetUpWithBus(int bus) override {
        InputMapperUnitTest::SetUpWithBus(bus);

        // Current scan code state - all keys are UP by default
        setScanCodeState(KeyState::UP,
                         {BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_BACK, BTN_SIDE, BTN_FORWARD,
                          BTN_EXTRA, BTN_TASK});
        EXPECT_CALL(mMockEventHub, hasRelativeAxis(EVENTHUB_ID, REL_WHEEL))
                .WillRepeatedly(Return(false));
        EXPECT_CALL(mMockEventHub, hasRelativeAxis(EVENTHUB_ID, REL_HWHEEL))
                .WillRepeatedly(Return(false));

        mFakePolicy->setDefaultPointerDisplayId(DISPLAY_ID);
        mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                        /*isActive=*/true, "local:0", NO_PORT,
                                        ViewportType::INTERNAL);
    }

    void createMapper() {
        createDevice();
        mMapper = createInputMapper<CursorInputMapper>(*mDeviceContext, mReaderConfiguration);
    }

    void setPointerCapture(bool enabled) {
        mReaderConfiguration.pointerCaptureRequest.enable = enabled;
        mReaderConfiguration.pointerCaptureRequest.seq = 1;
        int32_t generation = mDevice->getGeneration();
        std::list<NotifyArgs> args =
                mMapper->reconfigure(ARBITRARY_TIME, mReaderConfiguration,
                                     InputReaderConfiguration::Change::POINTER_CAPTURE);
        ASSERT_THAT(args,
                    ElementsAre(VariantWith<NotifyDeviceResetArgs>(
                            AllOf(WithDeviceId(DEVICE_ID), WithEventTime(ARBITRARY_TIME)))));

        // Check that generation also got bumped
        ASSERT_GT(mDevice->getGeneration(), generation);
    }
};

class CursorInputMapperUnitTest : public CursorInputMapperUnitTestBase {
protected:
    void SetUp() override {
        input_flags::enable_pointer_choreographer(false);
        CursorInputMapperUnitTestBase::SetUp();
    }
};

TEST_F(CursorInputMapperUnitTest, GetSourcesReturnsMouseInPointerMode) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    ASSERT_EQ(AINPUT_SOURCE_MOUSE, mMapper->getSources());
}

TEST_F(CursorInputMapperUnitTest, GetSourcesReturnsTrackballInNavigationMode) {
    mPropertyMap.addProperty("cursor.mode", "navigation");
    createMapper();

    ASSERT_EQ(AINPUT_SOURCE_TRACKBALL, mMapper->getSources());
}

/**
 * Move the mouse and then click the button. Check whether HOVER_EXIT is generated when hovering
 * ends. Currently, it is not.
 */
TEST_F(CursorInputMapperUnitTest, HoverAndLeftButtonPress) {
    createMapper();
    std::list<NotifyArgs> args;

    // Move the cursor a little
    args += process(EV_REL, REL_X, 10);
    args += process(EV_REL, REL_Y, 20);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args, ElementsAre(VariantWith<NotifyMotionArgs>(WithMotionAction(HOVER_MOVE))));

    // Now click the mouse button
    args.clear();
    args += process(EV_KEY, BTN_LEFT, 1);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(WithMotionAction(ACTION_DOWN)),
                            VariantWith<NotifyMotionArgs>(WithMotionAction(BUTTON_PRESS))));

    // Move some more.
    args.clear();
    args += process(EV_REL, REL_X, 10);
    args += process(EV_REL, REL_Y, 20);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args, ElementsAre(VariantWith<NotifyMotionArgs>(WithMotionAction(ACTION_MOVE))));

    // Release the button
    args.clear();
    args += process(EV_KEY, BTN_LEFT, 0);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(WithMotionAction(BUTTON_RELEASE)),
                            VariantWith<NotifyMotionArgs>(WithMotionAction(ACTION_UP)),
                            VariantWith<NotifyMotionArgs>(WithMotionAction(HOVER_MOVE))));
}

/**
 * Set pointer capture and check that ACTION_MOVE events are emitted from CursorInputMapper.
 * During pointer capture, source should be set to MOUSE_RELATIVE. When the capture is disabled,
 * the events should be generated normally:
 *   1) The source should return to SOURCE_MOUSE
 *   2) Cursor position should be incremented by the relative device movements
 *   3) Cursor position of NotifyMotionArgs should now be getting populated.
 * When it's not SOURCE_MOUSE, CursorInputMapper doesn't populate cursor position values.
 */
TEST_F(CursorInputMapperUnitTest, ProcessPointerCapture) {
    createMapper();
    setPointerCapture(true);
    std::list<NotifyArgs> args;

    // Move.
    args += process(EV_REL, REL_X, 10);
    args += process(EV_REL, REL_Y, 20);
    args += process(EV_SYN, SYN_REPORT, 0);

    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(ACTION_MOVE),
                              WithSource(AINPUT_SOURCE_MOUSE_RELATIVE), WithCoords(10.0f, 20.0f),
                              WithRelativeMotion(10.0f, 20.0f),
                              WithCursorPosition(INVALID_CURSOR_POSITION,
                                                 INVALID_CURSOR_POSITION)))));

    // Button press.
    args.clear();
    args += process(EV_KEY, BTN_MOUSE, 1);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(ACTION_DOWN),
                                          WithSource(AINPUT_SOURCE_MOUSE_RELATIVE),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(BUTTON_PRESS),
                                          WithSource(AINPUT_SOURCE_MOUSE_RELATIVE),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f)))));

    // Button release.
    args.clear();
    args += process(EV_KEY, BTN_MOUSE, 0);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(BUTTON_RELEASE),
                                          WithSource(AINPUT_SOURCE_MOUSE_RELATIVE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(ACTION_UP),
                                          WithSource(AINPUT_SOURCE_MOUSE_RELATIVE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f)))));

    // Another move.
    args.clear();
    args += process(EV_REL, REL_X, 30);
    args += process(EV_REL, REL_Y, 40);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(ACTION_MOVE),
                              WithSource(AINPUT_SOURCE_MOUSE_RELATIVE), WithCoords(30.0f, 40.0f),
                              WithRelativeMotion(30.0f, 40.0f)))));

    // Disable pointer capture. Afterwards, events should be generated the usual way.
    setPointerCapture(false);
    const auto expectedCoords = input_flags::enable_pointer_choreographer()
            ? WithCoords(0, 0)
            : WithCoords(INITIAL_CURSOR_X + 10.0f, INITIAL_CURSOR_Y + 20.0f);
    const auto expectedCursorPosition = input_flags::enable_pointer_choreographer()
            ? WithCursorPosition(INVALID_CURSOR_POSITION, INVALID_CURSOR_POSITION)
            : WithCursorPosition(INITIAL_CURSOR_X + 10.0f, INITIAL_CURSOR_Y + 20.0f);
    args.clear();
    args += process(EV_REL, REL_X, 10);
    args += process(EV_REL, REL_Y, 20);
    args += process(EV_SYN, SYN_REPORT, 0);
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(HOVER_MOVE), WithSource(AINPUT_SOURCE_MOUSE),
                              expectedCoords, expectedCursorPosition,
                              WithRelativeMotion(10.0f, 20.0f)))));
}

TEST_F(CursorInputMapperUnitTest,
       PopulateDeviceInfoReturnsRangeFromPointerControllerInPointerMode) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    mFakePolicy->clearViewports();
    mFakePointerController->clearBounds();
    createMapper();

    InputDeviceInfo info;
    mMapper->populateDeviceInfo(info);

    // Initially there should not be a valid motion range because there's no viewport or pointer
    // bounds.
    ASSERT_EQ(nullptr, info.getMotionRange(AINPUT_MOTION_RANGE_X, AINPUT_SOURCE_MOUSE));
    ASSERT_EQ(nullptr, info.getMotionRange(AINPUT_MOTION_RANGE_Y, AINPUT_SOURCE_MOUSE));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info, AINPUT_MOTION_RANGE_PRESSURE,
                                              AINPUT_SOURCE_MOUSE, 0.0f, 1.0f, 0.0f, 0.0f));

    // When the bounds are set, then there should be a valid motion range.
    mFakePointerController->setBounds(1, 2, 800 - 1, 480 - 1);
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, "local:0", NO_PORT, ViewportType::INTERNAL);
    std::list<NotifyArgs> args =
            mMapper->reconfigure(systemTime(), mReaderConfiguration,
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_THAT(args, testing::IsEmpty());

    InputDeviceInfo info2;
    mMapper->populateDeviceInfo(info2);

    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info2, AINPUT_MOTION_RANGE_X, AINPUT_SOURCE_MOUSE, 1,
                                              800 - 1, 0.0f, 0.0f));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info2, AINPUT_MOTION_RANGE_Y, AINPUT_SOURCE_MOUSE, 2,
                                              480 - 1, 0.0f, 0.0f));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info2, AINPUT_MOTION_RANGE_PRESSURE,
                                              AINPUT_SOURCE_MOUSE, 0.0f, 1.0f, 0.0f, 0.0f));
}

TEST_F(CursorInputMapperUnitTest, PopulateDeviceInfoReturnsScaledRangeInNavigationMode) {
    mPropertyMap.addProperty("cursor.mode", "navigation");
    createMapper();

    InputDeviceInfo info;
    mMapper->populateDeviceInfo(info);

    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info, AINPUT_MOTION_RANGE_X, AINPUT_SOURCE_TRACKBALL,
                                              -1.0f, 1.0f, 0.0f,
                                              1.0f / TRACKBALL_MOVEMENT_THRESHOLD));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info, AINPUT_MOTION_RANGE_Y, AINPUT_SOURCE_TRACKBALL,
                                              -1.0f, 1.0f, 0.0f,
                                              1.0f / TRACKBALL_MOVEMENT_THRESHOLD));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info, AINPUT_MOTION_RANGE_PRESSURE,
                                              AINPUT_SOURCE_TRACKBALL, 0.0f, 1.0f, 0.0f, 0.0f));
}

TEST_F(CursorInputMapperUnitTest, ProcessShouldSetAllFieldsAndIncludeGlobalMetaState) {
    mPropertyMap.addProperty("cursor.mode", "navigation");
    createMapper();

    EXPECT_CALL(mMockInputReaderContext, getGlobalMetaState())
            .WillRepeatedly(Return(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON));

    std::list<NotifyArgs> args;

    // Button press.
    // Mostly testing non x/y behavior here so we don't need to check again elsewhere.
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MOUSE, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithEventTime(ARBITRARY_TIME), WithDeviceId(DEVICE_ID),
                                          WithSource(AINPUT_SOURCE_TRACKBALL), WithFlags(0),
                                          WithEdgeFlags(0), WithPolicyFlags(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON),
                                          WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                                          WithPointerCount(1), WithPointerId(0, 0),
                                          WithToolType(ToolType::MOUSE), WithCoords(0.0f, 0.0f),
                                          WithPressure(1.0f),
                                          WithPrecision(TRACKBALL_MOVEMENT_THRESHOLD,
                                                        TRACKBALL_MOVEMENT_THRESHOLD),
                                          WithDownTime(ARBITRARY_TIME))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithEventTime(ARBITRARY_TIME), WithDeviceId(DEVICE_ID),
                                          WithSource(AINPUT_SOURCE_TRACKBALL), WithFlags(0),
                                          WithEdgeFlags(0), WithPolicyFlags(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON),
                                          WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                                          WithPointerCount(1), WithPointerId(0, 0),
                                          WithToolType(ToolType::MOUSE), WithCoords(0.0f, 0.0f),
                                          WithPressure(1.0f),
                                          WithPrecision(TRACKBALL_MOVEMENT_THRESHOLD,
                                                        TRACKBALL_MOVEMENT_THRESHOLD),
                                          WithDownTime(ARBITRARY_TIME)))));
    args.clear();

    // Button release.  Should have same down time.
    args += process(ARBITRARY_TIME + 1, EV_KEY, BTN_MOUSE, 0);
    args += process(ARBITRARY_TIME + 1, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithEventTime(ARBITRARY_TIME + 1),
                                          WithDeviceId(DEVICE_ID),
                                          WithSource(AINPUT_SOURCE_TRACKBALL), WithFlags(0),
                                          WithEdgeFlags(0), WithPolicyFlags(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON),
                                          WithButtonState(0), WithPointerCount(1),
                                          WithPointerId(0, 0), WithToolType(ToolType::MOUSE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f),
                                          WithPrecision(TRACKBALL_MOVEMENT_THRESHOLD,
                                                        TRACKBALL_MOVEMENT_THRESHOLD),
                                          WithDownTime(ARBITRARY_TIME))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithEventTime(ARBITRARY_TIME + 1),
                                          WithDeviceId(DEVICE_ID),
                                          WithSource(AINPUT_SOURCE_TRACKBALL), WithFlags(0),
                                          WithEdgeFlags(0), WithPolicyFlags(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON),
                                          WithButtonState(0), WithPointerCount(1),
                                          WithPointerId(0, 0), WithToolType(ToolType::MOUSE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f),
                                          WithPrecision(TRACKBALL_MOVEMENT_THRESHOLD,
                                                        TRACKBALL_MOVEMENT_THRESHOLD),
                                          WithDownTime(ARBITRARY_TIME)))));
}

TEST_F(CursorInputMapperUnitTest, ProcessShouldHandleIndependentXYUpdates) {
    mPropertyMap.addProperty("cursor.mode", "navigation");
    createMapper();

    std::list<NotifyArgs> args;

    // Motion in X but not Y.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                              WithCoords(1.0f / TRACKBALL_MOVEMENT_THRESHOLD, 0.0f),
                              WithPressure(0.0f)))));
    args.clear();

    // Motion in Y but not X.
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, -2);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                              WithCoords(0.0f, -2.0f / TRACKBALL_MOVEMENT_THRESHOLD),
                              WithPressure(0.0f)))));
    args.clear();
}

TEST_F(CursorInputMapperUnitTest, ProcessShouldHandleIndependentButtonUpdates) {
    mPropertyMap.addProperty("cursor.mode", "navigation");
    createMapper();

    std::list<NotifyArgs> args;

    // Button press.
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MOUSE, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f)))));
    args.clear();

    // Button release.
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MOUSE, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f)))));
}

TEST_F(CursorInputMapperUnitTest, ProcessShouldHandleCombinedXYAndButtonUpdates) {
    mPropertyMap.addProperty("cursor.mode", "navigation");
    createMapper();

    std::list<NotifyArgs> args;

    // Combined X, Y and Button.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, -2);
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MOUSE, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithCoords(1.0f / TRACKBALL_MOVEMENT_THRESHOLD,
                                                     -2.0f / TRACKBALL_MOVEMENT_THRESHOLD),
                                          WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithCoords(1.0f / TRACKBALL_MOVEMENT_THRESHOLD,
                                                     -2.0f / TRACKBALL_MOVEMENT_THRESHOLD),
                                          WithPressure(1.0f)))));
    args.clear();

    // Move X, Y a bit while pressed.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 2);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                              WithCoords(2.0f / TRACKBALL_MOVEMENT_THRESHOLD,
                                         1.0f / TRACKBALL_MOVEMENT_THRESHOLD),
                              WithPressure(1.0f)))));
    args.clear();

    // Release Button.
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MOUSE, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f)))));
    args.clear();
}

TEST_F(CursorInputMapperUnitTest, ProcessShouldHandleAllButtons) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(100, 200);

    std::list<NotifyArgs> args;

    // press BTN_LEFT, release BTN_LEFT
    args += process(ARBITRARY_TIME, EV_KEY, BTN_LEFT, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, BTN_LEFT, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(0), WithCoords(100.0f, 200.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithButtonState(0), WithCoords(100.0f, 200.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithButtonState(0), WithCoords(100.0f, 200.0f),
                                          WithPressure(0.0f)))));
    args.clear();

    // press BTN_RIGHT + BTN_MIDDLE, release BTN_RIGHT, release BTN_MIDDLE
    args += process(ARBITRARY_TIME, EV_KEY, BTN_RIGHT, 1);
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MIDDLE, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithButtonState(AMOTION_EVENT_BUTTON_SECONDARY |
                                                          AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(AMOTION_EVENT_BUTTON_SECONDARY |
                                                          AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, BTN_RIGHT, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                                          WithButtonState(AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(100.0f, 200.0f), WithPressure(1.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, BTN_MIDDLE, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(0), WithCoords(100.0f, 200.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithButtonState(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithCoords(100.0f, 200.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithButtonState(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithCoords(100.0f, 200.0f), WithPressure(0.0f)))));
}

class CursorInputMapperButtonKeyTest
      : public CursorInputMapperUnitTest,
        public testing::WithParamInterface<
                std::tuple<int32_t /*evdevCode*/, int32_t /*expectedButtonState*/,
                           int32_t /*expectedKeyCode*/>> {};

TEST_P(CursorInputMapperButtonKeyTest, ProcessShouldHandleButtonKey) {
    auto [evdevCode, expectedButtonState, expectedKeyCode] = GetParam();
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(100, 200);

    std::list<NotifyArgs> args;

    args += process(ARBITRARY_TIME, EV_KEY, evdevCode, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyKeyArgs>(AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN),
                                                             WithKeyCode(expectedKeyCode))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithButtonState(expectedButtonState),
                                          WithCoords(100.0f, 200.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(expectedButtonState),
                                          WithCoords(100.0f, 200.0f), WithPressure(0.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, evdevCode, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(0), WithCoords(100.0f, 200.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithButtonState(0), WithCoords(100.0f, 200.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyKeyArgs>(AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP),
                                                             WithKeyCode(expectedKeyCode)))));
}

INSTANTIATE_TEST_SUITE_P(
        SideExtraBackAndForward, CursorInputMapperButtonKeyTest,
        testing::Values(std::make_tuple(BTN_SIDE, AMOTION_EVENT_BUTTON_BACK, AKEYCODE_BACK),
                        std::make_tuple(BTN_EXTRA, AMOTION_EVENT_BUTTON_FORWARD, AKEYCODE_FORWARD),
                        std::make_tuple(BTN_BACK, AMOTION_EVENT_BUTTON_BACK, AKEYCODE_BACK),
                        std::make_tuple(BTN_FORWARD, AMOTION_EVENT_BUTTON_FORWARD,
                                        AKEYCODE_FORWARD)));

TEST_F(CursorInputMapperUnitTest, ProcessShouldMoveThePointerAroundInPointerMode) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(100, 200);

    std::list<NotifyArgs> args;

    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithSource(AINPUT_SOURCE_MOUSE),
                              WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithCoords(110.0f, 220.0f), WithPressure(0.0f), WithSize(0.0f),
                              WithTouchDimensions(0.0f, 0.0f), WithToolDimensions(0.0f, 0.0f),
                              WithOrientation(0.0f), WithDistance(0.0f)))));
    ASSERT_NO_FATAL_FAILURE(mFakePointerController->assertPosition(110.0f, 220.0f));
}

/**
 * When Pointer Capture is enabled, we expect to report unprocessed relative movements, so any
 * pointer acceleration or speed processing should not be applied.
 */
TEST_F(CursorInputMapperUnitTest, PointerCaptureDisablesVelocityProcessing) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    const VelocityControlParameters testParams(/*scale=*/5.f, /*lowThreshold=*/0.f,
                                               /*highThreshold=*/100.f, /*acceleration=*/10.f);
    mReaderConfiguration.pointerVelocityControlParameters = testParams;
    mFakePolicy->setVelocityControlParams(testParams);
    createMapper();

    std::list<NotifyArgs> args;

    // Move and verify scale is applied.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithSource(AINPUT_SOURCE_MOUSE),
                              WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE)))));
    NotifyMotionArgs motionArgs = std::get<NotifyMotionArgs>(args.front());
    const float relX = motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X);
    const float relY = motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y);
    ASSERT_GT(relX, 10);
    ASSERT_GT(relY, 20);
    args.clear();

    // Enable Pointer Capture
    setPointerCapture(true);

    // Move and verify scale is not applied.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithSource(AINPUT_SOURCE_MOUSE_RELATIVE),
                              WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithCoords(10, 20)))));
}

// TODO(b/311416205): De-duplicate the test cases after the refactoring is complete and the flagging
//   logic can be removed.
class CursorInputMapperUnitTestWithChoreographer : public CursorInputMapperUnitTestBase {
protected:
    void SetUp() override {
        input_flags::enable_pointer_choreographer(true);
        CursorInputMapperUnitTestBase::SetUp();
    }
};

TEST_F(CursorInputMapperUnitTestWithChoreographer, PopulateDeviceInfoReturnsRangeFromPolicy) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    mFakePolicy->clearViewports();
    mFakePointerController->clearBounds();
    createMapper();

    InputDeviceInfo info;
    mMapper->populateDeviceInfo(info);

    // Initially there should not be a valid motion range because there's no viewport or pointer
    // bounds.
    ASSERT_EQ(nullptr, info.getMotionRange(AINPUT_MOTION_RANGE_X, AINPUT_SOURCE_MOUSE));
    ASSERT_EQ(nullptr, info.getMotionRange(AINPUT_MOTION_RANGE_Y, AINPUT_SOURCE_MOUSE));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info, AINPUT_MOTION_RANGE_PRESSURE,
                                              AINPUT_SOURCE_MOUSE, 0.0f, 1.0f, 0.0f, 0.0f));

    // When the viewport and the default pointer display ID is set, then there should be a valid
    // motion range.
    mFakePolicy->setDefaultPointerDisplayId(DISPLAY_ID);
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, "local:0", NO_PORT, ViewportType::INTERNAL);
    std::list<NotifyArgs> args =
            mMapper->reconfigure(systemTime(), mReaderConfiguration,
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_THAT(args, testing::IsEmpty());

    InputDeviceInfo info2;
    mMapper->populateDeviceInfo(info2);

    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info2, AINPUT_MOTION_RANGE_X, AINPUT_SOURCE_MOUSE, 0,
                                              DISPLAY_WIDTH - 1, 0.0f, 0.0f));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info2, AINPUT_MOTION_RANGE_Y, AINPUT_SOURCE_MOUSE, 0,
                                              DISPLAY_HEIGHT - 1, 0.0f, 0.0f));
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info2, AINPUT_MOTION_RANGE_PRESSURE,
                                              AINPUT_SOURCE_MOUSE, 0.0f, 1.0f, 0.0f, 0.0f));
}

TEST_F(CursorInputMapperUnitTestWithChoreographer, ProcessShouldHandleAllButtonsWithZeroCoords) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(100, 200);

    std::list<NotifyArgs> args;

    // press BTN_LEFT, release BTN_LEFT
    args += process(ARBITRARY_TIME, EV_KEY, BTN_LEFT, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f)))));
    args.clear();
    args += process(ARBITRARY_TIME, EV_KEY, BTN_LEFT, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(0), WithCoords(0.0f, 0.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithButtonState(0), WithCoords(0.0f, 0.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithButtonState(0), WithCoords(0.0f, 0.0f),
                                          WithPressure(0.0f)))));
    args.clear();

    // press BTN_RIGHT + BTN_MIDDLE, release BTN_RIGHT, release BTN_MIDDLE
    args += process(ARBITRARY_TIME, EV_KEY, BTN_RIGHT, 1);
    args += process(ARBITRARY_TIME, EV_KEY, BTN_MIDDLE, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                          WithButtonState(AMOTION_EVENT_BUTTON_SECONDARY |
                                                          AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(AMOTION_EVENT_BUTTON_SECONDARY |
                                                          AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, BTN_RIGHT, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                                          WithButtonState(AMOTION_EVENT_BUTTON_TERTIARY),
                                          WithCoords(0.0f, 0.0f), WithPressure(1.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, BTN_MIDDLE, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(0), WithCoords(0.0f, 0.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithButtonState(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithButtonState(0),
                                          WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f)))));
}

class CursorInputMapperButtonKeyTestWithChoreographer
      : public CursorInputMapperUnitTestWithChoreographer,
        public testing::WithParamInterface<
                std::tuple<int32_t /*evdevCode*/, int32_t /*expectedButtonState*/,
                           int32_t /*expectedKeyCode*/>> {};

TEST_P(CursorInputMapperButtonKeyTestWithChoreographer,
       ProcessShouldHandleButtonKeyWithZeroCoords) {
    auto [evdevCode, expectedButtonState, expectedKeyCode] = GetParam();
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(100, 200);

    std::list<NotifyArgs> args;

    args += process(ARBITRARY_TIME, EV_KEY, evdevCode, 1);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyKeyArgs>(AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN),
                                                             WithKeyCode(expectedKeyCode))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithButtonState(expectedButtonState),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                                          WithButtonState(expectedButtonState),
                                          WithCoords(0.0f, 0.0f), WithPressure(0.0f)))));
    args.clear();

    args += process(ARBITRARY_TIME, EV_KEY, evdevCode, 0);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                                          WithButtonState(0), WithCoords(0.0f, 0.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyMotionArgs>(
                                    AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                          WithButtonState(0), WithCoords(0.0f, 0.0f),
                                          WithPressure(0.0f))),
                            VariantWith<NotifyKeyArgs>(AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP),
                                                             WithKeyCode(expectedKeyCode)))));
}

INSTANTIATE_TEST_SUITE_P(
        SideExtraBackAndForward, CursorInputMapperButtonKeyTestWithChoreographer,
        testing::Values(std::make_tuple(BTN_SIDE, AMOTION_EVENT_BUTTON_BACK, AKEYCODE_BACK),
                        std::make_tuple(BTN_EXTRA, AMOTION_EVENT_BUTTON_FORWARD, AKEYCODE_FORWARD),
                        std::make_tuple(BTN_BACK, AMOTION_EVENT_BUTTON_BACK, AKEYCODE_BACK),
                        std::make_tuple(BTN_FORWARD, AMOTION_EVENT_BUTTON_FORWARD,
                                        AKEYCODE_FORWARD)));

TEST_F(CursorInputMapperUnitTestWithChoreographer, ProcessWhenModeIsPointerShouldKeepZeroCoords) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();

    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(100, 200);

    std::list<NotifyArgs> args;

    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithSource(AINPUT_SOURCE_MOUSE),
                              WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithCoords(0.0f, 0.0f), WithPressure(0.0f), WithSize(0.0f),
                              WithTouchDimensions(0.0f, 0.0f), WithToolDimensions(0.0f, 0.0f),
                              WithOrientation(0.0f), WithDistance(0.0f)))));
}

TEST_F(CursorInputMapperUnitTestWithChoreographer, PointerCaptureDisablesVelocityProcessing) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    const VelocityControlParameters testParams(/*scale=*/5.f, /*lowThreshold=*/0.f,
                                               /*highThreshold=*/100.f, /*acceleration=*/10.f);
    mReaderConfiguration.pointerVelocityControlParameters = testParams;
    mFakePolicy->setVelocityControlParams(testParams);
    createMapper();

    NotifyMotionArgs motionArgs;
    std::list<NotifyArgs> args;

    // Move and verify scale is applied.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithSource(AINPUT_SOURCE_MOUSE),
                              WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE)))));
    motionArgs = std::get<NotifyMotionArgs>(args.front());
    const float relX = motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X);
    const float relY = motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y);
    ASSERT_GT(relX, 10);
    ASSERT_GT(relY, 20);
    args.clear();

    // Enable Pointer Capture
    setPointerCapture(true);

    // Move and verify scale is not applied.
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithSource(AINPUT_SOURCE_MOUSE_RELATIVE),
                              WithMotionAction(AMOTION_EVENT_ACTION_MOVE)))));
    motionArgs = std::get<NotifyMotionArgs>(args.front());
    const float relX2 = motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X);
    const float relY2 = motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y);
    ASSERT_EQ(10, relX2);
    ASSERT_EQ(20, relY2);
}

TEST_F(CursorInputMapperUnitTestWithChoreographer, ConfigureDisplayIdNoAssociatedViewport) {
    // Set up the default display.
    mFakePolicy->clearViewports();
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_90,
                                    /*isActive=*/true, "local:0", NO_PORT, ViewportType::INTERNAL);

    // Set up the secondary display as the display on which the pointer should be shown.
    // The InputDevice is not associated with any display.
    mFakePolicy->addDisplayViewport(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, "local:1", NO_PORT,
                                    ViewportType::EXTERNAL);
    mFakePolicy->setDefaultPointerDisplayId(SECONDARY_DISPLAY_ID);

    createMapper();

    mFakePointerController->setBounds(0, 0, DISPLAY_WIDTH - 1, DISPLAY_HEIGHT - 1);
    mFakePointerController->setPosition(100, 200);

    // Ensure input events are generated without display ID or coords, because they will be decided
    // later by PointerChoreographer.
    std::list<NotifyArgs> args;
    args += process(ARBITRARY_TIME, EV_REL, REL_X, 10);
    args += process(ARBITRARY_TIME, EV_REL, REL_Y, 20);
    args += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithSource(AINPUT_SOURCE_MOUSE), WithDisplayId(ADISPLAY_ID_NONE),
                              WithCoords(0.0f, 0.0f)))));
}

namespace {

// Minimum timestamp separation between subsequent input events from a Bluetooth device.
constexpr nsecs_t MIN_BLUETOOTH_TIMESTAMP_DELTA = ms2ns(4);
// Maximum smoothing time delta so that we don't generate events too far into the future.
constexpr nsecs_t MAX_BLUETOOTH_SMOOTHING_DELTA = ms2ns(32);

} // namespace

class BluetoothCursorInputMapperUnitTest : public CursorInputMapperUnitTestBase {
protected:
    void SetUp() override {
        input_flags::enable_pointer_choreographer(false);
        SetUpWithBus(BUS_BLUETOOTH);

        mFakePointerController = std::make_shared<FakePointerController>();
        mFakePolicy->setPointerController(mFakePointerController);
    }
};

TEST_F(BluetoothCursorInputMapperUnitTest, TimestampSmoothening) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();
    std::list<NotifyArgs> argsList;

    nsecs_t kernelEventTime = ARBITRARY_TIME;
    nsecs_t expectedEventTime = ARBITRARY_TIME;
    argsList += process(kernelEventTime, EV_REL, REL_X, 1);
    argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();

    // Process several events that come in quick succession, according to their timestamps.
    for (int i = 0; i < 3; i++) {
        constexpr static nsecs_t delta = ms2ns(1);
        static_assert(delta < MIN_BLUETOOTH_TIMESTAMP_DELTA);
        kernelEventTime += delta;
        expectedEventTime += MIN_BLUETOOTH_TIMESTAMP_DELTA;

        argsList += process(kernelEventTime, EV_REL, REL_X, 1);
        argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
        EXPECT_THAT(argsList,
                    ElementsAre(VariantWith<NotifyMotionArgs>(
                            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                  WithEventTime(expectedEventTime)))));
        argsList.clear();
    }
}

TEST_F(BluetoothCursorInputMapperUnitTest, TimestampSmootheningIsCapped) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();
    std::list<NotifyArgs> argsList;

    nsecs_t expectedEventTime = ARBITRARY_TIME;
    argsList += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
    argsList += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();

    // Process several events with the same timestamp from the kernel.
    // Ensure that we do not generate events too far into the future.
    constexpr static int32_t numEvents =
            MAX_BLUETOOTH_SMOOTHING_DELTA / MIN_BLUETOOTH_TIMESTAMP_DELTA;
    for (int i = 0; i < numEvents; i++) {
        expectedEventTime += MIN_BLUETOOTH_TIMESTAMP_DELTA;

        argsList += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
        argsList += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
        EXPECT_THAT(argsList,
                    ElementsAre(VariantWith<NotifyMotionArgs>(
                            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                  WithEventTime(expectedEventTime)))));
        argsList.clear();
    }

    // By processing more events with the same timestamp, we should not generate events with a
    // timestamp that is more than the specified max time delta from the timestamp at its injection.
    const nsecs_t cappedEventTime = ARBITRARY_TIME + MAX_BLUETOOTH_SMOOTHING_DELTA;
    for (int i = 0; i < 3; i++) {
        argsList += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
        argsList += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
        EXPECT_THAT(argsList,
                    ElementsAre(VariantWith<NotifyMotionArgs>(
                            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                  WithEventTime(cappedEventTime)))));
        argsList.clear();
    }
}

TEST_F(BluetoothCursorInputMapperUnitTest, TimestampSmootheningNotUsed) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();
    std::list<NotifyArgs> argsList;

    nsecs_t kernelEventTime = ARBITRARY_TIME;
    nsecs_t expectedEventTime = ARBITRARY_TIME;
    argsList += process(kernelEventTime, EV_REL, REL_X, 1);
    argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();

    // If the next event has a timestamp that is sufficiently spaced out so that Bluetooth timestamp
    // smoothening is not needed, its timestamp is not affected.
    kernelEventTime += MAX_BLUETOOTH_SMOOTHING_DELTA + ms2ns(1);
    expectedEventTime = kernelEventTime;

    argsList += process(kernelEventTime, EV_REL, REL_X, 1);
    argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();
}

// --- BluetoothCursorInputMapperUnitTestWithChoreographer ---

class BluetoothCursorInputMapperUnitTestWithChoreographer : public CursorInputMapperUnitTestBase {
protected:
    void SetUp() override {
        input_flags::enable_pointer_choreographer(true);
        SetUpWithBus(BUS_BLUETOOTH);

        mFakePointerController = std::make_shared<FakePointerController>();
        mFakePolicy->setPointerController(mFakePointerController);
    }
};

TEST_F(BluetoothCursorInputMapperUnitTestWithChoreographer, TimestampSmoothening) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();
    std::list<NotifyArgs> argsList;

    nsecs_t kernelEventTime = ARBITRARY_TIME;
    nsecs_t expectedEventTime = ARBITRARY_TIME;
    argsList += process(kernelEventTime, EV_REL, REL_X, 1);
    argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();

    // Process several events that come in quick succession, according to their timestamps.
    for (int i = 0; i < 3; i++) {
        constexpr static nsecs_t delta = ms2ns(1);
        static_assert(delta < MIN_BLUETOOTH_TIMESTAMP_DELTA);
        kernelEventTime += delta;
        expectedEventTime += MIN_BLUETOOTH_TIMESTAMP_DELTA;

        argsList += process(kernelEventTime, EV_REL, REL_X, 1);
        argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
        EXPECT_THAT(argsList,
                    ElementsAre(VariantWith<NotifyMotionArgs>(
                            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                  WithEventTime(expectedEventTime)))));
        argsList.clear();
    }
}

TEST_F(BluetoothCursorInputMapperUnitTestWithChoreographer, TimestampSmootheningIsCapped) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();
    std::list<NotifyArgs> argsList;

    nsecs_t expectedEventTime = ARBITRARY_TIME;
    argsList += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
    argsList += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();

    // Process several events with the same timestamp from the kernel.
    // Ensure that we do not generate events too far into the future.
    constexpr static int32_t numEvents =
            MAX_BLUETOOTH_SMOOTHING_DELTA / MIN_BLUETOOTH_TIMESTAMP_DELTA;
    for (int i = 0; i < numEvents; i++) {
        expectedEventTime += MIN_BLUETOOTH_TIMESTAMP_DELTA;

        argsList += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
        argsList += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
        EXPECT_THAT(argsList,
                    ElementsAre(VariantWith<NotifyMotionArgs>(
                            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                  WithEventTime(expectedEventTime)))));
        argsList.clear();
    }

    // By processing more events with the same timestamp, we should not generate events with a
    // timestamp that is more than the specified max time delta from the timestamp at its injection.
    const nsecs_t cappedEventTime = ARBITRARY_TIME + MAX_BLUETOOTH_SMOOTHING_DELTA;
    for (int i = 0; i < 3; i++) {
        argsList += process(ARBITRARY_TIME, EV_REL, REL_X, 1);
        argsList += process(ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
        EXPECT_THAT(argsList,
                    ElementsAre(VariantWith<NotifyMotionArgs>(
                            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                  WithEventTime(cappedEventTime)))));
        argsList.clear();
    }
}

TEST_F(BluetoothCursorInputMapperUnitTestWithChoreographer, TimestampSmootheningNotUsed) {
    mPropertyMap.addProperty("cursor.mode", "pointer");
    createMapper();
    std::list<NotifyArgs> argsList;

    nsecs_t kernelEventTime = ARBITRARY_TIME;
    nsecs_t expectedEventTime = ARBITRARY_TIME;
    argsList += process(kernelEventTime, EV_REL, REL_X, 1);
    argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();

    // If the next event has a timestamp that is sufficiently spaced out so that Bluetooth timestamp
    // smoothening is not needed, its timestamp is not affected.
    kernelEventTime += MAX_BLUETOOTH_SMOOTHING_DELTA + ms2ns(1);
    expectedEventTime = kernelEventTime;

    argsList += process(kernelEventTime, EV_REL, REL_X, 1);
    argsList += process(kernelEventTime, EV_SYN, SYN_REPORT, 0);
    EXPECT_THAT(argsList,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                              WithEventTime(expectedEventTime)))));
    argsList.clear();
}

} // namespace android
