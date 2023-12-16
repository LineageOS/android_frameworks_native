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

#include <android-base/logging.h>
#include <com_android_input_flags.h>
#include <gtest/gtest.h>

#include "FakePointerController.h"
#include "InputMapperTest.h"
#include "InterfaceMocks.h"
#include "TestEventMatchers.h"

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
constexpr int32_t DISPLAY_WIDTH = 480;
constexpr int32_t DISPLAY_HEIGHT = 800;
constexpr std::optional<uint8_t> NO_PORT = std::nullopt; // no physical port is specified

namespace input_flags = com::android::input::flags;

/**
 * Unit tests for CursorInputMapper.
 * This class is named 'CursorInputMapperUnitTest' to avoid name collision with the existing
 * 'CursorInputMapperTest'. If all of the CursorInputMapper tests are migrated here, the name
 * can be simplified to 'CursorInputMapperTest'.
 * TODO(b/283812079): move CursorInputMapper tests here.
 */
class CursorInputMapperUnitTest : public InputMapperUnitTest {
protected:
    void SetUp() override {
        InputMapperUnitTest::SetUp();

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
                    ElementsAre(
                            VariantWith<NotifyDeviceResetArgs>(AllOf(WithDeviceId(DEVICE_ID)))));

        // Check that generation also got bumped
        ASSERT_GT(mDevice->getGeneration(), generation);
    }
};

/**
 * Move the mouse and then click the button. Check whether HOVER_EXIT is generated when hovering
 * ends. Currently, it is not.
 */
TEST_F(CursorInputMapperUnitTest, HoverAndLeftButtonPress) {
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

} // namespace android
