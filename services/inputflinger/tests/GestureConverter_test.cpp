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

#include <memory>

#include <EventHub.h>
#include <gestures/GestureConverter.h>
#include <gtest/gtest.h>

#include "FakeEventHub.h"
#include "FakeInputReaderPolicy.h"
#include "FakePointerController.h"
#include "InstrumentedInputReader.h"
#include "NotifyArgs.h"
#include "TestConstants.h"
#include "TestInputListener.h"
#include "TestInputListenerMatchers.h"
#include "include/gestures.h"

namespace android {

using testing::AllOf;

class GestureConverterTest : public testing::Test {
protected:
    static constexpr int32_t DEVICE_ID = END_RESERVED_ID + 1000;
    static constexpr stime_t ARBITRARY_GESTURE_TIME = 1.2;
    static constexpr float POINTER_X = 100;
    static constexpr float POINTER_Y = 200;

    void SetUp() {
        mFakeEventHub = std::make_unique<FakeEventHub>();
        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        mFakeListener = std::make_unique<TestInputListener>();
        mReader = std::make_unique<InstrumentedInputReader>(mFakeEventHub, mFakePolicy,
                                                            *mFakeListener);

        mFakePointerController = std::make_shared<FakePointerController>();
        mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
        mFakePointerController->setPosition(POINTER_X, POINTER_Y);
        mFakePolicy->setPointerController(mFakePointerController);
    }

    std::shared_ptr<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    std::unique_ptr<TestInputListener> mFakeListener;
    std::unique_ptr<InstrumentedInputReader> mReader;
    std::shared_ptr<FakePointerController> mFakePointerController;
};

TEST_F(GestureConverterTest, Move) {
    GestureConverter converter(*mReader->getContext(), DEVICE_ID);

    Gesture moveGesture(kGestureMove, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME, -5, 10);
    std::list<NotifyArgs> args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, moveGesture);
    ASSERT_EQ(1u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                      WithCoords(POINTER_X - 5, POINTER_Y + 10), WithRelativeMotion(-5, 10),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER), WithButtonState(0),
                      WithPressure(0.0f)));

    ASSERT_NO_FATAL_FAILURE(mFakePointerController->assertPosition(95, 210));
}

TEST_F(GestureConverterTest, ButtonsChange) {
    GestureConverter converter(*mReader->getContext(), DEVICE_ID);

    // Press left and right buttons at once
    Gesture downGesture(kGestureButtonsChange, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME,
                        /* down= */ GESTURES_BUTTON_LEFT | GESTURES_BUTTON_RIGHT,
                        /* up= */ GESTURES_BUTTON_NONE, /* is_tap= */ false);
    std::list<NotifyArgs> args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, downGesture);
    ASSERT_EQ(3u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY |
                                      AMOTION_EVENT_BUTTON_SECONDARY),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
    args.pop_front();
    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                      WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
    args.pop_front();
    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                      WithActionButton(AMOTION_EVENT_BUTTON_SECONDARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY |
                                      AMOTION_EVENT_BUTTON_SECONDARY),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));

    // Then release the left button
    Gesture leftUpGesture(kGestureButtonsChange, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME,
                          /* down= */ GESTURES_BUTTON_NONE, /* up= */ GESTURES_BUTTON_LEFT,
                          /* is_tap= */ false);
    args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, leftUpGesture);
    ASSERT_EQ(1u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                      WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_SECONDARY),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));

    // Finally release the right button
    Gesture rightUpGesture(kGestureButtonsChange, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME,
                           /* down= */ GESTURES_BUTTON_NONE, /* up= */ GESTURES_BUTTON_RIGHT,
                           /* is_tap= */ false);
    args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, rightUpGesture);
    ASSERT_EQ(2u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                      WithActionButton(AMOTION_EVENT_BUTTON_SECONDARY), WithButtonState(0),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
    args.pop_front();
    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithButtonState(0),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
}

TEST_F(GestureConverterTest, DragWithButton) {
    GestureConverter converter(*mReader->getContext(), DEVICE_ID);

    // Press the button
    Gesture downGesture(kGestureButtonsChange, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME,
                        /* down= */ GESTURES_BUTTON_LEFT, /* up= */ GESTURES_BUTTON_NONE,
                        /* is_tap= */ false);
    std::list<NotifyArgs> args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, downGesture);
    ASSERT_EQ(2u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
    args.pop_front();
    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                      WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY),
                      WithCoords(POINTER_X, POINTER_Y),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));

    // Move
    Gesture moveGesture(kGestureMove, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME, -5, 10);
    args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, moveGesture);
    ASSERT_EQ(1u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                      WithCoords(POINTER_X - 5, POINTER_Y + 10), WithRelativeMotion(-5, 10),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER),
                      WithButtonState(AMOTION_EVENT_BUTTON_PRIMARY), WithPressure(1.0f)));

    ASSERT_NO_FATAL_FAILURE(mFakePointerController->assertPosition(95, 210));

    // Release the button
    Gesture upGesture(kGestureButtonsChange, ARBITRARY_GESTURE_TIME, ARBITRARY_GESTURE_TIME,
                      /* down= */ GESTURES_BUTTON_NONE, /* up= */ GESTURES_BUTTON_LEFT,
                      /* is_tap= */ false);
    args = converter.handleGesture(ARBITRARY_TIME, READ_TIME, upGesture);
    ASSERT_EQ(2u, args.size());

    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                      WithActionButton(AMOTION_EVENT_BUTTON_PRIMARY), WithButtonState(0),
                      WithCoords(POINTER_X - 5, POINTER_Y + 10),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
    args.pop_front();
    ASSERT_THAT(std::get<NotifyMotionArgs>(args.front()),
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithButtonState(0),
                      WithCoords(POINTER_X - 5, POINTER_Y + 10),
                      WithToolType(AMOTION_EVENT_TOOL_TYPE_FINGER)));
}

} // namespace android
