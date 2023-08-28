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
#include <gtest/gtest.h>

#include "FakePointerController.h"
#include "InputMapperTest.h"
#include "InterfaceMocks.h"
#include "TestInputListenerMatchers.h"

#define TAG "CursorInputMapper_test"

namespace android {

using testing::Return;
using testing::VariantWith;
constexpr auto ACTION_DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr auto ACTION_MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr auto ACTION_UP = AMOTION_EVENT_ACTION_UP;
constexpr auto BUTTON_PRESS = AMOTION_EVENT_ACTION_BUTTON_PRESS;
constexpr auto BUTTON_RELEASE = AMOTION_EVENT_ACTION_BUTTON_RELEASE;
constexpr auto HOVER_MOVE = AMOTION_EVENT_ACTION_HOVER_MOVE;

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

        EXPECT_CALL(mMockInputReaderContext, bumpGeneration()).WillRepeatedly(Return(1));

        mMapper = createInputMapper<CursorInputMapper>(*mDeviceContext, mReaderConfiguration);
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

} // namespace android
