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
constexpr int32_t STYLUS_DEVICE_ID = 4;

constexpr int DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr int MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr int UP = AMOTION_EVENT_ACTION_UP;
constexpr int CANCEL = AMOTION_EVENT_ACTION_CANCEL;
constexpr int32_t TOUCHSCREEN = AINPUT_SOURCE_TOUCHSCREEN;
constexpr int32_t STYLUS = AINPUT_SOURCE_STYLUS;

struct PointerData {
    float x;
    float y;
};

static NotifyMotionArgs generateMotionArgs(nsecs_t downTime, nsecs_t eventTime, int32_t action,
                                           const std::vector<PointerData>& points,
                                           uint32_t source) {
    size_t pointerCount = points.size();
    if (action == DOWN || action == UP) {
        EXPECT_EQ(1U, pointerCount) << "Actions DOWN and UP can only contain a single pointer";
    }

    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    const int32_t deviceId = isFromSource(source, TOUCHSCREEN) ? TOUCH_DEVICE_ID : STYLUS_DEVICE_ID;
    const int32_t toolType = isFromSource(source, TOUCHSCREEN) ? AMOTION_EVENT_TOOL_TYPE_FINGER
                                                               : AMOTION_EVENT_TOOL_TYPE_STYLUS;
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
    NotifyMotionArgs args(/* id */ 0, eventTime, 0 /*readTime*/, deviceId, source, 0 /*displayId*/,
                          POLICY_FLAG_PASS_TO_USER, action, /* actionButton */ 0,
                          /* flags */ 0, AMETA_NONE, /* buttonState */ 0,
                          MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount,
                          pointerProperties, pointerCoords, /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, downTime, /* videoFrames */ {});

    return args;
}

class PreferStylusOverTouchTest : public testing::Test {
protected:
    void assertNotBlocked(const NotifyMotionArgs& args) {
        ftl::StaticVector<NotifyMotionArgs, 2> processedArgs = mBlocker.processMotion(args);
        ASSERT_EQ(1u, processedArgs.size());
        ASSERT_EQ(args, processedArgs[0]);
    }

    void assertDropped(const NotifyMotionArgs& args) {
        ftl::StaticVector<NotifyMotionArgs, 2> processedArgs = mBlocker.processMotion(args);
        ASSERT_TRUE(processedArgs.empty());
    }

    void assertCanceled(const NotifyMotionArgs& args,
                        std::optional<NotifyMotionArgs> canceledArgs) {
        ftl::StaticVector<NotifyMotionArgs, 2> processedArgs = mBlocker.processMotion(args);
        ASSERT_EQ(2u, processedArgs.size());
        NotifyMotionArgs& cancelEvent = processedArgs[0];
        ASSERT_EQ(CANCEL, cancelEvent.action);
        ASSERT_EQ(AMOTION_EVENT_FLAG_CANCELED, cancelEvent.flags & AMOTION_EVENT_FLAG_CANCELED);
        ASSERT_TRUE(isFromSource(cancelEvent.source, TOUCHSCREEN));
        ASSERT_FALSE(isFromSource(cancelEvent.source, STYLUS));

        ASSERT_EQ(args, processedArgs[1]);
    }

private:
    PreferStylusOverTouchBlocker mBlocker;
};

TEST_F(PreferStylusOverTouchTest, TouchGestureIsNotBlocked) {
    NotifyMotionArgs args;

    args = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, UP, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);
}

TEST_F(PreferStylusOverTouchTest, StylusGestureIsNotBlocked) {
    NotifyMotionArgs args;

    args = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, MOVE, {{1, 3}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(0 /*downTime*/, 2 /*eventTime*/, UP, {{1, 3}}, STYLUS);
    assertNotBlocked(args);
}

/**
 * Existing touch gesture should be canceled when stylus goes down. There should be an ACTION_CANCEL
 * event generated.
 */
TEST_F(PreferStylusOverTouchTest, TouchIsCanceledWhenStylusGoesDown) {
    NotifyMotionArgs args;

    args = generateMotionArgs(0 /*downTime*/, 0 /*eventTime*/, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(3 /*downTime*/, 3 /*eventTime*/, DOWN, {{10, 30}}, STYLUS);
    NotifyMotionArgs cancelArgs =
            generateMotionArgs(0 /*downTime*/, 1 /*eventTime*/, CANCEL, {{1, 3}}, TOUCHSCREEN);
    assertCanceled(args, cancelArgs);

    // Both stylus and touch events continue. Stylus should be not blocked, and touch should be
    // blocked
    args = generateMotionArgs(3 /*downTime*/, 4 /*eventTime*/, MOVE, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(0 /*downTime*/, 5 /*eventTime*/, MOVE, {{1, 4}}, TOUCHSCREEN);
    assertDropped(args);
}

/**
 * New touch events should be simply blocked (dropped) when stylus is down. No CANCEL event should
 * be generated.
 */
TEST_F(PreferStylusOverTouchTest, NewTouchIsBlockedWhenStylusIsDown) {
    NotifyMotionArgs args;
    constexpr nsecs_t stylusDownTime = 0;
    constexpr nsecs_t touchDownTime = 1;

    args = generateMotionArgs(stylusDownTime, 0 /*eventTime*/, DOWN, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(touchDownTime, 1 /*eventTime*/, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertDropped(args);

    // Stylus should continue to work
    args = generateMotionArgs(stylusDownTime, 2 /*eventTime*/, MOVE, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    // Touch should continue to be blocked
    args = generateMotionArgs(touchDownTime, 1 /*eventTime*/, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertDropped(args);

    args = generateMotionArgs(0 /*downTime*/, 5 /*eventTime*/, MOVE, {{1, 4}}, TOUCHSCREEN);
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
    args = generateMotionArgs(stylusDownTime, 0 /*eventTime*/, DOWN, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(stylusDownTime, 2 /*eventTime*/, MOVE, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    args = generateMotionArgs(stylusDownTime, 3 /*eventTime*/, UP, {{10, 31}}, STYLUS);
    assertNotBlocked(args);

    // New touch goes down. It should not be blocked
    args = generateMotionArgs(touchDownTime, touchDownTime, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(touchDownTime, 5 /*eventTime*/, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertNotBlocked(args);

    args = generateMotionArgs(touchDownTime, 6 /*eventTime*/, UP, {{1, 3}}, TOUCHSCREEN);
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

    assertNotBlocked(generateMotionArgs(stylusDownTime, 0 /*eventTime*/, DOWN, {{10, 30}}, STYLUS));

    args = generateMotionArgs(touchDownTime, 1 /*eventTime*/, DOWN, {{1, 2}}, TOUCHSCREEN);
    assertDropped(args);

    // Lift the stylus
    args = generateMotionArgs(stylusDownTime, 2 /*eventTime*/, UP, {{10, 30}}, STYLUS);
    assertNotBlocked(args);

    // Touch should continue to be blocked
    args = generateMotionArgs(touchDownTime, 3 /*eventTime*/, MOVE, {{1, 3}}, TOUCHSCREEN);
    assertDropped(args);

    args = generateMotionArgs(touchDownTime, 4 /*eventTime*/, UP, {{1, 3}}, TOUCHSCREEN);
    assertDropped(args);

    // New touch should go through, though.
    constexpr nsecs_t newTouchDownTime = 5;
    args = generateMotionArgs(newTouchDownTime, 5 /*eventTime*/, DOWN, {{10, 20}}, TOUCHSCREEN);
    assertNotBlocked(args);
}

} // namespace android
