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

#include <NotifyArgs.h>
#include <utils/Timers.h>

#include <gtest/gtest.h>
#include "android/input.h"
#include "input/Input.h"
#include "input/TouchVideoFrame.h"

namespace android {

// --- NotifyArgsTest ---

/**
 * Validate basic copy assignment.
 */
TEST(NotifyMotionArgsTest, TestCopyAssignmentOperator) {
    int32_t id = 123;
    nsecs_t downTime = systemTime();
    nsecs_t eventTime = downTime++;
    nsecs_t readTime = downTime++;
    int32_t deviceId = 7;
    uint32_t source = AINPUT_SOURCE_TOUCHSCREEN;
    ui::LogicalDisplayId displayId = ui::LogicalDisplayId{42};
    uint32_t policyFlags = POLICY_FLAG_GESTURE;
    int32_t action = AMOTION_EVENT_ACTION_HOVER_MOVE;
    int32_t actionButton = AMOTION_EVENT_BUTTON_PRIMARY;
    int32_t flags = AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED;
    int32_t metaState = AMETA_SCROLL_LOCK_ON;
    uint32_t buttonState = AMOTION_EVENT_BUTTON_PRIMARY | AMOTION_EVENT_BUTTON_SECONDARY;
    MotionClassification classification = MotionClassification::DEEP_PRESS;
    int32_t edgeFlags = AMOTION_EVENT_EDGE_FLAG_TOP;
    uint32_t pointerCount = 2;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    float x = 0;
    float y = 10;

    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerProperties[i].toolType = ToolType::FINGER;

        pointerCoords[i].clear();
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, x++);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, y++);
    }

    float xPrecision = 1.2f;
    float yPrecision = 3.4f;
    float xCursorPosition = 5.6f;
    float yCursorPosition = 7.8f;

    std::vector<int16_t> videoData = {1, 2, 3, 4};
    timeval timestamp = {5, 6};
    TouchVideoFrame frame(2, 2, std::move(videoData), timestamp);
    std::vector<TouchVideoFrame> videoFrames = {frame};
    const NotifyMotionArgs args(id, eventTime, readTime, deviceId, source, displayId, policyFlags,
                                action, actionButton, flags, metaState, buttonState, classification,
                                edgeFlags, pointerCount, pointerProperties, pointerCoords,
                                xPrecision, yPrecision, xCursorPosition, yCursorPosition, downTime,
                                videoFrames);

    NotifyMotionArgs otherArgs{};
    otherArgs = args;

    EXPECT_EQ(args, otherArgs);
}

} // namespace android