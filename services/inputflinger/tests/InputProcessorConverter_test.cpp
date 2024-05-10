/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "../InputCommonConverter.h"

#include <gtest/gtest.h>
#include <utils/BitSet.h>

using namespace aidl::android::hardware::input;

namespace android {

// --- InputProcessorConverterTest ---

static NotifyMotionArgs generateBasicMotionArgs() {
    // Create a basic motion event for testing
    PointerProperties properties;
    properties.id = 0;
    properties.toolType = ToolType::FINGER;

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, 1);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, 2);
    coords.setAxisValue(AMOTION_EVENT_AXIS_SIZE, 0.5);
    static constexpr nsecs_t downTime = 2;
    NotifyMotionArgs motionArgs(/*sequenceNum=*/1, /*eventTime=*/downTime, /*readTime=*/2,
                                /*deviceId=*/3, AINPUT_SOURCE_ANY, ui::LogicalDisplayId::DEFAULT,
                                /*policyFlags=*/4, AMOTION_EVENT_ACTION_DOWN, /*actionButton=*/0,
                                /*flags=*/0, AMETA_NONE, /*buttonState=*/0,
                                MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE,
                                /*pointerCount=*/1, &properties, &coords, /*xPrecision=*/0,
                                /*yPrecision=*/0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                AMOTION_EVENT_INVALID_CURSOR_POSITION, downTime,
                                /*videoFrames=*/{});
    return motionArgs;
}

static float getMotionEventAxis(common::PointerCoords coords, common::Axis axis) {
    uint32_t index = BitSet64::getIndexOfBit(static_cast<uint64_t>(coords.bits),
                                             static_cast<uint64_t>(axis));
    return coords.values[index];
}

/**
 * Check that coordinates get converted properly from the framework's PointerCoords
 * to the hidl PointerCoords in input::common.
 */
TEST(InputProcessorConverterTest, PointerCoordsAxes) {
    const NotifyMotionArgs motionArgs = generateBasicMotionArgs();
    ASSERT_EQ(1, motionArgs.pointerCoords[0].getX());
    ASSERT_EQ(2, motionArgs.pointerCoords[0].getY());
    ASSERT_EQ(0.5, motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_SIZE));
    ASSERT_EQ(3U, BitSet64::count(motionArgs.pointerCoords[0].bits));

    common::MotionEvent motionEvent = notifyMotionArgsToHalMotionEvent(motionArgs);

    ASSERT_EQ(getMotionEventAxis(motionEvent.pointerCoords[0], common::Axis::X),
              motionArgs.pointerCoords[0].getX());
    ASSERT_EQ(getMotionEventAxis(motionEvent.pointerCoords[0], common::Axis::Y),
              motionArgs.pointerCoords[0].getY());
    ASSERT_EQ(getMotionEventAxis(motionEvent.pointerCoords[0], common::Axis::SIZE),
              motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_SIZE));
    ASSERT_EQ(BitSet64::count(motionArgs.pointerCoords[0].bits),
              BitSet64::count(motionEvent.pointerCoords[0].bits));
}

} // namespace android
