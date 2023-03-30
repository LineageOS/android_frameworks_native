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

// clang-format off
#include "../Macros.h"
// clang-format on
#include "gestures/HardwareStateConverter.h"

#include <chrono>
#include <vector>

#include <linux/input-event-codes.h>

namespace android {

HardwareStateConverter::HardwareStateConverter(const InputDeviceContext& deviceContext)
      : mDeviceContext(deviceContext), mTouchButtonAccumulator(deviceContext) {
    RawAbsoluteAxisInfo slotAxisInfo;
    deviceContext.getAbsoluteAxisInfo(ABS_MT_SLOT, &slotAxisInfo);
    if (!slotAxisInfo.valid || slotAxisInfo.maxValue <= 0) {
        ALOGW("Touchpad \"%s\" doesn't have a valid ABS_MT_SLOT axis, and probably won't work "
              "properly.",
              deviceContext.getName().c_str());
    }
    mMotionAccumulator.configure(deviceContext, slotAxisInfo.maxValue + 1, true);
    mTouchButtonAccumulator.configure();
}

std::optional<SelfContainedHardwareState> HardwareStateConverter::processRawEvent(
        const RawEvent* rawEvent) {
    std::optional<SelfContainedHardwareState> out;
    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        out = produceHardwareState(rawEvent->when);
        mMotionAccumulator.finishSync();
        mMscTimestamp = 0;
    }
    if (rawEvent->type == EV_MSC && rawEvent->code == MSC_TIMESTAMP) {
        mMscTimestamp = rawEvent->value;
    }
    mCursorButtonAccumulator.process(rawEvent);
    mMotionAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);
    return out;
}

SelfContainedHardwareState HardwareStateConverter::produceHardwareState(nsecs_t when) {
    SelfContainedHardwareState schs;
    // The gestures library uses doubles to represent timestamps in seconds.
    schs.state.timestamp = std::chrono::duration<stime_t>(std::chrono::nanoseconds(when)).count();
    schs.state.msc_timestamp =
            std::chrono::duration<stime_t>(std::chrono::microseconds(mMscTimestamp)).count();

    schs.state.buttons_down = 0;
    if (mCursorButtonAccumulator.isLeftPressed()) {
        schs.state.buttons_down |= GESTURES_BUTTON_LEFT;
    }
    if (mCursorButtonAccumulator.isMiddlePressed()) {
        schs.state.buttons_down |= GESTURES_BUTTON_MIDDLE;
    }
    if (mCursorButtonAccumulator.isRightPressed()) {
        schs.state.buttons_down |= GESTURES_BUTTON_RIGHT;
    }
    if (mCursorButtonAccumulator.isBackPressed() || mCursorButtonAccumulator.isSidePressed()) {
        schs.state.buttons_down |= GESTURES_BUTTON_BACK;
    }
    if (mCursorButtonAccumulator.isForwardPressed() || mCursorButtonAccumulator.isExtraPressed()) {
        schs.state.buttons_down |= GESTURES_BUTTON_FORWARD;
    }

    schs.fingers.clear();
    size_t numPalms = 0;
    for (size_t i = 0; i < mMotionAccumulator.getSlotCount(); i++) {
        MultiTouchMotionAccumulator::Slot slot = mMotionAccumulator.getSlot(i);
        if (!slot.isInUse()) {
            continue;
        }
        // Some touchpads continue to report contacts even after they've identified them as palms.
        // We want to exclude these contacts from the HardwareStates.
        if (slot.getToolType() == ToolType::PALM) {
            numPalms++;
            continue;
        }

        FingerState& fingerState = schs.fingers.emplace_back();
        fingerState = {};
        fingerState.touch_major = slot.getTouchMajor();
        fingerState.touch_minor = slot.getTouchMinor();
        fingerState.width_major = slot.getToolMajor();
        fingerState.width_minor = slot.getToolMinor();
        fingerState.pressure = slot.getPressure();
        fingerState.orientation = slot.getOrientation();
        fingerState.position_x = slot.getX();
        fingerState.position_y = slot.getY();
        fingerState.tracking_id = slot.getTrackingId();
    }
    schs.state.fingers = schs.fingers.data();
    schs.state.finger_cnt = schs.fingers.size();
    schs.state.touch_cnt = mTouchButtonAccumulator.getTouchCount() - numPalms;
    return schs;
}

void HardwareStateConverter::reset() {
    mCursorButtonAccumulator.reset(mDeviceContext);
    mTouchButtonAccumulator.reset();
    mMscTimestamp = 0;
}

} // namespace android
