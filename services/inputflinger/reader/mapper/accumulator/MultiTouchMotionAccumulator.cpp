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

// clang-format off
#include "../Macros.h"
// clang-format on
#include "MultiTouchMotionAccumulator.h"

namespace android {

// --- MultiTouchMotionAccumulator ---

MultiTouchMotionAccumulator::MultiTouchMotionAccumulator()
      : mCurrentSlot(-1), mUsingSlotsProtocol(false) {}

void MultiTouchMotionAccumulator::configure(const InputDeviceContext& deviceContext,
                                            size_t slotCount, bool usingSlotsProtocol) {
    mUsingSlotsProtocol = usingSlotsProtocol;
    mSlots = std::vector<Slot>(slotCount);
    reset(deviceContext);
}

void MultiTouchMotionAccumulator::reset(const InputDeviceContext& deviceContext) {
    resetSlots();

    if (!mUsingSlotsProtocol) {
        return;
    }

    // Query the driver for the current slot index and use it as the initial slot before we
    // start reading events from the device.  It is possible that the current slot index will
    // not be the same as it was when the first event was written into the evdev buffer, which
    // means the input mapper could start out of sync with the initial state of the events in
    // the evdev buffer. In the extremely unlikely case that this happens, the data from two
    // slots will be confused until the next ABS_MT_SLOT event is received. This can cause the
    // touch point to "jump", but at least there will be no stuck touches.
    int32_t initialSlot;
    if (const auto status = deviceContext.getAbsoluteAxisValue(ABS_MT_SLOT, &initialSlot);
        status == OK) {
        mCurrentSlot = initialSlot;
    } else {
        ALOGD("Could not retrieve current multi-touch slot index. status=%d", status);
    }
}

void MultiTouchMotionAccumulator::resetSlots() {
    for (Slot& slot : mSlots) {
        slot.clear();
    }
    mCurrentSlot = -1;
}

void MultiTouchMotionAccumulator::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_ABS) {
        bool newSlot = false;
        if (mUsingSlotsProtocol) {
            if (rawEvent->code == ABS_MT_SLOT) {
                mCurrentSlot = rawEvent->value;
                newSlot = true;
            }
        } else if (mCurrentSlot < 0) {
            mCurrentSlot = 0;
        }

        if (mCurrentSlot < 0 || size_t(mCurrentSlot) >= mSlots.size()) {
            if (newSlot) {
                ALOGW_IF(DEBUG_POINTERS,
                         "MultiTouch device emitted invalid slot index %d but it "
                         "should be between 0 and %zd; ignoring this slot.",
                         mCurrentSlot, mSlots.size() - 1);
            }
        } else {
            Slot& slot = mSlots[mCurrentSlot];
            // If mUsingSlotsProtocol is true, it means the raw pointer has axis info of
            // ABS_MT_TRACKING_ID and ABS_MT_SLOT, so driver should send a valid trackingId while
            // updating the slot.
            if (!mUsingSlotsProtocol) {
                slot.mInUse = true;
            }

            switch (rawEvent->code) {
                case ABS_MT_POSITION_X:
                    slot.mAbsMtPositionX = rawEvent->value;
                    warnIfNotInUse(*rawEvent, slot);
                    break;
                case ABS_MT_POSITION_Y:
                    slot.mAbsMtPositionY = rawEvent->value;
                    warnIfNotInUse(*rawEvent, slot);
                    break;
                case ABS_MT_TOUCH_MAJOR:
                    slot.mAbsMtTouchMajor = rawEvent->value;
                    break;
                case ABS_MT_TOUCH_MINOR:
                    slot.mAbsMtTouchMinor = rawEvent->value;
                    slot.mHaveAbsMtTouchMinor = true;
                    break;
                case ABS_MT_WIDTH_MAJOR:
                    slot.mAbsMtWidthMajor = rawEvent->value;
                    break;
                case ABS_MT_WIDTH_MINOR:
                    slot.mAbsMtWidthMinor = rawEvent->value;
                    slot.mHaveAbsMtWidthMinor = true;
                    break;
                case ABS_MT_ORIENTATION:
                    slot.mAbsMtOrientation = rawEvent->value;
                    break;
                case ABS_MT_TRACKING_ID:
                    if (mUsingSlotsProtocol && rawEvent->value < 0) {
                        // The slot is no longer in use but it retains its previous contents,
                        // which may be reused for subsequent touches.
                        slot.mInUse = false;
                    } else {
                        slot.mInUse = true;
                        slot.mAbsMtTrackingId = rawEvent->value;
                    }
                    break;
                case ABS_MT_PRESSURE:
                    slot.mAbsMtPressure = rawEvent->value;
                    break;
                case ABS_MT_DISTANCE:
                    slot.mAbsMtDistance = rawEvent->value;
                    break;
                case ABS_MT_TOOL_TYPE:
                    slot.mAbsMtToolType = rawEvent->value;
                    slot.mHaveAbsMtToolType = true;
                    break;
            }
        }
    } else if (rawEvent->type == EV_SYN && rawEvent->code == SYN_MT_REPORT) {
        // MultiTouch Sync: The driver has returned all data for *one* of the pointers.
        mCurrentSlot += 1;
    }
}

void MultiTouchMotionAccumulator::finishSync() {
    if (!mUsingSlotsProtocol) {
        resetSlots();
    }
}

void MultiTouchMotionAccumulator::warnIfNotInUse(const RawEvent& event, const Slot& slot) {
    if (!slot.mInUse) {
        ALOGW("Received unexpected event (0x%0x, 0x%0x) for slot %i with tracking id %i",
              event.code, event.value, mCurrentSlot, slot.mAbsMtTrackingId);
    }
}

size_t MultiTouchMotionAccumulator::getActiveSlotsCount() const {
    if (!mUsingSlotsProtocol) {
        return mCurrentSlot < 0 ? 0 : mCurrentSlot;
    }
    return std::count_if(mSlots.begin(), mSlots.end(),
                         [](const Slot& slot) { return slot.mInUse; });
}

// --- MultiTouchMotionAccumulator::Slot ---

ToolType MultiTouchMotionAccumulator::Slot::getToolType() const {
    if (mHaveAbsMtToolType) {
        switch (mAbsMtToolType) {
            case MT_TOOL_FINGER:
                return ToolType::FINGER;
            case MT_TOOL_PEN:
                return ToolType::STYLUS;
            case MT_TOOL_PALM:
                return ToolType::PALM;
        }
    }
    return ToolType::UNKNOWN;
}

} // namespace android
