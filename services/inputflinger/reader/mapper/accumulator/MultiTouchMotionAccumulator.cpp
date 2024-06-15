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
    populateCurrentSlot(deviceContext);
}

void MultiTouchMotionAccumulator::reset(const InputDeviceContext& deviceContext) {
    resetSlots();
    syncSlots(deviceContext);
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
            if (rawEvent->code == ABS_MT_POSITION_X || rawEvent->code == ABS_MT_POSITION_Y) {
                warnIfNotInUse(*rawEvent, slot);
            }
            slot.populateAxisValue(rawEvent->code, rawEvent->value);
        }
    } else if (rawEvent->type == EV_SYN && rawEvent->code == SYN_MT_REPORT) {
        // MultiTouch Sync: The driver has returned all data for *one* of the pointers.
        mCurrentSlot += 1;
    }
}

void MultiTouchMotionAccumulator::syncSlots(const InputDeviceContext& deviceContext) {
    if (!mUsingSlotsProtocol) {
        return;
    }
    constexpr std::array<int32_t, 11> axisCodes = {ABS_MT_POSITION_X,  ABS_MT_POSITION_Y,
                                                   ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR,
                                                   ABS_MT_WIDTH_MAJOR, ABS_MT_WIDTH_MINOR,
                                                   ABS_MT_ORIENTATION, ABS_MT_TRACKING_ID,
                                                   ABS_MT_PRESSURE,    ABS_MT_DISTANCE,
                                                   ABS_MT_TOOL_TYPE};
    const size_t numSlots = mSlots.size();
    for (int32_t axisCode : axisCodes) {
        if (!deviceContext.hasAbsoluteAxis(axisCode)) {
            continue;
        }
        const auto result = deviceContext.getMtSlotValues(axisCode, numSlots);
        if (result.ok()) {
            const std::vector<int32_t>& mtSlotValues = result.value();
            for (size_t i = 1; i <= numSlots; ++i) {
                // The returned slot values are in a 1-indexed vector of size numSlots + 1.
                mSlots[i - 1].populateAxisValue(axisCode, mtSlotValues[i]);
            }
        } else {
            ALOGE("Could not retrieve multi-touch slot value for axis=%d error=%s status=%d",
                  axisCode, result.error().message().c_str(), result.error().code().value());
        }
    }
    populateCurrentSlot(deviceContext);
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

void MultiTouchMotionAccumulator::populateCurrentSlot(
        const android::InputDeviceContext& deviceContext) {
    if (!mUsingSlotsProtocol) {
        return;
    }
    int32_t initialSlot;
    if (const auto status = deviceContext.getAbsoluteAxisValue(ABS_MT_SLOT, &initialSlot);
        status == OK) {
        mCurrentSlot = initialSlot;
    } else {
        ALOGE("Could not retrieve current multi-touch slot index. status=%s",
              statusToString(status).c_str());
    }
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

void MultiTouchMotionAccumulator::Slot::populateAxisValue(int32_t axisCode, int32_t value) {
    switch (axisCode) {
        case ABS_MT_POSITION_X:
            mAbsMtPositionX = value;
            break;
        case ABS_MT_POSITION_Y:
            mAbsMtPositionY = value;
            break;
        case ABS_MT_TOUCH_MAJOR:
            mAbsMtTouchMajor = value;
            break;
        case ABS_MT_TOUCH_MINOR:
            mAbsMtTouchMinor = value;
            mHaveAbsMtTouchMinor = true;
            break;
        case ABS_MT_WIDTH_MAJOR:
            mAbsMtWidthMajor = value;
            break;
        case ABS_MT_WIDTH_MINOR:
            mAbsMtWidthMinor = value;
            mHaveAbsMtWidthMinor = true;
            break;
        case ABS_MT_ORIENTATION:
            mAbsMtOrientation = value;
            break;
        case ABS_MT_TRACKING_ID:
            if (value < 0) {
                // The slot is no longer in use but it retains its previous contents,
                // which may be reused for subsequent touches.
                mInUse = false;
            } else {
                mInUse = true;
                mAbsMtTrackingId = value;
            }
            break;
        case ABS_MT_PRESSURE:
            mAbsMtPressure = value;
            break;
        case ABS_MT_DISTANCE:
            mAbsMtDistance = value;
            break;
        case ABS_MT_TOOL_TYPE:
            mAbsMtToolType = value;
            mHaveAbsMtToolType = true;
            break;
    }
}

} // namespace android
