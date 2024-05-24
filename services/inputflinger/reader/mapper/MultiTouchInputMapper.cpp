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

#include "../Macros.h"

#include <android/sysprop/InputProperties.sysprop.h>
#include "MultiTouchInputMapper.h"

namespace android {

// --- Constants ---

// Maximum number of slots supported when using the slot-based Multitouch Protocol B.
static constexpr size_t MAX_SLOTS = 32;

// --- MultiTouchInputMapper ---

MultiTouchInputMapper::MultiTouchInputMapper(InputDeviceContext& deviceContext,
                                             const InputReaderConfiguration& readerConfig)
      : TouchInputMapper(deviceContext, readerConfig) {}

MultiTouchInputMapper::~MultiTouchInputMapper() {}

std::list<NotifyArgs> MultiTouchInputMapper::reset(nsecs_t when) {
    mPointerIdBits.clear();
    mMultiTouchMotionAccumulator.reset(mDeviceContext);
    return TouchInputMapper::reset(when);
}

std::list<NotifyArgs> MultiTouchInputMapper::process(const RawEvent* rawEvent) {
    std::list<NotifyArgs> out = TouchInputMapper::process(rawEvent);

    mMultiTouchMotionAccumulator.process(rawEvent);
    return out;
}

std::optional<int32_t> MultiTouchInputMapper::getActiveBitId(
        const MultiTouchMotionAccumulator::Slot& inSlot) {
    if (mHavePointerIds) {
        int32_t trackingId = inSlot.getTrackingId();
        for (BitSet32 idBits(mPointerIdBits); !idBits.isEmpty();) {
            int32_t n = idBits.clearFirstMarkedBit();
            if (mPointerTrackingIdMap[n] == trackingId) {
                return std::make_optional(n);
            }
        }
    }
    return std::nullopt;
}

void MultiTouchInputMapper::syncTouch(nsecs_t when, RawState* outState) {
    size_t inCount = mMultiTouchMotionAccumulator.getSlotCount();
    size_t outCount = 0;
    BitSet32 newPointerIdBits;
    mHavePointerIds = true;

    for (size_t inIndex = 0; inIndex < inCount; inIndex++) {
        const MultiTouchMotionAccumulator::Slot& inSlot =
                mMultiTouchMotionAccumulator.getSlot(inIndex);
        if (!inSlot.isInUse()) {
            continue;
        }

        if (inSlot.getToolType() == ToolType::PALM) {
            std::optional<int32_t> id = getActiveBitId(inSlot);
            if (id) {
                outState->rawPointerData.canceledIdBits.markBit(id.value());
            }
            if (DEBUG_POINTERS) {
                ALOGI("Stop processing slot %zu for it received a palm event from device %s",
                      inIndex, getDeviceName().c_str());
            }
            continue;
        }

        if (outCount >= MAX_POINTERS) {
            if (DEBUG_POINTERS) {
                ALOGD("MultiTouch device %s emitted more than maximum of %zu pointers; "
                      "ignoring the rest.",
                      getDeviceName().c_str(), MAX_POINTERS);
            }
            break; // too many fingers!
        }

        RawPointerData::Pointer& outPointer = outState->rawPointerData.pointers[outCount];
        outPointer.x = inSlot.getX();
        outPointer.y = inSlot.getY();
        outPointer.pressure = inSlot.getPressure();
        outPointer.touchMajor = inSlot.getTouchMajor();
        outPointer.touchMinor = inSlot.getTouchMinor();
        outPointer.toolMajor = inSlot.getToolMajor();
        outPointer.toolMinor = inSlot.getToolMinor();
        outPointer.orientation = inSlot.getOrientation();
        outPointer.distance = inSlot.getDistance();
        outPointer.tiltX = 0;
        outPointer.tiltY = 0;

        outPointer.toolType = inSlot.getToolType();
        if (outPointer.toolType == ToolType::UNKNOWN) {
            outPointer.toolType = mTouchButtonAccumulator.getToolType();
            if (outPointer.toolType == ToolType::UNKNOWN) {
                outPointer.toolType = ToolType::FINGER;
            }
        } else if (outPointer.toolType == ToolType::STYLUS && !mStylusMtToolSeen) {
            mStylusMtToolSeen = true;
            // The multi-touch device produced a stylus event with MT_TOOL_PEN. Dynamically
            // re-configure this input device so that we add SOURCE_STYLUS if we haven't already.
            // This is to cover the case where we cannot reliably detect whether a multi-touch
            // device will ever produce stylus events when it is initially being configured.
            if (!isFromSource(mSource, AINPUT_SOURCE_STYLUS)) {
                // Add the stylus source immediately so that it is included in any events generated
                // before we have a chance to re-configure the device.
                mSource |= AINPUT_SOURCE_STYLUS;
                bumpGeneration();
            }
        }
        if (mShouldSimulateStylusWithTouch && outPointer.toolType == ToolType::FINGER) {
            outPointer.toolType = ToolType::STYLUS;
        }

        bool isHovering = mTouchButtonAccumulator.getToolType() != ToolType::MOUSE &&
                (mTouchButtonAccumulator.isHovering() ||
                 (mRawPointerAxes.pressure.valid && inSlot.getPressure() <= 0));
        outPointer.isHovering = isHovering;

        // Assign pointer id using tracking id if available.
        if (mHavePointerIds) {
            const int32_t trackingId = inSlot.getTrackingId();
            int32_t id = -1;
            if (trackingId >= 0) {
                for (BitSet32 idBits(mPointerIdBits); !idBits.isEmpty();) {
                    uint32_t n = idBits.clearFirstMarkedBit();
                    if (mPointerTrackingIdMap[n] == trackingId) {
                        id = n;
                        break;
                    }
                }

                if (id < 0 && !mPointerIdBits.isFull()) {
                    id = mPointerIdBits.markFirstUnmarkedBit();
                    mPointerTrackingIdMap[id] = trackingId;
                }
            }
            if (id < 0) {
                mHavePointerIds = false;
                outState->rawPointerData.clearIdBits();
                newPointerIdBits.clear();
            } else {
                outPointer.id = id;
                outState->rawPointerData.idToIndex[id] = outCount;
                outState->rawPointerData.markIdBit(id, isHovering);
                newPointerIdBits.markBit(id);
            }
        }
        outCount += 1;
    }

    outState->rawPointerData.pointerCount = outCount;
    mPointerIdBits = newPointerIdBits;

    mMultiTouchMotionAccumulator.finishSync();
}

std::list<NotifyArgs> MultiTouchInputMapper::reconfigure(nsecs_t when,
                                                         const InputReaderConfiguration& config,
                                                         ConfigurationChanges changes) {
    const bool simulateStylusWithTouch =
            sysprop::InputProperties::simulate_stylus_with_touch().value_or(false);
    if (simulateStylusWithTouch != mShouldSimulateStylusWithTouch) {
        mShouldSimulateStylusWithTouch = simulateStylusWithTouch;
        bumpGeneration();
    }
    return TouchInputMapper::reconfigure(when, config, changes);
}

void MultiTouchInputMapper::configureRawPointerAxes() {
    TouchInputMapper::configureRawPointerAxes();

    getAbsoluteAxisInfo(ABS_MT_POSITION_X, &mRawPointerAxes.x);
    getAbsoluteAxisInfo(ABS_MT_POSITION_Y, &mRawPointerAxes.y);
    getAbsoluteAxisInfo(ABS_MT_TOUCH_MAJOR, &mRawPointerAxes.touchMajor);
    getAbsoluteAxisInfo(ABS_MT_TOUCH_MINOR, &mRawPointerAxes.touchMinor);
    getAbsoluteAxisInfo(ABS_MT_WIDTH_MAJOR, &mRawPointerAxes.toolMajor);
    getAbsoluteAxisInfo(ABS_MT_WIDTH_MINOR, &mRawPointerAxes.toolMinor);
    getAbsoluteAxisInfo(ABS_MT_ORIENTATION, &mRawPointerAxes.orientation);
    getAbsoluteAxisInfo(ABS_MT_PRESSURE, &mRawPointerAxes.pressure);
    getAbsoluteAxisInfo(ABS_MT_DISTANCE, &mRawPointerAxes.distance);
    getAbsoluteAxisInfo(ABS_MT_TRACKING_ID, &mRawPointerAxes.trackingId);
    getAbsoluteAxisInfo(ABS_MT_SLOT, &mRawPointerAxes.slot);

    if (mRawPointerAxes.trackingId.valid && mRawPointerAxes.slot.valid &&
        mRawPointerAxes.slot.minValue == 0 && mRawPointerAxes.slot.maxValue > 0) {
        size_t slotCount = mRawPointerAxes.slot.maxValue + 1;
        if (slotCount > MAX_SLOTS) {
            ALOGW("MultiTouch Device %s reported %zu slots but the framework "
                  "only supports a maximum of %zu slots at this time.",
                  getDeviceName().c_str(), slotCount, MAX_SLOTS);
            slotCount = MAX_SLOTS;
        }
        mMultiTouchMotionAccumulator.configure(getDeviceContext(), slotCount,
                                               /*usingSlotsProtocol=*/true);
    } else {
        mMultiTouchMotionAccumulator.configure(getDeviceContext(), MAX_POINTERS,
                                               /*usingSlotsProtocol=*/false);
    }
}

bool MultiTouchInputMapper::hasStylus() const {
    return mStylusMtToolSeen || mTouchButtonAccumulator.hasStylus() ||
            mShouldSimulateStylusWithTouch;
}

} // namespace android
