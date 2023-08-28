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

#pragma once

#include <bitset>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <android/input.h>
#include <input/Input.h>
#include <utils/Timers.h>

#include "EventHub.h"
#include "InputDevice.h"
#include "accumulator/CursorButtonAccumulator.h"
#include "accumulator/MultiTouchMotionAccumulator.h"
#include "accumulator/TouchButtonAccumulator.h"

namespace android {

class CapturedTouchpadEventConverter {
public:
    explicit CapturedTouchpadEventConverter(InputReaderContext& readerContext,
                                            const InputDeviceContext& deviceContext,
                                            MultiTouchMotionAccumulator& motionAccumulator,
                                            int32_t deviceId);
    std::string dump() const;
    void populateMotionRanges(InputDeviceInfo& info) const;
    void reset();
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent& rawEvent);

private:
    void tryAddRawMotionRange(InputDeviceInfo& deviceInfo, int32_t androidAxis,
                              int32_t evdevAxis) const;
    [[nodiscard]] std::list<NotifyArgs> sync(nsecs_t when, nsecs_t readTime);
    [[nodiscard]] NotifyMotionArgs makeMotionArgs(nsecs_t when, nsecs_t readTime, int32_t action,
                                                  const std::vector<PointerCoords>& coords,
                                                  const std::vector<PointerProperties>& properties,
                                                  int32_t actionButton = 0, int32_t flags = 0);
    PointerCoords makePointerCoordsForSlot(const MultiTouchMotionAccumulator::Slot& slot) const;
    int32_t allocatePointerIdToSlot(size_t slotNumber);
    void freePointerIdForSlot(size_t slotNumber);

    const int32_t mDeviceId;
    InputReaderContext& mReaderContext;
    const InputDeviceContext& mDeviceContext;
    CursorButtonAccumulator mCursorButtonAccumulator;
    MultiTouchMotionAccumulator& mMotionAccumulator;

    float mOrientationScale = 0;
    float mPressureScale = 1;
    float mSizeScale = 0;
    bool mHasTouchMajor;
    const bool mHasTouchMinor;
    bool mHasToolMajor;
    const bool mHasToolMinor;
    nsecs_t mDownTime = 0;
    uint32_t mButtonState = 0;

    std::bitset<MAX_POINTER_ID + 1> mPointerIdsInUse;
    std::map<size_t, int32_t> mPointerIdForSlotNumber;

    static constexpr uint32_t SOURCE = AINPUT_SOURCE_TOUCHPAD;
};

} // namespace android
