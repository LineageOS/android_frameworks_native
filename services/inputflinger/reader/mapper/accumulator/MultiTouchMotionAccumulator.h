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

#pragma once

#include <linux/input-event-codes.h>
#include <stdint.h>
#include <vector>

#include "EventHub.h"
#include "InputDevice.h"

namespace android {

/* Keeps track of the state of multi-touch protocol. */
class MultiTouchMotionAccumulator {
public:
    class Slot {
    public:
        inline bool isInUse() const { return mInUse; }
        inline int32_t getX() const { return mAbsMtPositionX; }
        inline int32_t getY() const { return mAbsMtPositionY; }
        inline int32_t getTouchMajor() const { return mAbsMtTouchMajor; }
        inline int32_t getTouchMinor() const {
            return mHaveAbsMtTouchMinor ? mAbsMtTouchMinor : mAbsMtTouchMajor;
        }
        inline int32_t getToolMajor() const { return mAbsMtWidthMajor; }
        inline int32_t getToolMinor() const {
            return mHaveAbsMtWidthMinor ? mAbsMtWidthMinor : mAbsMtWidthMajor;
        }
        inline int32_t getOrientation() const { return mAbsMtOrientation; }
        inline int32_t getTrackingId() const { return mAbsMtTrackingId; }
        inline int32_t getPressure() const { return mAbsMtPressure; }
        inline int32_t getDistance() const { return mAbsMtDistance; }
        ToolType getToolType() const;

    private:
        friend class MultiTouchMotionAccumulator;

        bool mInUse = false;
        bool mHaveAbsMtTouchMinor = false;
        bool mHaveAbsMtWidthMinor = false;
        bool mHaveAbsMtToolType = false;

        int32_t mAbsMtPositionX = 0;
        int32_t mAbsMtPositionY = 0;
        int32_t mAbsMtTouchMajor = 0;
        int32_t mAbsMtTouchMinor = 0;
        int32_t mAbsMtWidthMajor = 0;
        int32_t mAbsMtWidthMinor = 0;
        int32_t mAbsMtOrientation = 0;
        int32_t mAbsMtTrackingId = -1;
        int32_t mAbsMtPressure = 0;
        int32_t mAbsMtDistance = 0;
        int32_t mAbsMtToolType = 0;

        void clear() { *this = Slot(); }
        void populateAxisValue(int32_t axisCode, int32_t value);
    };

    MultiTouchMotionAccumulator();

    void configure(const InputDeviceContext& deviceContext, size_t slotCount,
                   bool usingSlotsProtocol);
    void reset(const InputDeviceContext& deviceContext);
    void process(const RawEvent& rawEvent);
    void finishSync();

    size_t getActiveSlotsCount() const;
    inline size_t getSlotCount() const { return mSlots.size(); }
    inline const Slot& getSlot(size_t index) const {
        LOG_ALWAYS_FATAL_IF(index < 0 || index >= mSlots.size(), "Invalid index: %zu", index);
        return mSlots[index];
    }

private:
    int32_t mCurrentSlot{-1};
    std::vector<Slot> mSlots;
    bool mUsingSlotsProtocol;

    void resetSlots();
    void syncSlots(const InputDeviceContext& deviceContext);
    void warnIfNotInUse(const RawEvent& event, const Slot& slot);
    void populateCurrentSlot(const android::InputDeviceContext& deviceContext);
};

} // namespace android
