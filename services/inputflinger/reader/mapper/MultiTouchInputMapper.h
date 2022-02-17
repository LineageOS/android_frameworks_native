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

#ifndef _UI_INPUTREADER_MULTI_TOUCH_INPUT_MAPPER_H
#define _UI_INPUTREADER_MULTI_TOUCH_INPUT_MAPPER_H

#include "TouchInputMapper.h"

namespace android {

/* Keeps track of the state of multi-touch protocol. */
class MultiTouchMotionAccumulator {
public:
    class Slot {
    public:
        inline bool isInUse() const { return mInUse; }
        inline int32_t getX() const { return mAbsMTPositionX; }
        inline int32_t getY() const { return mAbsMTPositionY; }
        inline int32_t getTouchMajor() const { return mAbsMTTouchMajor; }
        inline int32_t getTouchMinor() const {
            return mHaveAbsMTTouchMinor ? mAbsMTTouchMinor : mAbsMTTouchMajor;
        }
        inline int32_t getToolMajor() const { return mAbsMTWidthMajor; }
        inline int32_t getToolMinor() const {
            return mHaveAbsMTWidthMinor ? mAbsMTWidthMinor : mAbsMTWidthMajor;
        }
        inline int32_t getOrientation() const { return mAbsMTOrientation; }
        inline int32_t getTrackingId() const { return mAbsMTTrackingId; }
        inline int32_t getPressure() const { return mAbsMTPressure; }
        inline int32_t getDistance() const { return mAbsMTDistance; }
        inline int32_t getToolType() const;

    private:
        friend class MultiTouchMotionAccumulator;

        bool mInUse = false;
        bool mHaveAbsMTTouchMinor = false;
        bool mHaveAbsMTWidthMinor = false;
        bool mHaveAbsMTToolType = false;

        int32_t mAbsMTPositionX = 0;
        int32_t mAbsMTPositionY = 0;
        int32_t mAbsMTTouchMajor = 0;
        int32_t mAbsMTTouchMinor = 0;
        int32_t mAbsMTWidthMajor = 0;
        int32_t mAbsMTWidthMinor = 0;
        int32_t mAbsMTOrientation = 0;
        int32_t mAbsMTTrackingId = -1;
        int32_t mAbsMTPressure = 0;
        int32_t mAbsMTDistance = 0;
        int32_t mAbsMTToolType = 0;

        void clear() { *this = Slot(); }
    };

    MultiTouchMotionAccumulator();

    void configure(InputDeviceContext& deviceContext, size_t slotCount, bool usingSlotsProtocol);
    void reset(InputDeviceContext& deviceContext);
    void process(const RawEvent* rawEvent);
    void finishSync();
    bool hasStylus() const;

    inline size_t getSlotCount() const { return mSlots.size(); }
    inline const Slot& getSlot(size_t index) const {
        LOG_ALWAYS_FATAL_IF(index < 0 || index >= mSlots.size(), "Invalid index: %zu", index);
        return mSlots[index];
    }

private:
    int32_t mCurrentSlot;
    std::vector<Slot> mSlots;
    bool mUsingSlotsProtocol;
    bool mHaveStylus;

    void clearSlots(int32_t initialSlot);
    void warnIfNotInUse(const RawEvent& event, const Slot& slot);
};

class MultiTouchInputMapper : public TouchInputMapper {
public:
    explicit MultiTouchInputMapper(InputDeviceContext& deviceContext);
    ~MultiTouchInputMapper() override;

    void reset(nsecs_t when) override;
    void process(const RawEvent* rawEvent) override;

protected:
    void syncTouch(nsecs_t when, RawState* outState) override;
    void configureRawPointerAxes() override;
    bool hasStylus() const override;

private:
    // simulate_stylus_with_touch is a debug mode that converts all finger pointers reported by this
    // mapper's touchscreen into stylus pointers, and adds SOURCE_STYLUS to the input device.
    // It is used to simulate stylus events for debugging and testing on a device that does not
    // support styluses. It can be enabled using
    // "adb shell setprop persist.debug.input.simulate_stylus_with_touch true",
    // and requires a reboot to take effect.
    inline bool shouldSimulateStylusWithTouch() const;

    // If the slot is in use, return the bit id. Return std::nullopt otherwise.
    std::optional<int32_t> getActiveBitId(const MultiTouchMotionAccumulator::Slot& inSlot);
    MultiTouchMotionAccumulator mMultiTouchMotionAccumulator;

    // Specifies the pointer id bits that are in use, and their associated tracking id.
    BitSet32 mPointerIdBits;
    int32_t mPointerTrackingIdMap[MAX_POINTER_ID + 1];
};

} // namespace android

#endif // _UI_INPUTREADER_MULTI_TOUCH_INPUT_MAPPER_H