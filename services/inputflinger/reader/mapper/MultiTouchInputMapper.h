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

#pragma once

#include "TouchInputMapper.h"
#include "accumulator/MultiTouchMotionAccumulator.h"

namespace android {

class MultiTouchInputMapper : public TouchInputMapper {
public:
    template <class T, class... Args>
    friend std::unique_ptr<T> createInputMapper(InputDeviceContext& deviceContext,
                                                const InputReaderConfiguration& readerConfig,
                                                Args... args);

    ~MultiTouchInputMapper() override;

    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent& rawEvent) override;
    [[nodiscard]] std::list<NotifyArgs> reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    ConfigurationChanges changes) override;

protected:
    void syncTouch(nsecs_t when, RawState* outState) override;
    void configureRawPointerAxes() override;
    bool hasStylus() const override;

private:
    explicit MultiTouchInputMapper(InputDeviceContext& deviceContext,
                                   const InputReaderConfiguration& readerConfig);

    // If the slot is in use, return the bit id. Return std::nullopt otherwise.
    std::optional<int32_t> getActiveBitId(const MultiTouchMotionAccumulator::Slot& inSlot);
    MultiTouchMotionAccumulator mMultiTouchMotionAccumulator;

    // Specifies the pointer id bits that are in use, and their associated tracking id.
    BitSet32 mPointerIdBits;
    int32_t mPointerTrackingIdMap[MAX_POINTER_ID + 1];

    bool mStylusMtToolSeen{false};

    // simulate_stylus_with_touch is a debug mode that converts all finger pointers reported by this
    // mapper's touchscreen into stylus pointers, and adds SOURCE_STYLUS to the input device.
    // It is used to simulate stylus events for debugging and testing on a device that does not
    // support styluses. It can be enabled using
    // "adb shell setprop debug.input.simulate_stylus_with_touch true".
    // After enabling, the touchscreen will need to be reconfigured. A reconfiguration usually
    // happens when turning the screen on/off or by rotating the device orientation.
    bool mShouldSimulateStylusWithTouch{false};
};

} // namespace android
