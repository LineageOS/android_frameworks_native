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

#include <cstdint>
#include "HidUsageAccumulator.h"

namespace android {

class InputDeviceContext;
struct RawEvent;

/* Keeps track of the state of touch, stylus and tool buttons. */
class TouchButtonAccumulator {
public:
    explicit TouchButtonAccumulator(const InputDeviceContext& deviceContext)
          : mDeviceContext(deviceContext){};

    void configure();
    void reset();

    void process(const RawEvent& rawEvent);

    uint32_t getButtonState() const;
    ToolType getToolType() const;
    bool isToolActive() const;
    bool isHovering() const;
    bool hasStylus() const;
    bool hasButtonTouch() const;

    /*
     * Returns the number of touches reported by the device through its BTN_TOOL_FINGER and
     * BTN_TOOL_*TAP "buttons". Note that this count includes touches reported with their
     * ABS_MT_TOOL_TYPE set to MT_TOOL_PALM.
     */
    int getTouchCount() const;

private:
    bool mHaveBtnTouch{};
    bool mHaveStylus{};

    bool mBtnTouch{};
    bool mBtnStylus{};
    bool mBtnStylus2{};
    bool mBtnToolFinger{};
    bool mBtnToolPen{};
    bool mBtnToolRubber{};
    bool mBtnToolBrush{};
    bool mBtnToolPencil{};
    bool mBtnToolAirbrush{};
    bool mBtnToolMouse{};
    bool mBtnToolLens{};
    bool mBtnToolDoubleTap{};
    bool mBtnToolTripleTap{};
    bool mBtnToolQuadTap{};
    bool mBtnToolQuintTap{};

    HidUsageAccumulator mHidUsageAccumulator{};

    const InputDeviceContext& mDeviceContext;

    void processMappedKey(int32_t scanCode, bool down);
};

} // namespace android
