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

#pragma once

#include <ftl/non_null.h>
#include <scheduler/Fps.h>

// TODO(b/241285191): Pull this to <ui/DisplayMode.h>
#include "DisplayHardware/DisplayMode.h"

namespace android::scheduler {

struct FrameRateMode {
    Fps fps; // The render frame rate, which is a divisor of modePtr->getFps().
    ftl::NonNull<DisplayModePtr> modePtr;

    bool operator==(const FrameRateMode& other) const {
        return isApproxEqual(fps, other.fps) && modePtr == other.modePtr;
    }

    bool operator!=(const FrameRateMode& other) const { return !(*this == other); }
};

inline std::string to_string(const FrameRateMode& mode) {
    return base::StringPrintf("{fps=%s, modePtr={id=%d, vsyncRate=%s, peakRefreshRate=%s}}",
                              to_string(mode.fps).c_str(),
                              ftl::to_underlying(mode.modePtr->getId()),
                              to_string(mode.modePtr->getVsyncRate()).c_str(),
                              to_string(mode.modePtr->getPeakFps()).c_str());
}

} // namespace android::scheduler
