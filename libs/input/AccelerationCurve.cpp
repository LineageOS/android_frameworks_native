/*
 * Copyright 2024 The Android Open Source Project
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

#include <input/AccelerationCurve.h>

#include <array>
#include <limits>

#include <log/log_main.h>

#define LOG_TAG "AccelerationCurve"

namespace android {

namespace {

// The last segment must have an infinite maximum speed, so that all speeds are covered.
constexpr std::array<AccelerationCurveSegment, 4> kSegments = {{
        {32.002, 3.19, 0},
        {52.83, 4.79, -51.254},
        {119.124, 7.28, -182.737},
        {std::numeric_limits<double>::infinity(), 15.04, -1107.556},
}};

static_assert(kSegments.back().maxPointerSpeedMmPerS == std::numeric_limits<double>::infinity());

constexpr std::array<double, 15> kSensitivityFactors = {1,  2,  4,  6,  7,  8,  9, 10,
                                                        11, 12, 13, 14, 16, 18, 20};

} // namespace

std::vector<AccelerationCurveSegment> createAccelerationCurveForPointerSensitivity(
        int32_t sensitivity) {
    LOG_ALWAYS_FATAL_IF(sensitivity < -7 || sensitivity > 7, "Invalid pointer sensitivity value");
    std::vector<AccelerationCurveSegment> output;
    output.reserve(kSegments.size());

    // The curves we want to produce for different sensitivity values are actually the same curve,
    // just scaled in the Y (gain) axis by a sensitivity factor and a couple of constants.
    double commonFactor = 0.64 * kSensitivityFactors[sensitivity + 7] / 10;
    for (AccelerationCurveSegment seg : kSegments) {
        output.push_back(AccelerationCurveSegment{seg.maxPointerSpeedMmPerS,
                                                  commonFactor * seg.baseGain,
                                                  commonFactor * seg.reciprocal});
    }

    return output;
}

} // namespace android