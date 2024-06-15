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

#pragma once

#include <cstdint>
#include <vector>

namespace android {

/**
 * Describes a section of an acceleration curve as a function which outputs a scaling factor (gain)
 * for the pointer movement, given the speed of the mouse or finger (in mm/s):
 *
 *     gain(input_speed_mm_per_s) = baseGain + reciprocal / input_speed_mm_per_s
 */
struct AccelerationCurveSegment {
    /**
     * The maximum pointer speed at which this segment should apply, in mm/s. The last segment in a
     * curve should always set this to infinity.
     */
    double maxPointerSpeedMmPerS;
    /** The gain for this segment before the reciprocal is taken into account. */
    double baseGain;
    /** The reciprocal part of the formula, which should be divided by the input speed. */
    double reciprocal;
};

/**
 * Creates an acceleration curve for the given pointer sensitivity value. The sensitivity value
 * should be between -7 (for the lowest sensitivity) and 7, inclusive.
 */
std::vector<AccelerationCurveSegment> createAccelerationCurveForPointerSensitivity(
        int32_t sensitivity);

} // namespace android
