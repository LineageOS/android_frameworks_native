/*
 * Copyright 2019 The Android Open Source Project
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

#include "PhaseOffsets.h"

#include <cutils/properties.h>

#include <optional>

#include "SurfaceFlingerProperties.h"

namespace {

std::optional<nsecs_t> getProperty(const char* name) {
    char value[PROPERTY_VALUE_MAX];
    property_get(name, value, "-1");
    if (const int i = atoi(value); i != -1) return i;
    return std::nullopt;
}

} // namespace

namespace android::scheduler {

PhaseOffsets::~PhaseOffsets() = default;

namespace impl {

PhaseOffsets::PhaseOffsets() {
    // Below defines the threshold when an offset is considered to be negative, i.e. targeting
    // for the N+2 vsync instead of N+1. This means that:
    // For offset < threshold, SF wake up (vsync_duration - offset) before HW vsync.
    // For offset >= threshold, SF wake up (2 * vsync_duration - offset) before HW vsync.
    const nsecs_t thresholdForNextVsync =
            getProperty("debug.sf.phase_offset_threshold_for_next_vsync_ns")
                    .value_or(std::numeric_limits<nsecs_t>::max());

    const Offsets defaultOffsets = getDefaultOffsets(thresholdForNextVsync);
    const Offsets highFpsOffsets = getHighFpsOffsets(thresholdForNextVsync);

    mOffsets.insert({RefreshRateType::DEFAULT, defaultOffsets});
    mOffsets.insert({RefreshRateType::PERFORMANCE, highFpsOffsets});
}

PhaseOffsets::Offsets PhaseOffsets::getOffsetsForRefreshRate(
        RefreshRateType refreshRateType) const {
    return mOffsets.at(refreshRateType);
}

void PhaseOffsets::dump(std::string& result) const {
    const auto [early, earlyGl, late, threshold] = getCurrentOffsets();
    using base::StringAppendF;
    StringAppendF(&result,
                  "           app phase: %9" PRId64 " ns\t         SF phase: %9" PRId64 " ns\n"
                  "     early app phase: %9" PRId64 " ns\t   early SF phase: %9" PRId64 " ns\n"
                  "  GL early app phase: %9" PRId64 " ns\tGL early SF phase: %9" PRId64 " ns\n"
                  "next VSYNC threshold: %9" PRId64 " ns\n",
                  late.app, late.sf, early.app, early.sf, earlyGl.app, earlyGl.sf, threshold);
}

PhaseOffsets::Offsets PhaseOffsets::getDefaultOffsets(nsecs_t thresholdForNextVsync) {
    const int64_t vsyncPhaseOffsetNs = sysprop::vsync_event_phase_offset_ns(1000000);
    const int64_t sfVsyncPhaseOffsetNs = sysprop::vsync_sf_event_phase_offset_ns(1000000);

    const auto earlySfOffsetNs = getProperty("debug.sf.early_phase_offset_ns");
    const auto earlyGlSfOffsetNs = getProperty("debug.sf.early_gl_phase_offset_ns");
    const auto earlyAppOffsetNs = getProperty("debug.sf.early_app_phase_offset_ns");
    const auto earlyGlAppOffsetNs = getProperty("debug.sf.early_gl_app_phase_offset_ns");

    return {{RefreshRateType::DEFAULT, earlySfOffsetNs.value_or(sfVsyncPhaseOffsetNs),
             earlyAppOffsetNs.value_or(vsyncPhaseOffsetNs)},

            {RefreshRateType::DEFAULT, earlyGlSfOffsetNs.value_or(sfVsyncPhaseOffsetNs),
             earlyGlAppOffsetNs.value_or(vsyncPhaseOffsetNs)},

            {RefreshRateType::DEFAULT, sfVsyncPhaseOffsetNs, vsyncPhaseOffsetNs},

            thresholdForNextVsync};
}

PhaseOffsets::Offsets PhaseOffsets::getHighFpsOffsets(nsecs_t thresholdForNextVsync) {
    // TODO(b/122905996): Define these in device.mk.
    const int highFpsLateAppOffsetNs =
            getProperty("debug.sf.high_fps_late_app_phase_offset_ns").value_or(2000000);
    const int highFpsLateSfOffsetNs =
            getProperty("debug.sf.high_fps_late_sf_phase_offset_ns").value_or(1000000);

    const auto highFpsEarlySfOffsetNs = getProperty("debug.sf.high_fps_early_phase_offset_ns");
    const auto highFpsEarlyGlSfOffsetNs = getProperty("debug.sf.high_fps_early_gl_phase_offset_ns");
    const auto highFpsEarlyAppOffsetNs = getProperty("debug.sf.high_fps_early_app_phase_offset_ns");
    const auto highFpsEarlyGlAppOffsetNs =
            getProperty("debug.sf.high_fps_early_gl_app_phase_offset_ns");

    return {{RefreshRateType::PERFORMANCE, highFpsEarlySfOffsetNs.value_or(highFpsLateSfOffsetNs),
             highFpsEarlyAppOffsetNs.value_or(highFpsLateAppOffsetNs)},

            {RefreshRateType::PERFORMANCE, highFpsEarlyGlSfOffsetNs.value_or(highFpsLateSfOffsetNs),
             highFpsEarlyGlAppOffsetNs.value_or(highFpsLateAppOffsetNs)},

            {RefreshRateType::PERFORMANCE, highFpsLateSfOffsetNs, highFpsLateAppOffsetNs},

            thresholdForNextVsync};
}

} // namespace impl
} // namespace android::scheduler
