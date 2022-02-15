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

#include <stdint.h>

#ifdef __cplusplus
#include <type_traits>

namespace android {
namespace gpuwork {
#endif

typedef struct {
    // The end time of the previous period from this UID in nanoseconds.
    uint64_t previous_end_time_ns;

    // The time spent at each GPU frequency while running GPU work from the UID,
    // in nanoseconds. Array index i stores the time for frequency i*50 MHz. So
    // index 0 is 0Mhz, index 1 is 50MHz, index 2 is 100MHz, etc., up to index
    // |kNumTrackedFrequencies|.
    uint64_t frequency_times_ns[21];

    // The number of times we received |GpuUidWorkPeriodEvent| events in an
    // unexpected order. See |GpuUidWorkPeriodEvent|.
    uint32_t error_count;

} UidTrackingInfo;

typedef struct {
    // We cannot query the number of entries in BPF map |gpu_work_map|. We track
    // the number of entries (approximately) using a counter so we can check if
    // the map is nearly full.
    uint64_t num_map_entries;
} GlobalData;

static const uint32_t kMaxTrackedUids = 512;
static const uint32_t kFrequencyGranularityMhz = 50;
static const uint32_t kNumTrackedFrequencies = 21;

#ifdef __cplusplus
static_assert(kNumTrackedFrequencies ==
              std::extent<decltype(UidTrackingInfo::frequency_times_ns)>::value);

} // namespace gpuwork
} // namespace android
#endif
