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

#include "include/gpuwork/gpu_work.h"

#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>

#ifdef MOCK_BPF
#include <test/mock_bpf_helpers.h>
#else
#include <bpf_helpers.h>
#endif

#define S_IN_NS (1000000000)
#define MHZ_IN_KHZS (1000)

typedef uint32_t Uid;

// A map from UID to |UidTrackingInfo|.
DEFINE_BPF_MAP_GRW(gpu_work_map, HASH, Uid, UidTrackingInfo, kMaxTrackedUids, AID_GRAPHICS);

// A map containing a single entry of |GlobalData|.
DEFINE_BPF_MAP_GRW(gpu_work_global_data, ARRAY, uint32_t, GlobalData, 1, AID_GRAPHICS);

// GpuUidWorkPeriodEvent defines the structure of a kernel tracepoint under the
// tracepoint system (also referred to as the group) "power" and name
// "gpu_work_period". In summary, the kernel tracepoint should be
// "power/gpu_work_period", available at:
//
//  /sys/kernel/tracing/events/power/gpu_work_period/
//
// GpuUidWorkPeriodEvent defines a non-overlapping, non-zero period of time when
// work was running on the GPU for a given application (identified by its UID;
// the persistent, unique ID of the application) from |start_time_ns| to
// |end_time_ns|. Drivers should issue this tracepoint as soon as possible
// (within 1 second) after |end_time_ns|. For a given UID, periods must not
// overlap, but periods from different UIDs can overlap (and should overlap, if
// and only if that is how the work was executed). The period includes
// information such as |frequency_khz|, the frequency that the GPU was running
// at during the period, and |includes_compute_work|, whether the work included
// compute shader work (not just graphics work). GPUs may have multiple
// frequencies that can be adjusted, but the driver should report the frequency
// that most closely estimates power usage (e.g. the frequency of shader cores,
// not a scheduling unit).
//
// If any information changes while work from the UID is running on the GPU
// (e.g. the GPU frequency changes, or the work starts/stops including compute
// work) then the driver must conceptually end the period, issue the tracepoint,
// start tracking a new period, and eventually issue a second tracepoint when
// the work completes or when the information changes again. In this case, the
// |end_time_ns| of the first period must equal the |start_time_ns| of the
// second period. The driver may also end and start a new period (without a
// gap), even if no information changes. For example, this might be convenient
// if there is a collection of work from a UID running on the GPU for a long
// time; ending and starting a period as individual parts of the work complete
// allows the consumer of the tracepoint to be updated about the ongoing work.
//
// For a given UID, the tracepoints must be emitted in order; that is, the
// |start_time_ns| of each subsequent tracepoint for a given UID must be
// monotonically increasing.
typedef struct {
    // Actual fields start at offset 8.
    uint64_t reserved;

    // The UID of the process (i.e. persistent, unique ID of the Android app)
    // that submitted work to the GPU.
    uint32_t uid;

    // The GPU frequency during the period. GPUs may have multiple frequencies
    // that can be adjusted, but the driver should report the frequency that
    // would most closely estimate power usage (e.g. the frequency of shader
    // cores, not a scheduling unit).
    uint32_t frequency_khz;

    // The start time of the period in nanoseconds. The clock must be
    // CLOCK_MONOTONIC, as returned by the ktime_get_ns(void) function.
    uint64_t start_time_ns;

    // The end time of the period in nanoseconds. The clock must be
    // CLOCK_MONOTONIC, as returned by the ktime_get_ns(void) function.
    uint64_t end_time_ns;

    // Flags about the work. Reserved for future use.
    uint64_t flags;

    // The maximum GPU frequency allowed during the period according to the
    // thermal throttling policy. Must be 0 if no thermal throttling was
    // enforced during the period. The value must relate to |frequency_khz|; in
    // other words, if |frequency_khz| is the frequency of the GPU shader cores,
    // then |thermally_throttled_max_frequency_khz| must be the maximum allowed
    // frequency of the GPU shader cores (not the maximum allowed frequency of
    // some other part of the GPU).
    //
    // Note: Unlike with other fields of this struct, if the
    // |thermally_throttled_max_frequency_khz| value conceptually changes while
    // work from a UID is running on the GPU then the GPU driver does NOT need
    // to accurately report this by ending the period and starting to track a
    // new period; instead, the GPU driver may report any one of the
    // |thermally_throttled_max_frequency_khz| values that was enforced during
    // the period. The motivation for this relaxation is that we assume the
    // maximum frequency will not be changing rapidly, and so capturing the
    // exact point at which the change occurs is unnecessary.
    uint32_t thermally_throttled_max_frequency_khz;

} GpuUidWorkPeriodEvent;

_Static_assert(offsetof(GpuUidWorkPeriodEvent, uid) == 8 &&
                       offsetof(GpuUidWorkPeriodEvent, frequency_khz) == 12 &&
                       offsetof(GpuUidWorkPeriodEvent, start_time_ns) == 16 &&
                       offsetof(GpuUidWorkPeriodEvent, end_time_ns) == 24 &&
                       offsetof(GpuUidWorkPeriodEvent, flags) == 32 &&
                       offsetof(GpuUidWorkPeriodEvent, thermally_throttled_max_frequency_khz) == 40,
               "Field offsets of struct GpuUidWorkPeriodEvent must not be changed because they "
               "must match the tracepoint field offsets found via adb shell cat "
               "/sys/kernel/tracing/events/power/gpu_work_period/format");

DEFINE_BPF_PROG("tracepoint/power/gpu_work_period", AID_ROOT, AID_GRAPHICS, tp_gpu_work_period)
(GpuUidWorkPeriodEvent* const args) {
    // Note: In BPF programs, |__sync_fetch_and_add| is translated to an atomic
    // add.

    const uint32_t uid = args->uid;

    // Get |UidTrackingInfo| for |uid|.
    UidTrackingInfo* uid_tracking_info = bpf_gpu_work_map_lookup_elem(&uid);
    if (!uid_tracking_info) {
        // There was no existing entry, so we add a new one.
        UidTrackingInfo initial_info;
        __builtin_memset(&initial_info, 0, sizeof(initial_info));
        if (0 == bpf_gpu_work_map_update_elem(&uid, &initial_info, BPF_NOEXIST)) {
            // We added an entry to the map, so we increment our entry counter in
            // |GlobalData|.
            const uint32_t zero = 0;
            // Get the |GlobalData|.
            GlobalData* global_data = bpf_gpu_work_global_data_lookup_elem(&zero);
            // Getting the global data never fails because it is an |ARRAY| map,
            // but we need to keep the verifier happy.
            if (global_data) {
                __sync_fetch_and_add(&global_data->num_map_entries, 1);
            }
        }
        uid_tracking_info = bpf_gpu_work_map_lookup_elem(&uid);
        if (!uid_tracking_info) {
            // This should never happen, unless entries are getting deleted at
            // this moment. If so, we just give up.
            return 0;
        }
    }

    // The period duration must be non-zero.
    if (args->start_time_ns >= args->end_time_ns) {
        __sync_fetch_and_add(&uid_tracking_info->error_count, 1);
        return 0;
    }

    // The frequency must not be 0.
    if (args->frequency_khz == 0) {
        __sync_fetch_and_add(&uid_tracking_info->error_count, 1);
        return 0;
    }

    // Calculate the frequency index: see |UidTrackingInfo.frequency_times_ns|.
    // Round to the nearest 50MHz bucket.
    uint32_t frequency_index =
            ((args->frequency_khz / MHZ_IN_KHZS) + (kFrequencyGranularityMhz / 2)) /
            kFrequencyGranularityMhz;
    if (frequency_index >= kNumTrackedFrequencies) {
        frequency_index = kNumTrackedFrequencies - 1;
    }

    // Never round down to 0MHz, as this is a special bucket (see below) and not
    // an actual operating point.
    if (frequency_index == 0) {
        frequency_index = 1;
    }

    // Update time in state.
    __sync_fetch_and_add(&uid_tracking_info->frequency_times_ns[frequency_index],
                         args->end_time_ns - args->start_time_ns);

    if (uid_tracking_info->previous_end_time_ns > args->start_time_ns) {
        // This must not happen because per-UID periods must not overlap and
        // must be emitted in order.
        __sync_fetch_and_add(&uid_tracking_info->error_count, 1);
    } else {
        // The period appears to have been emitted after the previous, as
        // expected, so we can calculate the gap between this and the previous
        // period.
        const uint64_t gap_time = args->start_time_ns - uid_tracking_info->previous_end_time_ns;

        // Update |previous_end_time_ns|.
        uid_tracking_info->previous_end_time_ns = args->end_time_ns;

        // Update the special 0MHz frequency time, which stores the gaps between
        // periods, but only if the gap is < 1 second.
        if (gap_time > 0 && gap_time < S_IN_NS) {
            __sync_fetch_and_add(&uid_tracking_info->frequency_times_ns[0], gap_time);
        }
    }

    return 0;
}

LICENSE("Apache 2.0");
