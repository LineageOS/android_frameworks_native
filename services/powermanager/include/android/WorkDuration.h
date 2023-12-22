/**
 * Copyright (C) 2023 The Android Open Source Project
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

#include <binder/Parcelable.h>
#include <math.h>

struct AWorkDuration {};

namespace android::os {

/**
 * C++ Parcelable version of {@link PerformanceHintManager.WorkDuration} that can be used in
 * binder calls.
 * This file needs to be kept in sync with the WorkDuration in
 * frameworks/base/core/java/android/os/WorkDuration.java
 */
struct WorkDuration : AWorkDuration, android::Parcelable {
    WorkDuration() = default;
    ~WorkDuration() = default;

    WorkDuration(int64_t workPeriodStartTimestampNanos, int64_t actualTotalDurationNanos,
                 int64_t actualCpuDurationNanos, int64_t actualGpuDurationNanos);
    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

    inline bool equalsWithoutTimestamp(const WorkDuration& other) const {
        return workPeriodStartTimestampNanos == other.workPeriodStartTimestampNanos &&
                actualTotalDurationNanos == other.actualTotalDurationNanos &&
                actualCpuDurationNanos == other.actualCpuDurationNanos &&
                actualGpuDurationNanos == other.actualGpuDurationNanos;
    }

    bool operator==(const WorkDuration& other) const {
        return timestampNanos == other.timestampNanos && equalsWithoutTimestamp(other);
    }

    bool operator!=(const WorkDuration& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const WorkDuration& workDuration) {
        os << "{"
           << "workPeriodStartTimestampNanos: " << workDuration.workPeriodStartTimestampNanos
           << ", actualTotalDurationNanos: " << workDuration.actualTotalDurationNanos
           << ", actualCpuDurationNanos: " << workDuration.actualCpuDurationNanos
           << ", actualGpuDurationNanos: " << workDuration.actualGpuDurationNanos
           << ", timestampNanos: " << workDuration.timestampNanos << "}";
        return os;
    }

    int64_t timestampNanos;
    int64_t actualTotalDurationNanos;
    int64_t workPeriodStartTimestampNanos;
    int64_t actualCpuDurationNanos;
    int64_t actualGpuDurationNanos;
};

} // namespace android::os
