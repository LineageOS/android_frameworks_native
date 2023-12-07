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

#define LOG_TAG "WorkDuration"

#include <android/WorkDuration.h>
#include <android/performance_hint.h>
#include <binder/Parcel.h>
#include <utils/Log.h>

namespace android::os {

WorkDuration::WorkDuration(int64_t startTimestampNanos, int64_t totalDurationNanos,
                           int64_t cpuDurationNanos, int64_t gpuDurationNanos)
      : timestampNanos(0),
        actualTotalDurationNanos(totalDurationNanos),
        workPeriodStartTimestampNanos(startTimestampNanos),
        actualCpuDurationNanos(cpuDurationNanos),
        actualGpuDurationNanos(gpuDurationNanos) {}

status_t WorkDuration::writeToParcel(Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    parcel->writeInt64(workPeriodStartTimestampNanos);
    parcel->writeInt64(actualTotalDurationNanos);
    parcel->writeInt64(actualCpuDurationNanos);
    parcel->writeInt64(actualGpuDurationNanos);
    parcel->writeInt64(timestampNanos);
    return OK;
}

status_t WorkDuration::readFromParcel(const Parcel*) {
    return INVALID_OPERATION;
}

} // namespace android::os
