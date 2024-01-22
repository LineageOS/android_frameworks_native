/*
 * Copyright 2023 The Android Open Source Project
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

// clang-format off
#include "../Macros.h"
// clang-format on

#include "SlopController.h"

namespace {
int signOf(float value) {
    if (value == 0) return 0;
    if (value > 0) return 1;
    return -1;
}
} // namespace

namespace android {

SlopController::SlopController(float slopThreshold, nsecs_t slopDurationNanos)
      : mSlopThreshold(slopThreshold), mSlopDurationNanos(slopDurationNanos) {}

float SlopController::consumeEvent(nsecs_t eventTimeNanos, float value) {
    if (mSlopDurationNanos == 0) {
        return value;
    }

    if (shouldResetSlopTracking(eventTimeNanos, value)) {
        mCumulativeValue = 0;
        mHasSlopBeenMet = false;
    }

    mLastEventTimeNanos = eventTimeNanos;

    if (mHasSlopBeenMet) {
        // Since slop has already been met, we know that all of the current value would pass the
        // slop threshold. So return that, without any further processing.
        return value;
    }

    mCumulativeValue += value;

    if (abs(mCumulativeValue) >= mSlopThreshold) {
        ALOGD("SlopController: did not drop event with value .%3f", value);
        mHasSlopBeenMet = true;
        // Return the amount of value that exceeds the slop.
        return signOf(value) * (abs(mCumulativeValue) - mSlopThreshold);
    }

    ALOGD("SlopController: dropping event with value .%3f", value);
    return 0;
}

bool SlopController::shouldResetSlopTracking(nsecs_t eventTimeNanos, float value) const {
    const nsecs_t ageNanos = eventTimeNanos - mLastEventTimeNanos;
    if (ageNanos >= mSlopDurationNanos) {
        return true;
    }
    if (value == 0) {
        return false;
    }
    if (signOf(mCumulativeValue) != signOf(value)) {
        return true;
    }
    return false;
}

} // namespace android
