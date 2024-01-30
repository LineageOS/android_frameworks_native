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

#pragma once

#include <utils/Timers.h>

namespace android {

/**
 * Controls a slop logic. Slop here refers to an approach to try and drop insignificant input
 * events. This is helpful in cases where unintentional input events may cause unintended outcomes,
 * like scrolling a screen or keeping the screen awake.
 *
 * Current slop logic:
 *      "If time since last event > Xns, then discard the next N values."
 */
class SlopController final {
public:
    SlopController(float slopThreshold, nsecs_t slopDurationNanos);

    /**
     * Consumes an event with a given time and value for slop processing.
     * Returns an amount <=value that should be consumed.
     */
    float consumeEvent(nsecs_t eventTime, float value);

private:
    bool shouldResetSlopTracking(nsecs_t eventTimeNanos, float value) const;

    /** The amount of event values ignored after an inactivity of the slop duration. */
    const float mSlopThreshold;
    /** The duration of inactivity that resets slop controlling. */
    const nsecs_t mSlopDurationNanos;

    nsecs_t mLastEventTimeNanos = 0;
    float mCumulativeValue = 0;
    bool mHasSlopBeenMet = false;
};

} // namespace android
