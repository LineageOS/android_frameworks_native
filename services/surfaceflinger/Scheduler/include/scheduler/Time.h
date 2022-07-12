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

#include <chrono>

#include <utils/Timers.h>

namespace android {
namespace scheduler {

// TODO(b/185535769): Pull Clock.h to libscheduler to reuse this.
using SchedulerClock = std::chrono::high_resolution_clock;
static_assert(SchedulerClock::is_steady);

} // namespace scheduler

struct Duration;

struct TimePoint : scheduler::SchedulerClock::time_point {
    constexpr TimePoint() = default;
    explicit constexpr TimePoint(const Duration&);

    // Implicit conversion from std::chrono counterpart.
    constexpr TimePoint(scheduler::SchedulerClock::time_point p)
          : scheduler::SchedulerClock::time_point(p) {}

    static constexpr TimePoint fromNs(nsecs_t);

    nsecs_t ns() const;
};

struct Duration : TimePoint::duration {
    // Implicit conversion from std::chrono counterpart.
    constexpr Duration(TimePoint::duration d) : TimePoint::duration(d) {}

    static constexpr Duration fromNs(nsecs_t ns) { return {std::chrono::nanoseconds(ns)}; }

    nsecs_t ns() const { return std::chrono::nanoseconds(*this).count(); }
};

using Period = Duration;

constexpr TimePoint::TimePoint(const Duration& d) : scheduler::SchedulerClock::time_point(d) {}

constexpr TimePoint TimePoint::fromNs(nsecs_t ns) {
    return TimePoint(Duration::fromNs(ns));
}

inline nsecs_t TimePoint::ns() const {
    return Duration(time_since_epoch()).ns();
}

} // namespace android
