/*
 * Copyright 2018 The Android Open Source Project
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

#include "OneShotTimer.h"

#include <chrono>
#include <sstream>
#include <thread>

namespace {
using namespace std::chrono_literals;

constexpr int64_t kNsToSeconds = std::chrono::duration_cast<std::chrono::nanoseconds>(1s).count();

// The syscall interface uses a pair of integers for the timestamp. The first
// (tv_sec) is the whole count of seconds. The second (tv_nsec) is the
// nanosecond part of the count. This function takes care of translation.
void calculateTimeoutTime(std::chrono::nanoseconds timestamp, timespec* spec) {
    clock_gettime(CLOCK_MONOTONIC, spec);
    spec->tv_sec += static_cast<__kernel_time_t>(timestamp.count() / kNsToSeconds);
    spec->tv_nsec += timestamp.count() % kNsToSeconds;
}
} // namespace

namespace android {
namespace scheduler {

OneShotTimer::OneShotTimer(const Interval& interval, const ResetCallback& resetCallback,
                           const TimeoutCallback& timeoutCallback)
      : mInterval(interval), mResetCallback(resetCallback), mTimeoutCallback(timeoutCallback) {}

OneShotTimer::~OneShotTimer() {
    stop();
}

void OneShotTimer::start() {
    sem_init(&mSemaphore, 0, 0);

    if (!mThread.joinable()) {
        // Only create thread if it has not been created.
        mThread = std::thread(&OneShotTimer::loop, this);
    }
}

void OneShotTimer::stop() {
    mStopTriggered = true;
    sem_post(&mSemaphore);

    if (mThread.joinable()) {
        mThread.join();
        sem_destroy(&mSemaphore);
    }
}

void OneShotTimer::loop() {
    TimerState state = TimerState::RESET;
    while (true) {
        bool triggerReset = false;
        bool triggerTimeout = false;

        state = checkForResetAndStop(state);
        if (state == TimerState::STOPPED) {
            break;
        }

        if (state == TimerState::IDLE) {
            sem_wait(&mSemaphore);
            continue;
        }

        if (state == TimerState::RESET) {
            triggerReset = true;
        }

        if (triggerReset && mResetCallback) {
            mResetCallback();
        }

        state = checkForResetAndStop(state);
        if (state == TimerState::STOPPED) {
            break;
        }

        auto triggerTime = std::chrono::steady_clock::now() + mInterval;
        state = TimerState::WAITING;
        while (state == TimerState::WAITING) {
            constexpr auto zero = std::chrono::steady_clock::duration::zero();
            // Wait for mInterval time for semaphore signal.
            struct timespec ts;
            calculateTimeoutTime(std::chrono::nanoseconds(mInterval), &ts);
            sem_clockwait(&mSemaphore, CLOCK_MONOTONIC, &ts);

            state = checkForResetAndStop(state);
            if (state == TimerState::RESET) {
                triggerTime = std::chrono::steady_clock::now() + mInterval;
                state = TimerState::WAITING;
            } else if (state == TimerState::WAITING &&
                       (triggerTime - std::chrono::steady_clock::now()) <= zero) {
                triggerTimeout = true;
                state = TimerState::IDLE;
            }
        }

        if (triggerTimeout && mTimeoutCallback) {
            mTimeoutCallback();
        }
    }
}

OneShotTimer::TimerState OneShotTimer::checkForResetAndStop(TimerState state) {
    // Stop takes precedence of the reset.
    if (mStopTriggered.exchange(false)) {
        return TimerState::STOPPED;
    }
    // If the state was stopped, the thread was joined, and we cannot reset
    // the timer anymore.
    if (state != TimerState::STOPPED && mResetTriggered.exchange(false)) {
        return TimerState::RESET;
    }
    return state;
}

void OneShotTimer::reset() {
    mResetTriggered = true;
    sem_post(&mSemaphore);
}

std::string OneShotTimer::dump() const {
    std::ostringstream stream;
    stream << mInterval.count() << " ms";
    return stream.str();
}

} // namespace scheduler
} // namespace android
