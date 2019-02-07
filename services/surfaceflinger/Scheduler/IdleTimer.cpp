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

#include "IdleTimer.h"

#include <chrono>
#include <thread>

namespace android {
namespace scheduler {

IdleTimer::IdleTimer(const Interval& interval, const TimeoutCallback& timeoutCallback)
      : mInterval(interval), mTimeoutCallback(timeoutCallback) {}

IdleTimer::~IdleTimer() {
    stop();
}

void IdleTimer::start() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::RESET;
    }
    mThread = std::thread(&IdleTimer::loop, this);
}

void IdleTimer::stop() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::STOPPED;
    }
    mCondition.notify_all();
    if (mThread.joinable()) {
        mThread.join();
    }
}

void IdleTimer::loop() {
    std::lock_guard<std::mutex> lock(mMutex);
    while (mState != TimerState::STOPPED) {
        if (mState == TimerState::IDLE) {
            mCondition.wait(mMutex);
        } else if (mState == TimerState::RESET) {
            auto triggerTime = std::chrono::steady_clock::now() + mInterval;
            mState = TimerState::WAITING;
            while (mState == TimerState::WAITING) {
                constexpr auto zero = std::chrono::steady_clock::duration::zero();
                auto waitTime = triggerTime - std::chrono::steady_clock::now();
                if (waitTime > zero) mCondition.wait_for(mMutex, waitTime);
                if (mState == TimerState::WAITING &&
                    (triggerTime - std::chrono::steady_clock::now()) <= zero) {
                    if (mTimeoutCallback) {
                        mTimeoutCallback();
                    }

                    mState = TimerState::IDLE;
                }
            }
        }
    }
} // namespace scheduler

void IdleTimer::reset() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::RESET;
    }
    mCondition.notify_all();
}

} // namespace scheduler
} // namespace android
