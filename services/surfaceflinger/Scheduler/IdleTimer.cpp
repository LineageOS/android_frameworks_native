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
            mState = TimerState::WAITING;
            if (mCondition.wait_for(mMutex, mInterval) == std::cv_status::timeout) {
                if (mTimeoutCallback) {
                    mTimeoutCallback();
                }
            }
            if (mState == TimerState::WAITING) {
                mState = TimerState::IDLE;
            }
        }
    }
}

void IdleTimer::reset() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::RESET;
    }
    mCondition.notify_all();
}

} // namespace scheduler
} // namespace android
