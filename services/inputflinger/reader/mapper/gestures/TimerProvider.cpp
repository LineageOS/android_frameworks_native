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

#include "TimerProvider.h"

#include <chrono>
#include <string>

#include <android-base/logging.h>
#include <input/PrintTools.h>

namespace android {

namespace {

nsecs_t stimeToNsecs(stime_t time) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::duration<stime_t>(time))
            .count();
}

stime_t nsecsToStime(nsecs_t time) {
    return std::chrono::duration_cast<std::chrono::duration<stime_t>>(
                   std::chrono::nanoseconds(time))
            .count();
}

GesturesTimer* createTimer(void* data) {
    return static_cast<TimerProvider*>(data)->createTimer();
}

void setDeadline(void* data, GesturesTimer* timer, stime_t delay, GesturesTimerCallback callback,
                 void* callbackData) {
    static_cast<TimerProvider*>(data)->setDeadline(timer, stimeToNsecs(delay), callback,
                                                   callbackData);
};

void cancelTimer(void* data, GesturesTimer* timer) {
    static_cast<TimerProvider*>(data)->cancelTimer(timer);
}

void freeTimer(void* data, GesturesTimer* timer) {
    static_cast<TimerProvider*>(data)->freeTimer(timer);
}

} // namespace

const GesturesTimerProvider kGestureTimerProvider = {
        .create_fn = createTimer,
        .set_fn = setDeadline,
        .cancel_fn = cancelTimer,
        .free_fn = freeTimer,
};

TimerProvider::TimerProvider(InputReaderContext& context) : mReaderContext(context) {}

std::string TimerProvider::dump() {
    std::string dump;
    auto timerPtrToString = [](const std::unique_ptr<GesturesTimer>& timer) {
        return std::to_string(timer->id);
    };
    dump += "Timer IDs: " + dumpVector<std::unique_ptr<GesturesTimer>>(mTimers, timerPtrToString) +
            "\n";
    dump += "Deadlines and corresponding timer IDs:\n";
    dump += addLinePrefix(dumpMap(mDeadlines, constToString,
                                  [](const Deadline& deadline) {
                                      return std::to_string(deadline.timerId);
                                  }),
                          "  ") +
            "\n";
    return dump;
}

void TimerProvider::triggerCallbacks(nsecs_t when) {
    while (!mDeadlines.empty() && when >= mDeadlines.begin()->first) {
        const auto& deadlinePair = mDeadlines.begin();
        deadlinePair->second.callback(when);
        mDeadlines.erase(deadlinePair);
    }
    requestTimeout();
}

GesturesTimer* TimerProvider::createTimer() {
    mTimers.push_back(std::make_unique<GesturesTimer>());
    mTimers.back()->id = mNextTimerId;
    mNextTimerId++;
    return mTimers.back().get();
}

void TimerProvider::setDeadline(GesturesTimer* timer, nsecs_t delay, GesturesTimerCallback callback,
                                void* callbackData) {
    setDeadlineWithoutRequestingTimeout(timer, delay, callback, callbackData);
    requestTimeout();
}

void TimerProvider::setDeadlineWithoutRequestingTimeout(GesturesTimer* timer, nsecs_t delay,
                                                        GesturesTimerCallback callback,
                                                        void* callbackData) {
    const nsecs_t now = getCurrentTime();
    const nsecs_t time = now + delay;
    std::function<void(nsecs_t)> wrappedCallback = [=, this](nsecs_t triggerTime) {
        stime_t nextDelay = callback(nsecsToStime(triggerTime), callbackData);
        if (nextDelay >= 0.0) {
            // When rescheduling a deadline, we know that we're running inside a call to
            // triggerCallbacks, at the end of which requestTimeout will be called. This means that
            // we don't want to call the public setDeadline, as that will request a timeout before
            // triggerCallbacks has removed this current deadline, resulting in a request for a
            // timeout that has already passed.
            setDeadlineWithoutRequestingTimeout(timer, stimeToNsecs(nextDelay), callback,
                                                callbackData);
        }
    };
    mDeadlines.insert({time, Deadline(wrappedCallback, timer->id)});
}

void TimerProvider::cancelTimer(GesturesTimer* timer) {
    int id = timer->id;
    std::erase_if(mDeadlines, [id](const auto& item) { return item.second.timerId == id; });
    requestTimeout();
}

void TimerProvider::freeTimer(GesturesTimer* timer) {
    cancelTimer(timer);
    std::erase_if(mTimers, [timer](std::unique_ptr<GesturesTimer>& t) { return t.get() == timer; });
}

void TimerProvider::requestTimeout() {
    if (!mDeadlines.empty()) {
        // Because a std::multimap is sorted by key, we simply use the time for the first entry.
        mReaderContext.requestTimeoutAtTime(mDeadlines.begin()->first);
    }
}

nsecs_t TimerProvider::getCurrentTime() {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

} // namespace android