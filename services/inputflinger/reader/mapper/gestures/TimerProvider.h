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

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <vector>

#include <utils/Timers.h>

#include "InputReaderContext.h"
#include "NotifyArgs.h"
#include "include/gestures.h"

namespace android {

extern const GesturesTimerProvider kGestureTimerProvider;

// Implementation of a gestures library timer provider, which allows the library to set and cancel
// callbacks.
class TimerProvider {
public:
    TimerProvider(InputReaderContext& context);
    virtual ~TimerProvider() = default;

    // Disable copy and move, since pointers to TimerProvider objects are used in callbacks.
    TimerProvider(const TimerProvider&) = delete;
    TimerProvider& operator=(const TimerProvider&) = delete;

    std::string dump();
    void triggerCallbacks(nsecs_t when);

    // Methods to be called by the gestures library:
    GesturesTimer* createTimer();
    void setDeadline(GesturesTimer* timer, nsecs_t delay, GesturesTimerCallback callback,
                     void* callbackData);
    void cancelTimer(GesturesTimer* timer);
    void freeTimer(GesturesTimer* timer);

protected:
    // A wrapper for the system clock, to allow tests to override it.
    virtual nsecs_t getCurrentTime();

private:
    void setDeadlineWithoutRequestingTimeout(GesturesTimer* timer, nsecs_t delay,
                                             GesturesTimerCallback callback, void* callbackData);
    // Requests a timeout from the InputReader for the nearest deadline in mDeadlines. Must be
    // called whenever mDeadlines is modified.
    void requestTimeout();

    InputReaderContext& mReaderContext;
    int mNextTimerId = 0;
    std::vector<std::unique_ptr<GesturesTimer>> mTimers;

    struct Deadline {
        Deadline(std::function<void(nsecs_t)> callback, int timerId)
              : callback(callback), timerId(timerId) {}
        const std::function<void(nsecs_t)> callback;
        const int timerId;
    };

    std::multimap<nsecs_t /*time*/, Deadline> mDeadlines;
};

} // namespace android

// Represents a "timer" registered by the gestures library. In practice, this just means a set of
// deadlines that can be cancelled as a group. The library's API requires this to be in the
// top-level namespace.
struct GesturesTimer {
    int id = -1;
};