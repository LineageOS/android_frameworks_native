/*
 * Copyright 2019 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>
#include <vector>

#include "TimeKeeper.h"
#include "VSyncDispatchTimerQueue.h"
#include "VSyncTracker.h"

namespace android::scheduler {

VSyncDispatch::~VSyncDispatch() = default;
VSyncTracker::~VSyncTracker() = default;
TimeKeeper::~TimeKeeper() = default;

VSyncDispatchTimerQueueEntry::VSyncDispatchTimerQueueEntry(std::string const& name,
                                                           std::function<void(nsecs_t)> const& cb)
      : mName(name), mCallback(cb), mWorkDuration(0), mEarliestVsync(0) {}

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::lastExecutedVsyncTarget() const {
    return mLastDispatchTime;
}

std::string_view VSyncDispatchTimerQueueEntry::name() const {
    return mName;
}

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::wakeupTime() const {
    if (!mArmedInfo) {
        return {};
    }
    return {mArmedInfo->mActualWakeupTime};
}

nsecs_t VSyncDispatchTimerQueueEntry::schedule(nsecs_t workDuration, nsecs_t earliestVsync,
                                               VSyncTracker& tracker, nsecs_t now) {
    mWorkDuration = workDuration;
    mEarliestVsync = earliestVsync;
    arm(tracker, now);
    return mArmedInfo->mActualWakeupTime;
}

void VSyncDispatchTimerQueueEntry::update(VSyncTracker& tracker, nsecs_t now) {
    if (!mArmedInfo) {
        return;
    }
    arm(tracker, now);
}

void VSyncDispatchTimerQueueEntry::arm(VSyncTracker& tracker, nsecs_t now) {
    auto const nextVsyncTime =
            tracker.nextAnticipatedVSyncTimeFrom(std::max(mEarliestVsync, now + mWorkDuration));
    mArmedInfo = {nextVsyncTime - mWorkDuration, nextVsyncTime};
}

void VSyncDispatchTimerQueueEntry::disarm() {
    mArmedInfo.reset();
}

nsecs_t VSyncDispatchTimerQueueEntry::executing() {
    mLastDispatchTime = mArmedInfo->mActualVsyncTime;
    disarm();
    return *mLastDispatchTime;
}

void VSyncDispatchTimerQueueEntry::callback(nsecs_t t) {
    {
        std::lock_guard<std::mutex> lk(mRunningMutex);
        mRunning = true;
    }

    mCallback(t);

    std::lock_guard<std::mutex> lk(mRunningMutex);
    mRunning = false;
    mCv.notify_all();
}

void VSyncDispatchTimerQueueEntry::ensureNotRunning() {
    std::unique_lock<std::mutex> lk(mRunningMutex);
    mCv.wait(lk, [this]() REQUIRES(mRunningMutex) { return !mRunning; });
}

VSyncDispatchTimerQueue::VSyncDispatchTimerQueue(std::unique_ptr<TimeKeeper> tk,
                                                 VSyncTracker& tracker, nsecs_t timerSlack)
      : mTimeKeeper(std::move(tk)), mTracker(tracker), mTimerSlack(timerSlack) {}

VSyncDispatchTimerQueue::~VSyncDispatchTimerQueue() {
    std::lock_guard<decltype(mMutex)> lk(mMutex);
    cancelTimer();
}

void VSyncDispatchTimerQueue::cancelTimer() {
    mIntendedWakeupTime = kInvalidTime;
    mTimeKeeper->alarmCancel();
}

void VSyncDispatchTimerQueue::setTimer(nsecs_t targetTime, nsecs_t now) {
    mIntendedWakeupTime = targetTime;
    mTimeKeeper->alarmIn(std::bind(&VSyncDispatchTimerQueue::timerCallback, this),
                         targetTime - now);
}

void VSyncDispatchTimerQueue::rearmTimer(nsecs_t now) {
    rearmTimerSkippingUpdateFor(now, mCallbacks.end());
}

void VSyncDispatchTimerQueue::rearmTimerSkippingUpdateFor(
        nsecs_t now, CallbackMap::iterator const& skipUpdateIt) {
    std::optional<nsecs_t> min;
    for (auto it = mCallbacks.begin(); it != mCallbacks.end(); it++) {
        auto& callback = it->second;
        if (!callback->wakeupTime()) {
            continue;
        }

        if (it != skipUpdateIt) {
            callback->update(mTracker, now);
        }
        auto const wakeupTime = *callback->wakeupTime();
        if (!min || (min && *min > wakeupTime)) {
            min = wakeupTime;
        }
    }

    if (min && (min < mIntendedWakeupTime)) {
        setTimer(*min, now);
    } else {
        cancelTimer();
    }
}

void VSyncDispatchTimerQueue::timerCallback() {
    struct Invocation {
        std::shared_ptr<VSyncDispatchTimerQueueEntry> callback;
        nsecs_t timestamp;
    };
    std::vector<Invocation> invocations;
    {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        for (auto it = mCallbacks.begin(); it != mCallbacks.end(); it++) {
            auto& callback = it->second;
            auto const wakeupTime = callback->wakeupTime();
            if (!wakeupTime) {
                continue;
            }

            if (*wakeupTime < mIntendedWakeupTime + mTimerSlack) {
                callback->executing();
                invocations.emplace_back(
                        Invocation{callback, *callback->lastExecutedVsyncTarget()});
            }
        }

        mIntendedWakeupTime = kInvalidTime;
        rearmTimer(mTimeKeeper->now());
    }

    for (auto const& invocation : invocations) {
        invocation.callback->callback(invocation.timestamp);
    }
}

VSyncDispatchTimerQueue::CallbackToken VSyncDispatchTimerQueue::registerCallback(
        std::function<void(nsecs_t)> const& callbackFn, std::string callbackName) {
    std::lock_guard<decltype(mMutex)> lk(mMutex);
    return CallbackToken{
            mCallbacks
                    .emplace(++mCallbackToken,
                             std::make_shared<VSyncDispatchTimerQueueEntry>(callbackName,
                                                                            callbackFn))
                    .first->first};
}

void VSyncDispatchTimerQueue::unregisterCallback(CallbackToken token) {
    std::shared_ptr<VSyncDispatchTimerQueueEntry> entry = nullptr;
    {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        auto it = mCallbacks.find(token);
        if (it != mCallbacks.end()) {
            entry = it->second;
            mCallbacks.erase(it);
        }
    }

    if (entry) {
        entry->ensureNotRunning();
    }
}

ScheduleResult VSyncDispatchTimerQueue::schedule(CallbackToken token, nsecs_t workDuration,
                                                 nsecs_t earliestVsync) {
    auto result = ScheduleResult::Error;
    {
        std::lock_guard<decltype(mMutex)> lk(mMutex);

        auto it = mCallbacks.find(token);
        if (it == mCallbacks.end()) {
            return result;
        }
        auto& callback = it->second;
        result = callback->wakeupTime() ? ScheduleResult::ReScheduled : ScheduleResult::Scheduled;

        auto const now = mTimeKeeper->now();
        auto const wakeupTime = callback->schedule(workDuration, earliestVsync, mTracker, now);

        if (wakeupTime < now - mTimerSlack || callback->lastExecutedVsyncTarget() > wakeupTime) {
            return ScheduleResult::CannotSchedule;
        }

        if (wakeupTime < mIntendedWakeupTime - mTimerSlack) {
            rearmTimerSkippingUpdateFor(now, it);
        }
    }

    return result;
}

CancelResult VSyncDispatchTimerQueue::cancel(CallbackToken token) {
    std::lock_guard<decltype(mMutex)> lk(mMutex);

    auto it = mCallbacks.find(token);
    if (it == mCallbacks.end()) {
        return CancelResult::Error;
    }
    auto& callback = it->second;

    if (callback->wakeupTime()) {
        callback->disarm();
        mIntendedWakeupTime = kInvalidTime;
        rearmTimer(mTimeKeeper->now());
        return CancelResult::Cancelled;
    }
    return CancelResult::TooLate;
}

VSyncCallbackRegistration::VSyncCallbackRegistration(VSyncDispatch& dispatch,
                                                     std::function<void(nsecs_t)> const& callbackFn,
                                                     std::string const& callbackName)
      : mDispatch(dispatch),
        mToken(dispatch.registerCallback(callbackFn, callbackName)),
        mValidToken(true) {}

VSyncCallbackRegistration::VSyncCallbackRegistration(VSyncCallbackRegistration&& other)
      : mDispatch(other.mDispatch),
        mToken(std::move(other.mToken)),
        mValidToken(std::move(other.mValidToken)) {
    other.mValidToken = false;
}

VSyncCallbackRegistration& VSyncCallbackRegistration::operator=(VSyncCallbackRegistration&& other) {
    mDispatch = std::move(other.mDispatch);
    mToken = std::move(other.mToken);
    mValidToken = std::move(other.mValidToken);
    other.mValidToken = false;
    return *this;
}

VSyncCallbackRegistration::~VSyncCallbackRegistration() {
    if (mValidToken) mDispatch.get().unregisterCallback(mToken);
}

ScheduleResult VSyncCallbackRegistration::schedule(nsecs_t workDuration, nsecs_t earliestVsync) {
    if (!mValidToken) return ScheduleResult::Error;
    return mDispatch.get().schedule(mToken, workDuration, earliestVsync);
}

CancelResult VSyncCallbackRegistration::cancel() {
    if (!mValidToken) return CancelResult::Error;
    return mDispatch.get().cancel(mToken);
}

} // namespace android::scheduler
