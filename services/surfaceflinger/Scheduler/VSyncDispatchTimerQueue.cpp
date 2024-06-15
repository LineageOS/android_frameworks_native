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

#include <vector>

#include <android-base/stringprintf.h>
#include <ftl/concat.h>
#include <utils/Trace.h>
#include <log/log_main.h>

#include <scheduler/TimeKeeper.h>

#include <common/FlagManager.h>
#include "VSyncDispatchTimerQueue.h"
#include "VSyncTracker.h"

#undef LOG_TAG
#define LOG_TAG "VSyncDispatch"

namespace android::scheduler {

using base::StringAppendF;

namespace {

ScheduleResult getExpectedCallbackTime(nsecs_t nextVsyncTime,
                                       const VSyncDispatch::ScheduleTiming& timing) {
    return {TimePoint::fromNs(nextVsyncTime - timing.readyDuration - timing.workDuration),
            TimePoint::fromNs(nextVsyncTime)};
}

} // namespace

VSyncDispatch::~VSyncDispatch() = default;
VSyncTracker::~VSyncTracker() = default;

VSyncDispatchTimerQueueEntry::VSyncDispatchTimerQueueEntry(std::string name,
                                                           VSyncDispatch::Callback callback,
                                                           nsecs_t minVsyncDistance)
      : mName(std::move(name)),
        mCallback(std::move(callback)),
        mMinVsyncDistance(minVsyncDistance) {}

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

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::readyTime() const {
    if (!mArmedInfo) {
        return {};
    }
    return {mArmedInfo->mActualReadyTime};
}

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::targetVsync() const {
    if (!mArmedInfo) {
        return {};
    }
    return {mArmedInfo->mActualVsyncTime};
}

ScheduleResult VSyncDispatchTimerQueueEntry::schedule(VSyncDispatch::ScheduleTiming timing,
                                                      VSyncTracker& tracker, nsecs_t now) {
    auto nextVsyncTime =
            tracker.nextAnticipatedVSyncTimeFrom(std::max(timing.lastVsync,
                                                          now + timing.workDuration +
                                                                  timing.readyDuration),
                                                 timing.lastVsync);
    auto nextWakeupTime = nextVsyncTime - timing.workDuration - timing.readyDuration;

    bool const wouldSkipAVsyncTarget =
            mArmedInfo && (nextVsyncTime > (mArmedInfo->mActualVsyncTime + mMinVsyncDistance));
    bool const wouldSkipAWakeup =
            mArmedInfo && ((nextWakeupTime > (mArmedInfo->mActualWakeupTime + mMinVsyncDistance)));
    if (FlagManager::getInstance().dont_skip_on_early_ro()) {
        if (wouldSkipAVsyncTarget || wouldSkipAWakeup) {
            nextVsyncTime = mArmedInfo->mActualVsyncTime;
        } else {
            nextVsyncTime = adjustVsyncIfNeeded(tracker, nextVsyncTime);
        }
        nextWakeupTime = std::max(now, nextVsyncTime - timing.workDuration - timing.readyDuration);
    } else {
        if (wouldSkipAVsyncTarget && wouldSkipAWakeup) {
            return getExpectedCallbackTime(nextVsyncTime, timing);
        }
        nextVsyncTime = adjustVsyncIfNeeded(tracker, nextVsyncTime);
        nextWakeupTime = nextVsyncTime - timing.workDuration - timing.readyDuration;
    }

    auto const nextReadyTime = nextVsyncTime - timing.readyDuration;
    mScheduleTiming = timing;
    mArmedInfo = {nextWakeupTime, nextVsyncTime, nextReadyTime};
    return ScheduleResult{TimePoint::fromNs(nextWakeupTime), TimePoint::fromNs(nextVsyncTime)};
}

ScheduleResult VSyncDispatchTimerQueueEntry::addPendingWorkloadUpdate(
        VSyncTracker& tracker, nsecs_t now, VSyncDispatch::ScheduleTiming timing) {
    mWorkloadUpdateInfo = timing;
    const auto armedInfo = update(tracker, now, timing, mArmedInfo);
    return {TimePoint::fromNs(armedInfo.mActualWakeupTime),
            TimePoint::fromNs(armedInfo.mActualVsyncTime)};
}

bool VSyncDispatchTimerQueueEntry::hasPendingWorkloadUpdate() const {
    return mWorkloadUpdateInfo.has_value();
}

nsecs_t VSyncDispatchTimerQueueEntry::adjustVsyncIfNeeded(VSyncTracker& tracker,
                                                          nsecs_t nextVsyncTime) const {
    bool const alreadyDispatchedForVsync = mLastDispatchTime &&
            ((*mLastDispatchTime + mMinVsyncDistance) >= nextVsyncTime &&
             (*mLastDispatchTime - mMinVsyncDistance) <= nextVsyncTime);
    const nsecs_t currentPeriod = tracker.currentPeriod();
    bool const nextVsyncTooClose = mLastDispatchTime &&
            (nextVsyncTime - *mLastDispatchTime + mMinVsyncDistance) <= currentPeriod;
    if (alreadyDispatchedForVsync) {
        return tracker.nextAnticipatedVSyncTimeFrom(*mLastDispatchTime + mMinVsyncDistance,
                                                    *mLastDispatchTime);
    }

    if (nextVsyncTooClose) {
        return tracker.nextAnticipatedVSyncTimeFrom(*mLastDispatchTime + currentPeriod,
                                                    *mLastDispatchTime + currentPeriod);
    }

    return nextVsyncTime;
}

auto VSyncDispatchTimerQueueEntry::update(VSyncTracker& tracker, nsecs_t now,
                                          VSyncDispatch::ScheduleTiming timing,
                                          std::optional<ArmingInfo> armedInfo) const -> ArmingInfo {
    const auto earliestReadyBy = now + timing.workDuration + timing.readyDuration;
    const auto earliestVsync = std::max(earliestReadyBy, timing.lastVsync);

    const auto nextVsyncTime =
            adjustVsyncIfNeeded(tracker, /*nextVsyncTime*/
                                tracker.nextAnticipatedVSyncTimeFrom(earliestVsync,
                                                                     timing.lastVsync));
    const auto nextReadyTime = nextVsyncTime - timing.readyDuration;
    const auto nextWakeupTime = nextReadyTime - timing.workDuration;

    bool const wouldSkipAVsyncTarget =
            armedInfo && (nextVsyncTime > (armedInfo->mActualVsyncTime + mMinVsyncDistance));
    bool const wouldSkipAWakeup =
            armedInfo && (nextWakeupTime > (armedInfo->mActualWakeupTime + mMinVsyncDistance));
    if (FlagManager::getInstance().dont_skip_on_early_ro() &&
        (wouldSkipAVsyncTarget || wouldSkipAWakeup)) {
        return *armedInfo;
    }

    return ArmingInfo{nextWakeupTime, nextVsyncTime, nextReadyTime};
}

void VSyncDispatchTimerQueueEntry::update(VSyncTracker& tracker, nsecs_t now) {
    if (!mArmedInfo && !mWorkloadUpdateInfo) {
        return;
    }

    if (mWorkloadUpdateInfo) {
        mScheduleTiming = *mWorkloadUpdateInfo;
        mWorkloadUpdateInfo.reset();
    }

    mArmedInfo = update(tracker, now, mScheduleTiming, mArmedInfo);
}

void VSyncDispatchTimerQueueEntry::disarm() {
    mArmedInfo.reset();
}

nsecs_t VSyncDispatchTimerQueueEntry::executing() {
    mLastDispatchTime = mArmedInfo->mActualVsyncTime;
    disarm();
    return *mLastDispatchTime;
}

void VSyncDispatchTimerQueueEntry::callback(nsecs_t vsyncTimestamp, nsecs_t wakeupTimestamp,
                                            nsecs_t deadlineTimestamp) {
    {
        std::lock_guard<std::mutex> lk(mRunningMutex);
        mRunning = true;
    }

    mCallback(vsyncTimestamp, wakeupTimestamp, deadlineTimestamp);

    std::lock_guard<std::mutex> lk(mRunningMutex);
    mRunning = false;
    mCv.notify_all();
}

void VSyncDispatchTimerQueueEntry::ensureNotRunning() {
    std::unique_lock<std::mutex> lk(mRunningMutex);
    mCv.wait(lk, [this]() REQUIRES(mRunningMutex) { return !mRunning; });
}

void VSyncDispatchTimerQueueEntry::dump(std::string& result) const {
    std::lock_guard<std::mutex> lk(mRunningMutex);
    std::string armedInfo;
    if (mArmedInfo) {
        StringAppendF(&armedInfo,
                      "[wake up in %.2fms deadline in %.2fms for vsync %.2fms from now]",
                      (mArmedInfo->mActualWakeupTime - systemTime()) / 1e6f,
                      (mArmedInfo->mActualReadyTime - systemTime()) / 1e6f,
                      (mArmedInfo->mActualVsyncTime - systemTime()) / 1e6f);
    }

    StringAppendF(&result, "\t\t%s: %s %s\n", mName.c_str(),
                  mRunning ? "(in callback function)" : "", armedInfo.c_str());
    StringAppendF(&result,
                  "\t\t\tworkDuration: %.2fms readyDuration: %.2fms lastVsync: %.2fms relative "
                  "to now\n",
                  mScheduleTiming.workDuration / 1e6f, mScheduleTiming.readyDuration / 1e6f,
                  (mScheduleTiming.lastVsync - systemTime()) / 1e6f);

    if (mLastDispatchTime) {
        StringAppendF(&result, "\t\t\tmLastDispatchTime: %.2fms ago\n",
                      (systemTime() - *mLastDispatchTime) / 1e6f);
    } else {
        StringAppendF(&result, "\t\t\tmLastDispatchTime unknown\n");
    }
}

VSyncDispatchTimerQueue::VSyncDispatchTimerQueue(std::unique_ptr<TimeKeeper> tk,
                                                 VsyncSchedule::TrackerPtr tracker,
                                                 nsecs_t timerSlack, nsecs_t minVsyncDistance)
      : mTimeKeeper(std::move(tk)),
        mTracker(std::move(tracker)),
        mTimerSlack(timerSlack),
        mMinVsyncDistance(minVsyncDistance) {}

VSyncDispatchTimerQueue::~VSyncDispatchTimerQueue() {
    std::lock_guard lock(mMutex);
    mRunning = false;
    cancelTimer();
    for (auto& [_, entry] : mCallbacks) {
        ALOGE("Forgot to unregister a callback on VSyncDispatch!");
        entry->ensureNotRunning();
    }
}

void VSyncDispatchTimerQueue::cancelTimer() {
    mIntendedWakeupTime = kInvalidTime;
    mTimeKeeper->alarmCancel();
}

void VSyncDispatchTimerQueue::setTimer(nsecs_t targetTime, nsecs_t /*now*/) {
    mIntendedWakeupTime = targetTime;
    mTimeKeeper->alarmAt(std::bind(&VSyncDispatchTimerQueue::timerCallback, this),
                         mIntendedWakeupTime);
    mLastTimerSchedule = mTimeKeeper->now();
}

void VSyncDispatchTimerQueue::rearmTimer(nsecs_t now) {
    rearmTimerSkippingUpdateFor(now, mCallbacks.cend());
}

void VSyncDispatchTimerQueue::rearmTimerSkippingUpdateFor(
        nsecs_t now, CallbackMap::const_iterator skipUpdateIt) {
    std::optional<nsecs_t> min;
    std::optional<nsecs_t> targetVsync;
    std::optional<std::string_view> nextWakeupName;
    for (auto it = mCallbacks.cbegin(); it != mCallbacks.cend(); ++it) {
        auto& callback = it->second;
        if (!callback->wakeupTime() && !callback->hasPendingWorkloadUpdate()) {
            continue;
        }

        if (it != skipUpdateIt) {
            callback->update(*mTracker, now);
        }
        auto const wakeupTime = *callback->wakeupTime();
        if (!min || *min > wakeupTime) {
            nextWakeupName = callback->name();
            min = wakeupTime;
            targetVsync = callback->targetVsync();
        }
    }

    if (min && min < mIntendedWakeupTime) {
        if (ATRACE_ENABLED() && nextWakeupName && targetVsync) {
            ftl::Concat trace(ftl::truncated<5>(*nextWakeupName), " alarm in ", ns2us(*min - now),
                              "us; VSYNC in ", ns2us(*targetVsync - now), "us");
            ATRACE_NAME(trace.c_str());
        }
        setTimer(*min, now);
    } else {
        ATRACE_NAME("cancel timer");
        cancelTimer();
    }
}

void VSyncDispatchTimerQueue::timerCallback() {
    struct Invocation {
        std::shared_ptr<VSyncDispatchTimerQueueEntry> callback;
        nsecs_t vsyncTimestamp;
        nsecs_t wakeupTimestamp;
        nsecs_t deadlineTimestamp;
    };
    std::vector<Invocation> invocations;
    {
        std::lock_guard lock(mMutex);
        if (!mRunning) {
            ALOGD("TimerQueue is not running. Skipping callback.");
            return;
        }
        auto const now = mTimeKeeper->now();
        mLastTimerCallback = now;
        for (auto it = mCallbacks.begin(); it != mCallbacks.end(); it++) {
            auto& callback = it->second;
            auto const wakeupTime = callback->wakeupTime();
            if (!wakeupTime) {
                continue;
            }

            auto const readyTime = callback->readyTime();

            auto const lagAllowance = std::max(now - mIntendedWakeupTime, static_cast<nsecs_t>(0));
            if (*wakeupTime < mIntendedWakeupTime + mTimerSlack + lagAllowance) {
                callback->executing();
                invocations.emplace_back(Invocation{callback, *callback->lastExecutedVsyncTarget(),
                                                    *wakeupTime, *readyTime});
            }
        }

        mIntendedWakeupTime = kInvalidTime;
        rearmTimer(mTimeKeeper->now());
    }

    for (auto const& invocation : invocations) {
        invocation.callback->callback(invocation.vsyncTimestamp, invocation.wakeupTimestamp,
                                      invocation.deadlineTimestamp);
    }
}

VSyncDispatchTimerQueue::CallbackToken VSyncDispatchTimerQueue::registerCallback(
        Callback callback, std::string callbackName) {
    std::lock_guard lock(mMutex);
    return mCallbacks
            .try_emplace(++mCallbackToken,
                         std::make_shared<VSyncDispatchTimerQueueEntry>(std::move(callbackName),
                                                                        std::move(callback),
                                                                        mMinVsyncDistance))
            .first->first;
}

void VSyncDispatchTimerQueue::unregisterCallback(CallbackToken token) {
    std::shared_ptr<VSyncDispatchTimerQueueEntry> entry = nullptr;
    {
        std::lock_guard lock(mMutex);
        auto it = mCallbacks.find(token);
        if (it != mCallbacks.end()) {
            entry = it->second;
            mCallbacks.erase(it->first);
        }
    }

    if (entry) {
        entry->ensureNotRunning();
    }
}

std::optional<ScheduleResult> VSyncDispatchTimerQueue::schedule(CallbackToken token,
                                                                ScheduleTiming scheduleTiming) {
    std::lock_guard lock(mMutex);
    return scheduleLocked(token, scheduleTiming);
}

std::optional<ScheduleResult> VSyncDispatchTimerQueue::scheduleLocked(
        CallbackToken token, ScheduleTiming scheduleTiming) {
    auto it = mCallbacks.find(token);
    if (it == mCallbacks.end()) {
        return {};
    }
    auto& callback = it->second;
    auto const now = mTimeKeeper->now();

    /* If the timer thread will run soon, we'll apply this work update via the callback
     * timer recalculation to avoid cancelling a callback that is about to fire. */
    auto const rearmImminent = now > mIntendedWakeupTime;
    if (CC_UNLIKELY(rearmImminent)) {
        return callback->addPendingWorkloadUpdate(*mTracker, now, scheduleTiming);
    }

    const auto result = callback->schedule(scheduleTiming, *mTracker, now);

    if (callback->wakeupTime() < mIntendedWakeupTime - mTimerSlack) {
        rearmTimerSkippingUpdateFor(now, it);
    }

    return result;
}

std::optional<ScheduleResult> VSyncDispatchTimerQueue::update(CallbackToken token,
                                                              ScheduleTiming scheduleTiming) {
    std::lock_guard lock(mMutex);
    const auto it = mCallbacks.find(token);
    if (it == mCallbacks.end()) {
        return {};
    }

    auto& callback = it->second;
    if (!callback->targetVsync().has_value()) {
        return {};
    }

    return scheduleLocked(token, scheduleTiming);
}

CancelResult VSyncDispatchTimerQueue::cancel(CallbackToken token) {
    std::lock_guard lock(mMutex);

    auto it = mCallbacks.find(token);
    if (it == mCallbacks.end()) {
        return CancelResult::Error;
    }
    auto& callback = it->second;

    auto const wakeupTime = callback->wakeupTime();
    if (wakeupTime) {
        callback->disarm();

        if (*wakeupTime == mIntendedWakeupTime) {
            mIntendedWakeupTime = kInvalidTime;
            rearmTimer(mTimeKeeper->now());
        }
        return CancelResult::Cancelled;
    }
    return CancelResult::TooLate;
}

void VSyncDispatchTimerQueue::dump(std::string& result) const {
    std::lock_guard lock(mMutex);
    StringAppendF(&result, "\tTimer:\n");
    mTimeKeeper->dump(result);
    StringAppendF(&result, "\tmTimerSlack: %.2fms mMinVsyncDistance: %.2fms\n", mTimerSlack / 1e6f,
                  mMinVsyncDistance / 1e6f);
    StringAppendF(&result, "\tmIntendedWakeupTime: %.2fms from now\n",
                  (mIntendedWakeupTime - mTimeKeeper->now()) / 1e6f);
    StringAppendF(&result, "\tmLastTimerCallback: %.2fms ago mLastTimerSchedule: %.2fms ago\n",
                  (mTimeKeeper->now() - mLastTimerCallback) / 1e6f,
                  (mTimeKeeper->now() - mLastTimerSchedule) / 1e6f);
    StringAppendF(&result, "\tCallbacks:\n");
    for (const auto& [token, entry] : mCallbacks) {
        entry->dump(result);
    }
}

VSyncCallbackRegistration::VSyncCallbackRegistration(std::shared_ptr<VSyncDispatch> dispatch,
                                                     VSyncDispatch::Callback callback,
                                                     std::string callbackName)
      : mDispatch(std::move(dispatch)),
        mToken(mDispatch->registerCallback(std::move(callback), std::move(callbackName))) {}

VSyncCallbackRegistration::VSyncCallbackRegistration(VSyncCallbackRegistration&& other)
      : mDispatch(std::move(other.mDispatch)), mToken(std::exchange(other.mToken, std::nullopt)) {}

VSyncCallbackRegistration& VSyncCallbackRegistration::operator=(VSyncCallbackRegistration&& other) {
    if (this == &other) return *this;
    if (mToken) {
        mDispatch->unregisterCallback(*mToken);
    }
    mDispatch = std::move(other.mDispatch);
    mToken = std::exchange(other.mToken, std::nullopt);
    return *this;
}

VSyncCallbackRegistration::~VSyncCallbackRegistration() {
    if (mToken) mDispatch->unregisterCallback(*mToken);
}

std::optional<ScheduleResult> VSyncCallbackRegistration::schedule(
        VSyncDispatch::ScheduleTiming scheduleTiming) {
    if (!mToken) {
        return std::nullopt;
    }
    return mDispatch->schedule(*mToken, scheduleTiming);
}

std::optional<ScheduleResult> VSyncCallbackRegistration::update(
        VSyncDispatch::ScheduleTiming scheduleTiming) {
    if (!mToken) {
        return std::nullopt;
    }
    return mDispatch->update(*mToken, scheduleTiming);
}

CancelResult VSyncCallbackRegistration::cancel() {
    if (!mToken) {
        return CancelResult::Error;
    }
    return mDispatch->cancel(*mToken);
}

} // namespace android::scheduler
