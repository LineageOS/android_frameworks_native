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

#pragma once

#include <android-base/thread_annotations.h>
#include <utils/Timers.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "StrongTyping.h"

namespace android::scheduler {
class TimeKeeper;
class VSyncTracker;

enum class ScheduleResult { Scheduled, ReScheduled, CannotSchedule, Error };
enum class CancelResult { Cancelled, TooLate, Error };

namespace impl {

// VSyncDispatchEntry is a helper class representing internal state for each entry in VSyncDispatch
// hoisted to public for unit testing.
class VSyncDispatchEntry {
public:
    // This is the state of the entry. There are 3 states, armed, running, disarmed.
    // Valid transition: disarmed -> armed ( when scheduled )
    // Valid transition: armed -> running -> disarmed ( when timer is called)
    // Valid transition: armed -> disarmed ( when cancelled )
    VSyncDispatchEntry(std::string const& name, std::function<void(nsecs_t)> const& fn);
    std::string_view name() const;

    // Start: functions that are not threadsafe.
    // Return the last vsync time this callback was invoked.
    std::optional<nsecs_t> lastExecutedVsyncTarget() const;

    // This moves the state from disarmed->armed and will calculate the wakeupTime.
    nsecs_t schedule(nsecs_t workDuration, nsecs_t earliestVsync, VSyncTracker& tracker,
                     nsecs_t now);
    // This will update armed entries with the latest vsync information. Entry remains armed.
    void update(VSyncTracker& tracker, nsecs_t now);

    // This will return empty if not armed, or the next calculated wakeup time if armed.
    // It will not update the wakeupTime.
    std::optional<nsecs_t> wakeupTime() const;

    // This moves state from armed->disarmed.
    void disarm();

    // This moves the state from armed->running.
    // Store the timestamp that this was intended for as the last called timestamp.
    nsecs_t executing();
    // End: functions that are not threadsafe.

    // Invoke the callback with the timestamp, moving the state from running->disarmed.
    void callback(nsecs_t timestamp);
    // Block calling thread while the callback is executing.
    void ensureNotRunning();

private:
    void arm(VSyncTracker& tracker, nsecs_t now);
    std::string const mName;
    std::function<void(nsecs_t)> const mCallback;

    nsecs_t mWorkDuration;
    nsecs_t mEarliestVsync;

    struct ArmingInfo {
        nsecs_t mActualWakeupTime;
        nsecs_t mActualVsyncTime;
    };
    std::optional<ArmingInfo> mArmedInfo;
    std::optional<nsecs_t> mLastDispatchTime;

    std::mutex mRunningMutex;
    std::condition_variable mCv;
    bool mRunning GUARDED_BY(mRunningMutex) = false;
};

} // namespace impl

/*
 * VSyncDispatch is a class that will dispatch callbacks relative to system vsync events.
 */
class VSyncDispatch {
public:
    using CallbackToken = StrongTyping<size_t, class CallbackTokenTag, Compare>;

    /* creates a VsyncDispatch.
     * \param [in]  a timekeeper object for dispatching events.
     * \param [in]  a tracker object that is monitoring expected vsync events.
     * \param [in]  a tunable in nanoseconds that indicates when events that fall close together
     *              should be dispatched in one timer wakeup.
     */
    explicit VSyncDispatch(std::unique_ptr<TimeKeeper> tk, VSyncTracker& tracker,
                           nsecs_t timerSlack);
    ~VSyncDispatch();

    /*
     * Registers a callback that will be called at designated points on the vsync timeline.
     * The callback can be scheduled, rescheduled targeting vsync times, or cancelled.
     * The token returned must be cleaned up via unregisterCallback.
     *
     * \param [in] callbackFn   A function to schedule for callback. The resources needed to invoke
     *                          callbackFn must have lifetimes encompassing the lifetime of the
     *                          CallbackToken returned.
     * \param [in] callbackName A human-readable, unique name to identify the callback.
     * \return                  A token that can be used to schedule, reschedule, or cancel the
     *                          invocation of callbackFn.
     *
     */
    CallbackToken registerCallback(std::function<void(nsecs_t)> const& callbackFn,
                                   std::string callbackName);

    /*
     * Unregisters a callback.
     *
     * \param [in] token        The callback to unregister.
     *
     */
    void unregisterCallback(CallbackToken token);

    /*
     * Schedules the registered callback to be dispatched.
     *
     * The callback will be dispatched at 'workDuration' nanoseconds before a vsync event.
     *
     * The caller designates the earliest vsync event that should be targeted by the earliestVsync
     * parameter.
     * The callback will be scheduled at (workDuration - predictedVsync), where predictedVsync
     * is the first vsync event time where ( predictedVsync >= earliestVsync ).
     *
     * If (workDuration - earliestVsync) is in the past, or if a callback has already been
     * dispatched for the predictedVsync, an error will be returned.
     *
     * It is valid to reschedule a callback to a different time.
     *
     * \param [in] token           The callback to schedule.
     * \param [in] workDuration    The time before the actual vsync time to invoke the callback
     *                             associated with token.
     * \param [in] earliestVsync   The targeted display time. This will be snapped to the closest
     *                             predicted vsync time after earliestVsync.
     * \return                     A ScheduleResult::Scheduled if callback was scheduled.
     *                             A ScheduleResult::ReScheduled if callback was rescheduled.
     *                             A ScheduleResult::CannotSchedule
     *                             if (workDuration - earliestVsync) is in the past, or
     *                             if a callback was dispatched for the predictedVsync already.
     *                             A ScheduleResult::Error if there was another error.
     */
    ScheduleResult schedule(CallbackToken token, nsecs_t workDuration, nsecs_t earliestVsync);

    /* Cancels a scheduled callback, if possible.
     *
     * \param [in] token    The callback to cancel.
     * \return              A CancelResult::TooLate if the callback was already dispatched.
     *                      A CancelResult::Cancelled if the callback was successfully cancelled.
     *                      A CancelResult::Error if there was an pre-condition violation.
     */
    CancelResult cancel(CallbackToken token);

private:
    VSyncDispatch(VSyncDispatch const&) = delete;
    VSyncDispatch& operator=(VSyncDispatch const&) = delete;

    using CallbackMap = std::unordered_map<size_t, std::shared_ptr<impl::VSyncDispatchEntry>>;

    void timerCallback();
    void setTimer(nsecs_t, nsecs_t) REQUIRES(mMutex);
    void rearmTimer(nsecs_t now) REQUIRES(mMutex);
    void rearmTimerSkippingUpdateFor(nsecs_t now, CallbackMap::iterator const& skipUpdate)
            REQUIRES(mMutex);
    void cancelTimer() REQUIRES(mMutex);

    static constexpr nsecs_t kInvalidTime = std::numeric_limits<int64_t>::max();
    std::unique_ptr<TimeKeeper> const mTimeKeeper;
    VSyncTracker& mTracker;
    nsecs_t const mTimerSlack;

    std::mutex mutable mMutex;
    size_t mCallbackToken GUARDED_BY(mMutex) = 0;

    CallbackMap mCallbacks GUARDED_BY(mMutex);
    nsecs_t mIntendedWakeupTime GUARDED_BY(mMutex) = kInvalidTime;
};

/*
 * Helper class to operate on registered callbacks. It is up to user of the class to ensure
 * that VsyncDispatch lifetime exceeds the lifetime of VSyncCallbackRegistation.
 */
class VSyncCallbackRegistration {
public:
    VSyncCallbackRegistration(VSyncDispatch&, std::function<void(nsecs_t)> const& callbackFn,
                              std::string const& callbackName);
    VSyncCallbackRegistration(VSyncCallbackRegistration&&);
    VSyncCallbackRegistration& operator=(VSyncCallbackRegistration&&);
    ~VSyncCallbackRegistration();

    // See documentation for VSyncDispatch::schedule.
    ScheduleResult schedule(nsecs_t workDuration, nsecs_t earliestVsync);

    // See documentation for VSyncDispatch::cancel.
    CancelResult cancel();

private:
    VSyncCallbackRegistration(VSyncCallbackRegistration const&) = delete;
    VSyncCallbackRegistration& operator=(VSyncCallbackRegistration const&) = delete;

    std::reference_wrapper<VSyncDispatch> mDispatch;
    VSyncDispatch::CallbackToken mToken;
    bool mValidToken;
};

} // namespace android::scheduler
