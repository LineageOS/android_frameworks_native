/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <binder/IPCThreadState.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/threads.h>

#include <scheduler/interface/ICompositor.h>

#include "EventThread.h"
#include "FrameTimeline.h"
#include "MessageQueue.h"

namespace android::impl {

void MessageQueue::Handler::dispatchFrame(VsyncId vsyncId, TimePoint expectedVsyncTime) {
    if (!mFramePending.exchange(true)) {
        mVsyncId = vsyncId;
        mExpectedVsyncTime = expectedVsyncTime;
        mQueue.mLooper->sendMessage(sp<MessageHandler>::fromExisting(this), Message());
    }
}

bool MessageQueue::Handler::isFramePending() const {
    return mFramePending.load();
}

void MessageQueue::Handler::handleMessage(const Message&) {
    mFramePending.store(false);
    mQueue.onFrameSignal(mQueue.mCompositor, mVsyncId, mExpectedVsyncTime);
}

MessageQueue::MessageQueue(ICompositor& compositor)
      : MessageQueue(compositor, sp<Handler>::make(*this)) {}

constexpr bool kAllowNonCallbacks = true;

MessageQueue::MessageQueue(ICompositor& compositor, sp<Handler> handler)
      : mCompositor(compositor),
        mLooper(sp<Looper>::make(kAllowNonCallbacks)),
        mHandler(std::move(handler)) {}

void MessageQueue::vsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime, nsecs_t readyTime) {
    ATRACE_CALL();
    // Trace VSYNC-sf
    mVsync.value = (mVsync.value + 1) % 2;

    const auto expectedVsyncTime = TimePoint::fromNs(vsyncTime);
    {
        std::lock_guard lock(mVsync.mutex);
        mVsync.lastCallbackTime = expectedVsyncTime;
        mVsync.scheduledFrameTimeOpt.reset();
    }

    const auto vsyncId = VsyncId{mVsync.tokenManager->generateTokenForPredictions(
            {targetWakeupTime, readyTime, vsyncTime})};

    mHandler->dispatchFrame(vsyncId, expectedVsyncTime);
}

void MessageQueue::initVsyncInternal(std::shared_ptr<scheduler::VSyncDispatch> dispatch,
                                     frametimeline::TokenManager& tokenManager,
                                     std::chrono::nanoseconds workDuration) {
    std::unique_ptr<scheduler::VSyncCallbackRegistration> oldRegistration;
    {
        std::lock_guard lock(mVsync.mutex);
        mVsync.workDuration = workDuration;
        mVsync.tokenManager = &tokenManager;
        oldRegistration = onNewVsyncScheduleLocked(std::move(dispatch));
    }

    // See comments in onNewVsyncSchedule. Today, oldRegistration should be
    // empty, but nothing prevents us from calling initVsyncInternal multiple times, so
    // go ahead and destruct it outside the lock for safety.
    oldRegistration.reset();
}

void MessageQueue::onNewVsyncSchedule(std::shared_ptr<scheduler::VSyncDispatch> dispatch) {
    std::unique_ptr<scheduler::VSyncCallbackRegistration> oldRegistration;
    {
        std::lock_guard lock(mVsync.mutex);
        oldRegistration = onNewVsyncScheduleLocked(std::move(dispatch));
    }

    // The old registration needs to be deleted after releasing mVsync.mutex to
    // avoid deadlock. This is because the callback may be running on the timer
    // thread. In that case, timerCallback sets
    // VSyncDispatchTimerQueueEntry::mRunning to true, then attempts to lock
    // mVsync.mutex. But if it's already locked, the VSyncCallbackRegistration's
    // destructor has to wait until VSyncDispatchTimerQueueEntry::mRunning is
    // set back to false, but it won't be until mVsync.mutex is released.
    oldRegistration.reset();
}

std::unique_ptr<scheduler::VSyncCallbackRegistration> MessageQueue::onNewVsyncScheduleLocked(
        std::shared_ptr<scheduler::VSyncDispatch> dispatch) {
    const bool reschedule = mVsync.registration &&
            mVsync.registration->cancel() == scheduler::CancelResult::Cancelled;
    auto oldRegistration = std::move(mVsync.registration);
    mVsync.registration = std::make_unique<
            scheduler::VSyncCallbackRegistration>(std::move(dispatch),
                                                  std::bind(&MessageQueue::vsyncCallback, this,
                                                            std::placeholders::_1,
                                                            std::placeholders::_2,
                                                            std::placeholders::_3),
                                                  "sf");
    if (reschedule) {
        mVsync.scheduledFrameTimeOpt =
                mVsync.registration->schedule({.workDuration = mVsync.workDuration.get().count(),
                                               .readyDuration = 0,
                                               .lastVsync = mVsync.lastCallbackTime.ns()});
    }
    return oldRegistration;
}

void MessageQueue::destroyVsync() {
    std::lock_guard lock(mVsync.mutex);
    mVsync.tokenManager = nullptr;
    mVsync.registration.reset();
}

void MessageQueue::setDuration(std::chrono::nanoseconds workDuration) {
    ATRACE_CALL();
    std::lock_guard lock(mVsync.mutex);
    mVsync.workDuration = workDuration;
    mVsync.scheduledFrameTimeOpt =
            mVsync.registration->update({.workDuration = mVsync.workDuration.get().count(),
                                         .readyDuration = 0,
                                         .lastVsync = mVsync.lastCallbackTime.ns()});
}

void MessageQueue::waitMessage() {
    do {
        IPCThreadState::self()->flushCommands();
        int32_t ret = mLooper->pollOnce(-1);
        switch (ret) {
            case Looper::POLL_WAKE:
            case Looper::POLL_CALLBACK:
                continue;
            case Looper::POLL_ERROR:
                ALOGE("Looper::POLL_ERROR");
                continue;
            case Looper::POLL_TIMEOUT:
                // timeout (should not happen)
                continue;
            default:
                // should not happen
                ALOGE("Looper::pollOnce() returned unknown status %d", ret);
                continue;
        }
    } while (true);
}

void MessageQueue::postMessage(sp<MessageHandler>&& handler) {
    mLooper->sendMessage(handler, Message());
}

void MessageQueue::postMessageDelayed(sp<MessageHandler>&& handler, nsecs_t uptimeDelay) {
    mLooper->sendMessageDelayed(uptimeDelay, handler, Message());
}

void MessageQueue::scheduleConfigure() {
    struct ConfigureHandler : MessageHandler {
        explicit ConfigureHandler(ICompositor& compositor) : compositor(compositor) {}

        void handleMessage(const Message&) override { compositor.configure(); }

        ICompositor& compositor;
    };

    // TODO(b/241285876): Batch configure tasks that happen within some duration.
    postMessage(sp<ConfigureHandler>::make(mCompositor));
}

void MessageQueue::scheduleFrame() {
    ATRACE_CALL();

    std::lock_guard lock(mVsync.mutex);
    mVsync.scheduledFrameTimeOpt =
            mVsync.registration->schedule({.workDuration = mVsync.workDuration.get().count(),
                                           .readyDuration = 0,
                                           .lastVsync = mVsync.lastCallbackTime.ns()});
}

std::optional<scheduler::ScheduleResult> MessageQueue::getScheduledFrameResult() const {
    if (mHandler->isFramePending()) {
        return scheduler::ScheduleResult{TimePoint::now(), mHandler->getExpectedVsyncTime()};
    }
    std::lock_guard lock(mVsync.mutex);
    if (const auto scheduledFrameTimeline = mVsync.scheduledFrameTimeOpt) {
        return scheduledFrameTimeline;
    }
    return std::nullopt;
}

} // namespace android::impl
