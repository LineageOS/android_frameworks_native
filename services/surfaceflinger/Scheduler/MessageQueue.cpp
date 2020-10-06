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

#include <gui/DisplayEventReceiver.h>
#include <gui/IDisplayEventConnection.h>

#include "EventThread.h"
#include "FrameTimeline.h"
#include "MessageQueue.h"
#include "SurfaceFlinger.h"

namespace android::impl {

void MessageQueue::Handler::dispatchRefresh() {
    if ((android_atomic_or(eventMaskRefresh, &mEventMask) & eventMaskRefresh) == 0) {
        mQueue.mLooper->sendMessage(this, Message(MessageQueue::REFRESH));
    }
}

void MessageQueue::Handler::dispatchInvalidate(int64_t vsyncId, nsecs_t expectedVSyncTimestamp) {
    if ((android_atomic_or(eventMaskInvalidate, &mEventMask) & eventMaskInvalidate) == 0) {
        mVsyncId = vsyncId;
        mExpectedVSyncTime = expectedVSyncTimestamp;
        mQueue.mLooper->sendMessage(this, Message(MessageQueue::INVALIDATE));
    }
}

void MessageQueue::Handler::handleMessage(const Message& message) {
    switch (message.what) {
        case INVALIDATE:
            android_atomic_and(~eventMaskInvalidate, &mEventMask);
            mQueue.mFlinger->onMessageReceived(message.what, mVsyncId, mExpectedVSyncTime);
            break;
        case REFRESH:
            android_atomic_and(~eventMaskRefresh, &mEventMask);
            mQueue.mFlinger->onMessageReceived(message.what, mVsyncId, mExpectedVSyncTime);
            break;
    }
}

// ---------------------------------------------------------------------------

void MessageQueue::init(const sp<SurfaceFlinger>& flinger) {
    mFlinger = flinger;
    mLooper = new Looper(true);
    mHandler = new Handler(*this);
}

// TODO(b/169865816): refactor VSyncInjections to use MessageQueue directly
// and remove the EventThread from MessageQueue
void MessageQueue::setEventConnection(const sp<EventThreadConnection>& connection) {
    if (mEventTube.getFd() >= 0) {
        mLooper->removeFd(mEventTube.getFd());
    }

    mEvents = connection;
    if (mEvents) {
        mEvents->stealReceiveChannel(&mEventTube);
        mLooper->addFd(mEventTube.getFd(), 0, Looper::EVENT_INPUT, MessageQueue::cb_eventReceiver,
                       this);
    }
}

void MessageQueue::vsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime, nsecs_t readyTime) {
    ATRACE_CALL();
    // Trace VSYNC-sf
    mVsync.value = (mVsync.value + 1) % 2;

    {
        std::lock_guard lock(mVsync.mutex);
        mVsync.lastCallbackTime = std::chrono::nanoseconds(vsyncTime);
    }
    mHandler->dispatchInvalidate(mVsync.tokenManager->generateTokenForPredictions(
                                         {targetWakeupTime, readyTime, vsyncTime}),
                                 vsyncTime);
}

void MessageQueue::initVsync(scheduler::VSyncDispatch& dispatch,
                             frametimeline::TokenManager& tokenManager,
                             std::chrono::nanoseconds workDuration) {
    setDuration(workDuration);
    mVsync.tokenManager = &tokenManager;
    mVsync.registration = std::make_unique<
            scheduler::VSyncCallbackRegistration>(dispatch,
                                                  std::bind(&MessageQueue::vsyncCallback, this,
                                                            std::placeholders::_1,
                                                            std::placeholders::_2,
                                                            std::placeholders::_3),
                                                  "sf");
}

void MessageQueue::setDuration(std::chrono::nanoseconds workDuration) {
    ATRACE_CALL();
    std::lock_guard lock(mVsync.mutex);
    mVsync.workDuration = workDuration;
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

void MessageQueue::invalidate() {
    ATRACE_CALL();
    if (mEvents) {
        mEvents->requestNextVsync();
    } else {
        const auto [workDuration, lastVsyncCallback] = [&] {
            std::lock_guard lock(mVsync.mutex);
            std::chrono::nanoseconds mWorkDurationNanos = mVsync.workDuration;
            return std::make_pair(mWorkDurationNanos.count(), mVsync.lastCallbackTime.count());
        }();

        mVsync.registration->schedule({workDuration, /*readyDuration=*/0, lastVsyncCallback});
    }
}

void MessageQueue::refresh() {
    mHandler->dispatchRefresh();
}

int MessageQueue::cb_eventReceiver(int fd, int events, void* data) {
    MessageQueue* queue = reinterpret_cast<MessageQueue*>(data);
    return queue->eventReceiver(fd, events);
}

int MessageQueue::eventReceiver(int /*fd*/, int /*events*/) {
    ssize_t n;
    DisplayEventReceiver::Event buffer[8];
    while ((n = DisplayEventReceiver::getEvents(&mEventTube, buffer, 8)) > 0) {
        for (int i = 0; i < n; i++) {
            if (buffer[i].header.type == DisplayEventReceiver::DISPLAY_EVENT_VSYNC) {
                mHandler->dispatchInvalidate(buffer[i].vsync.vsyncId,
                                             buffer[i].vsync.expectedVSyncTimestamp);
                break;
            }
        }
    }
    return 1;
}

} // namespace android::impl

