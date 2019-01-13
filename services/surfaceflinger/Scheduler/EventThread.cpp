/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <chrono>
#include <cstdint>

#include <android-base/stringprintf.h>

#include <cutils/compiler.h>
#include <cutils/sched_policy.h>

#include <gui/DisplayEventReceiver.h>

#include <utils/Errors.h>
#include <utils/Trace.h>

#include "EventThread.h"

using namespace std::chrono_literals;
using android::base::StringAppendF;

// ---------------------------------------------------------------------------

namespace android {

// ---------------------------------------------------------------------------

EventThreadConnection::EventThreadConnection(EventThread* eventThread)
      : count(-1), mEventThread(eventThread), mChannel(gui::BitTube::DefaultSize) {}

EventThreadConnection::~EventThreadConnection() {
    // do nothing here -- clean-up will happen automatically
    // when the main thread wakes up
}

void EventThreadConnection::onFirstRef() {
    // NOTE: mEventThread doesn't hold a strong reference on us
    mEventThread->registerDisplayEventConnection(this);
}

status_t EventThreadConnection::stealReceiveChannel(gui::BitTube* outChannel) {
    outChannel->setReceiveFd(mChannel.moveReceiveFd());
    return NO_ERROR;
}

status_t EventThreadConnection::setVsyncRate(uint32_t count) {
    mEventThread->setVsyncRate(count, this);
    return NO_ERROR;
}

void EventThreadConnection::requestNextVsync() {
    ATRACE_NAME("requestNextVsync");
    mEventThread->requestNextVsync(this, true);
}

void EventThreadConnection::requestNextVsyncForHWC() {
    ATRACE_NAME("requestNextVsyncForHWC");
    mEventThread->requestNextVsync(this, false);
}

status_t EventThreadConnection::postEvent(const DisplayEventReceiver::Event& event) {
    ssize_t size = DisplayEventReceiver::sendEvents(&mChannel, &event, 1);
    return size < 0 ? status_t(size) : status_t(NO_ERROR);
}

// ---------------------------------------------------------------------------

EventThread::~EventThread() = default;

namespace impl {

EventThread::EventThread(std::unique_ptr<VSyncSource> src,
                         const ResyncWithRateLimitCallback& resyncWithRateLimitCallback,
                         const InterceptVSyncsCallback& interceptVSyncsCallback,
                         const ResetIdleTimerCallback& resetIdleTimerCallback,
                         const char* threadName)
      : EventThread(nullptr, std::move(src), resyncWithRateLimitCallback, interceptVSyncsCallback,
                    threadName) {
    mResetIdleTimer = resetIdleTimerCallback;
}

EventThread::EventThread(VSyncSource* src, ResyncWithRateLimitCallback resyncWithRateLimitCallback,
                         InterceptVSyncsCallback interceptVSyncsCallback, const char* threadName)
      : EventThread(src, nullptr, resyncWithRateLimitCallback, interceptVSyncsCallback,
                    threadName) {}

EventThread::EventThread(VSyncSource* src, std::unique_ptr<VSyncSource> uniqueSrc,
                         ResyncWithRateLimitCallback resyncWithRateLimitCallback,
                         InterceptVSyncsCallback interceptVSyncsCallback, const char* threadName)
      : mVSyncSource(src),
        mVSyncSourceUnique(std::move(uniqueSrc)),
        mResyncWithRateLimitCallback(resyncWithRateLimitCallback),
        mInterceptVSyncsCallback(interceptVSyncsCallback) {
    if (src == nullptr) {
        mVSyncSource = mVSyncSourceUnique.get();
    }
    for (auto& event : mVSyncEvent) {
        event.header.type = DisplayEventReceiver::DISPLAY_EVENT_VSYNC;
        event.header.id = 0;
        event.header.timestamp = 0;
        event.vsync.count = 0;
    }

    mThread = std::thread(&EventThread::threadMain, this);

    pthread_setname_np(mThread.native_handle(), threadName);

    pid_t tid = pthread_gettid_np(mThread.native_handle());

    // Use SCHED_FIFO to minimize jitter
    constexpr int EVENT_THREAD_PRIORITY = 2;
    struct sched_param param = {0};
    param.sched_priority = EVENT_THREAD_PRIORITY;
    if (pthread_setschedparam(mThread.native_handle(), SCHED_FIFO, &param) != 0) {
        ALOGE("Couldn't set SCHED_FIFO for EventThread");
    }

    set_sched_policy(tid, SP_FOREGROUND);
}

EventThread::~EventThread() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mKeepRunning = false;
        mCondition.notify_all();
    }
    mThread.join();
}

void EventThread::setPhaseOffset(nsecs_t phaseOffset) {
    std::lock_guard<std::mutex> lock(mMutex);
    mVSyncSource->setPhaseOffset(phaseOffset);
}

sp<EventThreadConnection> EventThread::createEventConnection() const {
    return new EventThreadConnection(const_cast<EventThread*>(this));
}

status_t EventThread::registerDisplayEventConnection(const sp<EventThreadConnection>& connection) {
    std::lock_guard<std::mutex> lock(mMutex);

    // this should never happen
    auto it = std::find(mDisplayEventConnections.cbegin(),
            mDisplayEventConnections.cend(), connection);
    if (it != mDisplayEventConnections.cend()) {
        ALOGW("DisplayEventConnection %p already exists", connection.get());
        mCondition.notify_all();
        return ALREADY_EXISTS;
    }

    mDisplayEventConnections.push_back(connection);
    mCondition.notify_all();
    return NO_ERROR;
}

void EventThread::removeDisplayEventConnectionLocked(const wp<EventThreadConnection>& connection) {
    auto it = std::find(mDisplayEventConnections.cbegin(),
            mDisplayEventConnections.cend(), connection);
    if (it != mDisplayEventConnections.cend()) {
        mDisplayEventConnections.erase(it);
    }
}

void EventThread::setVsyncRate(uint32_t count, const sp<EventThreadConnection>& connection) {
    if (int32_t(count) >= 0) { // server must protect against bad params
        std::lock_guard<std::mutex> lock(mMutex);
        const int32_t new_count = (count == 0) ? -1 : count;
        if (connection->count != new_count) {
            connection->count = new_count;
            mCondition.notify_all();
        }
    }
}

void EventThread::requestNextVsync(const sp<EventThreadConnection>& connection, bool reset) {
    if (mResetIdleTimer && reset) {
        ATRACE_NAME("resetIdleTimer");
        mResetIdleTimer();
    }
    if (mResyncWithRateLimitCallback) {
        mResyncWithRateLimitCallback();
    }

    std::lock_guard<std::mutex> lock(mMutex);

    if (connection->count < 0) {
        connection->count = 0;
        mCondition.notify_all();
    }
}

void EventThread::onScreenReleased() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mUseSoftwareVSync) {
        // disable reliance on h/w vsync
        mUseSoftwareVSync = true;
        mCondition.notify_all();
    }
}

void EventThread::onScreenAcquired() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mUseSoftwareVSync) {
        // resume use of h/w vsync
        mUseSoftwareVSync = false;
        mCondition.notify_all();
    }
}

void EventThread::onVSyncEvent(nsecs_t timestamp) {
    std::lock_guard<std::mutex> lock(mMutex);
    mVSyncEvent[0].header.type = DisplayEventReceiver::DISPLAY_EVENT_VSYNC;
    mVSyncEvent[0].header.id = 0;
    mVSyncEvent[0].header.timestamp = timestamp;
    mVSyncEvent[0].vsync.count++;
    mCondition.notify_all();
}

void EventThread::onHotplugReceived(DisplayType displayType, bool connected) {
    std::lock_guard<std::mutex> lock(mMutex);

    DisplayEventReceiver::Event event;
    event.header.type = DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG;
    event.header.id = displayType == DisplayType::Primary ? 0 : 1;
    event.header.timestamp = systemTime();
    event.hotplug.connected = connected;

    mPendingEvents.push(event);
    mCondition.notify_all();
}

void EventThread::threadMain() NO_THREAD_SAFETY_ANALYSIS {
    std::unique_lock<std::mutex> lock(mMutex);
    while (mKeepRunning) {
        DisplayEventReceiver::Event event;
        std::vector<sp<EventThreadConnection>> signalConnections;
        signalConnections = waitForEventLocked(&lock, &event);

        // dispatch events to listeners...
        for (const sp<EventThreadConnection>& conn : signalConnections) {
            // now see if we still need to report this event
            status_t err = conn->postEvent(event);
            if (err == -EAGAIN || err == -EWOULDBLOCK) {
                // The destination doesn't accept events anymore, it's probably
                // full. For now, we just drop the events on the floor.
                // FIXME: Note that some events cannot be dropped and would have
                // to be re-sent later.
                // Right-now we don't have the ability to do this.
                ALOGW("EventThread: dropping event (%08x) for connection %p", event.header.type,
                      conn.get());
            } else if (err < 0) {
                // handle any other error on the pipe as fatal. the only
                // reasonable thing to do is to clean-up this connection.
                // The most common error we'll get here is -EPIPE.
                removeDisplayEventConnectionLocked(conn);
            }
        }
    }
}

// This will return when (1) a vsync event has been received, and (2) there was
// at least one connection interested in receiving it when we started waiting.
std::vector<sp<EventThreadConnection>> EventThread::waitForEventLocked(
        std::unique_lock<std::mutex>* lock, DisplayEventReceiver::Event* outEvent) {
    std::vector<sp<EventThreadConnection>> signalConnections;

    while (signalConnections.empty() && mKeepRunning) {
        bool eventPending = false;
        bool waitForVSync = false;

        size_t vsyncCount = 0;
        nsecs_t timestamp = 0;
        for (auto& event : mVSyncEvent) {
            timestamp = event.header.timestamp;
            if (timestamp) {
                // we have a vsync event to dispatch
                if (mInterceptVSyncsCallback) {
                    mInterceptVSyncsCallback(timestamp);
                }
                *outEvent = event;
                event.header.timestamp = 0;
                vsyncCount = event.vsync.count;
                break;
            }
        }

        if (!timestamp) {
            // no vsync event, see if there are some other event
            eventPending = !mPendingEvents.empty();
            if (eventPending) {
                // we have some other event to dispatch
                *outEvent = mPendingEvents.front();
                mPendingEvents.pop();
            }
        }

        // find out connections waiting for events
        auto it = mDisplayEventConnections.begin();
        while (it != mDisplayEventConnections.end()) {
            sp<EventThreadConnection> connection(it->promote());
            if (connection != nullptr) {
                bool added = false;
                if (connection->count >= 0) {
                    // we need vsync events because at least
                    // one connection is waiting for it
                    waitForVSync = true;
                    if (timestamp) {
                        // we consume the event only if it's time
                        // (ie: we received a vsync event)
                        if (connection->count == 0) {
                            // fired this time around
                            connection->count = -1;
                            signalConnections.push_back(connection);
                            added = true;
                        } else if (connection->count == 1 ||
                                   (vsyncCount % connection->count) == 0) {
                            // continuous event, and time to report it
                            signalConnections.push_back(connection);
                            added = true;
                        }
                    }
                }

                if (eventPending && !timestamp && !added) {
                    // we don't have a vsync event to process
                    // (timestamp==0), but we have some pending
                    // messages.
                    signalConnections.push_back(connection);
                }
                ++it;
            } else {
                // we couldn't promote this reference, the connection has
                // died, so clean-up!
                it = mDisplayEventConnections.erase(it);
            }
        }

        // Here we figure out if we need to enable or disable vsyncs
        if (timestamp && !waitForVSync) {
            // we received a VSYNC but we have no clients
            // don't report it, and disable VSYNC events
            disableVSyncLocked();
        } else if (!timestamp && waitForVSync) {
            // we have at least one client, so we want vsync enabled
            // (TODO: this function is called right after we finish
            // notifying clients of a vsync, so this call will be made
            // at the vsync rate, e.g. 60fps.  If we can accurately
            // track the current state we could avoid making this call
            // so often.)
            enableVSyncLocked();
        }

        // note: !timestamp implies signalConnections.isEmpty(), because we
        // don't populate signalConnections if there's no vsync pending
        if (!timestamp && !eventPending) {
            // wait for something to happen
            if (waitForVSync) {
                // This is where we spend most of our time, waiting
                // for vsync events and new client registrations.
                //
                // If the screen is off, we can't use h/w vsync, so we
                // use a 16ms timeout instead.  It doesn't need to be
                // precise, we just need to keep feeding our clients.
                //
                // We don't want to stall if there's a driver bug, so we
                // use a (long) timeout when waiting for h/w vsync, and
                // generate fake events when necessary.
                bool softwareSync = mUseSoftwareVSync;
                auto timeout = softwareSync ? 16ms : 1000ms;
                if (mCondition.wait_for(*lock, timeout) == std::cv_status::timeout) {
                    if (!softwareSync) {
                        ALOGW("Timed out waiting for hw vsync; faking it");
                    }
                    // FIXME: how do we decide which display id the fake
                    // vsync came from ?
                    mVSyncEvent[0].header.type = DisplayEventReceiver::DISPLAY_EVENT_VSYNC;
                    mVSyncEvent[0].header.id = 0;
                    mVSyncEvent[0].header.timestamp = systemTime(SYSTEM_TIME_MONOTONIC);
                    mVSyncEvent[0].vsync.count++;
                }
            } else {
                // Nobody is interested in vsync, so we just want to sleep.
                // h/w vsync should be disabled, so this will wait until we
                // get a new connection, or an existing connection becomes
                // interested in receiving vsync again.
                mCondition.wait(*lock);
            }
        }
    }

    // here we're guaranteed to have a timestamp and some connections to signal
    // (The connections might have dropped out of mDisplayEventConnections
    // while we were asleep, but we'll still have strong references to them.)
    return signalConnections;
}

void EventThread::enableVSyncLocked() {
    if (!mUseSoftwareVSync) {
        // never enable h/w VSYNC when screen is off
        if (!mVsyncEnabled) {
            mVsyncEnabled = true;
            mVSyncSource->setCallback(this);
            mVSyncSource->setVSyncEnabled(true);
        }
    }
    mDebugVsyncEnabled = true;
}

void EventThread::disableVSyncLocked() {
    if (mVsyncEnabled) {
        mVsyncEnabled = false;
        mVSyncSource->setVSyncEnabled(false);
        mDebugVsyncEnabled = false;
    }
}

void EventThread::dump(std::string& result) const {
    std::lock_guard<std::mutex> lock(mMutex);
    StringAppendF(&result, "VSYNC state: %s\n", mDebugVsyncEnabled ? "enabled" : "disabled");
    StringAppendF(&result, "  soft-vsync: %s\n", mUseSoftwareVSync ? "enabled" : "disabled");
    StringAppendF(&result, "  numListeners=%zu,\n  events-delivered: %u\n",
                  mDisplayEventConnections.size(), mVSyncEvent[0].vsync.count);
    for (const wp<EventThreadConnection>& weak : mDisplayEventConnections) {
        sp<EventThreadConnection> connection = weak.promote();
        StringAppendF(&result, "    %p: count=%d\n", connection.get(),
                      connection != nullptr ? connection->count : 0);
    }
    StringAppendF(&result, "  other-events-pending: %zu\n", mPendingEvents.size());
}

} // namespace impl
} // namespace android
