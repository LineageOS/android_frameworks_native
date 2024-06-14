/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "DisplayEventDispatcher"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <cinttypes>
#include <cstdint>

#include <gui/DisplayEventDispatcher.h>
#include <gui/DisplayEventReceiver.h>
#include <utils/Log.h>
#include <utils/Looper.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <com_android_graphics_libgui_flags.h>

namespace android {
using namespace com::android::graphics::libgui;

// Number of events to read at a time from the DisplayEventDispatcher pipe.
// The value should be large enough that we can quickly drain the pipe
// using just a few large reads.
static const size_t EVENT_BUFFER_SIZE = 100;

static constexpr nsecs_t WAITING_FOR_VSYNC_TIMEOUT = ms2ns(300);

DisplayEventDispatcher::DisplayEventDispatcher(const sp<Looper>& looper,
                                               gui::ISurfaceComposer::VsyncSource vsyncSource,
                                               EventRegistrationFlags eventRegistration,
                                               const sp<IBinder>& layerHandle)
      : mLooper(looper),
        mReceiver(vsyncSource, eventRegistration, layerHandle),
        mWaitingForVsync(false),
        mLastVsyncCount(0),
        mLastScheduleVsyncTime(0) {
    ALOGV("dispatcher %p ~ Initializing display event dispatcher.", this);
}

status_t DisplayEventDispatcher::initialize() {
    status_t result = mReceiver.initCheck();
    if (result) {
        ALOGW("Failed to initialize display event receiver, status=%d", result);
        return result;
    }

    if (mLooper != nullptr) {
        int rc = mLooper->addFd(mReceiver.getFd(), 0, Looper::EVENT_INPUT, this, NULL);
        if (rc < 0) {
            return UNKNOWN_ERROR;
        }
    }

    return OK;
}

void DisplayEventDispatcher::dispose() {
    ALOGV("dispatcher %p ~ Disposing display event dispatcher.", this);

    if (!mReceiver.initCheck() && mLooper != nullptr) {
        mLooper->removeFd(mReceiver.getFd());
    }
}

status_t DisplayEventDispatcher::scheduleVsync() {
    if (!mWaitingForVsync) {
        ALOGV("dispatcher %p ~ Scheduling vsync.", this);

        // Drain all pending events.
        nsecs_t vsyncTimestamp;
        PhysicalDisplayId vsyncDisplayId;
        uint32_t vsyncCount;
        VsyncEventData vsyncEventData;
        if (processPendingEvents(&vsyncTimestamp, &vsyncDisplayId, &vsyncCount, &vsyncEventData)) {
            ALOGE("dispatcher %p ~ last event processed while scheduling was for %" PRId64 "", this,
                  ns2ms(static_cast<nsecs_t>(vsyncTimestamp)));
        }

        status_t status = mReceiver.requestNextVsync();
        if (status) {
            ALOGW("Failed to request next vsync, status=%d", status);
            return status;
        }

        mWaitingForVsync = true;
        mLastScheduleVsyncTime = systemTime(SYSTEM_TIME_MONOTONIC);
    }
    return OK;
}

void DisplayEventDispatcher::injectEvent(const DisplayEventReceiver::Event& event) {
    mReceiver.sendEvents(&event, 1);
}

int DisplayEventDispatcher::getFd() const {
    return mReceiver.getFd();
}

int DisplayEventDispatcher::handleEvent(int, int events, void*) {
    if (events & (Looper::EVENT_ERROR | Looper::EVENT_HANGUP)) {
        ALOGE("Display event receiver pipe was closed or an error occurred.  "
              "events=0x%x",
              events);
        return 0; // remove the callback
    }

    if (!(events & Looper::EVENT_INPUT)) {
        ALOGW("Received spurious callback for unhandled poll event.  "
              "events=0x%x",
              events);
        return 1; // keep the callback
    }

    // Drain all pending events, keep the last vsync.
    nsecs_t vsyncTimestamp;
    PhysicalDisplayId vsyncDisplayId;
    uint32_t vsyncCount;
    VsyncEventData vsyncEventData;
    if (processPendingEvents(&vsyncTimestamp, &vsyncDisplayId, &vsyncCount, &vsyncEventData)) {
        ALOGV("dispatcher %p ~ Vsync pulse: timestamp=%" PRId64
              ", displayId=%s, count=%d, vsyncId=%" PRId64,
              this, ns2ms(vsyncTimestamp), to_string(vsyncDisplayId).c_str(), vsyncCount,
              vsyncEventData.preferredVsyncId());
        mWaitingForVsync = false;
        mLastVsyncCount = vsyncCount;
        dispatchVsync(vsyncTimestamp, vsyncDisplayId, vsyncCount, vsyncEventData);
    }

    if (mWaitingForVsync) {
        const nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
        const nsecs_t vsyncScheduleDelay = currentTime - mLastScheduleVsyncTime;
        if (vsyncScheduleDelay > WAITING_FOR_VSYNC_TIMEOUT) {
            ALOGW("Vsync time out! vsyncScheduleDelay=%" PRId64 "ms", ns2ms(vsyncScheduleDelay));
            mWaitingForVsync = false;
            dispatchVsync(currentTime, vsyncDisplayId /* displayId is not used */,
                          ++mLastVsyncCount, vsyncEventData /* empty data */);
        }
    }

    return 1; // keep the callback
}

bool DisplayEventDispatcher::processPendingEvents(nsecs_t* outTimestamp,
                                                  PhysicalDisplayId* outDisplayId,
                                                  uint32_t* outCount,
                                                  VsyncEventData* outVsyncEventData) {
    bool gotVsync = false;
    DisplayEventReceiver::Event buf[EVENT_BUFFER_SIZE];
    ssize_t n;
    while ((n = mReceiver.getEvents(buf, EVENT_BUFFER_SIZE)) > 0) {
        ALOGV("dispatcher %p ~ Read %d events.", this, int(n));
        mFrameRateOverrides.reserve(n);
        for (ssize_t i = 0; i < n; i++) {
            const DisplayEventReceiver::Event& ev = buf[i];
            switch (ev.header.type) {
                case DisplayEventReceiver::DISPLAY_EVENT_VSYNC:
                    // Later vsync events will just overwrite the info from earlier
                    // ones. That's fine, we only care about the most recent.
                    gotVsync = true;
                    *outTimestamp = ev.header.timestamp;
                    *outDisplayId = ev.header.displayId;
                    *outCount = ev.vsync.count;
                    *outVsyncEventData = ev.vsync.vsyncData;

                    // Trace the RenderRate for this app
                    if (ATRACE_ENABLED() && flags::trace_frame_rate_override()) {
                        const auto frameInterval = ev.vsync.vsyncData.frameInterval;
                        int fps = frameInterval > 0 ? 1e9f / frameInterval : 0;
                        ATRACE_INT("RenderRate", fps);
                    }
                    break;
                case DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG:
                    if (ev.hotplug.connectionError == 0) {
                        dispatchHotplug(ev.header.timestamp, ev.header.displayId,
                                        ev.hotplug.connected);
                    } else {
                        dispatchHotplugConnectionError(ev.header.timestamp,
                                                       ev.hotplug.connectionError);
                    }
                    break;
                case DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE:
                    dispatchModeChanged(ev.header.timestamp, ev.header.displayId,
                                        ev.modeChange.modeId, ev.modeChange.vsyncPeriod);
                    break;
                case DisplayEventReceiver::DISPLAY_EVENT_NULL:
                    dispatchNullEvent(ev.header.timestamp, ev.header.displayId);
                    break;
                case DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE:
                    mFrameRateOverrides.emplace_back(ev.frameRateOverride);
                    break;
                case DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH:
                    dispatchFrameRateOverrides(ev.header.timestamp, ev.header.displayId,
                                               std::move(mFrameRateOverrides));
                    break;
                case DisplayEventReceiver::DISPLAY_EVENT_HDCP_LEVELS_CHANGE:
                    dispatchHdcpLevelsChanged(ev.header.displayId,
                                              ev.hdcpLevelsChange.connectedLevel,
                                              ev.hdcpLevelsChange.maxLevel);
                    break;
                default:
                    ALOGW("dispatcher %p ~ ignoring unknown event type %#x", this, ev.header.type);
                    break;
            }
        }
    }
    if (n < 0) {
        ALOGW("Failed to get events from display event dispatcher, status=%d", status_t(n));
    }
    return gotVsync;
}

status_t DisplayEventDispatcher::getLatestVsyncEventData(
        ParcelableVsyncEventData* outVsyncEventData) const {
    return mReceiver.getLatestVsyncEventData(outVsyncEventData);
}

} // namespace android
