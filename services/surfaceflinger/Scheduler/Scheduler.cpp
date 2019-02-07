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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Scheduler.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <memory>
#include <numeric>

#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.2/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>
#include <cutils/properties.h>
#include <ui/DisplayStatInfo.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include "DispSync.h"
#include "DispSyncSource.h"
#include "EventControlThread.h"
#include "EventThread.h"
#include "IdleTimer.h"
#include "InjectVSyncSource.h"
#include "SchedulerUtils.h"
#include "SurfaceFlingerProperties.h"

namespace android {

using namespace android::hardware::configstore;
using namespace android::hardware::configstore::V1_0;
using namespace android::sysprop;

#define RETURN_VALUE_IF_INVALID(value) \
    if (handle == nullptr || mConnections.count(handle->id) == 0) return value
#define RETURN_IF_INVALID() \
    if (handle == nullptr || mConnections.count(handle->id) == 0) return

std::atomic<int64_t> Scheduler::sNextId = 0;

Scheduler::Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function)
      : mHasSyncFramework(running_without_sync_framework(true)),
        mDispSyncPresentTimeOffset(present_time_offset_from_vsync_ns(0)),
        mPrimaryHWVsyncEnabled(false),
        mHWVsyncAvailable(false) {
    // Note: We create a local temporary with the real DispSync implementation
    // type temporarily so we can initialize it with the configured values,
    // before storing it for more generic use using the interface type.
    auto primaryDispSync = std::make_unique<impl::DispSync>("SchedulerDispSync");
    primaryDispSync->init(mHasSyncFramework, mDispSyncPresentTimeOffset);
    mPrimaryDispSync = std::move(primaryDispSync);
    mEventControlThread = std::make_unique<impl::EventControlThread>(function);

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.set_idle_timer_ms", value, "0");
    mSetIdleTimerMs = atoi(value);

    if (mSetIdleTimerMs > 0) {
        mIdleTimer =
                std::make_unique<scheduler::IdleTimer>(std::chrono::milliseconds(mSetIdleTimerMs),
                                                       [this] { expiredTimerCallback(); });
        mIdleTimer->start();
    }
}

Scheduler::~Scheduler() {
    // Ensure the IdleTimer thread is joined before we start destroying state.
    mIdleTimer.reset();
}

sp<Scheduler::ConnectionHandle> Scheduler::createConnection(
        const char* connectionName, int64_t phaseOffsetNs, ResyncCallback resyncCallback,
        ResetIdleTimerCallback resetIdleTimerCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const int64_t id = sNextId++;
    ALOGV("Creating a connection handle with ID: %" PRId64 "\n", id);

    std::unique_ptr<EventThread> eventThread =
            makeEventThread(connectionName, mPrimaryDispSync.get(), phaseOffsetNs,
                            std::move(interceptCallback));

    auto eventThreadConnection =
            createConnectionInternal(eventThread.get(), std::move(resyncCallback),
                                     std::move(resetIdleTimerCallback));
    mConnections.emplace(id,
                         std::make_unique<Connection>(new ConnectionHandle(id),
                                                      eventThreadConnection,
                                                      std::move(eventThread)));
    return mConnections[id]->handle;
}

std::unique_ptr<EventThread> Scheduler::makeEventThread(
        const char* connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    std::unique_ptr<VSyncSource> eventThreadSource =
            std::make_unique<DispSyncSource>(dispSync, phaseOffsetNs, true, connectionName);
    return std::make_unique<impl::EventThread>(std::move(eventThreadSource),
                                               std::move(interceptCallback), connectionName);
}

sp<EventThreadConnection> Scheduler::createConnectionInternal(
        EventThread* eventThread, ResyncCallback&& resyncCallback,
        ResetIdleTimerCallback&& resetIdleTimerCallback) {
    return eventThread->createEventConnection(std::move(resyncCallback),
                                              [this,
                                               resetIdleTimerCallback =
                                                       std::move(resetIdleTimerCallback)] {
                                                  resetIdleTimer();
                                                  if (resetIdleTimerCallback) {
                                                      resetIdleTimerCallback();
                                                  }
                                              });
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        const sp<Scheduler::ConnectionHandle>& handle, ResyncCallback resyncCallback,
        ResetIdleTimerCallback resetIdleTimerCallback) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return createConnectionInternal(mConnections[handle->id]->thread.get(),
                                    std::move(resyncCallback), std::move(resetIdleTimerCallback));
}

EventThread* Scheduler::getEventThread(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->thread.get();
}

sp<EventThreadConnection> Scheduler::getEventConnection(const sp<ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->eventConnection;
}

void Scheduler::hotplugReceived(const sp<Scheduler::ConnectionHandle>& handle,
                                PhysicalDisplayId displayId, bool connected) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onHotplugReceived(displayId, connected);
}

void Scheduler::onScreenAcquired(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onScreenAcquired();
}

void Scheduler::onScreenReleased(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onScreenReleased();
}

void Scheduler::dump(const sp<Scheduler::ConnectionHandle>& handle, std::string& result) const {
    RETURN_IF_INVALID();
    mConnections.at(handle->id)->thread->dump(result);
}

void Scheduler::setPhaseOffset(const sp<Scheduler::ConnectionHandle>& handle, nsecs_t phaseOffset) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->setPhaseOffset(phaseOffset);
}

void Scheduler::getDisplayStatInfo(DisplayStatInfo* stats) {
    stats->vsyncTime = mPrimaryDispSync->computeNextRefresh(0);
    stats->vsyncPeriod = mPrimaryDispSync->getPeriod();
}

void Scheduler::enableHardwareVsync() {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (!mPrimaryHWVsyncEnabled && mHWVsyncAvailable) {
        mPrimaryDispSync->beginResync();
        mEventControlThread->setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::disableHardwareVsync(bool makeUnavailable) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (mPrimaryHWVsyncEnabled) {
        mEventControlThread->setVsyncEnabled(false);
        mPrimaryDispSync->endResync();
        mPrimaryHWVsyncEnabled = false;
    }
    if (makeUnavailable) {
        mHWVsyncAvailable = false;
    }
}

void Scheduler::setVsyncPeriod(const nsecs_t period) {
    mPrimaryDispSync->reset();
    mPrimaryDispSync->setPeriod(period);
    enableHardwareVsync();
}

void Scheduler::addResyncSample(const nsecs_t timestamp) {
    bool needsHwVsync = false;
    { // Scope for the lock
        std::lock_guard<std::mutex> lock(mHWVsyncLock);
        if (mPrimaryHWVsyncEnabled) {
            needsHwVsync = mPrimaryDispSync->addResyncSample(timestamp);
        }
    }

    if (needsHwVsync) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::addPresentFence(const std::shared_ptr<FenceTime>& fenceTime) {
    if (mPrimaryDispSync->addPresentFence(fenceTime)) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::setIgnorePresentFences(bool ignore) {
    mPrimaryDispSync->setIgnorePresentFences(ignore);
}

void Scheduler::makeHWSyncAvailable(bool makeAvailable) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    mHWVsyncAvailable = makeAvailable;
}

nsecs_t Scheduler::expectedPresentTime() {
    return mPrimaryDispSync->expectedPresentTime();
}

void Scheduler::addFramePresentTimeForLayer(const nsecs_t framePresentTime, bool isAutoTimestamp,
                                            const std::string layerName) {
    // This is V1 logic. It calculates the average FPS based on the timestamp frequency
    // regardless of which layer the timestamp came from.
    // For now, the averages and FPS are recorded in the systrace.
    determineTimestampAverage(isAutoTimestamp, framePresentTime);

    // This is V2 logic. It calculates the average and median timestamp difference based on the
    // individual layer history. The results are recorded in the systrace.
    determineLayerTimestampStats(layerName, framePresentTime);
}

void Scheduler::incrementFrameCounter() {
    mLayerHistory.incrementCounter();
}

void Scheduler::setExpiredIdleTimerCallback(const ExpiredIdleTimerCallback& expiredTimerCallback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mExpiredTimerCallback = expiredTimerCallback;
}

void Scheduler::updateFrameSkipping(const int64_t skipCount) {
    ATRACE_INT("FrameSkipCount", skipCount);
    if (mSkipCount != skipCount) {
        // Only update DispSync if it hasn't been updated yet.
        mPrimaryDispSync->setRefreshSkipCount(skipCount);
        mSkipCount = skipCount;
    }
}

void Scheduler::determineLayerTimestampStats(const std::string layerName,
                                             const nsecs_t framePresentTime) {
    mLayerHistory.insert(layerName, framePresentTime);
    std::vector<int64_t> differencesMs;

    // Traverse through the layer history, and determine the differences in present times.
    nsecs_t newestPresentTime = framePresentTime;
    std::string differencesText = "";
    for (int i = 1; i < mLayerHistory.getSize(); i++) {
        std::unordered_map<std::string, nsecs_t> layers = mLayerHistory.get(i);
        for (auto layer : layers) {
            if (layer.first != layerName) {
                continue;
            }
            int64_t differenceMs = (newestPresentTime - layer.second) / 1000000;
            // Dismiss noise.
            if (differenceMs > 10 && differenceMs < 60) {
                differencesMs.push_back(differenceMs);
            }
            IF_ALOGV() { differencesText += (std::to_string(differenceMs) + " "); }
            newestPresentTime = layer.second;
        }
    }
    ALOGV("Layer %s timestamp intervals: %s", layerName.c_str(), differencesText.c_str());

    if (!differencesMs.empty()) {
        // Mean/Average is a good indicator for when 24fps videos are playing, because the frames
        // come in 33, and 49 ms intervals with occasional 41ms.
        const int64_t meanMs = scheduler::calculate_mean(differencesMs);
        const auto tagMean = "TimestampMean_" + layerName;
        ATRACE_INT(tagMean.c_str(), meanMs);

        // Mode and median are good indicators for 30 and 60 fps videos, because the majority of
        // frames come in 16, or 33 ms intervals.
        const auto tagMedian = "TimestampMedian_" + layerName;
        ATRACE_INT(tagMedian.c_str(), scheduler::calculate_median(&differencesMs));

        const auto tagMode = "TimestampMode_" + layerName;
        ATRACE_INT(tagMode.c_str(), scheduler::calculate_mode(differencesMs));
    }
}

void Scheduler::determineTimestampAverage(bool isAutoTimestamp, const nsecs_t framePresentTime) {
    ATRACE_INT("AutoTimestamp", isAutoTimestamp);

    // Video does not have timestamp automatically set, so we discard timestamps that are
    // coming in from other sources for now.
    if (isAutoTimestamp) {
        return;
    }
    int64_t differenceMs = (framePresentTime - mPreviousFrameTimestamp) / 1000000;
    mPreviousFrameTimestamp = framePresentTime;

    if (differenceMs < 10 || differenceMs > 100) {
        // Dismiss noise.
        return;
    }
    ATRACE_INT("TimestampDiff", differenceMs);

    mTimeDifferences[mCounter % scheduler::ARRAY_SIZE] = differenceMs;
    mCounter++;
    int64_t mean = scheduler::calculate_mean(mTimeDifferences);
    ATRACE_INT("AutoTimestampMean", mean);

    // TODO(b/113612090): This are current numbers from trial and error while running videos
    // from YouTube at 24, 30, and 60 fps.
    if (mean > 14 && mean < 18) {
        ATRACE_INT("MediaFPS", 60);
    } else if (mean > 31 && mean < 34) {
        ATRACE_INT("MediaFPS", 30);
        return;
    } else if (mean > 39 && mean < 42) {
        ATRACE_INT("MediaFPS", 24);
    }
}

void Scheduler::resetIdleTimer() {
    if (mIdleTimer) {
        mIdleTimer->reset();
        ATRACE_INT("ExpiredIdleTimer", 0);
    }
}

void Scheduler::expiredTimerCallback() {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    if (mExpiredTimerCallback) {
        mExpiredTimerCallback();
        ATRACE_INT("ExpiredIdleTimer", 1);
    }
}

std::string Scheduler::doDump() {
    std::ostringstream stream;
    stream << "+  Idle timer interval: " << mSetIdleTimerMs << " ms" << std::endl;
    return stream.str();
}

} // namespace android
