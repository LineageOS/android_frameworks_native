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

#include <cinttypes>
#include <cstdint>
#include <memory>
#include <numeric>

#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.2/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>

#include <gui/ISurfaceComposer.h>
#include <ui/DisplayStatInfo.h>
#include <utils/Trace.h>

#include "DispSync.h"
#include "DispSyncSource.h"
#include "EventControlThread.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"

namespace android {

using namespace android::hardware::configstore;
using namespace android::hardware::configstore::V1_0;

#define RETURN_VALUE_IF_INVALID(value) \
    if (handle == nullptr || mConnections.count(handle->id) == 0) return value
#define RETURN_IF_INVALID() \
    if (handle == nullptr || mConnections.count(handle->id) == 0) return

std::atomic<int64_t> Scheduler::sNextId = 0;

Scheduler::Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function)
      : mHasSyncFramework(
                getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::hasSyncFramework>(true)),
        mDispSyncPresentTimeOffset(
                getInt64<ISurfaceFlingerConfigs,
                         &ISurfaceFlingerConfigs::presentTimeOffsetFromVSyncNs>(0)),
        mPrimaryHWVsyncEnabled(false),
        mHWVsyncAvailable(false) {
    // Note: We create a local temporary with the real DispSync implementation
    // type temporarily so we can initialize it with the configured values,
    // before storing it for more generic use using the interface type.
    auto primaryDispSync = std::make_unique<impl::DispSync>("SchedulerDispSync");
    primaryDispSync->init(mHasSyncFramework, mDispSyncPresentTimeOffset);
    mPrimaryDispSync = std::move(primaryDispSync);
    mEventControlThread = std::make_unique<impl::EventControlThread>(function);
}

Scheduler::~Scheduler() = default;

sp<Scheduler::ConnectionHandle> Scheduler::createConnection(
        const std::string& connectionName, int64_t phaseOffsetNs,
        impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const int64_t id = sNextId++;
    ALOGV("Creating a connection handle with ID: %" PRId64 "\n", id);

    std::unique_ptr<EventThread> eventThread =
            makeEventThread(connectionName, mPrimaryDispSync.get(), phaseOffsetNs, resyncCallback,
                            interceptCallback);
    auto connection = std::make_unique<Connection>(new ConnectionHandle(id),
                                                   eventThread->createEventConnection(),
                                                   std::move(eventThread));
    mConnections.insert(std::make_pair(id, std::move(connection)));
    return mConnections[id]->handle;
}

std::unique_ptr<EventThread> Scheduler::makeEventThread(
        const std::string& connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
        impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const std::string sourceName = connectionName + "Source";
    std::unique_ptr<VSyncSource> eventThreadSource =
            std::make_unique<DispSyncSource>(dispSync, phaseOffsetNs, true, sourceName.c_str());
    const std::string threadName = connectionName + "Thread";
    return std::make_unique<impl::EventThread>(std::move(eventThreadSource), resyncCallback,
                                               interceptCallback, threadName.c_str());
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->thread->createEventConnection();
}

EventThread* Scheduler::getEventThread(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->thread.get();
}

sp<BnDisplayEventConnection> Scheduler::getEventConnection(const sp<ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->eventConnection;
}

void Scheduler::hotplugReceived(const sp<Scheduler::ConnectionHandle>& handle,
                                EventThread::DisplayType displayType, bool connected) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onHotplugReceived(displayType, connected);
}

void Scheduler::onScreenAcquired(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onScreenAcquired();
}

void Scheduler::onScreenReleased(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onScreenReleased();
}

void Scheduler::dump(const sp<Scheduler::ConnectionHandle>& handle, String8& result) const {
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

void Scheduler::addNewFrameTimestamp(const nsecs_t newFrameTimestamp, bool isAutoTimestamp) {
    ATRACE_INT("AutoTimestamp", isAutoTimestamp);
    // Video does not have timestamp automatically set, so we discard timestamps that are
    // coming in from other sources for now.
    if (isAutoTimestamp) {
        return;
    }
    int64_t differenceMs = (newFrameTimestamp - mPreviousFrameTimestamp) / 1000000;
    mPreviousFrameTimestamp = newFrameTimestamp;

    if (differenceMs < 10 || differenceMs > 100) {
        // Dismiss noise.
        return;
    }
    ATRACE_INT("TimestampDiff", differenceMs);

    mTimeDifferences[mCounter % ARRAY_SIZE] = differenceMs;
    mCounter++;
    nsecs_t average = calculateAverage();
    ATRACE_INT("TimestampAverage", average);

    // TODO(b/113612090): This are current numbers from trial and error while running videos
    // from YouTube at 24, 30, and 60 fps.
    if (average > 14 && average < 18) {
        ATRACE_INT("FPS", 60);
    } else if (average > 31 && average < 34) {
        ATRACE_INT("FPS", 30);
        updateFrameSkipping(1);
        return;
    } else if (average > 39 && average < 42) {
        ATRACE_INT("FPS", 24);
    }
    updateFrameSkipping(0);
}

nsecs_t Scheduler::calculateAverage() const {
    nsecs_t sum = std::accumulate(mTimeDifferences.begin(), mTimeDifferences.end(), 0);
    return (sum / ARRAY_SIZE);
}

void Scheduler::updateFrameSkipping(const int64_t skipCount) {
    ATRACE_INT("FrameSkipCount", skipCount);
    if (mSkipCount != skipCount) {
        // Only update DispSync if it hasn't been updated yet.
        mPrimaryDispSync->setRefreshSkipCount(skipCount);
        mSkipCount = skipCount;
    }
}

} // namespace android
