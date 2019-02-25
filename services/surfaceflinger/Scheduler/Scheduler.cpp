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
#include <configstore/Utils.h>
#include <cutils/properties.h>
#include <system/window.h>
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

    mSetIdleTimerMs = set_idle_timer_ms(0);

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.set_idle_timer_ms", value, "0");
    int int_value = atoi(value);
    if (int_value) {
        mSetIdleTimerMs = atoi(value);
    }

    if (mSetIdleTimerMs > 0) {
        mIdleTimer =
                std::make_unique<scheduler::IdleTimer>(std::chrono::milliseconds(mSetIdleTimerMs),
                                                       [this] { resetTimerCallback(); },
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
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const int64_t id = sNextId++;
    ALOGV("Creating a connection handle with ID: %" PRId64 "\n", id);

    std::unique_ptr<EventThread> eventThread =
            makeEventThread(connectionName, mPrimaryDispSync.get(), phaseOffsetNs,
                            std::move(interceptCallback));

    auto eventThreadConnection =
            createConnectionInternal(eventThread.get(), std::move(resyncCallback));
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

sp<EventThreadConnection> Scheduler::createConnectionInternal(EventThread* eventThread,
                                                              ResyncCallback&& resyncCallback) {
    return eventThread->createEventConnection(std::move(resyncCallback),
                                              [this] { resetIdleTimer(); });
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        const sp<Scheduler::ConnectionHandle>& handle, ResyncCallback resyncCallback) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return createConnectionInternal(mConnections[handle->id]->thread.get(),
                                    std::move(resyncCallback));
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

void Scheduler::onConfigChanged(const sp<ConnectionHandle>& handle, PhysicalDisplayId displayId,
                                int32_t configId) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onConfigChanged(displayId, configId);
}

void Scheduler::dump(const sp<Scheduler::ConnectionHandle>& handle, std::string& result) const {
    RETURN_IF_INVALID();
    mConnections.at(handle->id)->thread->dump(result);
}

void Scheduler::setPhaseOffset(const sp<Scheduler::ConnectionHandle>& handle, nsecs_t phaseOffset) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->setPhaseOffset(phaseOffset);
}

void Scheduler::pauseVsyncCallback(const android::sp<android::Scheduler::ConnectionHandle>& handle,
                                   bool pause) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->pauseVsyncCallback(pause);
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

void Scheduler::resyncToHardwareVsync(bool makeAvailable, nsecs_t period) {
    {
        std::lock_guard<std::mutex> lock(mHWVsyncLock);
        if (makeAvailable) {
            mHWVsyncAvailable = makeAvailable;
        } else if (!mHWVsyncAvailable) {
            // Hardware vsync is not currently available, so abort the resync
            // attempt for now
            return;
        }
    }

    if (period <= 0) {
        return;
    }

    setVsyncPeriod(period);
}

ResyncCallback Scheduler::makeResyncCallback(GetVsyncPeriod&& getVsyncPeriod) {
    std::weak_ptr<VsyncState> ptr = mPrimaryVsyncState;
    return [ptr, getVsyncPeriod = std::move(getVsyncPeriod)]() {
        if (const auto vsync = ptr.lock()) {
            vsync->resync(getVsyncPeriod);
        }
    };
}

void Scheduler::VsyncState::resync(const GetVsyncPeriod& getVsyncPeriod) {
    static constexpr nsecs_t kIgnoreDelay = ms2ns(500);

    const nsecs_t now = systemTime();
    const nsecs_t last = lastResyncTime.exchange(now);

    if (now - last > kIgnoreDelay) {
        scheduler.resyncToHardwareVsync(false, getVsyncPeriod());
    }
}

void Scheduler::setRefreshSkipCount(int count) {
    mPrimaryDispSync->setRefreshSkipCount(count);
}

void Scheduler::setVsyncPeriod(const nsecs_t period) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    mPrimaryDispSync->reset();
    mPrimaryDispSync->setPeriod(period);

    if (!mPrimaryHWVsyncEnabled) {
        mPrimaryDispSync->beginResync();
        mEventControlThread->setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
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

nsecs_t Scheduler::expectedPresentTime() {
    return mPrimaryDispSync->expectedPresentTime();
}

void Scheduler::dumpPrimaryDispSync(std::string& result) const {
    mPrimaryDispSync->dump(result);
}

void Scheduler::addNativeWindowApi(int apiId) {
    std::lock_guard<std::mutex> lock(mWindowApiHistoryLock);
    mWindowApiHistory[mApiHistoryCounter] = apiId;
    mApiHistoryCounter++;
    mApiHistoryCounter = mApiHistoryCounter % scheduler::ARRAY_SIZE;
}

void Scheduler::withPrimaryDispSync(std::function<void(DispSync&)> const& fn) {
    fn(*mPrimaryDispSync);
}

void Scheduler::updateFpsBasedOnNativeWindowApi() {
    int mode;
    {
        std::lock_guard<std::mutex> lock(mWindowApiHistoryLock);
        mode = scheduler::calculate_mode(mWindowApiHistory);
    }
    ATRACE_INT("NativeWindowApiMode", mode);

    if (mode == NATIVE_WINDOW_API_MEDIA) {
        // TODO(b/127365162): These callback names are not accurate anymore. Update.
        mediaChangeRefreshRate(MediaFeatureState::MEDIA_PLAYING);
        ATRACE_INT("DetectedVideo", 1);
    } else {
        mediaChangeRefreshRate(MediaFeatureState::MEDIA_OFF);
        ATRACE_INT("DetectedVideo", 0);
    }
}

void Scheduler::setChangeRefreshRateCallback(
        const ChangeRefreshRateCallback& changeRefreshRateCallback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mChangeRefreshRateCallback = changeRefreshRateCallback;
}

void Scheduler::updateFrameSkipping(const int64_t skipCount) {
    ATRACE_INT("FrameSkipCount", skipCount);
    if (mSkipCount != skipCount) {
        // Only update DispSync if it hasn't been updated yet.
        mPrimaryDispSync->setRefreshSkipCount(skipCount);
        mSkipCount = skipCount;
    }
}

void Scheduler::resetIdleTimer() {
    if (mIdleTimer) {
        mIdleTimer->reset();
    }
}

void Scheduler::resetTimerCallback() {
    // We do not notify the applications about config changes when idle timer is reset.
    timerChangeRefreshRate(IdleTimerState::RESET);
    ATRACE_INT("ExpiredIdleTimer", 0);
}

void Scheduler::expiredTimerCallback() {
    // We do not notify the applications about config changes when idle timer expires.
    timerChangeRefreshRate(IdleTimerState::EXPIRED);
    ATRACE_INT("ExpiredIdleTimer", 1);
}

std::string Scheduler::doDump() {
    std::ostringstream stream;
    stream << "+  Idle timer interval: " << mSetIdleTimerMs << " ms" << std::endl;
    return stream.str();
}

void Scheduler::mediaChangeRefreshRate(MediaFeatureState mediaFeatureState) {
    // Default playback for media is DEFAULT when media is on.
    RefreshRateType refreshRateType = RefreshRateType::DEFAULT;
    ConfigEvent configEvent = ConfigEvent::None;

    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        mCurrentMediaFeatureState = mediaFeatureState;
        // Only switch to PERFORMANCE if idle timer was reset, when turning
        // media off. If the timer is IDLE, stay at DEFAULT.
        if (mediaFeatureState == MediaFeatureState::MEDIA_OFF &&
            mCurrentIdleTimerState == IdleTimerState::RESET) {
            refreshRateType = RefreshRateType::PERFORMANCE;
        }
    }
    changeRefreshRate(refreshRateType, configEvent);
}

void Scheduler::timerChangeRefreshRate(IdleTimerState idleTimerState) {
    RefreshRateType refreshRateType = RefreshRateType::DEFAULT;
    ConfigEvent configEvent = ConfigEvent::None;

    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        mCurrentIdleTimerState = idleTimerState;
        // Only switch to PERFOMANCE if the idle timer was reset, and media is
        // not playing. Otherwise, stay at DEFAULT.
        if (idleTimerState == IdleTimerState::RESET &&
            mCurrentMediaFeatureState == MediaFeatureState::MEDIA_OFF) {
            refreshRateType = RefreshRateType::PERFORMANCE;
        }
    }
    changeRefreshRate(refreshRateType, configEvent);
}

void Scheduler::changeRefreshRate(RefreshRateType refreshRateType, ConfigEvent configEvent) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    if (mChangeRefreshRateCallback) {
        mChangeRefreshRateCallback(refreshRateType, configEvent);
    }
}

} // namespace android
