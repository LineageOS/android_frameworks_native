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
#include <input/InputWindow.h>
#include <system/window.h>
#include <ui/DisplayStatInfo.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include "DispSync.h"
#include "DispSyncSource.h"
#include "EventControlThread.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"
#include "LayerInfo.h"
#include "OneShotTimer.h"
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

Scheduler::Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function,
                     const scheduler::RefreshRateConfigs& refreshRateConfig)
      : mHasSyncFramework(running_without_sync_framework(true)),
        mDispSyncPresentTimeOffset(present_time_offset_from_vsync_ns(0)),
        mPrimaryHWVsyncEnabled(false),
        mHWVsyncAvailable(false),
        mRefreshRateConfigs(refreshRateConfig) {
    // Note: We create a local temporary with the real DispSync implementation
    // type temporarily so we can initialize it with the configured values,
    // before storing it for more generic use using the interface type.
    auto primaryDispSync = std::make_unique<impl::DispSync>("SchedulerDispSync");
    primaryDispSync->init(mHasSyncFramework, mDispSyncPresentTimeOffset);
    mPrimaryDispSync = std::move(primaryDispSync);
    mEventControlThread = std::make_unique<impl::EventControlThread>(function);

    mSetIdleTimerMs = set_idle_timer_ms(0);
    mSupportKernelTimer = support_kernel_idle_timer(false);

    mSetTouchTimerMs = set_touch_timer_ms(0);
    mSetDisplayPowerTimerMs = set_display_power_timer_ms(0);

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.set_idle_timer_ms", value, "0");
    int int_value = atoi(value);
    if (int_value) {
        mSetIdleTimerMs = atoi(value);
    }

    if (mSetIdleTimerMs > 0) {
        if (mSupportKernelTimer) {
            mIdleTimer = std::make_unique<scheduler::OneShotTimer>(
                    std::chrono::milliseconds(mSetIdleTimerMs),
                    [this] { kernelIdleTimerCallback(TimerState::Reset); },
                    [this] { kernelIdleTimerCallback(TimerState::Expired); });
        } else {
            mIdleTimer = std::make_unique<scheduler::OneShotTimer>(
                    std::chrono::milliseconds(mSetIdleTimerMs),
                    [this] { idleTimerCallback(TimerState::Reset); },
                    [this] { idleTimerCallback(TimerState::Expired); });
        }
        mIdleTimer->start();
    }

    if (mSetTouchTimerMs > 0) {
        // Touch events are coming to SF every 100ms, so the timer needs to be higher than that
        mTouchTimer = std::make_unique<scheduler::OneShotTimer>(
                std::chrono::milliseconds(mSetTouchTimerMs),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    if (mSetDisplayPowerTimerMs > 0) {
        mDisplayPowerTimer = std::make_unique<scheduler::OneShotTimer>(
                std::chrono::milliseconds(mSetDisplayPowerTimerMs),
                [this] { displayPowerTimerCallback(TimerState::Reset); },
                [this] { displayPowerTimerCallback(TimerState::Expired); });
        mDisplayPowerTimer->start();
    }
}

Scheduler::~Scheduler() {
    // Ensure the OneShotTimer threads are joined before we start destroying state.
    mDisplayPowerTimer.reset();
    mTouchTimer.reset();
    mIdleTimer.reset();
}

sp<Scheduler::ConnectionHandle> Scheduler::createConnection(
        const char* connectionName, nsecs_t phaseOffsetNs, nsecs_t offsetThresholdForNextVsync,
        ResyncCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const int64_t id = sNextId++;
    ALOGV("Creating a connection handle with ID: %" PRId64 "\n", id);

    std::unique_ptr<EventThread> eventThread =
            makeEventThread(connectionName, mPrimaryDispSync.get(), phaseOffsetNs,
                            offsetThresholdForNextVsync, std::move(interceptCallback));

    auto eventThreadConnection =
            createConnectionInternal(eventThread.get(), std::move(resyncCallback),
                                     ISurfaceComposer::eConfigChangedSuppress);
    mConnections.emplace(id,
                         std::make_unique<Connection>(new ConnectionHandle(id),
                                                      eventThreadConnection,
                                                      std::move(eventThread)));
    return mConnections[id]->handle;
}

std::unique_ptr<EventThread> Scheduler::makeEventThread(
        const char* connectionName, DispSync* dispSync, nsecs_t phaseOffsetNs,
        nsecs_t offsetThresholdForNextVsync,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    std::unique_ptr<VSyncSource> eventThreadSource =
            std::make_unique<DispSyncSource>(dispSync, phaseOffsetNs, offsetThresholdForNextVsync,
                                             true, connectionName);
    return std::make_unique<impl::EventThread>(std::move(eventThreadSource),
                                               std::move(interceptCallback), connectionName);
}

sp<EventThreadConnection> Scheduler::createConnectionInternal(
        EventThread* eventThread, ResyncCallback&& resyncCallback,
        ISurfaceComposer::ConfigChanged configChanged) {
    return eventThread->createEventConnection(std::move(resyncCallback), configChanged);
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        const sp<Scheduler::ConnectionHandle>& handle, ResyncCallback resyncCallback,
        ISurfaceComposer::ConfigChanged configChanged) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return createConnectionInternal(mConnections[handle->id]->thread.get(),
                                    std::move(resyncCallback), configChanged);
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
    mPrimaryDispSync->setPeriod(period);

    if (!mPrimaryHWVsyncEnabled) {
        mPrimaryDispSync->beginResync();
        mEventControlThread->setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::addResyncSample(const nsecs_t timestamp, bool* periodFlushed) {
    bool needsHwVsync = false;
    *periodFlushed = false;
    { // Scope for the lock
        std::lock_guard<std::mutex> lock(mHWVsyncLock);
        if (mPrimaryHWVsyncEnabled) {
            needsHwVsync = mPrimaryDispSync->addResyncSample(timestamp, periodFlushed);
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

nsecs_t Scheduler::getDispSyncExpectedPresentTime() {
    return mPrimaryDispSync->expectedPresentTime();
}

void Scheduler::dumpPrimaryDispSync(std::string& result) const {
    mPrimaryDispSync->dump(result);
}

std::unique_ptr<scheduler::LayerHistory::LayerHandle> Scheduler::registerLayer(
        std::string const& name, int windowType) {
    RefreshRateType refreshRateType = (windowType == InputWindowInfo::TYPE_WALLPAPER)
            ? RefreshRateType::DEFAULT
            : RefreshRateType::PERFORMANCE;

    const auto refreshRate = mRefreshRateConfigs.getRefreshRate(refreshRateType);
    const uint32_t performanceFps = (refreshRate) ? refreshRate->fps : 0;

    const auto defaultRefreshRate = mRefreshRateConfigs.getRefreshRate(RefreshRateType::DEFAULT);
    const uint32_t defaultFps = (defaultRefreshRate) ? defaultRefreshRate->fps : 0;
    return mLayerHistory.createLayer(name, defaultFps, performanceFps);
}

void Scheduler::addLayerPresentTimeAndHDR(
        const std::unique_ptr<scheduler::LayerHistory::LayerHandle>& layerHandle,
        nsecs_t presentTime, bool isHDR) {
    mLayerHistory.insert(layerHandle, presentTime, isHDR);
}

void Scheduler::setLayerVisibility(
        const std::unique_ptr<scheduler::LayerHistory::LayerHandle>& layerHandle, bool visible) {
    mLayerHistory.setVisibility(layerHandle, visible);
}

void Scheduler::withPrimaryDispSync(std::function<void(DispSync&)> const& fn) {
    fn(*mPrimaryDispSync);
}

void Scheduler::updateFpsBasedOnContent() {
    auto [refreshRate, isHDR] = mLayerHistory.getDesiredRefreshRateAndHDR();
    const uint32_t refreshRateRound = std::round(refreshRate);
    RefreshRateType newRefreshRateType;
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        if (mFeatures.contentRefreshRate == refreshRateRound && mFeatures.isHDRContent == isHDR) {
            return;
        }
        mFeatures.contentRefreshRate = refreshRateRound;
        ATRACE_INT("ContentFPS", refreshRateRound);

        mFeatures.isHDRContent = isHDR;
        ATRACE_INT("ContentHDR", isHDR);

        mFeatures.contentDetection =
                refreshRateRound > 0 ? ContentDetectionState::On : ContentDetectionState::Off;
        newRefreshRateType = calculateRefreshRateType();
        if (mFeatures.refreshRateType == newRefreshRateType) {
            return;
        }
        mFeatures.refreshRateType = newRefreshRateType;
    }
    changeRefreshRate(newRefreshRateType, ConfigEvent::Changed);
}

void Scheduler::setChangeRefreshRateCallback(
        const ChangeRefreshRateCallback&& changeRefreshRateCallback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mChangeRefreshRateCallback = changeRefreshRateCallback;
}

void Scheduler::setGetCurrentRefreshRateTypeCallback(
        const GetCurrentRefreshRateTypeCallback&& getCurrentRefreshRateTypeCallback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mGetCurrentRefreshRateTypeCallback = getCurrentRefreshRateTypeCallback;
}

void Scheduler::setGetVsyncPeriodCallback(const GetVsyncPeriod&& getVsyncPeriod) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mGetVsyncPeriod = getVsyncPeriod;
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

void Scheduler::notifyTouchEvent() {
    if (mTouchTimer) {
        mTouchTimer->reset();
    }

    if (mSupportKernelTimer) {
        resetIdleTimer();
    }

    // Touch event will boost the refresh rate to performance.
    // Clear Layer History to get fresh FPS detection
    mLayerHistory.clearHistory();
}

void Scheduler::setDisplayPowerState(bool normal) {
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        mFeatures.isDisplayPowerStateNormal = normal;
    }

    if (mDisplayPowerTimer) {
        mDisplayPowerTimer->reset();
    }

    // Display Power event will boost the refresh rate to performance.
    // Clear Layer History to get fresh FPS detection
    mLayerHistory.clearHistory();
}

void Scheduler::kernelIdleTimerCallback(TimerState state) {
    ATRACE_INT("ExpiredKernelIdleTimer", static_cast<int>(state));

    std::lock_guard<std::mutex> lock(mCallbackLock);
    if (!mGetCurrentRefreshRateTypeCallback || !mGetVsyncPeriod) return;

    const auto type = mGetCurrentRefreshRateTypeCallback();
    if (state == TimerState::Reset && type == RefreshRateType::PERFORMANCE) {
        // If we're not in performance mode then the kernel timer shouldn't do
        // anything, as the refresh rate during DPU power collapse will be the
        // same.
        resyncToHardwareVsync(true /* makeAvailable */, mGetVsyncPeriod());
    } else if (state == TimerState::Expired && type != RefreshRateType::PERFORMANCE) {
        // Disable HW VSYNC if the timer expired, as we don't need it enabled if
        // we're not pushing frames, and if we're in PERFORMANCE mode then we'll
        // need to update the DispSync model anyway.
        disableHardwareVsync(false /* makeUnavailable */);
    }
}

void Scheduler::idleTimerCallback(TimerState state) {
    handleTimerStateChanged(&mFeatures.idleTimer, state, false /* eventOnContentDetection */);
    ATRACE_INT("ExpiredIdleTimer", static_cast<int>(state));
}

void Scheduler::touchTimerCallback(TimerState state) {
    const TouchState touch = state == TimerState::Reset ? TouchState::Active : TouchState::Inactive;
    handleTimerStateChanged(&mFeatures.touch, touch, true /* eventOnContentDetection */);
    ATRACE_INT("TouchState", static_cast<int>(touch));
}

void Scheduler::displayPowerTimerCallback(TimerState state) {
    handleTimerStateChanged(&mFeatures.displayPowerTimer, state,
                            true /* eventOnContentDetection */);
    ATRACE_INT("ExpiredDisplayPowerTimer", static_cast<int>(state));
}

std::string Scheduler::doDump() {
    std::ostringstream stream;
    stream << "+  Idle timer interval: " << mSetIdleTimerMs << " ms" << std::endl;
    stream << "+  Touch timer interval: " << mSetTouchTimerMs << " ms" << std::endl;
    return stream.str();
}

template <class T>
void Scheduler::handleTimerStateChanged(T* currentState, T newState, bool eventOnContentDetection) {
    ConfigEvent event = ConfigEvent::None;
    RefreshRateType newRefreshRateType;
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        if (*currentState == newState) {
            return;
        }
        *currentState = newState;
        newRefreshRateType = calculateRefreshRateType();
        if (mFeatures.refreshRateType == newRefreshRateType) {
            return;
        }
        mFeatures.refreshRateType = newRefreshRateType;
        if (eventOnContentDetection && mFeatures.contentDetection == ContentDetectionState::On) {
            event = ConfigEvent::Changed;
        }
    }
    changeRefreshRate(newRefreshRateType, event);
}

Scheduler::RefreshRateType Scheduler::calculateRefreshRateType() {
    // HDR content is not supported on PERFORMANCE mode
    if (mForceHDRContentToDefaultRefreshRate && mFeatures.isHDRContent) {
        return RefreshRateType::DEFAULT;
    }

    // If Display Power is not in normal operation we want to be in performance mode.
    // When coming back to normal mode, a grace period is given with DisplayPowerTimer
    if (!mFeatures.isDisplayPowerStateNormal || mFeatures.displayPowerTimer == TimerState::Reset) {
        return RefreshRateType::PERFORMANCE;
    }

    // As long as touch is active we want to be in performance mode
    if (mFeatures.touch == TouchState::Active) {
        return RefreshRateType::PERFORMANCE;
    }

    // If timer has expired as it means there is no new content on the screen
    if (mFeatures.idleTimer == TimerState::Expired) {
        return RefreshRateType::DEFAULT;
    }

    // If content detection is off we choose performance as we don't know the content fps
    if (mFeatures.contentDetection == ContentDetectionState::Off) {
        return RefreshRateType::PERFORMANCE;
    }

    // Content detection is on, find the appropriate refresh rate with minimal error
    const float rate = static_cast<float>(mFeatures.contentRefreshRate);
    auto iter = min_element(mRefreshRateConfigs.getRefreshRates().cbegin(),
                            mRefreshRateConfigs.getRefreshRates().cend(),
                            [rate](const auto& lhs, const auto& rhs) -> bool {
                                return std::abs(lhs.second->fps - rate) <
                                        std::abs(rhs.second->fps - rate);
                            });
    RefreshRateType currRefreshRateType = iter->first;

    // Some content aligns better on higher refresh rate. For example for 45fps we should choose
    // 90Hz config. However we should still prefer a lower refresh rate if the content doesn't
    // align well with both
    constexpr float MARGIN = 0.05f;
    float ratio = mRefreshRateConfigs.getRefreshRate(currRefreshRateType)->fps / rate;
    if (std::abs(std::round(ratio) - ratio) > MARGIN) {
        while (iter != mRefreshRateConfigs.getRefreshRates().cend()) {
            ratio = iter->second->fps / rate;

            if (std::abs(std::round(ratio) - ratio) <= MARGIN) {
                currRefreshRateType = iter->first;
                break;
            }
            ++iter;
        }
    }

    return currRefreshRateType;
}

void Scheduler::changeRefreshRate(RefreshRateType refreshRateType, ConfigEvent configEvent) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    if (mChangeRefreshRateCallback) {
        mChangeRefreshRateCallback(refreshRateType, configEvent);
    }
}

} // namespace android
