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

#undef LOG_TAG
#define LOG_TAG "Scheduler"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Scheduler.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <functional>
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
#include "OneShotTimer.h"
#include "SchedulerUtils.h"
#include "SurfaceFlingerProperties.h"

#define RETURN_IF_INVALID_HANDLE(handle, ...)                        \
    do {                                                             \
        if (mConnections.count(handle) == 0) {                       \
            ALOGE("Invalid connection handle %" PRIuPTR, handle.id); \
            return __VA_ARGS__;                                      \
        }                                                            \
    } while (false)

namespace android {

Scheduler::Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function,
                     const scheduler::RefreshRateConfigs& refreshRateConfig)
      : mPrimaryDispSync(new impl::DispSync("SchedulerDispSync",
                                            sysprop::running_without_sync_framework(true))),
        mEventControlThread(new impl::EventControlThread(std::move(function))),
        mSupportKernelTimer(sysprop::support_kernel_idle_timer(false)),
        mRefreshRateConfigs(refreshRateConfig) {
    using namespace sysprop;

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.set_idle_timer_ms", value, "0");
    const int setIdleTimerMs = atoi(value);

    if (const auto millis = setIdleTimerMs ? setIdleTimerMs : set_idle_timer_ms(0); millis > 0) {
        const auto callback = mSupportKernelTimer ? &Scheduler::kernelIdleTimerCallback
                                                  : &Scheduler::idleTimerCallback;

        mIdleTimer.emplace(
                std::chrono::milliseconds(millis),
                [this, callback] { std::invoke(callback, this, TimerState::Reset); },
                [this, callback] { std::invoke(callback, this, TimerState::Expired); });
        mIdleTimer->start();
    }

    if (const int64_t millis = set_touch_timer_ms(0); millis > 0) {
        // Touch events are coming to SF every 100ms, so the timer needs to be higher than that
        mTouchTimer.emplace(
                std::chrono::milliseconds(millis),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    if (const int64_t millis = set_display_power_timer_ms(0); millis > 0) {
        mDisplayPowerTimer.emplace(
                std::chrono::milliseconds(millis),
                [this] { displayPowerTimerCallback(TimerState::Reset); },
                [this] { displayPowerTimerCallback(TimerState::Expired); });
        mDisplayPowerTimer->start();
    }
}

Scheduler::Scheduler(std::unique_ptr<DispSync> primaryDispSync,
                     std::unique_ptr<EventControlThread> eventControlThread,
                     const scheduler::RefreshRateConfigs& configs)
      : mPrimaryDispSync(std::move(primaryDispSync)),
        mEventControlThread(std::move(eventControlThread)),
        mSupportKernelTimer(false),
        mRefreshRateConfigs(configs) {}

Scheduler::~Scheduler() {
    // Ensure the OneShotTimer threads are joined before we start destroying state.
    mDisplayPowerTimer.reset();
    mTouchTimer.reset();
    mIdleTimer.reset();
}

DispSync& Scheduler::getPrimaryDispSync() {
    return *mPrimaryDispSync;
}

Scheduler::ConnectionHandle Scheduler::createConnection(
        const char* connectionName, nsecs_t phaseOffsetNs, nsecs_t offsetThresholdForNextVsync,
        ResyncCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    auto eventThread = makeEventThread(connectionName, phaseOffsetNs, offsetThresholdForNextVsync,
                                       std::move(interceptCallback));
    return createConnection(std::move(eventThread), std::move(resyncCallback));
}

Scheduler::ConnectionHandle Scheduler::createConnection(std::unique_ptr<EventThread> eventThread,
                                                        ResyncCallback&& resyncCallback) {
    const ConnectionHandle handle = ConnectionHandle{mNextConnectionHandleId++};
    ALOGV("Creating a connection handle with ID %" PRIuPTR, handle.id);

    auto connection = createConnectionInternal(eventThread.get(), std::move(resyncCallback),
                                               ISurfaceComposer::eConfigChangedSuppress);

    mConnections.emplace(handle, Connection{connection, std::move(eventThread)});
    return handle;
}

std::unique_ptr<EventThread> Scheduler::makeEventThread(
        const char* connectionName, nsecs_t phaseOffsetNs, nsecs_t offsetThresholdForNextVsync,
        impl::EventThread::InterceptVSyncsCallback&& interceptCallback) {
    auto source = std::make_unique<DispSyncSource>(mPrimaryDispSync.get(), phaseOffsetNs,
                                                   offsetThresholdForNextVsync,
                                                   true /* traceVsync */, connectionName);
    return std::make_unique<impl::EventThread>(std::move(source), std::move(interceptCallback),
                                               connectionName);
}

sp<EventThreadConnection> Scheduler::createConnectionInternal(
        EventThread* eventThread, ResyncCallback&& resyncCallback,
        ISurfaceComposer::ConfigChanged configChanged) {
    return eventThread->createEventConnection(std::move(resyncCallback), configChanged);
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        ConnectionHandle handle, ResyncCallback resyncCallback,
        ISurfaceComposer::ConfigChanged configChanged) {
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return createConnectionInternal(mConnections[handle].thread.get(), std::move(resyncCallback),
                                    configChanged);
}

EventThread* Scheduler::getEventThread(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return mConnections[handle].thread.get();
}

sp<EventThreadConnection> Scheduler::getEventConnection(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return mConnections[handle].connection;
}

void Scheduler::onHotplugReceived(ConnectionHandle handle, PhysicalDisplayId displayId,
                                  bool connected) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onHotplugReceived(displayId, connected);
}

void Scheduler::onScreenAcquired(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onScreenAcquired();
}

void Scheduler::onScreenReleased(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onScreenReleased();
}

void Scheduler::onConfigChanged(ConnectionHandle handle, PhysicalDisplayId displayId,
                                int32_t configId) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onConfigChanged(displayId, configId);
}

void Scheduler::dump(ConnectionHandle handle, std::string& result) const {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections.at(handle).thread->dump(result);
}

void Scheduler::setPhaseOffset(ConnectionHandle handle, nsecs_t phaseOffset) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->setPhaseOffset(phaseOffset);
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

void Scheduler::setVsyncPeriod(nsecs_t period) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    mPrimaryDispSync->setPeriod(period);

    if (!mPrimaryHWVsyncEnabled) {
        mPrimaryDispSync->beginResync();
        mEventControlThread->setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::addResyncSample(nsecs_t timestamp, bool* periodFlushed) {
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

void Scheduler::setChangeRefreshRateCallback(ChangeRefreshRateCallback&& callback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mChangeRefreshRateCallback = std::move(callback);
}

void Scheduler::setGetCurrentRefreshRateTypeCallback(GetCurrentRefreshRateTypeCallback&& callback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mGetCurrentRefreshRateTypeCallback = std::move(callback);
}

void Scheduler::setGetVsyncPeriodCallback(GetVsyncPeriod&& callback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mGetVsyncPeriod = std::move(callback);
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

    if (mSupportKernelTimer && mIdleTimer) {
        mIdleTimer->reset();
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

void Scheduler::dump(std::string& result) const {
    std::ostringstream stream;
    if (mIdleTimer) {
        stream << "+  Idle timer interval: " << mIdleTimer->interval().count() << " ms\n";
    }
    if (mTouchTimer) {
        stream << "+  Touch timer interval: " << mTouchTimer->interval().count() << " ms\n";
    }

    result.append(stream.str());
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
