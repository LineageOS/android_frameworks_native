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

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>
#include <input/InputWindow.h>
#include <system/window.h>
#include <ui/DisplayStatInfo.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <FrameTimeline/FrameTimeline.h>
#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>

#include "../Layer.h"
#include "DispSyncSource.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"
#include "OneShotTimer.h"
#include "SchedulerUtils.h"
#include "SurfaceFlingerProperties.h"
#include "Timer.h"
#include "VSyncDispatchTimerQueue.h"
#include "VSyncPredictor.h"
#include "VSyncReactor.h"
#include "VsyncController.h"

#define RETURN_IF_INVALID_HANDLE(handle, ...)                        \
    do {                                                             \
        if (mConnections.count(handle) == 0) {                       \
            ALOGE("Invalid connection handle %" PRIuPTR, handle.id); \
            return __VA_ARGS__;                                      \
        }                                                            \
    } while (false)

using namespace std::string_literals;

namespace android {

namespace {

std::unique_ptr<scheduler::VSyncTracker> createVSyncTracker() {
    // TODO(b/144707443): Tune constants.
    constexpr int kDefaultRate = 60;
    constexpr auto initialPeriod = std::chrono::duration<nsecs_t, std::ratio<1, kDefaultRate>>(1);
    constexpr nsecs_t idealPeriod =
            std::chrono::duration_cast<std::chrono::nanoseconds>(initialPeriod).count();
    constexpr size_t vsyncTimestampHistorySize = 20;
    constexpr size_t minimumSamplesForPrediction = 6;
    constexpr uint32_t discardOutlierPercent = 20;
    return std::make_unique<scheduler::VSyncPredictor>(idealPeriod, vsyncTimestampHistorySize,
                                                       minimumSamplesForPrediction,
                                                       discardOutlierPercent);
}

std::unique_ptr<scheduler::VSyncDispatch> createVSyncDispatch(scheduler::VSyncTracker& tracker) {
    // TODO(b/144707443): Tune constants.
    constexpr std::chrono::nanoseconds vsyncMoveThreshold = 3ms;
    constexpr std::chrono::nanoseconds timerSlack = 500us;
    return std::make_unique<
            scheduler::VSyncDispatchTimerQueue>(std::make_unique<scheduler::Timer>(), tracker,
                                                timerSlack.count(), vsyncMoveThreshold.count());
}

const char* toContentDetectionString(bool useContentDetection, bool useContentDetectionV2) {
    if (!useContentDetection) return "off";
    return useContentDetectionV2 ? "V2" : "V1";
}

} // namespace

class PredictedVsyncTracer {
public:
    PredictedVsyncTracer(scheduler::VSyncDispatch& dispatch)
          : mRegistration(dispatch, std::bind(&PredictedVsyncTracer::callback, this),
                          "PredictedVsyncTracer") {
        scheduleRegistration();
    }

private:
    TracedOrdinal<bool> mParity = {"VSYNC-predicted", 0};
    scheduler::VSyncCallbackRegistration mRegistration;

    void scheduleRegistration() { mRegistration.schedule({0, 0, 0}); }

    void callback() {
        mParity = !mParity;
        scheduleRegistration();
    }
};

Scheduler::Scheduler(const scheduler::RefreshRateConfigs& configs, ISchedulerCallback& callback)
      : Scheduler(configs, callback,
                  {.supportKernelTimer = sysprop::support_kernel_idle_timer(false),
                   .useContentDetection = sysprop::use_content_detection_for_refresh_rate(false),
                   .useContentDetectionV2 =
                           base::GetBoolProperty("debug.sf.use_content_detection_v2"s, true)}) {}

Scheduler::Scheduler(const scheduler::RefreshRateConfigs& configs, ISchedulerCallback& callback,
                     Options options)
      : Scheduler(createVsyncSchedule(options.supportKernelTimer), configs, callback,
                  createLayerHistory(configs, options.useContentDetectionV2), options) {
    using namespace sysprop;

    const int setIdleTimerMs = base::GetIntProperty("debug.sf.set_idle_timer_ms"s, 0);

    if (const auto millis = setIdleTimerMs ? setIdleTimerMs : set_idle_timer_ms(0); millis > 0) {
        const auto callback = mOptions.supportKernelTimer ? &Scheduler::kernelIdleTimerCallback
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

Scheduler::Scheduler(VsyncSchedule schedule, const scheduler::RefreshRateConfigs& configs,
                     ISchedulerCallback& schedulerCallback,
                     std::unique_ptr<LayerHistory> layerHistory, Options options)
      : mOptions(options),
        mVsyncSchedule(std::move(schedule)),
        mLayerHistory(std::move(layerHistory)),
        mSchedulerCallback(schedulerCallback),
        mRefreshRateConfigs(configs),
        mPredictedVsyncTracer(
                base::GetBoolProperty("debug.sf.show_predicted_vsync", false)
                        ? std::make_unique<PredictedVsyncTracer>(*mVsyncSchedule.dispatch)
                        : nullptr) {
    mSchedulerCallback.setVsyncEnabled(false);
}

Scheduler::~Scheduler() {
    // Ensure the OneShotTimer threads are joined before we start destroying state.
    mDisplayPowerTimer.reset();
    mTouchTimer.reset();
    mIdleTimer.reset();
}

Scheduler::VsyncSchedule Scheduler::createVsyncSchedule(bool supportKernelTimer) {
    auto clock = std::make_unique<scheduler::SystemClock>();
    auto tracker = createVSyncTracker();
    auto dispatch = createVSyncDispatch(*tracker);

    // TODO(b/144707443): Tune constants.
    constexpr size_t pendingFenceLimit = 20;
    auto controller =
            std::make_unique<scheduler::VSyncReactor>(std::move(clock), *tracker, pendingFenceLimit,
                                                      supportKernelTimer);
    return {std::move(controller), std::move(tracker), std::move(dispatch)};
}

std::unique_ptr<LayerHistory> Scheduler::createLayerHistory(
        const scheduler::RefreshRateConfigs& configs, bool useContentDetectionV2) {
    if (!configs.canSwitch()) return nullptr;

    if (useContentDetectionV2) {
        return std::make_unique<scheduler::impl::LayerHistoryV2>(configs);
    }

    return std::make_unique<scheduler::impl::LayerHistory>();
}

std::unique_ptr<VSyncSource> Scheduler::makePrimaryDispSyncSource(
        const char* name, std::chrono::nanoseconds workDuration,
        std::chrono::nanoseconds readyDuration, bool traceVsync) {
    return std::make_unique<scheduler::DispSyncSource>(*mVsyncSchedule.dispatch, workDuration,
                                                       readyDuration, traceVsync, name);
}

Scheduler::ConnectionHandle Scheduler::createConnection(
        const char* connectionName, frametimeline::TokenManager* tokenManager,
        std::chrono::nanoseconds workDuration, std::chrono::nanoseconds readyDuration,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    auto vsyncSource = makePrimaryDispSyncSource(connectionName, workDuration, readyDuration);
    auto eventThread = std::make_unique<impl::EventThread>(std::move(vsyncSource), tokenManager,
                                                           std::move(interceptCallback));
    return createConnection(std::move(eventThread));
}

Scheduler::ConnectionHandle Scheduler::createConnection(std::unique_ptr<EventThread> eventThread) {
    const ConnectionHandle handle = ConnectionHandle{mNextConnectionHandleId++};
    ALOGV("Creating a connection handle with ID %" PRIuPTR, handle.id);

    auto connection =
            createConnectionInternal(eventThread.get(), ISurfaceComposer::eConfigChangedSuppress);

    std::lock_guard<std::mutex> lock(mConnectionsLock);
    mConnections.emplace(handle, Connection{connection, std::move(eventThread)});
    return handle;
}

sp<EventThreadConnection> Scheduler::createConnectionInternal(
        EventThread* eventThread, ISurfaceComposer::ConfigChanged configChanged) {
    return eventThread->createEventConnection([&] { resync(); }, configChanged);
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        ConnectionHandle handle, ISurfaceComposer::ConfigChanged configChanged) {
    std::lock_guard<std::mutex> lock(mConnectionsLock);
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return createConnectionInternal(mConnections[handle].thread.get(), configChanged);
}

sp<EventThreadConnection> Scheduler::getEventConnection(ConnectionHandle handle) {
    std::lock_guard<std::mutex> lock(mConnectionsLock);
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return mConnections[handle].connection;
}

void Scheduler::onHotplugReceived(ConnectionHandle handle, PhysicalDisplayId displayId,
                                  bool connected) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }

    thread->onHotplugReceived(displayId, connected);
}

void Scheduler::onScreenAcquired(ConnectionHandle handle) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->onScreenAcquired();
}

void Scheduler::onScreenReleased(ConnectionHandle handle) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->onScreenReleased();
}

void Scheduler::onPrimaryDisplayConfigChanged(ConnectionHandle handle, PhysicalDisplayId displayId,
                                              HwcConfigIndexType configId, nsecs_t vsyncPeriod) {
    std::lock_guard<std::mutex> lock(mFeatureStateLock);
    // Cache the last reported config for primary display.
    mFeatures.cachedConfigChangedParams = {handle, displayId, configId, vsyncPeriod};
    onNonPrimaryDisplayConfigChanged(handle, displayId, configId, vsyncPeriod);
}

void Scheduler::dispatchCachedReportedConfig() {
    // Check optional fields first.
    if (!mFeatures.configId.has_value()) {
        ALOGW("No config ID found, not dispatching cached config.");
        return;
    }
    if (!mFeatures.cachedConfigChangedParams.has_value()) {
        ALOGW("No config changed params found, not dispatching cached config.");
        return;
    }

    const auto configId = *mFeatures.configId;
    const auto vsyncPeriod =
            mRefreshRateConfigs.getRefreshRateFromConfigId(configId).getVsyncPeriod();

    // If there is no change from cached config, there is no need to dispatch an event
    if (configId == mFeatures.cachedConfigChangedParams->configId &&
        vsyncPeriod == mFeatures.cachedConfigChangedParams->vsyncPeriod) {
        return;
    }

    mFeatures.cachedConfigChangedParams->configId = configId;
    mFeatures.cachedConfigChangedParams->vsyncPeriod = vsyncPeriod;
    onNonPrimaryDisplayConfigChanged(mFeatures.cachedConfigChangedParams->handle,
                                     mFeatures.cachedConfigChangedParams->displayId,
                                     mFeatures.cachedConfigChangedParams->configId,
                                     mFeatures.cachedConfigChangedParams->vsyncPeriod);
}

void Scheduler::onNonPrimaryDisplayConfigChanged(ConnectionHandle handle,
                                                 PhysicalDisplayId displayId,
                                                 HwcConfigIndexType configId, nsecs_t vsyncPeriod) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->onConfigChanged(displayId, configId, vsyncPeriod);
}

size_t Scheduler::getEventThreadConnectionCount(ConnectionHandle handle) {
    std::lock_guard<std::mutex> lock(mConnectionsLock);
    RETURN_IF_INVALID_HANDLE(handle, 0);
    return mConnections[handle].thread->getEventThreadConnectionCount();
}

void Scheduler::dump(ConnectionHandle handle, std::string& result) const {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections.at(handle).thread.get();
    }
    thread->dump(result);
}

void Scheduler::setDuration(ConnectionHandle handle, std::chrono::nanoseconds workDuration,
                            std::chrono::nanoseconds readyDuration) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->setDuration(workDuration, readyDuration);
}

void Scheduler::getDisplayStatInfo(DisplayStatInfo* stats, nsecs_t now) {
    stats->vsyncTime = mVsyncSchedule.tracker->nextAnticipatedVSyncTimeFrom(now);
    stats->vsyncPeriod = mVsyncSchedule.tracker->currentPeriod();
}

Scheduler::ConnectionHandle Scheduler::enableVSyncInjection(bool enable) {
    if (mInjectVSyncs == enable) {
        return {};
    }

    ALOGV("%s VSYNC injection", enable ? "Enabling" : "Disabling");

    if (!mInjectorConnectionHandle) {
        auto vsyncSource = std::make_unique<InjectVSyncSource>();
        mVSyncInjector = vsyncSource.get();

        auto eventThread =
                std::make_unique<impl::EventThread>(std::move(vsyncSource),
                                                    /*tokenManager=*/nullptr,
                                                    impl::EventThread::InterceptVSyncsCallback());

        mInjectorConnectionHandle = createConnection(std::move(eventThread));
    }

    mInjectVSyncs = enable;
    return mInjectorConnectionHandle;
}

bool Scheduler::injectVSync(nsecs_t when, nsecs_t expectedVSyncTime, nsecs_t deadlineTimestamp) {
    if (!mInjectVSyncs || !mVSyncInjector) {
        return false;
    }

    mVSyncInjector->onInjectSyncEvent(when, expectedVSyncTime, deadlineTimestamp);
    return true;
}

void Scheduler::enableHardwareVsync() {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (!mPrimaryHWVsyncEnabled && mHWVsyncAvailable) {
        mVsyncSchedule.tracker->resetModel();
        mSchedulerCallback.setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::disableHardwareVsync(bool makeUnavailable) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (mPrimaryHWVsyncEnabled) {
        mSchedulerCallback.setVsyncEnabled(false);
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

void Scheduler::resync() {
    static constexpr nsecs_t kIgnoreDelay = ms2ns(750);

    const nsecs_t now = systemTime();
    const nsecs_t last = mLastResyncTime.exchange(now);

    if (now - last > kIgnoreDelay) {
        resyncToHardwareVsync(false, mRefreshRateConfigs.getCurrentRefreshRate().getVsyncPeriod());
    }
}

void Scheduler::setVsyncPeriod(nsecs_t period) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    mVsyncSchedule.controller->startPeriodTransition(period);

    if (!mPrimaryHWVsyncEnabled) {
        mVsyncSchedule.tracker->resetModel();
        mSchedulerCallback.setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::addResyncSample(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                                bool* periodFlushed) {
    bool needsHwVsync = false;
    *periodFlushed = false;
    { // Scope for the lock
        std::lock_guard<std::mutex> lock(mHWVsyncLock);
        if (mPrimaryHWVsyncEnabled) {
            needsHwVsync = mVsyncSchedule.controller->addHwVsyncTimestamp(timestamp, hwcVsyncPeriod,
                                                                          periodFlushed);
        }
    }

    if (needsHwVsync) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::addPresentFence(const std::shared_ptr<FenceTime>& fenceTime) {
    if (mVsyncSchedule.controller->addPresentFence(fenceTime)) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::setIgnorePresentFences(bool ignore) {
    mVsyncSchedule.controller->setIgnorePresentFences(ignore);
}

void Scheduler::registerLayer(Layer* layer) {
    if (!mLayerHistory) return;

    const auto minFps = mRefreshRateConfigs.getMinRefreshRate().getFps();
    const auto maxFps = mRefreshRateConfigs.getMaxRefreshRate().getFps();

    if (layer->getWindowType() == InputWindowInfo::Type::STATUS_BAR) {
        mLayerHistory->registerLayer(layer, minFps, maxFps,
                                     scheduler::LayerHistory::LayerVoteType::NoVote);
    } else if (!mOptions.useContentDetection) {
        // If the content detection feature is off, all layers are registered at Max. We still keep
        // the layer history, since we use it for other features (like Frame Rate API), so layers
        // still need to be registered.
        mLayerHistory->registerLayer(layer, minFps, maxFps,
                                     scheduler::LayerHistory::LayerVoteType::Max);
    } else if (!mOptions.useContentDetectionV2) {
        // In V1 of content detection, all layers are registered as Heuristic (unless it's
        // wallpaper).
        const auto highFps =
                layer->getWindowType() == InputWindowInfo::Type::WALLPAPER ? minFps : maxFps;

        mLayerHistory->registerLayer(layer, minFps, highFps,
                                     scheduler::LayerHistory::LayerVoteType::Heuristic);
    } else {
        if (layer->getWindowType() == InputWindowInfo::Type::WALLPAPER) {
            // Running Wallpaper at Min is considered as part of content detection.
            mLayerHistory->registerLayer(layer, minFps, maxFps,
                                         scheduler::LayerHistory::LayerVoteType::Min);
        } else {
            mLayerHistory->registerLayer(layer, minFps, maxFps,
                                         scheduler::LayerHistory::LayerVoteType::Heuristic);
        }
    }
}

void Scheduler::recordLayerHistory(Layer* layer, nsecs_t presentTime,
                                   LayerHistory::LayerUpdateType updateType) {
    if (mLayerHistory) {
        mLayerHistory->record(layer, presentTime, systemTime(), updateType);
    }
}

void Scheduler::setConfigChangePending(bool pending) {
    if (mLayerHistory) {
        mLayerHistory->setConfigChangePending(pending);
    }
}

void Scheduler::chooseRefreshRateForContent() {
    if (!mLayerHistory) return;

    ATRACE_CALL();

    scheduler::LayerHistory::Summary summary = mLayerHistory->summarize(systemTime());
    HwcConfigIndexType newConfigId;
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        if (mFeatures.contentRequirements == summary) {
            return;
        }
        mFeatures.contentRequirements = summary;
        mFeatures.contentDetectionV1 =
                !summary.empty() ? ContentDetectionState::On : ContentDetectionState::Off;

        scheduler::RefreshRateConfigs::GlobalSignals consideredSignals;
        newConfigId = calculateRefreshRateConfigIndexType(&consideredSignals);
        if (mFeatures.configId == newConfigId) {
            // We don't need to change the config, but we might need to send an event
            // about a config change, since it was suppressed due to a previous idleConsidered
            if (!consideredSignals.idle) {
                dispatchCachedReportedConfig();
            }
            return;
        }
        mFeatures.configId = newConfigId;
        auto& newRefreshRate = mRefreshRateConfigs.getRefreshRateFromConfigId(newConfigId);
        mSchedulerCallback.changeRefreshRate(newRefreshRate,
                                             consideredSignals.idle ? ConfigEvent::None
                                                                    : ConfigEvent::Changed);
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

        if (mOptions.supportKernelTimer && mIdleTimer) {
            mIdleTimer->reset();
        }
    }
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
    if (mLayerHistory) {
        mLayerHistory->clear();
    }
}

void Scheduler::kernelIdleTimerCallback(TimerState state) {
    ATRACE_INT("ExpiredKernelIdleTimer", static_cast<int>(state));

    // TODO(145561154): cleanup the kernel idle timer implementation and the refresh rate
    // magic number
    const auto& refreshRate = mRefreshRateConfigs.getCurrentRefreshRate();
    constexpr float FPS_THRESHOLD_FOR_KERNEL_TIMER = 65.0f;
    if (state == TimerState::Reset && refreshRate.getFps() > FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // If we're not in performance mode then the kernel timer shouldn't do
        // anything, as the refresh rate during DPU power collapse will be the
        // same.
        resyncToHardwareVsync(true /* makeAvailable */, refreshRate.getVsyncPeriod());
    } else if (state == TimerState::Expired &&
               refreshRate.getFps() <= FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // Disable HW VSYNC if the timer expired, as we don't need it enabled if
        // we're not pushing frames, and if we're in PERFORMANCE mode then we'll
        // need to update the VsyncController model anyway.
        disableHardwareVsync(false /* makeUnavailable */);
    }

    mSchedulerCallback.kernelTimerChanged(state == TimerState::Expired);
}

void Scheduler::idleTimerCallback(TimerState state) {
    handleTimerStateChanged(&mFeatures.idleTimer, state);
    ATRACE_INT("ExpiredIdleTimer", static_cast<int>(state));
}

void Scheduler::touchTimerCallback(TimerState state) {
    const TouchState touch = state == TimerState::Reset ? TouchState::Active : TouchState::Inactive;
    // Touch event will boost the refresh rate to performance.
    // Clear layer history to get fresh FPS detection.
    // NOTE: Instead of checking all the layers, we should be checking the layer
    // that is currently on top. b/142507166 will give us this capability.
    if (handleTimerStateChanged(&mFeatures.touch, touch)) {
        if (mLayerHistory) {
            mLayerHistory->clear();
        }
    }
    ATRACE_INT("TouchState", static_cast<int>(touch));
}

void Scheduler::displayPowerTimerCallback(TimerState state) {
    handleTimerStateChanged(&mFeatures.displayPowerTimer, state);
    ATRACE_INT("ExpiredDisplayPowerTimer", static_cast<int>(state));
}

void Scheduler::dump(std::string& result) const {
    using base::StringAppendF;

    StringAppendF(&result, "+  Idle timer: %s\n", mIdleTimer ? mIdleTimer->dump().c_str() : "off");
    StringAppendF(&result, "+  Touch timer: %s\n",
                  mTouchTimer ? mTouchTimer->dump().c_str() : "off");
    StringAppendF(&result, "+  Content detection: %s %s\n\n",
                  toContentDetectionString(mOptions.useContentDetection,
                                           mOptions.useContentDetectionV2),
                  mLayerHistory ? mLayerHistory->dump().c_str() : "(no layer history)");
}

void Scheduler::dumpVsync(std::string& s) const {
    using base::StringAppendF;

    StringAppendF(&s, "VSyncReactor:\n");
    mVsyncSchedule.controller->dump(s);
    StringAppendF(&s, "VSyncDispatch:\n");
    mVsyncSchedule.dispatch->dump(s);
}

template <class T>
bool Scheduler::handleTimerStateChanged(T* currentState, T newState) {
    HwcConfigIndexType newConfigId;
    scheduler::RefreshRateConfigs::GlobalSignals consideredSignals;
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        if (*currentState == newState) {
            return false;
        }
        *currentState = newState;
        newConfigId = calculateRefreshRateConfigIndexType(&consideredSignals);
        if (mFeatures.configId == newConfigId) {
            // We don't need to change the config, but we might need to send an event
            // about a config change, since it was suppressed due to a previous idleConsidered
            if (!consideredSignals.idle) {
                dispatchCachedReportedConfig();
            }
            return consideredSignals.touch;
        }
        mFeatures.configId = newConfigId;
    }
    const RefreshRate& newRefreshRate = mRefreshRateConfigs.getRefreshRateFromConfigId(newConfigId);
    mSchedulerCallback.changeRefreshRate(newRefreshRate,
                                         consideredSignals.idle ? ConfigEvent::None
                                                                : ConfigEvent::Changed);
    return consideredSignals.touch;
}

HwcConfigIndexType Scheduler::calculateRefreshRateConfigIndexType(
        scheduler::RefreshRateConfigs::GlobalSignals* consideredSignals) {
    ATRACE_CALL();
    if (consideredSignals) *consideredSignals = {};

    // If Display Power is not in normal operation we want to be in performance mode. When coming
    // back to normal mode, a grace period is given with DisplayPowerTimer.
    if (mDisplayPowerTimer &&
        (!mFeatures.isDisplayPowerStateNormal ||
         mFeatures.displayPowerTimer == TimerState::Reset)) {
        return mRefreshRateConfigs.getMaxRefreshRateByPolicy().getConfigId();
    }

    const bool touchActive = mTouchTimer && mFeatures.touch == TouchState::Active;
    const bool idle = mIdleTimer && mFeatures.idleTimer == TimerState::Expired;

    if (!mOptions.useContentDetectionV2) {
        // As long as touch is active we want to be in performance mode.
        if (touchActive) {
            return mRefreshRateConfigs.getMaxRefreshRateByPolicy().getConfigId();
        }

        // If timer has expired as it means there is no new content on the screen.
        if (idle) {
            if (consideredSignals) consideredSignals->idle = true;
            return mRefreshRateConfigs.getMinRefreshRateByPolicy().getConfigId();
        }

        // If content detection is off we choose performance as we don't know the content fps.
        if (mFeatures.contentDetectionV1 == ContentDetectionState::Off) {
            // NOTE: V1 always calls this, but this is not a default behavior for V2.
            return mRefreshRateConfigs.getMaxRefreshRateByPolicy().getConfigId();
        }

        // Content detection is on, find the appropriate refresh rate with minimal error
        return mRefreshRateConfigs.getRefreshRateForContent(mFeatures.contentRequirements)
                .getConfigId();
    }

    return mRefreshRateConfigs
            .getBestRefreshRate(mFeatures.contentRequirements, {.touch = touchActive, .idle = idle},
                                consideredSignals)
            .getConfigId();
}

std::optional<HwcConfigIndexType> Scheduler::getPreferredConfigId() {
    std::lock_guard<std::mutex> lock(mFeatureStateLock);
    // Make sure that the default config ID is first updated, before returned.
    if (mFeatures.configId.has_value()) {
        mFeatures.configId = calculateRefreshRateConfigIndexType();
    }
    return mFeatures.configId;
}

void Scheduler::onNewVsyncPeriodChangeTimeline(const hal::VsyncPeriodChangeTimeline& timeline) {
    if (timeline.refreshRequired) {
        mSchedulerCallback.repaintEverythingForHWC();
    }

    std::lock_guard<std::mutex> lock(mVsyncTimelineLock);
    mLastVsyncPeriodChangeTimeline = std::make_optional(timeline);

    const auto maxAppliedTime = systemTime() + MAX_VSYNC_APPLIED_TIME.count();
    if (timeline.newVsyncAppliedTimeNanos > maxAppliedTime) {
        mLastVsyncPeriodChangeTimeline->newVsyncAppliedTimeNanos = maxAppliedTime;
    }
}

void Scheduler::onDisplayRefreshed(nsecs_t timestamp) {
    bool callRepaint = false;
    {
        std::lock_guard<std::mutex> lock(mVsyncTimelineLock);
        if (mLastVsyncPeriodChangeTimeline && mLastVsyncPeriodChangeTimeline->refreshRequired) {
            if (mLastVsyncPeriodChangeTimeline->refreshTimeNanos < timestamp) {
                mLastVsyncPeriodChangeTimeline->refreshRequired = false;
            } else {
                // We need to send another refresh as refreshTimeNanos is still in the future
                callRepaint = true;
            }
        }
    }

    if (callRepaint) {
        mSchedulerCallback.repaintEverythingForHWC();
    }
}

void Scheduler::onPrimaryDisplayAreaChanged(uint32_t displayArea) {
    if (mLayerHistory) {
        mLayerHistory->setDisplayArea(displayArea);
    }
}

} // namespace android
