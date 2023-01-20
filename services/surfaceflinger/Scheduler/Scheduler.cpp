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
#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <ftl/small_map.h>
#include <gui/WindowInfo.h>
#include <system/window.h>
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
#include "Display/DisplayMap.h"
#include "EventThread.h"
#include "FrameRateOverrideMappings.h"
#include "OneShotTimer.h"
#include "SurfaceFlingerProperties.h"
#include "VSyncPredictor.h"
#include "VSyncReactor.h"

#define RETURN_IF_INVALID_HANDLE(handle, ...)                        \
    do {                                                             \
        if (mConnections.count(handle) == 0) {                       \
            ALOGE("Invalid connection handle %" PRIuPTR, handle.id); \
            return __VA_ARGS__;                                      \
        }                                                            \
    } while (false)

namespace android::scheduler {

Scheduler::Scheduler(ICompositor& compositor, ISchedulerCallback& callback, FeatureFlags features,
                     sp<VsyncModulator> modulatorPtr)
      : impl::MessageQueue(compositor),
        mFeatures(features),
        mVsyncModulator(std::move(modulatorPtr)),
        mSchedulerCallback(callback) {}

Scheduler::~Scheduler() {
    // MessageQueue depends on VsyncSchedule, so first destroy it.
    // Otherwise, MessageQueue will get destroyed after Scheduler's dtor,
    // which will cause a use-after-free issue.
    Impl::destroyVsync();

    // Stop timers and wait for their threads to exit.
    mDisplayPowerTimer.reset();
    mTouchTimer.reset();

    // Stop idle timer and clear callbacks, as the RefreshRateSelector may outlive the Scheduler.
    demoteLeaderDisplay();
}

void Scheduler::startTimers() {
    using namespace sysprop;
    using namespace std::string_literals;

    if (const int64_t millis = set_touch_timer_ms(0); millis > 0) {
        // Touch events are coming to SF every 100ms, so the timer needs to be higher than that
        mTouchTimer.emplace(
                "TouchTimer", std::chrono::milliseconds(millis),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    if (const int64_t millis = set_display_power_timer_ms(0); millis > 0) {
        mDisplayPowerTimer.emplace(
                "DisplayPowerTimer", std::chrono::milliseconds(millis),
                [this] { displayPowerTimerCallback(TimerState::Reset); },
                [this] { displayPowerTimerCallback(TimerState::Expired); });
        mDisplayPowerTimer->start();
    }
}

void Scheduler::setLeaderDisplay(std::optional<PhysicalDisplayId> leaderIdOpt) {
    demoteLeaderDisplay();

    std::scoped_lock lock(mDisplayLock);
    promoteLeaderDisplay(leaderIdOpt);
}

void Scheduler::registerDisplay(PhysicalDisplayId displayId, RefreshRateSelectorPtr selectorPtr) {
    demoteLeaderDisplay();

    std::scoped_lock lock(mDisplayLock);
    mRefreshRateSelectors.emplace_or_replace(displayId, std::move(selectorPtr));

    promoteLeaderDisplay();
}

void Scheduler::unregisterDisplay(PhysicalDisplayId displayId) {
    demoteLeaderDisplay();

    std::scoped_lock lock(mDisplayLock);
    mRefreshRateSelectors.erase(displayId);

    promoteLeaderDisplay();
}

void Scheduler::run() {
    while (true) {
        waitMessage();
    }
}

void Scheduler::onFrameSignal(ICompositor& compositor, VsyncId vsyncId,
                              TimePoint expectedVsyncTime) {
    const TimePoint frameTime = SchedulerClock::now();

    if (!compositor.commit(frameTime, vsyncId, expectedVsyncTime)) {
        return;
    }

    compositor.composite(frameTime, vsyncId);
    compositor.sample();
}

void Scheduler::createVsyncSchedule(FeatureFlags features) {
    mVsyncSchedule.emplace(features);
}

std::optional<Fps> Scheduler::getFrameRateOverride(uid_t uid) const {
    const bool supportsFrameRateOverrideByContent =
            leaderSelectorPtr()->supportsAppFrameRateOverrideByContent();
    return mFrameRateOverrideMappings
            .getFrameRateOverrideForUid(uid, supportsFrameRateOverrideByContent);
}

bool Scheduler::isVsyncValid(TimePoint expectedVsyncTimestamp, uid_t uid) const {
    const auto frameRate = getFrameRateOverride(uid);
    if (!frameRate.has_value()) {
        return true;
    }

    return mVsyncSchedule->getTracker().isVSyncInPhase(expectedVsyncTimestamp.ns(), *frameRate);
}

impl::EventThread::ThrottleVsyncCallback Scheduler::makeThrottleVsyncCallback() const {
    return [this](nsecs_t expectedVsyncTimestamp, uid_t uid) {
        return !isVsyncValid(TimePoint::fromNs(expectedVsyncTimestamp), uid);
    };
}

impl::EventThread::GetVsyncPeriodFunction Scheduler::makeGetVsyncPeriodFunction() const {
    return [this](uid_t uid) {
        const Fps refreshRate = leaderSelectorPtr()->getActiveMode().fps;
        const nsecs_t currentPeriod = mVsyncSchedule->period().ns() ?: refreshRate.getPeriodNsecs();

        const auto frameRate = getFrameRateOverride(uid);
        if (!frameRate.has_value()) {
            return currentPeriod;
        }

        const auto divisor = RefreshRateSelector::getFrameRateDivisor(refreshRate, *frameRate);
        if (divisor <= 1) {
            return currentPeriod;
        }
        return currentPeriod * divisor;
    };
}

ConnectionHandle Scheduler::createEventThread(Cycle cycle,
                                              frametimeline::TokenManager* tokenManager,
                                              std::chrono::nanoseconds workDuration,
                                              std::chrono::nanoseconds readyDuration) {
    auto eventThread = std::make_unique<impl::EventThread>(cycle == Cycle::Render ? "app" : "appSf",
                                                           *mVsyncSchedule, tokenManager,
                                                           makeThrottleVsyncCallback(),
                                                           makeGetVsyncPeriodFunction(),
                                                           workDuration, readyDuration);

    auto& handle = cycle == Cycle::Render ? mAppConnectionHandle : mSfConnectionHandle;
    handle = createConnection(std::move(eventThread));
    return handle;
}

ConnectionHandle Scheduler::createConnection(std::unique_ptr<EventThread> eventThread) {
    const ConnectionHandle handle = ConnectionHandle{mNextConnectionHandleId++};
    ALOGV("Creating a connection handle with ID %" PRIuPTR, handle.id);

    auto connection = createConnectionInternal(eventThread.get());

    std::lock_guard<std::mutex> lock(mConnectionsLock);
    mConnections.emplace(handle, Connection{connection, std::move(eventThread)});
    return handle;
}

sp<EventThreadConnection> Scheduler::createConnectionInternal(
        EventThread* eventThread, EventRegistrationFlags eventRegistration) {
    return eventThread->createEventConnection([&] { resync(); }, eventRegistration);
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        ConnectionHandle handle, EventRegistrationFlags eventRegistration) {
    std::lock_guard<std::mutex> lock(mConnectionsLock);
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return createConnectionInternal(mConnections[handle].thread.get(), eventRegistration);
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
    mScreenAcquired = true;
}

void Scheduler::onScreenReleased(ConnectionHandle handle) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->onScreenReleased();
    mScreenAcquired = false;
}

void Scheduler::onFrameRateOverridesChanged(ConnectionHandle handle, PhysicalDisplayId displayId) {
    const bool supportsFrameRateOverrideByContent =
            leaderSelectorPtr()->supportsAppFrameRateOverrideByContent();

    std::vector<FrameRateOverride> overrides =
            mFrameRateOverrideMappings.getAllFrameRateOverrides(supportsFrameRateOverrideByContent);

    android::EventThread* thread;
    {
        std::lock_guard lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->onFrameRateOverridesChanged(displayId, std::move(overrides));
}

void Scheduler::onPrimaryDisplayModeChanged(ConnectionHandle handle, const FrameRateMode& mode) {
    {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        // Cache the last reported modes for primary display.
        mPolicy.cachedModeChangedParams = {handle, mode};

        // Invalidate content based refresh rate selection so it could be calculated
        // again for the new refresh rate.
        mPolicy.contentRequirements.clear();
    }
    onNonPrimaryDisplayModeChanged(handle, mode);
}

void Scheduler::dispatchCachedReportedMode() {
    // Check optional fields first.
    if (!mPolicy.modeOpt) {
        ALOGW("No mode ID found, not dispatching cached mode.");
        return;
    }
    if (!mPolicy.cachedModeChangedParams) {
        ALOGW("No mode changed params found, not dispatching cached mode.");
        return;
    }

    // If the mode is not the current mode, this means that a
    // mode change is in progress. In that case we shouldn't dispatch an event
    // as it will be dispatched when the current mode changes.
    if (leaderSelectorPtr()->getActiveMode() != mPolicy.modeOpt) {
        return;
    }

    // If there is no change from cached mode, there is no need to dispatch an event
    if (*mPolicy.modeOpt == mPolicy.cachedModeChangedParams->mode) {
        return;
    }

    mPolicy.cachedModeChangedParams->mode = *mPolicy.modeOpt;
    onNonPrimaryDisplayModeChanged(mPolicy.cachedModeChangedParams->handle,
                                   mPolicy.cachedModeChangedParams->mode);
}

void Scheduler::onNonPrimaryDisplayModeChanged(ConnectionHandle handle, const FrameRateMode& mode) {
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->onModeChanged(mode);
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

void Scheduler::setVsyncConfigSet(const VsyncConfigSet& configs, Period vsyncPeriod) {
    setVsyncConfig(mVsyncModulator->setVsyncConfigSet(configs), vsyncPeriod);
}

void Scheduler::setVsyncConfig(const VsyncConfig& config, Period vsyncPeriod) {
    setDuration(mAppConnectionHandle,
                /* workDuration */ config.appWorkDuration,
                /* readyDuration */ config.sfWorkDuration);
    setDuration(mSfConnectionHandle,
                /* workDuration */ vsyncPeriod,
                /* readyDuration */ config.sfWorkDuration);
    setDuration(config.sfWorkDuration);
}

void Scheduler::enableHardwareVsync() {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (!mPrimaryHWVsyncEnabled && mHWVsyncAvailable) {
        mVsyncSchedule->getTracker().resetModel();
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

void Scheduler::resyncToHardwareVsync(bool makeAvailable, Fps refreshRate) {
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

    setVsyncPeriod(refreshRate.getPeriodNsecs());
}

void Scheduler::setRenderRate(Fps renderFrameRate) {
    const auto mode = leaderSelectorPtr()->getActiveMode();

    using fps_approx_ops::operator!=;
    LOG_ALWAYS_FATAL_IF(renderFrameRate != mode.fps,
                        "Mismatch in render frame rates. Selector: %s, Scheduler: %s",
                        to_string(mode.fps).c_str(), to_string(renderFrameRate).c_str());

    ALOGV("%s %s (%s)", __func__, to_string(mode.fps).c_str(),
          to_string(mode.modePtr->getFps()).c_str());

    const auto divisor = RefreshRateSelector::getFrameRateDivisor(mode.modePtr->getFps(), mode.fps);
    LOG_ALWAYS_FATAL_IF(divisor == 0, "%s <> %s -- not divisors", to_string(mode.fps).c_str(),
                        to_string(mode.fps).c_str());

    mVsyncSchedule->getTracker().setDivisor(static_cast<unsigned>(divisor));
}

void Scheduler::resync() {
    static constexpr nsecs_t kIgnoreDelay = ms2ns(750);

    const nsecs_t now = systemTime();
    const nsecs_t last = mLastResyncTime.exchange(now);

    if (now - last > kIgnoreDelay) {
        const auto refreshRate = leaderSelectorPtr()->getActiveMode().modePtr->getFps();
        resyncToHardwareVsync(false, refreshRate);
    }
}

void Scheduler::setVsyncPeriod(nsecs_t period) {
    if (period <= 0) return;

    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    mVsyncSchedule->getController().startPeriodTransition(period);

    if (!mPrimaryHWVsyncEnabled) {
        mVsyncSchedule->getTracker().resetModel();
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
            needsHwVsync =
                    mVsyncSchedule->getController().addHwVsyncTimestamp(timestamp, hwcVsyncPeriod,
                                                                        periodFlushed);
        }
    }

    if (needsHwVsync) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::addPresentFence(std::shared_ptr<FenceTime> fence) {
    if (mVsyncSchedule->getController().addPresentFence(std::move(fence))) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::registerLayer(Layer* layer) {
    // If the content detection feature is off, we still keep the layer history,
    // since we use it for other features (like Frame Rate API), so layers
    // still need to be registered.
    mLayerHistory.registerLayer(layer, mFeatures.test(Feature::kContentDetection));
}

void Scheduler::deregisterLayer(Layer* layer) {
    mLayerHistory.deregisterLayer(layer);
}

void Scheduler::recordLayerHistory(Layer* layer, nsecs_t presentTime,
                                   LayerHistory::LayerUpdateType updateType) {
    if (leaderSelectorPtr()->canSwitch()) {
        mLayerHistory.record(layer, presentTime, systemTime(), updateType);
    }
}

void Scheduler::setModeChangePending(bool pending) {
    mLayerHistory.setModeChangePending(pending);
}

void Scheduler::setDefaultFrameRateCompatibility(Layer* layer) {
    mLayerHistory.setDefaultFrameRateCompatibility(layer,
                                                   mFeatures.test(Feature::kContentDetection));
}

void Scheduler::chooseRefreshRateForContent() {
    const auto selectorPtr = leaderSelectorPtr();
    if (!selectorPtr->canSwitch()) return;

    ATRACE_CALL();

    LayerHistory::Summary summary = mLayerHistory.summarize(*selectorPtr, systemTime());
    applyPolicy(&Policy::contentRequirements, std::move(summary));
}

void Scheduler::resetIdleTimer() {
    leaderSelectorPtr()->resetIdleTimer();
}

void Scheduler::onTouchHint() {
    if (mTouchTimer) {
        mTouchTimer->reset();
        leaderSelectorPtr()->resetKernelIdleTimer();
    }
}

void Scheduler::setDisplayPowerMode(hal::PowerMode powerMode) {
    {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.displayPowerMode = powerMode;
    }
    mVsyncSchedule->getController().setDisplayPowerMode(powerMode);

    if (mDisplayPowerTimer) {
        mDisplayPowerTimer->reset();
    }

    // Display Power event will boost the refresh rate to performance.
    // Clear Layer History to get fresh FPS detection
    mLayerHistory.clear();
}

void Scheduler::kernelIdleTimerCallback(TimerState state) {
    ATRACE_INT("ExpiredKernelIdleTimer", static_cast<int>(state));

    // TODO(145561154): cleanup the kernel idle timer implementation and the refresh rate
    // magic number
    const Fps refreshRate = leaderSelectorPtr()->getActiveMode().modePtr->getFps();

    constexpr Fps FPS_THRESHOLD_FOR_KERNEL_TIMER = 65_Hz;
    using namespace fps_approx_ops;

    if (state == TimerState::Reset && refreshRate > FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // If we're not in performance mode then the kernel timer shouldn't do
        // anything, as the refresh rate during DPU power collapse will be the
        // same.
        resyncToHardwareVsync(true /* makeAvailable */, refreshRate);
    } else if (state == TimerState::Expired && refreshRate <= FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // Disable HW VSYNC if the timer expired, as we don't need it enabled if
        // we're not pushing frames, and if we're in PERFORMANCE mode then we'll
        // need to update the VsyncController model anyway.
        disableHardwareVsync(false /* makeUnavailable */);
    }

    mSchedulerCallback.kernelTimerChanged(state == TimerState::Expired);
}

void Scheduler::idleTimerCallback(TimerState state) {
    applyPolicy(&Policy::idleTimer, state);
    ATRACE_INT("ExpiredIdleTimer", static_cast<int>(state));
}

void Scheduler::touchTimerCallback(TimerState state) {
    const TouchState touch = state == TimerState::Reset ? TouchState::Active : TouchState::Inactive;
    // Touch event will boost the refresh rate to performance.
    // Clear layer history to get fresh FPS detection.
    // NOTE: Instead of checking all the layers, we should be checking the layer
    // that is currently on top. b/142507166 will give us this capability.
    if (applyPolicy(&Policy::touch, touch).touch) {
        mLayerHistory.clear();
    }
    ATRACE_INT("TouchState", static_cast<int>(touch));
}

void Scheduler::displayPowerTimerCallback(TimerState state) {
    applyPolicy(&Policy::displayPowerTimer, state);
    ATRACE_INT("ExpiredDisplayPowerTimer", static_cast<int>(state));
}

void Scheduler::dump(utils::Dumper& dumper) const {
    using namespace std::string_view_literals;

    {
        utils::Dumper::Section section(dumper, "Features"sv);

        for (Feature feature : ftl::enum_range<Feature>()) {
            if (const auto flagOpt = ftl::flag_name(feature)) {
                dumper.dump(flagOpt->substr(1), mFeatures.test(feature));
            }
        }
    }
    {
        utils::Dumper::Section section(dumper, "Policy"sv);
        {
            std::scoped_lock lock(mDisplayLock);
            ftl::FakeGuard guard(kMainThreadContext);
            dumper.dump("leaderDisplayId"sv, mLeaderDisplayId);
        }
        dumper.dump("layerHistory"sv, mLayerHistory.dump());
        dumper.dump("touchTimer"sv, mTouchTimer.transform(&OneShotTimer::interval));
        dumper.dump("displayPowerTimer"sv, mDisplayPowerTimer.transform(&OneShotTimer::interval));
    }

    mFrameRateOverrideMappings.dump(dumper);
    dumper.eol();

    {
        utils::Dumper::Section section(dumper, "Hardware VSYNC"sv);

        std::lock_guard lock(mHWVsyncLock);
        dumper.dump("screenAcquired"sv, mScreenAcquired.load());
        dumper.dump("hwVsyncAvailable"sv, mHWVsyncAvailable);
        dumper.dump("hwVsyncEnabled"sv, mPrimaryHWVsyncEnabled);
    }
}

void Scheduler::dumpVsync(std::string& out) const {
    mVsyncSchedule->dump(out);
}

bool Scheduler::updateFrameRateOverrides(GlobalSignals consideredSignals, Fps displayRefreshRate) {
    if (consideredSignals.idle) return false;

    const auto frameRateOverrides =
            leaderSelectorPtr()->getFrameRateOverrides(mPolicy.contentRequirements,
                                                       displayRefreshRate, consideredSignals);

    // Note that RefreshRateSelector::supportsFrameRateOverrideByContent is checked when querying
    // the FrameRateOverrideMappings rather than here.
    return mFrameRateOverrideMappings.updateFrameRateOverridesByContent(frameRateOverrides);
}

void Scheduler::promoteLeaderDisplay(std::optional<PhysicalDisplayId> leaderIdOpt) {
    // TODO(b/241286431): Choose the leader display.
    mLeaderDisplayId = leaderIdOpt.value_or(mRefreshRateSelectors.begin()->first);
    ALOGI("Display %s is the leader", to_string(*mLeaderDisplayId).c_str());

    if (const auto leaderPtr = leaderSelectorPtrLocked()) {
        leaderPtr->setIdleTimerCallbacks(
                {.platform = {.onReset = [this] { idleTimerCallback(TimerState::Reset); },
                              .onExpired = [this] { idleTimerCallback(TimerState::Expired); }},
                 .kernel = {.onReset = [this] { kernelIdleTimerCallback(TimerState::Reset); },
                            .onExpired =
                                    [this] { kernelIdleTimerCallback(TimerState::Expired); }}});

        leaderPtr->startIdleTimer();
    }
}

void Scheduler::demoteLeaderDisplay() {
    // No need to lock for reads on kMainThreadContext.
    if (const auto leaderPtr = FTL_FAKE_GUARD(mDisplayLock, leaderSelectorPtrLocked())) {
        leaderPtr->stopIdleTimer();
        leaderPtr->clearIdleTimerCallbacks();
    }

    // Clear state that depends on the leader's RefreshRateSelector.
    std::scoped_lock lock(mPolicyLock);
    mPolicy = {};
}

template <typename S, typename T>
auto Scheduler::applyPolicy(S Policy::*statePtr, T&& newState) -> GlobalSignals {
    ATRACE_CALL();
    std::vector<display::DisplayModeRequest> modeRequests;
    GlobalSignals consideredSignals;

    bool refreshRateChanged = false;
    bool frameRateOverridesChanged;

    {
        std::scoped_lock lock(mPolicyLock);

        auto& currentState = mPolicy.*statePtr;
        if (currentState == newState) return {};
        currentState = std::forward<T>(newState);

        DisplayModeChoiceMap modeChoices;
        ftl::Optional<FrameRateMode> modeOpt;
        {
            std::scoped_lock lock(mDisplayLock);
            ftl::FakeGuard guard(kMainThreadContext);

            modeChoices = chooseDisplayModes();

            // TODO(b/240743786): The leader display's mode must change for any DisplayModeRequest
            // to go through. Fix this by tracking per-display Scheduler::Policy and timers.
            std::tie(modeOpt, consideredSignals) =
                    modeChoices.get(*mLeaderDisplayId)
                            .transform([](const DisplayModeChoice& choice) {
                                return std::make_pair(choice.mode, choice.consideredSignals);
                            })
                            .value();
        }

        modeRequests.reserve(modeChoices.size());
        for (auto& [id, choice] : modeChoices) {
            modeRequests.emplace_back(
                    display::DisplayModeRequest{.mode = std::move(choice.mode),
                                                .emitEvent = !choice.consideredSignals.idle});
        }

        frameRateOverridesChanged = updateFrameRateOverrides(consideredSignals, modeOpt->fps);

        if (mPolicy.modeOpt != modeOpt) {
            mPolicy.modeOpt = modeOpt;
            refreshRateChanged = true;
        } else {
            // We don't need to change the display mode, but we might need to send an event
            // about a mode change, since it was suppressed if previously considered idle.
            if (!consideredSignals.idle) {
                dispatchCachedReportedMode();
            }
        }
    }
    if (refreshRateChanged) {
        mSchedulerCallback.requestDisplayModes(std::move(modeRequests));
    }
    if (frameRateOverridesChanged) {
        mSchedulerCallback.triggerOnFrameRateOverridesChanged();
    }
    return consideredSignals;
}

auto Scheduler::chooseDisplayModes() const -> DisplayModeChoiceMap {
    ATRACE_CALL();

    using RankedRefreshRates = RefreshRateSelector::RankedFrameRates;
    display::PhysicalDisplayVector<RankedRefreshRates> perDisplayRanking;

    // Tallies the score of a refresh rate across `displayCount` displays.
    struct RefreshRateTally {
        explicit RefreshRateTally(float score) : score(score) {}

        float score;
        size_t displayCount = 1;
    };

    // Chosen to exceed a typical number of refresh rates across displays.
    constexpr size_t kStaticCapacity = 8;
    ftl::SmallMap<Fps, RefreshRateTally, kStaticCapacity, FpsApproxEqual> refreshRateTallies;

    const auto globalSignals = makeGlobalSignals();

    for (const auto& [id, selectorPtr] : mRefreshRateSelectors) {
        auto rankedFrameRates =
                selectorPtr->getRankedFrameRates(mPolicy.contentRequirements, globalSignals);

        for (const auto& [frameRateMode, score] : rankedFrameRates.ranking) {
            const auto [it, inserted] = refreshRateTallies.try_emplace(frameRateMode.fps, score);

            if (!inserted) {
                auto& tally = it->second;
                tally.score += score;
                tally.displayCount++;
            }
        }

        perDisplayRanking.push_back(std::move(rankedFrameRates));
    }

    auto maxScoreIt = refreshRateTallies.cbegin();

    // Find the first refresh rate common to all displays.
    while (maxScoreIt != refreshRateTallies.cend() &&
           maxScoreIt->second.displayCount != mRefreshRateSelectors.size()) {
        ++maxScoreIt;
    }

    if (maxScoreIt != refreshRateTallies.cend()) {
        // Choose the highest refresh rate common to all displays, if any.
        for (auto it = maxScoreIt + 1; it != refreshRateTallies.cend(); ++it) {
            const auto [fps, tally] = *it;

            if (tally.displayCount == mRefreshRateSelectors.size() &&
                tally.score > maxScoreIt->second.score) {
                maxScoreIt = it;
            }
        }
    }

    const std::optional<Fps> chosenFps = maxScoreIt != refreshRateTallies.cend()
            ? std::make_optional(maxScoreIt->first)
            : std::nullopt;

    DisplayModeChoiceMap modeChoices;

    using fps_approx_ops::operator==;

    for (auto& [ranking, signals] : perDisplayRanking) {
        if (!chosenFps) {
            const auto& [frameRateMode, _] = ranking.front();
            modeChoices.try_emplace(frameRateMode.modePtr->getPhysicalDisplayId(),
                                    DisplayModeChoice{frameRateMode, signals});
            continue;
        }

        for (auto& [frameRateMode, _] : ranking) {
            if (frameRateMode.fps == *chosenFps) {
                modeChoices.try_emplace(frameRateMode.modePtr->getPhysicalDisplayId(),
                                        DisplayModeChoice{frameRateMode, signals});
                break;
            }
        }
    }
    return modeChoices;
}

GlobalSignals Scheduler::makeGlobalSignals() const {
    const bool powerOnImminent = mDisplayPowerTimer &&
            (mPolicy.displayPowerMode != hal::PowerMode::ON ||
             mPolicy.displayPowerTimer == TimerState::Reset);

    return {.touch = mTouchTimer && mPolicy.touch == TouchState::Active,
            .idle = mPolicy.idleTimer == TimerState::Expired,
            .powerOnImminent = powerOnImminent};
}

FrameRateMode Scheduler::getPreferredDisplayMode() {
    std::lock_guard<std::mutex> lock(mPolicyLock);
    const auto frameRateMode =
            leaderSelectorPtr()
                    ->getRankedFrameRates(mPolicy.contentRequirements, makeGlobalSignals())
                    .ranking.front()
                    .frameRateMode;

    // Make sure the stored mode is up to date.
    mPolicy.modeOpt = frameRateMode;

    return frameRateMode;
}

void Scheduler::onNewVsyncPeriodChangeTimeline(const hal::VsyncPeriodChangeTimeline& timeline) {
    std::lock_guard<std::mutex> lock(mVsyncTimelineLock);
    mLastVsyncPeriodChangeTimeline = std::make_optional(timeline);

    const auto maxAppliedTime = systemTime() + MAX_VSYNC_APPLIED_TIME.count();
    if (timeline.newVsyncAppliedTimeNanos > maxAppliedTime) {
        mLastVsyncPeriodChangeTimeline->newVsyncAppliedTimeNanos = maxAppliedTime;
    }
}

bool Scheduler::onPostComposition(nsecs_t presentTime) {
    std::lock_guard<std::mutex> lock(mVsyncTimelineLock);
    if (mLastVsyncPeriodChangeTimeline && mLastVsyncPeriodChangeTimeline->refreshRequired) {
        if (presentTime < mLastVsyncPeriodChangeTimeline->refreshTimeNanos) {
            // We need to composite again as refreshTimeNanos is still in the future.
            return true;
        }

        mLastVsyncPeriodChangeTimeline->refreshRequired = false;
    }
    return false;
}

void Scheduler::onActiveDisplayAreaChanged(uint32_t displayArea) {
    mLayerHistory.setDisplayArea(displayArea);
}

void Scheduler::setGameModeRefreshRateForUid(FrameRateOverride frameRateOverride) {
    if (frameRateOverride.frameRateHz > 0.f && frameRateOverride.frameRateHz < 1.f) {
        return;
    }

    mFrameRateOverrideMappings.setGameModeRefreshRateForUid(frameRateOverride);
}

void Scheduler::setPreferredRefreshRateForUid(FrameRateOverride frameRateOverride) {
    if (frameRateOverride.frameRateHz > 0.f && frameRateOverride.frameRateHz < 1.f) {
        return;
    }

    mFrameRateOverrideMappings.setPreferredRefreshRateForUid(frameRateOverride);
}

} // namespace android::scheduler
