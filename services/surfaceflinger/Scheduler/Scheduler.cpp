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
#include <ftl/concat.h>
#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <ftl/small_map.h>
#include <gui/TraceUtils.h>
#include <gui/WindowInfo.h>
#include <system/window.h>
#include <ui/DisplayMap.h>
#include <utils/Timers.h>

#include <FrameTimeline/FrameTimeline.h>
#include <scheduler/interface/ICompositor.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>

#include "../Layer.h"
#include "EventThread.h"
#include "FrameRateOverrideMappings.h"
#include "FrontEnd/LayerHandle.h"
#include "OneShotTimer.h"
#include "SurfaceFlingerProperties.h"
#include "VSyncTracker.h"
#include "VsyncController.h"
#include "VsyncSchedule.h"

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
    demotePacesetterDisplay();
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

void Scheduler::setPacesetterDisplay(std::optional<PhysicalDisplayId> pacesetterIdOpt) {
    demotePacesetterDisplay();

    promotePacesetterDisplay(pacesetterIdOpt);
}

void Scheduler::registerDisplay(PhysicalDisplayId displayId, RefreshRateSelectorPtr selectorPtr) {
    auto schedulePtr = std::make_shared<VsyncSchedule>(displayId, mFeatures,
                                                       [this](PhysicalDisplayId id, bool enable) {
                                                           onHardwareVsyncRequest(id, enable);
                                                       });

    registerDisplayInternal(displayId, std::move(selectorPtr), std::move(schedulePtr));
}

void Scheduler::registerDisplayInternal(PhysicalDisplayId displayId,
                                        RefreshRateSelectorPtr selectorPtr,
                                        VsyncSchedulePtr schedulePtr) {
    demotePacesetterDisplay();

    auto [pacesetterVsyncSchedule, isNew] = [&]() FTL_FAKE_GUARD(kMainThreadContext) {
        std::scoped_lock lock(mDisplayLock);
        const bool isNew = mDisplays
                                   .emplace_or_replace(displayId, displayId, std::move(selectorPtr),
                                                       std::move(schedulePtr), mFeatures)
                                   .second;

        return std::make_pair(promotePacesetterDisplayLocked(), isNew);
    }();

    applyNewVsyncSchedule(std::move(pacesetterVsyncSchedule));

    // Disable hardware VSYNC if the registration is new, as opposed to a renewal.
    if (isNew) {
        onHardwareVsyncRequest(displayId, false);
    }
}

void Scheduler::unregisterDisplay(PhysicalDisplayId displayId) {
    demotePacesetterDisplay();

    std::shared_ptr<VsyncSchedule> pacesetterVsyncSchedule;
    {
        std::scoped_lock lock(mDisplayLock);
        mDisplays.erase(displayId);

        // Do not allow removing the final display. Code in the scheduler expects
        // there to be at least one display. (This may be relaxed in the future with
        // headless virtual display.)
        LOG_ALWAYS_FATAL_IF(mDisplays.empty(), "Cannot unregister all displays!");

        pacesetterVsyncSchedule = promotePacesetterDisplayLocked();
    }
    applyNewVsyncSchedule(std::move(pacesetterVsyncSchedule));
}

void Scheduler::run() {
    while (true) {
        waitMessage();
    }
}

void Scheduler::onFrameSignal(ICompositor& compositor, VsyncId vsyncId,
                              TimePoint expectedVsyncTime) {
    const FrameTargeter::BeginFrameArgs beginFrameArgs =
            {.frameBeginTime = SchedulerClock::now(),
             .vsyncId = vsyncId,
             // TODO(b/255601557): Calculate per display.
             .expectedVsyncTime = expectedVsyncTime,
             .sfWorkDuration = mVsyncModulator->getVsyncConfig().sfWorkDuration};

    LOG_ALWAYS_FATAL_IF(!mPacesetterDisplayId);
    const auto pacesetterId = *mPacesetterDisplayId;
    const auto pacesetterOpt = mDisplays.get(pacesetterId);

    FrameTargeter& pacesetterTargeter = *pacesetterOpt->get().targeterPtr;
    pacesetterTargeter.beginFrame(beginFrameArgs, *pacesetterOpt->get().schedulePtr);

    FrameTargets targets;
    targets.try_emplace(pacesetterId, &pacesetterTargeter.target());

    for (const auto& [id, display] : mDisplays) {
        if (id == pacesetterId) continue;

        const FrameTargeter& targeter = *display.targeterPtr;
        targets.try_emplace(id, &targeter.target());
    }

    if (!compositor.commit(pacesetterId, targets)) return;

    // TODO(b/256196556): Choose the frontrunner display.
    FrameTargeters targeters;
    targeters.try_emplace(pacesetterId, &pacesetterTargeter);

    for (auto& [id, display] : mDisplays) {
        if (id == pacesetterId) continue;

        FrameTargeter& targeter = *display.targeterPtr;
        targeter.beginFrame(beginFrameArgs, *display.schedulePtr);

        targeters.try_emplace(id, &targeter);
    }

    const auto resultsPerDisplay = compositor.composite(pacesetterId, targeters);
    compositor.sample();

    for (const auto& [id, targeter] : targeters) {
        const auto resultOpt = resultsPerDisplay.get(id);
        LOG_ALWAYS_FATAL_IF(!resultOpt);
        targeter->endFrame(*resultOpt);
    }
}

std::optional<Fps> Scheduler::getFrameRateOverride(uid_t uid) const {
    const bool supportsFrameRateOverrideByContent =
            pacesetterSelectorPtr()->supportsAppFrameRateOverrideByContent();
    return mFrameRateOverrideMappings
            .getFrameRateOverrideForUid(uid, supportsFrameRateOverrideByContent);
}

bool Scheduler::isVsyncValid(TimePoint expectedVsyncTime, uid_t uid) const {
    const auto frameRate = getFrameRateOverride(uid);
    if (!frameRate.has_value()) {
        return true;
    }

    ATRACE_FORMAT("%s uid: %d frameRate: %s", __func__, uid, to_string(*frameRate).c_str());
    return getVsyncSchedule()->getTracker().isVSyncInPhase(expectedVsyncTime.ns(), *frameRate);
}

bool Scheduler::isVsyncInPhase(TimePoint expectedVsyncTime, Fps frameRate) const {
    return getVsyncSchedule()->getTracker().isVSyncInPhase(expectedVsyncTime.ns(), frameRate);
}

impl::EventThread::ThrottleVsyncCallback Scheduler::makeThrottleVsyncCallback() const {
    return [this](nsecs_t expectedVsyncTime, uid_t uid) {
        return !isVsyncValid(TimePoint::fromNs(expectedVsyncTime), uid);
    };
}

impl::EventThread::GetVsyncPeriodFunction Scheduler::makeGetVsyncPeriodFunction() const {
    return [this](uid_t uid) {
        const auto [refreshRate, period] = [this] {
            std::scoped_lock lock(mDisplayLock);
            const auto pacesetterOpt = pacesetterDisplayLocked();
            LOG_ALWAYS_FATAL_IF(!pacesetterOpt);
            const Display& pacesetter = *pacesetterOpt;
            return std::make_pair(pacesetter.selectorPtr->getActiveMode().fps,
                                  pacesetter.schedulePtr->period());
        }();

        const Period currentPeriod = period != Period::zero() ? period : refreshRate.getPeriod();

        const auto frameRate = getFrameRateOverride(uid);
        if (!frameRate.has_value()) {
            return currentPeriod.ns();
        }

        const auto divisor = RefreshRateSelector::getFrameRateDivisor(refreshRate, *frameRate);
        if (divisor <= 1) {
            return currentPeriod.ns();
        }
        return currentPeriod.ns() * divisor;
    };
}

ConnectionHandle Scheduler::createEventThread(Cycle cycle,
                                              frametimeline::TokenManager* tokenManager,
                                              std::chrono::nanoseconds workDuration,
                                              std::chrono::nanoseconds readyDuration) {
    auto eventThread = std::make_unique<impl::EventThread>(cycle == Cycle::Render ? "app" : "appSf",
                                                           getVsyncSchedule(), tokenManager,
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
        EventThread* eventThread, EventRegistrationFlags eventRegistration,
        const sp<IBinder>& layerHandle) {
    int32_t layerId = static_cast<int32_t>(LayerHandle::getLayerId(layerHandle));
    auto connection = eventThread->createEventConnection([&] { resync(); }, eventRegistration);
    mLayerHistory.attachChoreographer(layerId, connection);
    return connection;
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        ConnectionHandle handle, EventRegistrationFlags eventRegistration,
        const sp<IBinder>& layerHandle) {
    std::lock_guard<std::mutex> lock(mConnectionsLock);
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return createConnectionInternal(mConnections[handle].thread.get(), eventRegistration,
                                    layerHandle);
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

void Scheduler::enableSyntheticVsync(bool enable) {
    // TODO(b/241285945): Remove connection handles.
    const ConnectionHandle handle = mAppConnectionHandle;
    android::EventThread* thread;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        RETURN_IF_INVALID_HANDLE(handle);
        thread = mConnections[handle].thread.get();
    }
    thread->enableSyntheticVsync(enable);
}

void Scheduler::onFrameRateOverridesChanged(ConnectionHandle handle, PhysicalDisplayId displayId) {
    const bool supportsFrameRateOverrideByContent =
            pacesetterSelectorPtr()->supportsAppFrameRateOverrideByContent();

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
    if (pacesetterSelectorPtr()->getActiveMode() != mPolicy.modeOpt) {
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

void Scheduler::enableHardwareVsync(PhysicalDisplayId id) {
    auto schedule = getVsyncSchedule(id);
    LOG_ALWAYS_FATAL_IF(!schedule);
    schedule->enableHardwareVsync();
}

void Scheduler::disableHardwareVsync(PhysicalDisplayId id, bool disallow) {
    auto schedule = getVsyncSchedule(id);
    LOG_ALWAYS_FATAL_IF(!schedule);
    schedule->disableHardwareVsync(disallow);
}

void Scheduler::resyncAllToHardwareVsync(bool allowToEnable) {
    ATRACE_CALL();
    std::scoped_lock lock(mDisplayLock);
    ftl::FakeGuard guard(kMainThreadContext);

    for (const auto& [id, _] : mDisplays) {
        resyncToHardwareVsyncLocked(id, allowToEnable);
    }
}

void Scheduler::resyncToHardwareVsyncLocked(PhysicalDisplayId id, bool allowToEnable,
                                            std::optional<Fps> refreshRate) {
    const auto displayOpt = mDisplays.get(id);
    if (!displayOpt) {
        ALOGW("%s: Invalid display %s!", __func__, to_string(id).c_str());
        return;
    }
    const Display& display = *displayOpt;

    if (display.schedulePtr->isHardwareVsyncAllowed(allowToEnable)) {
        if (!refreshRate) {
            refreshRate = display.selectorPtr->getActiveMode().modePtr->getFps();
        }
        if (refreshRate->isValid()) {
            constexpr bool kForce = false;
            display.schedulePtr->startPeriodTransition(refreshRate->getPeriod(), kForce);
        }
    }
}

void Scheduler::onHardwareVsyncRequest(PhysicalDisplayId id, bool enabled) {
    static const auto& whence = __func__;
    ATRACE_NAME(ftl::Concat(whence, ' ', id.value, ' ', enabled).c_str());

    // On main thread to serialize reads/writes of pending hardware VSYNC state.
    static_cast<void>(
            schedule([=]() FTL_FAKE_GUARD(mDisplayLock) FTL_FAKE_GUARD(kMainThreadContext) {
                ATRACE_NAME(ftl::Concat(whence, ' ', id.value, ' ', enabled).c_str());

                if (const auto displayOpt = mDisplays.get(id)) {
                    auto& display = displayOpt->get();
                    display.schedulePtr->setPendingHardwareVsyncState(enabled);

                    if (display.powerMode != hal::PowerMode::OFF) {
                        mSchedulerCallback.requestHardwareVsync(id, enabled);
                    }
                }
            }));
}

void Scheduler::setRenderRate(PhysicalDisplayId id, Fps renderFrameRate) {
    std::scoped_lock lock(mDisplayLock);
    ftl::FakeGuard guard(kMainThreadContext);

    const auto displayOpt = mDisplays.get(id);
    if (!displayOpt) {
        ALOGW("%s: Invalid display %s!", __func__, to_string(id).c_str());
        return;
    }
    const Display& display = *displayOpt;
    const auto mode = display.selectorPtr->getActiveMode();

    using fps_approx_ops::operator!=;
    LOG_ALWAYS_FATAL_IF(renderFrameRate != mode.fps,
                        "Mismatch in render frame rates. Selector: %s, Scheduler: %s, Display: "
                        "%" PRIu64,
                        to_string(mode.fps).c_str(), to_string(renderFrameRate).c_str(), id.value);

    ALOGV("%s %s (%s)", __func__, to_string(mode.fps).c_str(),
          to_string(mode.modePtr->getFps()).c_str());

    display.schedulePtr->getTracker().setRenderRate(renderFrameRate);
}

void Scheduler::resync() {
    static constexpr nsecs_t kIgnoreDelay = ms2ns(750);

    const nsecs_t now = systemTime();
    const nsecs_t last = mLastResyncTime.exchange(now);

    if (now - last > kIgnoreDelay) {
        resyncAllToHardwareVsync(false /* allowToEnable */);
    }
}

bool Scheduler::addResyncSample(PhysicalDisplayId id, nsecs_t timestamp,
                                std::optional<nsecs_t> hwcVsyncPeriodIn) {
    const auto hwcVsyncPeriod = ftl::Optional(hwcVsyncPeriodIn).transform([](nsecs_t nanos) {
        return Period::fromNs(nanos);
    });
    auto schedule = getVsyncSchedule(id);
    if (!schedule) {
        ALOGW("%s: Invalid display %s!", __func__, to_string(id).c_str());
        return false;
    }
    return schedule->addResyncSample(TimePoint::fromNs(timestamp), hwcVsyncPeriod);
}

void Scheduler::addPresentFence(PhysicalDisplayId id, std::shared_ptr<FenceTime> fence) {
    const auto scheduleOpt =
            (ftl::FakeGuard(mDisplayLock), mDisplays.get(id)).and_then([](const Display& display) {
                return display.powerMode == hal::PowerMode::OFF
                        ? std::nullopt
                        : std::make_optional(display.schedulePtr);
            });

    if (!scheduleOpt) return;
    const auto& schedule = scheduleOpt->get();

    const bool needMoreSignals = schedule->getController().addPresentFence(std::move(fence));
    if (needMoreSignals) {
        schedule->enableHardwareVsync();
    } else {
        constexpr bool kDisallow = false;
        schedule->disableHardwareVsync(kDisallow);
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

void Scheduler::recordLayerHistory(int32_t id, const LayerProps& layerProps, nsecs_t presentTime,
                                   LayerHistory::LayerUpdateType updateType) {
    if (pacesetterSelectorPtr()->canSwitch()) {
        mLayerHistory.record(id, layerProps, presentTime, systemTime(), updateType);
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
    const auto selectorPtr = pacesetterSelectorPtr();
    if (!selectorPtr->canSwitch()) return;

    ATRACE_CALL();

    LayerHistory::Summary summary = mLayerHistory.summarize(*selectorPtr, systemTime());
    applyPolicy(&Policy::contentRequirements, std::move(summary));
}

void Scheduler::resetIdleTimer() {
    pacesetterSelectorPtr()->resetIdleTimer();
}

void Scheduler::onTouchHint() {
    if (mTouchTimer) {
        mTouchTimer->reset();
        pacesetterSelectorPtr()->resetKernelIdleTimer();
    }
}

void Scheduler::setDisplayPowerMode(PhysicalDisplayId id, hal::PowerMode powerMode) {
    const bool isPacesetter = [this, id]() REQUIRES(kMainThreadContext) {
        ftl::FakeGuard guard(mDisplayLock);
        return id == mPacesetterDisplayId;
    }();
    if (isPacesetter) {
        // TODO (b/255657128): This needs to be handled per display.
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.displayPowerMode = powerMode;
    }
    {
        std::scoped_lock lock(mDisplayLock);

        const auto displayOpt = mDisplays.get(id);
        LOG_ALWAYS_FATAL_IF(!displayOpt);
        auto& display = displayOpt->get();

        display.powerMode = powerMode;
        display.schedulePtr->getController().setDisplayPowerMode(powerMode);
    }
    if (!isPacesetter) return;

    if (mDisplayPowerTimer) {
        mDisplayPowerTimer->reset();
    }

    // Display Power event will boost the refresh rate to performance.
    // Clear Layer History to get fresh FPS detection
    mLayerHistory.clear();
}

auto Scheduler::getVsyncSchedule(std::optional<PhysicalDisplayId> idOpt) const
        -> ConstVsyncSchedulePtr {
    std::scoped_lock lock(mDisplayLock);
    return getVsyncScheduleLocked(idOpt);
}

auto Scheduler::getVsyncScheduleLocked(std::optional<PhysicalDisplayId> idOpt) const
        -> ConstVsyncSchedulePtr {
    ftl::FakeGuard guard(kMainThreadContext);

    if (!idOpt) {
        LOG_ALWAYS_FATAL_IF(!mPacesetterDisplayId, "Missing a pacesetter!");
        idOpt = mPacesetterDisplayId;
    }

    const auto displayOpt = mDisplays.get(*idOpt);
    if (!displayOpt) {
        return nullptr;
    }
    return displayOpt->get().schedulePtr;
}

void Scheduler::kernelIdleTimerCallback(TimerState state) {
    ATRACE_INT("ExpiredKernelIdleTimer", static_cast<int>(state));

    // TODO(145561154): cleanup the kernel idle timer implementation and the refresh rate
    // magic number
    const Fps refreshRate = pacesetterSelectorPtr()->getActiveMode().modePtr->getFps();

    constexpr Fps FPS_THRESHOLD_FOR_KERNEL_TIMER = 65_Hz;
    using namespace fps_approx_ops;

    if (state == TimerState::Reset && refreshRate > FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // If we're not in performance mode then the kernel timer shouldn't do
        // anything, as the refresh rate during DPU power collapse will be the
        // same.
        resyncAllToHardwareVsync(true /* allowToEnable */);
    } else if (state == TimerState::Expired && refreshRate <= FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // Disable HW VSYNC if the timer expired, as we don't need it enabled if
        // we're not pushing frames, and if we're in PERFORMANCE mode then we'll
        // need to update the VsyncController model anyway.
        std::scoped_lock lock(mDisplayLock);
        ftl::FakeGuard guard(kMainThreadContext);
        for (const auto& [_, display] : mDisplays) {
            constexpr bool kDisallow = false;
            display.schedulePtr->disableHardwareVsync(kDisallow);
        }
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
            dumper.dump("pacesetterDisplayId"sv, mPacesetterDisplayId);
        }
        dumper.dump("layerHistory"sv, mLayerHistory.dump());
        dumper.dump("touchTimer"sv, mTouchTimer.transform(&OneShotTimer::interval));
        dumper.dump("displayPowerTimer"sv, mDisplayPowerTimer.transform(&OneShotTimer::interval));
    }

    mFrameRateOverrideMappings.dump(dumper);
    dumper.eol();

    {
        utils::Dumper::Section section(dumper, "Frame Targeting"sv);

        std::scoped_lock lock(mDisplayLock);
        ftl::FakeGuard guard(kMainThreadContext);

        for (const auto& [id, display] : mDisplays) {
            utils::Dumper::Section
                    section(dumper,
                            id == mPacesetterDisplayId
                                    ? ftl::Concat("Pacesetter Display ", id.value).c_str()
                                    : ftl::Concat("Follower Display ", id.value).c_str());

            display.targeterPtr->dump(dumper);
            dumper.eol();
        }
    }
}

void Scheduler::dumpVsync(std::string& out) const {
    std::scoped_lock lock(mDisplayLock);
    ftl::FakeGuard guard(kMainThreadContext);
    if (mPacesetterDisplayId) {
        base::StringAppendF(&out, "VsyncSchedule for pacesetter %s:\n",
                            to_string(*mPacesetterDisplayId).c_str());
        getVsyncScheduleLocked()->dump(out);
    }
    for (auto& [id, display] : mDisplays) {
        if (id == mPacesetterDisplayId) {
            continue;
        }
        base::StringAppendF(&out, "VsyncSchedule for follower %s:\n", to_string(id).c_str());
        display.schedulePtr->dump(out);
    }
}

bool Scheduler::updateFrameRateOverrides(GlobalSignals consideredSignals, Fps displayRefreshRate) {
    if (consideredSignals.idle) return false;

    const auto frameRateOverrides =
            pacesetterSelectorPtr()->getFrameRateOverrides(mPolicy.contentRequirements,
                                                           displayRefreshRate, consideredSignals);

    // Note that RefreshRateSelector::supportsFrameRateOverrideByContent is checked when querying
    // the FrameRateOverrideMappings rather than here.
    return mFrameRateOverrideMappings.updateFrameRateOverridesByContent(frameRateOverrides);
}

void Scheduler::promotePacesetterDisplay(std::optional<PhysicalDisplayId> pacesetterIdOpt) {
    std::shared_ptr<VsyncSchedule> pacesetterVsyncSchedule;

    {
        std::scoped_lock lock(mDisplayLock);
        pacesetterVsyncSchedule = promotePacesetterDisplayLocked(pacesetterIdOpt);
    }

    applyNewVsyncSchedule(std::move(pacesetterVsyncSchedule));
}

std::shared_ptr<VsyncSchedule> Scheduler::promotePacesetterDisplayLocked(
        std::optional<PhysicalDisplayId> pacesetterIdOpt) {
    // TODO(b/241286431): Choose the pacesetter display.
    mPacesetterDisplayId = pacesetterIdOpt.value_or(mDisplays.begin()->first);
    ALOGI("Display %s is the pacesetter", to_string(*mPacesetterDisplayId).c_str());

    std::shared_ptr<VsyncSchedule> newVsyncSchedulePtr;
    if (const auto pacesetterOpt = pacesetterDisplayLocked()) {
        const Display& pacesetter = *pacesetterOpt;

        pacesetter.selectorPtr->setIdleTimerCallbacks(
                {.platform = {.onReset = [this] { idleTimerCallback(TimerState::Reset); },
                              .onExpired = [this] { idleTimerCallback(TimerState::Expired); }},
                 .kernel = {.onReset = [this] { kernelIdleTimerCallback(TimerState::Reset); },
                            .onExpired =
                                    [this] { kernelIdleTimerCallback(TimerState::Expired); }}});

        pacesetter.selectorPtr->startIdleTimer();

        newVsyncSchedulePtr = pacesetter.schedulePtr;

        const Fps refreshRate = pacesetter.selectorPtr->getActiveMode().modePtr->getFps();
        constexpr bool kForce = true;
        newVsyncSchedulePtr->startPeriodTransition(refreshRate.getPeriod(), kForce);
    }
    return newVsyncSchedulePtr;
}

void Scheduler::applyNewVsyncSchedule(std::shared_ptr<VsyncSchedule> vsyncSchedule) {
    onNewVsyncSchedule(vsyncSchedule->getDispatch());
    std::vector<android::EventThread*> threads;
    {
        std::lock_guard<std::mutex> lock(mConnectionsLock);
        threads.reserve(mConnections.size());
        for (auto& [_, connection] : mConnections) {
            threads.push_back(connection.thread.get());
        }
    }
    for (auto* thread : threads) {
        thread->onNewVsyncSchedule(vsyncSchedule);
    }
}

void Scheduler::demotePacesetterDisplay() {
    // No need to lock for reads on kMainThreadContext.
    if (const auto pacesetterPtr = FTL_FAKE_GUARD(mDisplayLock, pacesetterSelectorPtrLocked())) {
        pacesetterPtr->stopIdleTimer();
        pacesetterPtr->clearIdleTimerCallbacks();
    }

    // Clear state that depends on the pacesetter's RefreshRateSelector.
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

            // TODO(b/240743786): The pacesetter display's mode must change for any
            // DisplayModeRequest to go through. Fix this by tracking per-display Scheduler::Policy
            // and timers.
            std::tie(modeOpt, consideredSignals) =
                    modeChoices.get(*mPacesetterDisplayId)
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
    ui::PhysicalDisplayVector<RankedRefreshRates> perDisplayRanking;
    const auto globalSignals = makeGlobalSignals();
    Fps pacesetterFps;

    for (const auto& [id, display] : mDisplays) {
        auto rankedFrameRates =
                display.selectorPtr->getRankedFrameRates(mPolicy.contentRequirements,
                                                         globalSignals);
        if (id == *mPacesetterDisplayId) {
            pacesetterFps = rankedFrameRates.ranking.front().frameRateMode.fps;
        }
        perDisplayRanking.push_back(std::move(rankedFrameRates));
    }

    DisplayModeChoiceMap modeChoices;
    using fps_approx_ops::operator==;

    for (auto& [rankings, signals] : perDisplayRanking) {
        const auto chosenFrameRateMode =
                ftl::find_if(rankings,
                             [&](const auto& ranking) {
                                 return ranking.frameRateMode.fps == pacesetterFps;
                             })
                        .transform([](const auto& scoredFrameRate) {
                            return scoredFrameRate.get().frameRateMode;
                        })
                        .value_or(rankings.front().frameRateMode);

        modeChoices.try_emplace(chosenFrameRateMode.modePtr->getPhysicalDisplayId(),
                                DisplayModeChoice{chosenFrameRateMode, signals});
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
            pacesetterSelectorPtr()
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

void Scheduler::updateSmallAreaDetection(
        std::vector<std::pair<uid_t, float>>& uidThresholdMappings) {
    mSmallAreaDetectionAllowMappings.update(uidThresholdMappings);
}

void Scheduler::setSmallAreaDetectionThreshold(uid_t uid, float threshold) {
    mSmallAreaDetectionAllowMappings.setThesholdForUid(uid, threshold);
}

bool Scheduler::isSmallDirtyArea(uid_t uid, uint32_t dirtyArea) {
    std::optional<float> oThreshold = mSmallAreaDetectionAllowMappings.getThresholdForUid(uid);
    if (oThreshold) return mLayerHistory.isSmallDirtyArea(dirtyArea, oThreshold.value());

    return false;
}

} // namespace android::scheduler
