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

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"
#include <ui/GraphicTypes.h>
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

#include <ftl/fake_guard.h>
#include <ftl/optional.h>
#include <scheduler/Features.h>
#include <scheduler/Time.h>
#include <scheduler/VsyncConfig.h>
#include <ui/DisplayId.h>

#include "Display/DisplayMap.h"
#include "Display/DisplayModeRequest.h"
#include "EventThread.h"
#include "FrameRateOverrideMappings.h"
#include "ISchedulerCallback.h"
#include "LayerHistory.h"
#include "MessageQueue.h"
#include "OneShotTimer.h"
#include "RefreshRateSelector.h"
#include "Utils/Dumper.h"
#include "VsyncModulator.h"
#include "VsyncSchedule.h"

namespace android::scheduler {

// Opaque handle to scheduler connection.
struct ConnectionHandle {
    using Id = std::uintptr_t;
    static constexpr Id INVALID_ID = static_cast<Id>(-1);

    Id id = INVALID_ID;

    explicit operator bool() const { return id != INVALID_ID; }
};

inline bool operator==(ConnectionHandle lhs, ConnectionHandle rhs) {
    return lhs.id == rhs.id;
}

} // namespace android::scheduler

namespace std {

template <>
struct hash<android::scheduler::ConnectionHandle> {
    size_t operator()(android::scheduler::ConnectionHandle handle) const {
        return hash<android::scheduler::ConnectionHandle::Id>()(handle.id);
    }
};

} // namespace std

namespace android {

class FenceTime;

namespace frametimeline {
class TokenManager;
} // namespace frametimeline

namespace scheduler {

using GlobalSignals = RefreshRateSelector::GlobalSignals;

class Scheduler : android::impl::MessageQueue {
    using Impl = android::impl::MessageQueue;

public:
    Scheduler(ICompositor&, ISchedulerCallback&, FeatureFlags, sp<VsyncModulator>);
    virtual ~Scheduler();

    void startTimers();

    // TODO(b/241285191): Remove this API by promoting pacesetter in onScreen{Acquired,Released}.
    void setPacesetterDisplay(std::optional<PhysicalDisplayId>) REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);

    using RefreshRateSelectorPtr = std::shared_ptr<RefreshRateSelector>;

    void registerDisplay(PhysicalDisplayId, RefreshRateSelectorPtr) REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);
    void unregisterDisplay(PhysicalDisplayId) REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

    void run();

    using Impl::initVsync;

    using Impl::getScheduledFrameTime;
    using Impl::setDuration;

    using Impl::scheduleConfigure;
    using Impl::scheduleFrame;

    // Schedule an asynchronous or synchronous task on the main thread.
    template <typename F, typename T = std::invoke_result_t<F>>
    [[nodiscard]] std::future<T> schedule(F&& f) {
        auto [task, future] = makeTask(std::move(f));
        postMessage(std::move(task));
        return std::move(future);
    }

    template <typename F, typename T = std::invoke_result_t<F>>
    [[nodiscard]] std::future<T> scheduleDelayed(F&& f, nsecs_t uptimeDelay) {
        auto [task, future] = makeTask(std::move(f));
        postMessageDelayed(std::move(task), uptimeDelay);
        return std::move(future);
    }

    enum class Cycle {
        Render,       // Surface rendering.
        LastComposite // Ahead of display compositing by one refresh period.
    };

    ConnectionHandle createEventThread(Cycle, frametimeline::TokenManager*,
                                       std::chrono::nanoseconds workDuration,
                                       std::chrono::nanoseconds readyDuration);

    sp<IDisplayEventConnection> createDisplayEventConnection(
            ConnectionHandle, EventRegistrationFlags eventRegistration = {},
            const sp<IBinder>& layerHandle = nullptr);

    sp<EventThreadConnection> getEventConnection(ConnectionHandle);

    void onHotplugReceived(ConnectionHandle, PhysicalDisplayId, bool connected);
    void onPrimaryDisplayModeChanged(ConnectionHandle, const FrameRateMode&) EXCLUDES(mPolicyLock);
    void onNonPrimaryDisplayModeChanged(ConnectionHandle, const FrameRateMode&);

    void enableSyntheticVsync(bool = true) REQUIRES(kMainThreadContext);

    void onFrameRateOverridesChanged(ConnectionHandle, PhysicalDisplayId)
            EXCLUDES(mConnectionsLock);

    // Modifies work duration in the event thread.
    void setDuration(ConnectionHandle, std::chrono::nanoseconds workDuration,
                     std::chrono::nanoseconds readyDuration);

    VsyncModulator& vsyncModulator() { return *mVsyncModulator; }

    // In some cases, we should only modulate for the pacesetter display. In those
    // cases, the caller should pass in the relevant display, and the method
    // will no-op if it's not the pacesetter. Other cases are not specific to a
    // display.
    template <typename... Args,
              typename Handler = std::optional<VsyncConfig> (VsyncModulator::*)(Args...)>
    void modulateVsync(std::optional<PhysicalDisplayId> id, Handler handler, Args... args) {
        if (id) {
            std::scoped_lock lock(mDisplayLock);
            ftl::FakeGuard guard(kMainThreadContext);
            if (id != mPacesetterDisplayId) {
                return;
            }
        }

        if (const auto config = (*mVsyncModulator.*handler)(args...)) {
            setVsyncConfig(*config, getPacesetterVsyncPeriod());
        }
    }

    void setVsyncConfigSet(const VsyncConfigSet&, Period vsyncPeriod);

    // Sets the render rate for the scheduler to run at.
    void setRenderRate(PhysicalDisplayId, Fps);

    void enableHardwareVsync(PhysicalDisplayId);
    void disableHardwareVsync(PhysicalDisplayId, bool disallow);

    // Resyncs the scheduler to hardware vsync.
    // If allowToEnable is true, then hardware vsync will be turned on.
    // Otherwise, if hardware vsync is not already enabled then this method will
    // no-op.
    // If refreshRate is nullopt, use the existing refresh rate of the display.
    void resyncToHardwareVsync(PhysicalDisplayId id, bool allowToEnable,
                               std::optional<Fps> refreshRate = std::nullopt)
            EXCLUDES(mDisplayLock) {
        std::scoped_lock lock(mDisplayLock);
        ftl::FakeGuard guard(kMainThreadContext);
        resyncToHardwareVsyncLocked(id, allowToEnable, refreshRate);
    }
    void resync() EXCLUDES(mDisplayLock);
    void forceNextResync() { mLastResyncTime = 0; }

    // Passes a vsync sample to VsyncController. Returns true if
    // VsyncController detected that the vsync period changed and false
    // otherwise.
    bool addResyncSample(PhysicalDisplayId, nsecs_t timestamp,
                         std::optional<nsecs_t> hwcVsyncPeriod);
    void addPresentFence(PhysicalDisplayId, std::shared_ptr<FenceTime>) EXCLUDES(mDisplayLock);

    // Layers are registered on creation, and unregistered when the weak reference expires.
    void registerLayer(Layer*);
    void recordLayerHistory(int32_t id, const LayerProps& layerProps, nsecs_t presentTime,
                            LayerHistory::LayerUpdateType) EXCLUDES(mDisplayLock);
    void setModeChangePending(bool pending);
    void setDefaultFrameRateCompatibility(Layer*);
    void deregisterLayer(Layer*);

    // Detects content using layer history, and selects a matching refresh rate.
    void chooseRefreshRateForContent() EXCLUDES(mDisplayLock);

    void resetIdleTimer();

    // Indicates that touch interaction is taking place.
    void onTouchHint();

    void setDisplayPowerMode(PhysicalDisplayId, hal::PowerMode powerMode)
            REQUIRES(kMainThreadContext);

    std::shared_ptr<const VsyncSchedule> getVsyncSchedule(
            std::optional<PhysicalDisplayId> idOpt = std::nullopt) const EXCLUDES(mDisplayLock);
    std::shared_ptr<VsyncSchedule> getVsyncSchedule(
            std::optional<PhysicalDisplayId> idOpt = std::nullopt) EXCLUDES(mDisplayLock) {
        return std::const_pointer_cast<VsyncSchedule>(
                static_cast<const Scheduler*>(this)->getVsyncSchedule(idOpt));
    }

    // Returns true if a given vsync timestamp is considered valid vsync
    // for a given uid
    bool isVsyncValid(TimePoint expectedVsyncTimestamp, uid_t uid) const;

    bool isVsyncInPhase(TimePoint expectedVsyncTime, Fps frameRate) const;

    void dump(utils::Dumper&) const;
    void dump(ConnectionHandle, std::string&) const;
    void dumpVsync(std::string&) const EXCLUDES(mDisplayLock);

    // Returns the preferred refresh rate and frame rate for the pacesetter display.
    FrameRateMode getPreferredDisplayMode();

    // Notifies the scheduler about a refresh rate timeline change.
    void onNewVsyncPeriodChangeTimeline(const hal::VsyncPeriodChangeTimeline& timeline);

    // Notifies the scheduler post composition. Returns if recomposite is needed.
    bool onPostComposition(nsecs_t presentTime);

    // Notifies the scheduler when the display size has changed. Called from SF's main thread
    void onActiveDisplayAreaChanged(uint32_t displayArea);

    size_t getEventThreadConnectionCount(ConnectionHandle handle);

    // Stores the preferred refresh rate that an app should run at.
    // FrameRateOverride.refreshRateHz == 0 means no preference.
    void setPreferredRefreshRateForUid(FrameRateOverride);

    void setGameModeRefreshRateForUid(FrameRateOverride);

    // Retrieves the overridden refresh rate for a given uid.
    std::optional<Fps> getFrameRateOverride(uid_t) const EXCLUDES(mDisplayLock);

    Period getPacesetterVsyncPeriod() const EXCLUDES(mDisplayLock) {
        return pacesetterSelectorPtr()->getActiveMode().fps.getPeriod();
    }

    Fps getPacesetterRefreshRate() const EXCLUDES(mDisplayLock) {
        return pacesetterSelectorPtr()->getActiveMode().fps;
    }

    // Returns the framerate of the layer with the given sequence ID
    float getLayerFramerate(nsecs_t now, int32_t id) const {
        return mLayerHistory.getLayerFramerate(now, id);
    }

private:
    friend class TestableScheduler;

    enum class ContentDetectionState { Off, On };
    enum class TimerState { Reset, Expired };
    enum class TouchState { Inactive, Active };

    // impl::MessageQueue overrides:
    void onFrameSignal(ICompositor&, VsyncId, TimePoint expectedVsyncTime) override;

    // Create a connection on the given EventThread.
    ConnectionHandle createConnection(std::unique_ptr<EventThread>);
    sp<EventThreadConnection> createConnectionInternal(
            EventThread*, EventRegistrationFlags eventRegistration = {},
            const sp<IBinder>& layerHandle = nullptr);

    // Update feature state machine to given state when corresponding timer resets or expires.
    void kernelIdleTimerCallback(TimerState) EXCLUDES(mDisplayLock);
    void idleTimerCallback(TimerState);
    void touchTimerCallback(TimerState);
    void displayPowerTimerCallback(TimerState);

    void resyncToHardwareVsyncLocked(PhysicalDisplayId, bool allowToEnable,
                                     std::optional<Fps> refreshRate = std::nullopt)
            REQUIRES(kMainThreadContext, mDisplayLock);
    void resyncAllToHardwareVsync(bool allowToEnable) EXCLUDES(mDisplayLock);
    void setVsyncConfig(const VsyncConfig&, Period vsyncPeriod);

    // Chooses a pacesetter among the registered displays, unless `pacesetterIdOpt` is specified.
    // The new `mPacesetterDisplayId` is never `std::nullopt`.
    void promotePacesetterDisplay(std::optional<PhysicalDisplayId> pacesetterIdOpt = std::nullopt)
            REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

    // Changes to the displays (e.g. registering and unregistering) must be made
    // while mDisplayLock is locked, and the new pacesetter then must be promoted while
    // mDisplayLock is still locked. However, a new pacesetter means that
    // MessageQueue and EventThread need to use the new pacesetter's
    // VsyncSchedule, and this must happen while mDisplayLock is *not* locked,
    // or else we may deadlock with EventThread.
    // Returns the new pacesetter's VsyncSchedule, or null if the pacesetter is
    // unchanged.
    std::shared_ptr<VsyncSchedule> promotePacesetterDisplayLocked(
            std::optional<PhysicalDisplayId> pacesetterIdOpt = std::nullopt)
            REQUIRES(kMainThreadContext, mDisplayLock);
    void applyNewVsyncScheduleIfNonNull(std::shared_ptr<VsyncSchedule>) EXCLUDES(mDisplayLock);

    // Blocks until the pacesetter's idle timer thread exits. `mDisplayLock` must not be locked by
    // the caller on the main thread to avoid deadlock, since the timer thread locks it before exit.
    void demotePacesetterDisplay() REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock, mPolicyLock);

    void registerDisplayInternal(PhysicalDisplayId, RefreshRateSelectorPtr,
                                 std::shared_ptr<VsyncSchedule>) REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);

    struct Policy;

    // Sets the S state of the policy to the T value under mPolicyLock, and chooses a display mode
    // that fulfills the new policy if the state changed. Returns the signals that were considered.
    template <typename S, typename T>
    GlobalSignals applyPolicy(S Policy::*, T&&) EXCLUDES(mPolicyLock);

    struct DisplayModeChoice {
        DisplayModeChoice(FrameRateMode mode, GlobalSignals consideredSignals)
              : mode(std::move(mode)), consideredSignals(consideredSignals) {}

        FrameRateMode mode;
        GlobalSignals consideredSignals;

        bool operator==(const DisplayModeChoice& other) const {
            return mode == other.mode && consideredSignals == other.consideredSignals;
        }

        // For tests.
        friend std::ostream& operator<<(std::ostream& stream, const DisplayModeChoice& choice) {
            return stream << '{' << to_string(*choice.mode.modePtr) << " considering "
                          << choice.consideredSignals.toString().c_str() << '}';
        }
    };

    using DisplayModeChoiceMap = display::PhysicalDisplayMap<PhysicalDisplayId, DisplayModeChoice>;

    // See mDisplayLock for thread safety.
    DisplayModeChoiceMap chooseDisplayModes() const
            REQUIRES(mPolicyLock, mDisplayLock, kMainThreadContext);

    GlobalSignals makeGlobalSignals() const REQUIRES(mPolicyLock);

    bool updateFrameRateOverrides(GlobalSignals, Fps displayRefreshRate) REQUIRES(mPolicyLock);

    void dispatchCachedReportedMode() REQUIRES(mPolicyLock) EXCLUDES(mDisplayLock);

    android::impl::EventThread::ThrottleVsyncCallback makeThrottleVsyncCallback() const;
    android::impl::EventThread::GetVsyncPeriodFunction makeGetVsyncPeriodFunction() const;

    // Stores EventThread associated with a given VSyncSource, and an initial EventThreadConnection.
    struct Connection {
        sp<EventThreadConnection> connection;
        std::unique_ptr<EventThread> thread;
    };

    ConnectionHandle::Id mNextConnectionHandleId = 0;
    mutable std::mutex mConnectionsLock;
    std::unordered_map<ConnectionHandle, Connection> mConnections GUARDED_BY(mConnectionsLock);

    ConnectionHandle mAppConnectionHandle;
    ConnectionHandle mSfConnectionHandle;

    std::atomic<nsecs_t> mLastResyncTime = 0;

    const FeatureFlags mFeatures;

    // Shifts the VSYNC phase during certain transactions and refresh rate changes.
    const sp<VsyncModulator> mVsyncModulator;

    // Used to choose refresh rate if content detection is enabled.
    LayerHistory mLayerHistory;

    // Timer used to monitor touch events.
    ftl::Optional<OneShotTimer> mTouchTimer;
    // Timer used to monitor display power mode.
    ftl::Optional<OneShotTimer> mDisplayPowerTimer;

    ISchedulerCallback& mSchedulerCallback;

    // mDisplayLock may be locked while under mPolicyLock.
    mutable std::mutex mPolicyLock;

    // Only required for reads outside kMainThreadContext. kMainThreadContext is the only writer, so
    // must lock for writes but not reads. See also mPolicyLock for locking order.
    mutable std::mutex mDisplayLock;

    display::PhysicalDisplayMap<PhysicalDisplayId, RefreshRateSelectorPtr> mRefreshRateSelectors
            GUARDED_BY(mDisplayLock) GUARDED_BY(kMainThreadContext);

    // TODO (b/266715559): Store in the same map as mRefreshRateSelectors.
    display::PhysicalDisplayMap<PhysicalDisplayId, std::shared_ptr<VsyncSchedule>> mVsyncSchedules
            GUARDED_BY(mDisplayLock) GUARDED_BY(kMainThreadContext);

    ftl::Optional<PhysicalDisplayId> mPacesetterDisplayId GUARDED_BY(mDisplayLock)
            GUARDED_BY(kMainThreadContext);

    RefreshRateSelectorPtr pacesetterSelectorPtr() const EXCLUDES(mDisplayLock) {
        std::scoped_lock lock(mDisplayLock);
        return pacesetterSelectorPtrLocked();
    }

    RefreshRateSelectorPtr pacesetterSelectorPtrLocked() const REQUIRES(mDisplayLock) {
        ftl::FakeGuard guard(kMainThreadContext);
        const RefreshRateSelectorPtr noPacesetter;
        return mPacesetterDisplayId
                .and_then([this](PhysicalDisplayId pacesetterId)
                                  REQUIRES(mDisplayLock, kMainThreadContext) {
                                      return mRefreshRateSelectors.get(pacesetterId);
                                  })
                .value_or(std::cref(noPacesetter));
    }

    std::shared_ptr<const VsyncSchedule> getVsyncScheduleLocked(
            std::optional<PhysicalDisplayId> idOpt = std::nullopt) const REQUIRES(mDisplayLock);
    std::shared_ptr<VsyncSchedule> getVsyncScheduleLocked(
            std::optional<PhysicalDisplayId> idOpt = std::nullopt) REQUIRES(mDisplayLock) {
        return std::const_pointer_cast<VsyncSchedule>(
                static_cast<const Scheduler*>(this)->getVsyncScheduleLocked(idOpt));
    }

    struct Policy {
        // Policy for choosing the display mode.
        LayerHistory::Summary contentRequirements;
        TimerState idleTimer = TimerState::Reset;
        TouchState touch = TouchState::Inactive;
        TimerState displayPowerTimer = TimerState::Expired;
        hal::PowerMode displayPowerMode = hal::PowerMode::ON;

        // Chosen display mode.
        ftl::Optional<FrameRateMode> modeOpt;

        struct ModeChangedParams {
            ConnectionHandle handle;
            FrameRateMode mode;
        };

        // Parameters for latest dispatch of mode change event.
        std::optional<ModeChangedParams> cachedModeChangedParams;
    } mPolicy GUARDED_BY(mPolicyLock);

    std::mutex mVsyncTimelineLock;
    std::optional<hal::VsyncPeriodChangeTimeline> mLastVsyncPeriodChangeTimeline
            GUARDED_BY(mVsyncTimelineLock);
    static constexpr std::chrono::nanoseconds MAX_VSYNC_APPLIED_TIME = 200ms;

    FrameRateOverrideMappings mFrameRateOverrideMappings;
};

} // namespace scheduler
} // namespace android
