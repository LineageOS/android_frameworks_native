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
#include <ftl/non_null.h>
#include <ftl/optional.h>
#include <scheduler/Features.h>
#include <scheduler/FrameTargeter.h>
#include <scheduler/Time.h>
#include <scheduler/VsyncConfig.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMap.h>

#include "Display/DisplayModeRequest.h"
#include "EventThread.h"
#include "FrameRateOverrideMappings.h"
#include "ISchedulerCallback.h"
#include "LayerHistory.h"
#include "MessageQueue.h"
#include "OneShotTimer.h"
#include "RefreshRateSelector.h"
#include "SmallAreaDetectionAllowMappings.h"
#include "Utils/Dumper.h"
#include "VsyncModulator.h"

#include <FrontEnd/LayerHierarchy.h>

namespace android {

class FenceTime;
class TimeStats;

namespace frametimeline {
class TokenManager;
} // namespace frametimeline

namespace surfaceflinger {
class Factory;
} // namespace surfaceflinger

namespace scheduler {

using GlobalSignals = RefreshRateSelector::GlobalSignals;

class RefreshRateStats;
class VsyncConfiguration;
class VsyncSchedule;

enum class Cycle {
    Render,       // Surface rendering.
    LastComposite // Ahead of display compositing by one refresh period.
};

class Scheduler : public IEventThreadCallback, android::impl::MessageQueue {
    using Impl = android::impl::MessageQueue;

public:
    Scheduler(ICompositor&, ISchedulerCallback&, FeatureFlags, surfaceflinger::Factory&,
              Fps activeRefreshRate, TimeStats&);
    virtual ~Scheduler();

    void startTimers();

    // TODO(b/241285191): Remove this API by promoting pacesetter in onScreen{Acquired,Released}.
    void setPacesetterDisplay(std::optional<PhysicalDisplayId>) REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);

    using RefreshRateSelectorPtr = std::shared_ptr<RefreshRateSelector>;

    using ConstVsyncSchedulePtr = std::shared_ptr<const VsyncSchedule>;
    using VsyncSchedulePtr = std::shared_ptr<VsyncSchedule>;

    void registerDisplay(PhysicalDisplayId, RefreshRateSelectorPtr) REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);
    void unregisterDisplay(PhysicalDisplayId) REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

    void run();

    void initVsync(frametimeline::TokenManager&, std::chrono::nanoseconds workDuration);

    using Impl::setDuration;

    using Impl::getScheduledFrameResult;
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

    void createEventThread(Cycle, frametimeline::TokenManager*,
                           std::chrono::nanoseconds workDuration,
                           std::chrono::nanoseconds readyDuration);

    sp<IDisplayEventConnection> createDisplayEventConnection(
            Cycle, EventRegistrationFlags eventRegistration = {},
            const sp<IBinder>& layerHandle = nullptr) EXCLUDES(mChoreographerLock);

    const sp<EventThreadConnection>& getEventConnection(Cycle cycle) const {
        return cycle == Cycle::Render ? mRenderEventConnection : mLastCompositeEventConnection;
    }

    enum class Hotplug { Connected, Disconnected };
    void dispatchHotplug(PhysicalDisplayId, Hotplug);

    void dispatchHotplugError(int32_t errorCode);

    void onPrimaryDisplayModeChanged(Cycle, const FrameRateMode&) EXCLUDES(mPolicyLock);
    void onNonPrimaryDisplayModeChanged(Cycle, const FrameRateMode&);

    void enableSyntheticVsync(bool = true) REQUIRES(kMainThreadContext);

    void onFrameRateOverridesChanged(Cycle, PhysicalDisplayId);

    void onHdcpLevelsChanged(Cycle, PhysicalDisplayId, int32_t, int32_t);

    // Modifies work duration in the event thread.
    void setDuration(Cycle, std::chrono::nanoseconds workDuration,
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

    void updatePhaseConfiguration(Fps);
    void resetPhaseConfiguration(Fps) REQUIRES(kMainThreadContext);

    const VsyncConfiguration& getVsyncConfiguration() const { return *mVsyncConfiguration; }

    // Sets the render rate for the scheduler to run at.
    void setRenderRate(PhysicalDisplayId, Fps);

    void enableHardwareVsync(PhysicalDisplayId) REQUIRES(kMainThreadContext);
    void disableHardwareVsync(PhysicalDisplayId, bool disallow) REQUIRES(kMainThreadContext);

    // Resyncs the scheduler to hardware vsync.
    // If allowToEnable is true, then hardware vsync will be turned on.
    // Otherwise, if hardware vsync is not already enabled then this method will
    // no-op.
    // If modePtr is nullopt, use the active display mode.
    void resyncToHardwareVsync(PhysicalDisplayId id, bool allowToEnable,
                               DisplayModePtr modePtr = nullptr) EXCLUDES(mDisplayLock) {
        std::scoped_lock lock(mDisplayLock);
        ftl::FakeGuard guard(kMainThreadContext);
        resyncToHardwareVsyncLocked(id, allowToEnable, modePtr);
    }
    void forceNextResync() { mLastResyncTime = 0; }

    // Passes a vsync sample to VsyncController. Returns true if
    // VsyncController detected that the vsync period changed and false
    // otherwise.
    bool addResyncSample(PhysicalDisplayId, nsecs_t timestamp,
                         std::optional<nsecs_t> hwcVsyncPeriod);
    void addPresentFence(PhysicalDisplayId, std::shared_ptr<FenceTime>)
            REQUIRES(kMainThreadContext);

    // Layers are registered on creation, and unregistered when the weak reference expires.
    void registerLayer(Layer*);
    void recordLayerHistory(int32_t id, const LayerProps& layerProps, nsecs_t presentTime,
                            nsecs_t now, LayerHistory::LayerUpdateType) EXCLUDES(mDisplayLock);
    void setModeChangePending(bool pending);
    void setDefaultFrameRateCompatibility(int32_t id, scheduler::FrameRateCompatibility);
    void setLayerProperties(int32_t id, const LayerProps&);
    void deregisterLayer(Layer*);
    void onLayerDestroyed(Layer*) EXCLUDES(mChoreographerLock);

    // Detects content using layer history, and selects a matching refresh rate.
    void chooseRefreshRateForContent(const surfaceflinger::frontend::LayerHierarchy*,
                                     bool updateAttachedChoreographer) EXCLUDES(mDisplayLock);

    void resetIdleTimer();

    // Indicates that touch interaction is taking place.
    void onTouchHint();

    void setDisplayPowerMode(PhysicalDisplayId, hal::PowerMode) REQUIRES(kMainThreadContext);

    // TODO(b/255635821): Track this per display.
    void setActiveDisplayPowerModeForRefreshRateStats(hal::PowerMode) REQUIRES(kMainThreadContext);

    ConstVsyncSchedulePtr getVsyncSchedule(std::optional<PhysicalDisplayId> = std::nullopt) const
            EXCLUDES(mDisplayLock);

    VsyncSchedulePtr getVsyncSchedule(std::optional<PhysicalDisplayId> idOpt = std::nullopt)
            EXCLUDES(mDisplayLock) {
        return std::const_pointer_cast<VsyncSchedule>(std::as_const(*this).getVsyncSchedule(idOpt));
    }

    TimePoint expectedPresentTimeForPacesetter() const EXCLUDES(mDisplayLock) {
        std::scoped_lock lock(mDisplayLock);
        return pacesetterDisplayLocked()
                .transform([](const Display& display) {
                    return display.targeterPtr->target().expectedPresentTime();
                })
                .value_or(TimePoint());
    }

    // Returns true if a given vsync timestamp is considered valid vsync
    // for a given uid
    bool isVsyncValid(TimePoint expectedVsyncTime, uid_t uid) const;

    bool isVsyncInPhase(TimePoint expectedVsyncTime, Fps frameRate) const;

    void dump(utils::Dumper&) const;
    void dump(Cycle, std::string&) const;
    void dumpVsync(std::string&) const EXCLUDES(mDisplayLock);

    // Returns the preferred refresh rate and frame rate for the pacesetter display.
    FrameRateMode getPreferredDisplayMode();

    // Notifies the scheduler about a refresh rate timeline change.
    void onNewVsyncPeriodChangeTimeline(const hal::VsyncPeriodChangeTimeline& timeline);

    // Notifies the scheduler once the composition is presented. Returns if recomposite is needed.
    bool onCompositionPresented(nsecs_t presentTime);

    // Notifies the scheduler when the display size has changed. Called from SF's main thread
    void onActiveDisplayAreaChanged(uint32_t displayArea);

    // Stores the preferred refresh rate that an app should run at.
    // FrameRateOverride.refreshRateHz == 0 means no preference.
    void setPreferredRefreshRateForUid(FrameRateOverride);

    // Stores the frame rate override that a game should run at set by game interventions.
    // FrameRateOverride.refreshRateHz == 0 means no preference.
    void setGameModeFrameRateForUid(FrameRateOverride) EXCLUDES(mDisplayLock);

    // Stores the frame rate override that a game should run rat set by default game frame rate.
    // FrameRateOverride.refreshRateHz == 0 means no preference, game default game frame rate is not
    // enabled.
    //
    // "ro.surface_flinger.game_default_frame_rate_override" sets the frame rate value,
    // "persist.graphics.game_default_frame_rate.enabled" controls whether this feature is enabled.
    void setGameDefaultFrameRateForUid(FrameRateOverride) EXCLUDES(mDisplayLock);

    void updateSmallAreaDetection(std::vector<std::pair<int32_t, float>>& uidThresholdMappings);

    void setSmallAreaDetectionThreshold(int32_t appId, float threshold);

    // Returns true if the dirty area is less than threshold.
    bool isSmallDirtyArea(int32_t appId, uint32_t dirtyArea);

    // Retrieves the overridden refresh rate for a given uid.
    std::optional<Fps> getFrameRateOverride(uid_t) const EXCLUDES(mDisplayLock);

    Period getPacesetterVsyncPeriod() const EXCLUDES(mDisplayLock) {
        return pacesetterSelectorPtr()->getActiveMode().fps.getPeriod();
    }

    Fps getPacesetterRefreshRate() const EXCLUDES(mDisplayLock) {
        return pacesetterSelectorPtr()->getActiveMode().fps;
    }

    Fps getNextFrameInterval(PhysicalDisplayId, TimePoint currentExpectedPresentTime) const
            EXCLUDES(mDisplayLock);

    // Returns the framerate of the layer with the given sequence ID
    float getLayerFramerate(nsecs_t now, int32_t id) const {
        return mLayerHistory.getLayerFramerate(now, id);
    }

    bool updateFrameRateOverrides(GlobalSignals, Fps displayRefreshRate) EXCLUDES(mPolicyLock);

    // Returns true if the small dirty detection is enabled for the appId.
    bool supportSmallDirtyDetection(int32_t appId) {
        return mFeatures.test(Feature::kSmallDirtyContentDetection) &&
                mSmallAreaDetectionAllowMappings.getThresholdForAppId(appId).has_value();
    }

    // Injects a delay that is a fraction of the predicted frame duration for the next frame.
    void injectPacesetterDelay(float frameDurationFraction) REQUIRES(kMainThreadContext) {
        mPacesetterFrameDurationFractionToSkip = frameDurationFraction;
    }

private:
    friend class TestableScheduler;

    enum class ContentDetectionState { Off, On };
    enum class TimerState { Reset, Expired };
    enum class TouchState { Inactive, Active };

    // impl::MessageQueue overrides:
    void onFrameSignal(ICompositor&, VsyncId, TimePoint expectedVsyncTime) override
            REQUIRES(kMainThreadContext, mDisplayLock);

    // Used to skip event dispatch before EventThread creation during boot.
    // TODO: b/241285191 - Reorder Scheduler initialization to avoid this.
    bool hasEventThreads() const {
        return CC_LIKELY(mRenderEventThread && mLastCompositeEventThread);
    }

    EventThread& eventThreadFor(Cycle cycle) const {
        return *(cycle == Cycle::Render ? mRenderEventThread : mLastCompositeEventThread);
    }

    // Update feature state machine to given state when corresponding timer resets or expires.
    void kernelIdleTimerCallback(TimerState) EXCLUDES(mDisplayLock);
    void idleTimerCallback(TimerState);
    void touchTimerCallback(TimerState);
    void displayPowerTimerCallback(TimerState);

    // VsyncSchedule delegate.
    void onHardwareVsyncRequest(PhysicalDisplayId, bool enable);

    void resyncToHardwareVsyncLocked(PhysicalDisplayId, bool allowToEnable,
                                     DisplayModePtr modePtr = nullptr)
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
    std::shared_ptr<VsyncSchedule> promotePacesetterDisplayLocked(
            std::optional<PhysicalDisplayId> pacesetterIdOpt = std::nullopt)
            REQUIRES(kMainThreadContext, mDisplayLock);
    void applyNewVsyncSchedule(std::shared_ptr<VsyncSchedule>) EXCLUDES(mDisplayLock);

    // Blocks until the pacesetter's idle timer thread exits. `mDisplayLock` must not be locked by
    // the caller on the main thread to avoid deadlock, since the timer thread locks it before exit.
    void demotePacesetterDisplay() REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock, mPolicyLock);

    void registerDisplayInternal(PhysicalDisplayId, RefreshRateSelectorPtr, VsyncSchedulePtr)
            REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

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

    using DisplayModeChoiceMap = ui::PhysicalDisplayMap<PhysicalDisplayId, DisplayModeChoice>;

    // See mDisplayLock for thread safety.
    DisplayModeChoiceMap chooseDisplayModes() const
            REQUIRES(mPolicyLock, mDisplayLock, kMainThreadContext);

    GlobalSignals makeGlobalSignals() const REQUIRES(mPolicyLock);

    bool updateFrameRateOverridesLocked(GlobalSignals, Fps displayRefreshRate)
            REQUIRES(mPolicyLock);
    void updateAttachedChoreographers(const surfaceflinger::frontend::LayerHierarchy&,
                                      Fps displayRefreshRate);
    int updateAttachedChoreographersInternal(const surfaceflinger::frontend::LayerHierarchy&,
                                             Fps displayRefreshRate, int parentDivisor);
    void updateAttachedChoreographersFrameRate(const surfaceflinger::frontend::RequestedLayerState&,
                                               Fps fps) EXCLUDES(mChoreographerLock);

    void dispatchCachedReportedMode() REQUIRES(mPolicyLock) EXCLUDES(mDisplayLock);

    // IEventThreadCallback overrides
    bool throttleVsync(TimePoint, uid_t) override;
    Period getVsyncPeriod(uid_t) override EXCLUDES(mDisplayLock);
    void resync() override EXCLUDES(mDisplayLock);
    void onExpectedPresentTimePosted(TimePoint expectedPresentTime) override EXCLUDES(mDisplayLock);

    std::unique_ptr<EventThread> mRenderEventThread;
    sp<EventThreadConnection> mRenderEventConnection;

    std::unique_ptr<EventThread> mLastCompositeEventThread;
    sp<EventThreadConnection> mLastCompositeEventConnection;

    std::atomic<nsecs_t> mLastResyncTime = 0;

    const FeatureFlags mFeatures;

    // Stores phase offsets configured per refresh rate.
    const std::unique_ptr<VsyncConfiguration> mVsyncConfiguration;

    // Shifts the VSYNC phase during certain transactions and refresh rate changes.
    const sp<VsyncModulator> mVsyncModulator;

    const std::unique_ptr<RefreshRateStats> mRefreshRateStats;

    // Used to choose refresh rate if content detection is enabled.
    LayerHistory mLayerHistory;

    // Timer used to monitor touch events.
    ftl::Optional<OneShotTimer> mTouchTimer;
    // Timer used to monitor display power mode.
    ftl::Optional<OneShotTimer> mDisplayPowerTimer;

    // Injected delay prior to compositing, for simulating jank.
    float mPacesetterFrameDurationFractionToSkip GUARDED_BY(kMainThreadContext) = 0.f;

    ISchedulerCallback& mSchedulerCallback;

    // mDisplayLock may be locked while under mPolicyLock.
    mutable std::mutex mPolicyLock;

    // Only required for reads outside kMainThreadContext. kMainThreadContext is the only writer, so
    // must lock for writes but not reads. See also mPolicyLock for locking order.
    mutable std::mutex mDisplayLock;

    using FrameTargeterPtr = std::unique_ptr<FrameTargeter>;

    struct Display {
        Display(PhysicalDisplayId displayId, RefreshRateSelectorPtr selectorPtr,
                VsyncSchedulePtr schedulePtr, FeatureFlags features)
              : displayId(displayId),
                selectorPtr(std::move(selectorPtr)),
                schedulePtr(std::move(schedulePtr)),
                targeterPtr(std::make_unique<FrameTargeter>(displayId, features)) {}

        const PhysicalDisplayId displayId;

        // Effectively const except in move constructor.
        RefreshRateSelectorPtr selectorPtr;
        VsyncSchedulePtr schedulePtr;
        FrameTargeterPtr targeterPtr;

        hal::PowerMode powerMode = hal::PowerMode::OFF;
    };

    using DisplayRef = std::reference_wrapper<Display>;
    using ConstDisplayRef = std::reference_wrapper<const Display>;

    ui::PhysicalDisplayMap<PhysicalDisplayId, Display> mDisplays GUARDED_BY(mDisplayLock)
            GUARDED_BY(kMainThreadContext);

    ftl::Optional<PhysicalDisplayId> mPacesetterDisplayId GUARDED_BY(mDisplayLock)
            GUARDED_BY(kMainThreadContext);

    ftl::Optional<DisplayRef> pacesetterDisplayLocked() REQUIRES(mDisplayLock) {
        return static_cast<const Scheduler*>(this)->pacesetterDisplayLocked().transform(
                [](const Display& display) { return std::ref(const_cast<Display&>(display)); });
    }

    ftl::Optional<ConstDisplayRef> pacesetterDisplayLocked() const REQUIRES(mDisplayLock) {
        ftl::FakeGuard guard(kMainThreadContext);
        return mPacesetterDisplayId.and_then([this](PhysicalDisplayId pacesetterId)
                                                     REQUIRES(mDisplayLock, kMainThreadContext) {
                                                         return mDisplays.get(pacesetterId);
                                                     });
    }

    // The pacesetter must exist as a precondition.
    ftl::NonNull<const Display*> pacesetterPtrLocked() const REQUIRES(mDisplayLock) {
        return ftl::as_non_null(&pacesetterDisplayLocked()->get());
    }

    RefreshRateSelectorPtr pacesetterSelectorPtr() const EXCLUDES(mDisplayLock) {
        std::scoped_lock lock(mDisplayLock);
        return pacesetterSelectorPtrLocked();
    }

    RefreshRateSelectorPtr pacesetterSelectorPtrLocked() const REQUIRES(mDisplayLock) {
        return pacesetterDisplayLocked()
                .transform([](const Display& display) { return display.selectorPtr; })
                .or_else([] { return std::optional<RefreshRateSelectorPtr>(nullptr); })
                .value();
    }

    ConstVsyncSchedulePtr getVsyncScheduleLocked(
            std::optional<PhysicalDisplayId> = std::nullopt) const REQUIRES(mDisplayLock);

    VsyncSchedulePtr getVsyncScheduleLocked(std::optional<PhysicalDisplayId> idOpt = std::nullopt)
            REQUIRES(mDisplayLock) {
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
            Cycle cycle;
            FrameRateMode mode;
        };

        // Parameters for latest dispatch of mode change event.
        std::optional<ModeChangedParams> cachedModeChangedParams;
    } mPolicy GUARDED_BY(mPolicyLock);

    std::mutex mChoreographerLock;

    struct AttachedChoreographers {
        Fps frameRate;
        std::unordered_set<wp<EventThreadConnection>, WpHash> connections;
    };
    // Map keyed by layer ID (sequence) to choreographer connections.
    std::unordered_map<int32_t, AttachedChoreographers> mAttachedChoreographers
            GUARDED_BY(mChoreographerLock);

    std::mutex mVsyncTimelineLock;
    std::optional<hal::VsyncPeriodChangeTimeline> mLastVsyncPeriodChangeTimeline
            GUARDED_BY(mVsyncTimelineLock);
    static constexpr std::chrono::nanoseconds MAX_VSYNC_APPLIED_TIME = 200ms;

    FrameRateOverrideMappings mFrameRateOverrideMappings;
    SmallAreaDetectionAllowMappings mSmallAreaDetectionAllowMappings;
};

} // namespace scheduler
} // namespace android
