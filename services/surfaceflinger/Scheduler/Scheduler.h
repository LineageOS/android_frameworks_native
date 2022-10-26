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
#include <optional>
#include <unordered_map>
#include <utility>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"
#include <ui/GraphicTypes.h>
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

#include <scheduler/Features.h>
#include <scheduler/Time.h>
#include <ui/DisplayId.h>

#include "Display/DisplayMap.h"
#include "Display/DisplayModeRequest.h"
#include "DisplayDevice.h"
#include "EventThread.h"
#include "FrameRateOverrideMappings.h"
#include "LayerHistory.h"
#include "MessageQueue.h"
#include "OneShotTimer.h"
#include "RefreshRateSelector.h"
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

struct ISchedulerCallback {
    virtual void setVsyncEnabled(bool) = 0;
    virtual void requestDisplayModes(std::vector<display::DisplayModeRequest>) = 0;
    virtual void kernelTimerChanged(bool expired) = 0;
    virtual void triggerOnFrameRateOverridesChanged() = 0;

protected:
    ~ISchedulerCallback() = default;
};

class Scheduler : android::impl::MessageQueue {
    using Impl = android::impl::MessageQueue;

public:
    Scheduler(ICompositor&, ISchedulerCallback&, FeatureFlags);
    virtual ~Scheduler();

    void startTimers();
    void setRefreshRateSelector(std::shared_ptr<RefreshRateSelector>)
            EXCLUDES(mRefreshRateSelectorLock);

    void registerDisplay(sp<const DisplayDevice>);
    void unregisterDisplay(PhysicalDisplayId);

    void run();

    void createVsyncSchedule(FeatureFlags);

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

    ConnectionHandle createConnection(const char* connectionName, frametimeline::TokenManager*,
                                      std::chrono::nanoseconds workDuration,
                                      std::chrono::nanoseconds readyDuration);

    sp<IDisplayEventConnection> createDisplayEventConnection(
            ConnectionHandle, EventRegistrationFlags eventRegistration = {});

    sp<EventThreadConnection> getEventConnection(ConnectionHandle);

    void onHotplugReceived(ConnectionHandle, PhysicalDisplayId, bool connected);
    void onPrimaryDisplayModeChanged(ConnectionHandle, DisplayModePtr) EXCLUDES(mPolicyLock);
    void onNonPrimaryDisplayModeChanged(ConnectionHandle, DisplayModePtr);
    void onScreenAcquired(ConnectionHandle);
    void onScreenReleased(ConnectionHandle);

    void onFrameRateOverridesChanged(ConnectionHandle, PhysicalDisplayId)
            EXCLUDES(mConnectionsLock);

    // Modifies work duration in the event thread.
    void setDuration(ConnectionHandle, std::chrono::nanoseconds workDuration,
                     std::chrono::nanoseconds readyDuration);

    void enableHardwareVsync();
    void disableHardwareVsync(bool makeUnavailable);

    // Resyncs the scheduler to hardware vsync.
    // If makeAvailable is true, then hardware vsync will be turned on.
    // Otherwise, if hardware vsync is not already enabled then this method will
    // no-op.
    void resyncToHardwareVsync(bool makeAvailable, Fps refreshRate);
    void resync() EXCLUDES(mRefreshRateSelectorLock);
    void forceNextResync() { mLastResyncTime = 0; }

    // Passes a vsync sample to VsyncController. periodFlushed will be true if
    // VsyncController detected that the vsync period changed, and false otherwise.
    void addResyncSample(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                         bool* periodFlushed);
    void addPresentFence(std::shared_ptr<FenceTime>);

    // Layers are registered on creation, and unregistered when the weak reference expires.
    void registerLayer(Layer*);
    void recordLayerHistory(Layer*, nsecs_t presentTime, LayerHistory::LayerUpdateType updateType)
            EXCLUDES(mRefreshRateSelectorLock);
    void setModeChangePending(bool pending);
    void setDefaultFrameRateCompatibility(Layer*);
    void deregisterLayer(Layer*);

    // Detects content using layer history, and selects a matching refresh rate.
    void chooseRefreshRateForContent() EXCLUDES(mRefreshRateSelectorLock);

    void resetIdleTimer();

    // Indicates that touch interaction is taking place.
    void onTouchHint();

    void setDisplayPowerMode(hal::PowerMode powerMode);

    VsyncSchedule& getVsyncSchedule() { return *mVsyncSchedule; }

    // Returns true if a given vsync timestamp is considered valid vsync
    // for a given uid
    bool isVsyncValid(TimePoint expectedVsyncTimestamp, uid_t uid) const;

    void dump(std::string&) const;
    void dump(ConnectionHandle, std::string&) const;
    void dumpVsync(std::string&) const;

    // Get the appropriate refresh for current conditions.
    DisplayModePtr getPreferredDisplayMode();

    // Notifies the scheduler about a refresh rate timeline change.
    void onNewVsyncPeriodChangeTimeline(const hal::VsyncPeriodChangeTimeline& timeline);

    // Notifies the scheduler post composition. Returns if recomposite is needed.
    bool onPostComposition(nsecs_t presentTime);

    // Notifies the scheduler when the display size has changed. Called from SF's main thread
    void onActiveDisplayAreaChanged(uint32_t displayArea);

    size_t getEventThreadConnectionCount(ConnectionHandle handle);

    std::unique_ptr<VSyncSource> makePrimaryDispSyncSource(const char* name,
                                                           std::chrono::nanoseconds workDuration,
                                                           std::chrono::nanoseconds readyDuration,
                                                           bool traceVsync = true);

    // Stores the preferred refresh rate that an app should run at.
    // FrameRateOverride.refreshRateHz == 0 means no preference.
    void setPreferredRefreshRateForUid(FrameRateOverride);

    void setGameModeRefreshRateForUid(FrameRateOverride);

    // Retrieves the overridden refresh rate for a given uid.
    std::optional<Fps> getFrameRateOverride(uid_t uid) const EXCLUDES(mRefreshRateSelectorLock);

    nsecs_t getVsyncPeriodFromRefreshRateSelector() const EXCLUDES(mRefreshRateSelectorLock) {
        std::scoped_lock lock(mRefreshRateSelectorLock);
        return mRefreshRateSelector->getActiveModePtr()->getFps().getPeriodNsecs();
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
            EventThread*, EventRegistrationFlags eventRegistration = {});

    // Update feature state machine to given state when corresponding timer resets or expires.
    void kernelIdleTimerCallback(TimerState) EXCLUDES(mRefreshRateSelectorLock);
    void idleTimerCallback(TimerState);
    void touchTimerCallback(TimerState);
    void displayPowerTimerCallback(TimerState);

    void setVsyncPeriod(nsecs_t period);

    struct Policy;

    // Sets the S state of the policy to the T value under mPolicyLock, and chooses a display mode
    // that fulfills the new policy if the state changed. Returns the signals that were considered.
    template <typename S, typename T>
    GlobalSignals applyPolicy(S Policy::*, T&&) EXCLUDES(mPolicyLock);

    struct DisplayModeChoice {
        DisplayModeChoice(DisplayModePtr modePtr, GlobalSignals consideredSignals)
              : modePtr(std::move(modePtr)), consideredSignals(consideredSignals) {}

        DisplayModePtr modePtr;
        GlobalSignals consideredSignals;

        bool operator==(const DisplayModeChoice& other) const {
            return modePtr == other.modePtr && consideredSignals == other.consideredSignals;
        }

        // For tests.
        friend std::ostream& operator<<(std::ostream& stream, const DisplayModeChoice& choice) {
            return stream << '{' << to_string(*choice.modePtr) << " considering "
                          << choice.consideredSignals.toString().c_str() << '}';
        }
    };

    using DisplayModeChoiceMap = display::PhysicalDisplayMap<PhysicalDisplayId, DisplayModeChoice>;
    DisplayModeChoiceMap chooseDisplayModes() const REQUIRES(mPolicyLock);

    GlobalSignals makeGlobalSignals() const REQUIRES(mPolicyLock);

    bool updateFrameRateOverrides(GlobalSignals, Fps displayRefreshRate) REQUIRES(mPolicyLock);

    void dispatchCachedReportedMode() REQUIRES(mPolicyLock) EXCLUDES(mRefreshRateSelectorLock);

    android::impl::EventThread::ThrottleVsyncCallback makeThrottleVsyncCallback() const
            EXCLUDES(mRefreshRateSelectorLock);
    android::impl::EventThread::GetVsyncPeriodFunction makeGetVsyncPeriodFunction() const;

    std::shared_ptr<RefreshRateSelector> holdRefreshRateSelector() const
            EXCLUDES(mRefreshRateSelectorLock) {
        std::scoped_lock lock(mRefreshRateSelectorLock);
        return mRefreshRateSelector;
    }

    // Stores EventThread associated with a given VSyncSource, and an initial EventThreadConnection.
    struct Connection {
        sp<EventThreadConnection> connection;
        std::unique_ptr<EventThread> thread;
    };

    ConnectionHandle::Id mNextConnectionHandleId = 0;
    mutable std::mutex mConnectionsLock;
    std::unordered_map<ConnectionHandle, Connection> mConnections GUARDED_BY(mConnectionsLock);

    mutable std::mutex mHWVsyncLock;
    bool mPrimaryHWVsyncEnabled GUARDED_BY(mHWVsyncLock) = false;
    bool mHWVsyncAvailable GUARDED_BY(mHWVsyncLock) = false;

    std::atomic<nsecs_t> mLastResyncTime = 0;

    const FeatureFlags mFeatures;
    std::optional<VsyncSchedule> mVsyncSchedule;

    // Used to choose refresh rate if content detection is enabled.
    LayerHistory mLayerHistory;

    // Timer used to monitor touch events.
    std::optional<OneShotTimer> mTouchTimer;
    // Timer used to monitor display power mode.
    std::optional<OneShotTimer> mDisplayPowerTimer;

    ISchedulerCallback& mSchedulerCallback;

    mutable std::mutex mPolicyLock;

    display::PhysicalDisplayMap<PhysicalDisplayId, sp<const DisplayDevice>> mDisplays;
    std::optional<PhysicalDisplayId> mLeaderDisplayId;

    struct Policy {
        // Policy for choosing the display mode.
        LayerHistory::Summary contentRequirements;
        TimerState idleTimer = TimerState::Reset;
        TouchState touch = TouchState::Inactive;
        TimerState displayPowerTimer = TimerState::Expired;
        hal::PowerMode displayPowerMode = hal::PowerMode::ON;

        // Chosen display mode.
        DisplayModePtr mode;

        struct ModeChangedParams {
            ConnectionHandle handle;
            DisplayModePtr mode;
        };

        // Parameters for latest dispatch of mode change event.
        std::optional<ModeChangedParams> cachedModeChangedParams;
    } mPolicy GUARDED_BY(mPolicyLock);

    mutable std::mutex mRefreshRateSelectorLock;
    std::shared_ptr<RefreshRateSelector> mRefreshRateSelector GUARDED_BY(mRefreshRateSelectorLock);

    std::mutex mVsyncTimelineLock;
    std::optional<hal::VsyncPeriodChangeTimeline> mLastVsyncPeriodChangeTimeline
            GUARDED_BY(mVsyncTimelineLock);
    static constexpr std::chrono::nanoseconds MAX_VSYNC_APPLIED_TIME = 200ms;

    FrameRateOverrideMappings mFrameRateOverrideMappings;

    // Keeps track of whether the screen is acquired for debug
    std::atomic<bool> mScreenAcquired = false;
};

} // namespace scheduler
} // namespace android
