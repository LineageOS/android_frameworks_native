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
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

#include <ui/GraphicTypes.h>

#include "EventControlThread.h"
#include "EventThread.h"
#include "LayerHistory.h"
#include "OneShotTimer.h"
#include "RefreshRateConfigs.h"
#include "SchedulerUtils.h"

namespace android {

class DispSync;
class FenceTime;
struct DisplayStateInfo;

class Scheduler {
public:
    using RefreshRateType = scheduler::RefreshRateConfigs::RefreshRateType;
    using ConfigEvent = scheduler::RefreshRateConfigEvent;

    using ChangeRefreshRateCallback = std::function<void(RefreshRateType, ConfigEvent)>;

    // Indicates whether to start the transaction early, or at vsync time.
    enum class TransactionStart { EARLY, NORMAL };

    Scheduler(impl::EventControlThread::SetVSyncEnabledFunction,
              const scheduler::RefreshRateConfigs&);

    virtual ~Scheduler();

    DispSync& getPrimaryDispSync();

    using ConnectionHandle = scheduler::ConnectionHandle;
    ConnectionHandle createConnection(const char* connectionName, nsecs_t phaseOffsetNs,
                                      nsecs_t offsetThresholdForNextVsync,
                                      impl::EventThread::InterceptVSyncsCallback);

    sp<IDisplayEventConnection> createDisplayEventConnection(ConnectionHandle,
                                                             ISurfaceComposer::ConfigChanged);

    EventThread* getEventThread(ConnectionHandle);
    sp<EventThreadConnection> getEventConnection(ConnectionHandle);

    void onHotplugReceived(ConnectionHandle, PhysicalDisplayId, bool connected);
    void onConfigChanged(ConnectionHandle, PhysicalDisplayId, int32_t configId);

    void onScreenAcquired(ConnectionHandle);
    void onScreenReleased(ConnectionHandle);

    // Modifies phase offset in the event thread.
    void setPhaseOffset(ConnectionHandle, nsecs_t phaseOffset);

    void getDisplayStatInfo(DisplayStatInfo* stats);

    void enableHardwareVsync();
    void disableHardwareVsync(bool makeUnavailable);

    // Resyncs the scheduler to hardware vsync.
    // If makeAvailable is true, then hardware vsync will be turned on.
    // Otherwise, if hardware vsync is not already enabled then this method will
    // no-op.
    // The period is the vsync period from the current display configuration.
    void resyncToHardwareVsync(bool makeAvailable, nsecs_t period);
    void resync();

    // Passes a vsync sample to DispSync. periodFlushed will be true if
    // DispSync detected that the vsync period changed, and false otherwise.
    void addResyncSample(nsecs_t timestamp, bool* periodFlushed);
    void addPresentFence(const std::shared_ptr<FenceTime>&);
    void setIgnorePresentFences(bool ignore);
    nsecs_t getDispSyncExpectedPresentTime();
    // Registers the layer in the scheduler, and returns the handle for future references.
    std::unique_ptr<scheduler::LayerHistory::LayerHandle> registerLayer(std::string const& name,
                                                                        int windowType);

    // Stores present time for a layer.
    void addLayerPresentTimeAndHDR(
            const std::unique_ptr<scheduler::LayerHistory::LayerHandle>& layerHandle,
            nsecs_t presentTime, bool isHDR);
    // Stores visibility for a layer.
    void setLayerVisibility(
            const std::unique_ptr<scheduler::LayerHistory::LayerHandle>& layerHandle, bool visible);
    // Updates FPS based on the most content presented.
    void updateFpsBasedOnContent();

    // Called by Scheduler to change refresh rate.
    void setChangeRefreshRateCallback(ChangeRefreshRateCallback&&);

    bool isIdleTimerEnabled() const { return mIdleTimer.has_value(); }
    void resetIdleTimer();

    // Function that resets the touch timer.
    void notifyTouchEvent();

    void setDisplayPowerState(bool normal);

    void dump(std::string&) const;
    void dump(ConnectionHandle, std::string&) const;

    // Get the appropriate refresh type for current conditions.
    RefreshRateType getPreferredRefreshRateType();

private:
    friend class TestableScheduler;

    // In order to make sure that the features don't override themselves, we need a state machine
    // to keep track which feature requested the config change.
    enum class ContentDetectionState { Off, On };
    enum class TimerState { Reset, Expired };
    enum class TouchState { Inactive, Active };

    // Used by tests to inject mocks.
    Scheduler(std::unique_ptr<DispSync>, std::unique_ptr<EventControlThread>,
              const scheduler::RefreshRateConfigs&);

    // Creates a connection on the given EventThread and forwards the given callbacks.
    std::unique_ptr<EventThread> makeEventThread(const char* connectionName, nsecs_t phaseOffsetNs,
                                                 nsecs_t offsetThresholdForNextVsync,
                                                 impl::EventThread::InterceptVSyncsCallback&&);

    // Create a connection on the given EventThread and forward the resync callback.
    ConnectionHandle createConnection(std::unique_ptr<EventThread>);
    sp<EventThreadConnection> createConnectionInternal(EventThread*,
                                                       ISurfaceComposer::ConfigChanged);

    // Update feature state machine to given state when corresponding timer resets or expires.
    void kernelIdleTimerCallback(TimerState);
    void idleTimerCallback(TimerState);
    void touchTimerCallback(TimerState);
    void displayPowerTimerCallback(TimerState);

    // handles various timer features to change the refresh rate.
    template <class T>
    void handleTimerStateChanged(T* currentState, T newState, bool eventOnContentDetection);

    void setVsyncPeriod(nsecs_t period);

    RefreshRateType calculateRefreshRateType() REQUIRES(mFeatureStateLock);
    // Acquires a lock and calls the ChangeRefreshRateCallback with given parameters.
    void changeRefreshRate(RefreshRateType, ConfigEvent);

    // Stores EventThread associated with a given VSyncSource, and an initial EventThreadConnection.
    struct Connection {
        sp<EventThreadConnection> connection;
        std::unique_ptr<EventThread> thread;
    };

    ConnectionHandle::Id mNextConnectionHandleId = 0;
    std::unordered_map<ConnectionHandle, Connection> mConnections;

    std::mutex mHWVsyncLock;
    bool mPrimaryHWVsyncEnabled GUARDED_BY(mHWVsyncLock) = false;
    bool mHWVsyncAvailable GUARDED_BY(mHWVsyncLock) = false;

    std::atomic<nsecs_t> mLastResyncTime = 0;

    std::unique_ptr<DispSync> mPrimaryDispSync;
    std::unique_ptr<EventControlThread> mEventControlThread;

    // Historical information about individual layers. Used for predicting the refresh rate.
    scheduler::LayerHistory mLayerHistory;

    // Whether to use idle timer callbacks that support the kernel timer.
    const bool mSupportKernelTimer;

    // Timer that records time between requests for next vsync.
    std::optional<scheduler::OneShotTimer> mIdleTimer;
    // Timer used to monitor touch events.
    std::optional<scheduler::OneShotTimer> mTouchTimer;
    // Timer used to monitor display power mode.
    std::optional<scheduler::OneShotTimer> mDisplayPowerTimer;

    std::mutex mCallbackLock;
    ChangeRefreshRateCallback mChangeRefreshRateCallback GUARDED_BY(mCallbackLock);

    // In order to make sure that the features don't override themselves, we need a state machine
    // to keep track which feature requested the config change.
    std::mutex mFeatureStateLock;

    struct {
        ContentDetectionState contentDetection = ContentDetectionState::Off;
        TimerState idleTimer = TimerState::Reset;
        TouchState touch = TouchState::Inactive;
        TimerState displayPowerTimer = TimerState::Expired;

        RefreshRateType refreshRateType = RefreshRateType::DEFAULT;
        uint32_t contentRefreshRate = 0;

        bool isHDRContent = false;
        bool isDisplayPowerStateNormal = true;
    } mFeatures GUARDED_BY(mFeatureStateLock);

    const scheduler::RefreshRateConfigs& mRefreshRateConfigs;

    // Global config to force HDR content to work on DEFAULT refreshRate
    static constexpr bool mForceHDRContentToDefaultRefreshRate = false;
};

} // namespace android
