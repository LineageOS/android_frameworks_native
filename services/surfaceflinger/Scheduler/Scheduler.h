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

#include <cstdint>
#include <memory>

#include <ui/DisplayStatInfo.h>
#include <ui/GraphicTypes.h>

#include "DispSync.h"
#include "EventControlThread.h"
#include "EventThread.h"
#include "IdleTimer.h"
#include "InjectVSyncSource.h"
#include "LayerHistory.h"
#include "SchedulerUtils.h"

namespace android {

class EventControlThread;

class Scheduler {
public:
    using ExpiredIdleTimerCallback = std::function<void()>;
    using GetVsyncPeriod = std::function<nsecs_t()>;
    using ResetIdleTimerCallback = std::function<void()>;

    // Enum to indicate whether to start the transaction early, or at vsync time.
    enum class TransactionStart { EARLY, NORMAL };

    /* The scheduler handle is a BBinder object passed to the client from which we can extract
     * an ID for subsequent operations.
     */
    class ConnectionHandle : public BBinder {
    public:
        ConnectionHandle(int64_t id) : id(id) {}

        ~ConnectionHandle() = default;

        const int64_t id;
    };

    class Connection {
    public:
        Connection(sp<ConnectionHandle> handle, sp<EventThreadConnection> eventConnection,
                   std::unique_ptr<EventThread> eventThread)
              : handle(handle), eventConnection(eventConnection), thread(std::move(eventThread)) {}

        ~Connection() = default;

        sp<ConnectionHandle> handle;
        sp<EventThreadConnection> eventConnection;
        const std::unique_ptr<EventThread> thread;
    };

    // Stores per-display state about VSYNC.
    struct VsyncState {
        explicit VsyncState(Scheduler& scheduler) : scheduler(scheduler) {}

        void resync(const GetVsyncPeriod&);

        Scheduler& scheduler;
        std::atomic<nsecs_t> lastResyncTime = 0;
    };

    explicit Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function);

    virtual ~Scheduler();

    /** Creates an EventThread connection. */
    sp<ConnectionHandle> createConnection(const char* connectionName, int64_t phaseOffsetNs,
                                          ResyncCallback,
                                          impl::EventThread::InterceptVSyncsCallback);

    sp<IDisplayEventConnection> createDisplayEventConnection(const sp<ConnectionHandle>& handle,
                                                             ResyncCallback);

    // Getter methods.
    EventThread* getEventThread(const sp<ConnectionHandle>& handle);

    sp<EventThreadConnection> getEventConnection(const sp<ConnectionHandle>& handle);

    // Should be called when receiving a hotplug event.
    void hotplugReceived(const sp<ConnectionHandle>& handle, PhysicalDisplayId displayId,
                         bool connected);

    // Should be called after the screen is turned on.
    void onScreenAcquired(const sp<ConnectionHandle>& handle);

    // Should be called before the screen is turned off.
    void onScreenReleased(const sp<ConnectionHandle>& handle);

    // Should be called when display config changed
    void onConfigChanged(const sp<ConnectionHandle>& handle, PhysicalDisplayId displayId,
                         int32_t configId);

    // Should be called when dumpsys command is received.
    void dump(const sp<ConnectionHandle>& handle, std::string& result) const;

    // Offers ability to modify phase offset in the event thread.
    void setPhaseOffset(const sp<ConnectionHandle>& handle, nsecs_t phaseOffset);

    // pause/resume vsync callback generation to avoid sending vsync callbacks during config switch
    void pauseVsyncCallback(const sp<ConnectionHandle>& handle, bool pause);

    void getDisplayStatInfo(DisplayStatInfo* stats);

    void enableHardwareVsync();
    void disableHardwareVsync(bool makeUnavailable);
    void resyncToHardwareVsync(bool makeAvailable, nsecs_t period);
    // Creates a callback for resyncing.
    ResyncCallback makeResyncCallback(GetVsyncPeriod&& getVsyncPeriod);
    void setRefreshSkipCount(int count);
    void addResyncSample(const nsecs_t timestamp);
    void addPresentFence(const std::shared_ptr<FenceTime>& fenceTime);
    void setIgnorePresentFences(bool ignore);
    nsecs_t expectedPresentTime();
    // Adds the present time for given layer to the history of present times.
    void addFramePresentTimeForLayer(const nsecs_t framePresentTime, bool isAutoTimestamp,
                                     const std::string layerName);
    // Increments counter in the layer history to indicate that SF has started a new frame.
    void incrementFrameCounter();
    // Callback that gets invoked once the idle timer expires.
    void setExpiredIdleTimerCallback(const ExpiredIdleTimerCallback& expiredTimerCallback);
    // Callback that gets invoked once the idle timer is reset.
    void setResetIdleTimerCallback(const ResetIdleTimerCallback& resetTimerCallback);
    // Returns relevant information about Scheduler for dumpsys purposes.
    std::string doDump();

    // calls DispSync::dump() on primary disp sync
    void dumpPrimaryDispSync(std::string& result) const;

protected:
    virtual std::unique_ptr<EventThread> makeEventThread(
            const char* connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
            impl::EventThread::InterceptVSyncsCallback interceptCallback);

private:
    friend class TestableScheduler;

    // Creates a connection on the given EventThread and forwards the given callbacks.
    sp<EventThreadConnection> createConnectionInternal(EventThread*, ResyncCallback&&);

    nsecs_t calculateAverage() const;
    void updateFrameSkipping(const int64_t skipCount);
    // Collects the statistical mean (average) and median between timestamp
    // intervals for each frame for each layer.
    void determineLayerTimestampStats(const std::string layerName, const nsecs_t framePresentTime);
    // Collects the average difference between timestamps for each frame regardless
    // of which layer the timestamp came from.
    void determineTimestampAverage(bool isAutoTimestamp, const nsecs_t framePresentTime);
    // Function that resets the idle timer.
    void resetIdleTimer();
    // Function that is called when the timer resets.
    void resetTimerCallback();
    // Function that is called when the timer expires.
    void expiredTimerCallback();
    // Sets vsync period.
    void setVsyncPeriod(const nsecs_t period);

    // If fences from sync Framework are supported.
    const bool mHasSyncFramework;

    // The offset in nanoseconds to use, when DispSync timestamps present fence
    // signaling time.
    nsecs_t mDispSyncPresentTimeOffset;

    // Each connection has it's own ID. This variable keeps track of the count.
    static std::atomic<int64_t> sNextId;

    // Connections are stored in a map <connection ID, connection> for easy retrieval.
    std::unordered_map<int64_t, std::unique_ptr<Connection>> mConnections;

    std::mutex mHWVsyncLock;
    bool mPrimaryHWVsyncEnabled GUARDED_BY(mHWVsyncLock);
    bool mHWVsyncAvailable GUARDED_BY(mHWVsyncLock);
    const std::shared_ptr<VsyncState> mPrimaryVsyncState{std::make_shared<VsyncState>(*this)};

    std::unique_ptr<DispSync> mPrimaryDispSync;
    std::unique_ptr<EventControlThread> mEventControlThread;

    // TODO(b/113612090): The following set of variables needs to be revised. For now, this is
    // a proof of concept. We turn on frame skipping if the difference between the timestamps
    // is between 32 and 34ms. We expect this currently for 30fps videos, so we render them at 30Hz.
    nsecs_t mPreviousFrameTimestamp = 0;
    // Keeping track of whether we are skipping the refresh count. If we want to
    // simulate 30Hz rendering, we skip every other frame, and this variable is set
    // to 1.
    int64_t mSkipCount = 0;
    std::array<int64_t, scheduler::ARRAY_SIZE> mTimeDifferences{};
    size_t mCounter = 0;

    // DetermineLayerTimestampStats is called from BufferQueueLayer::onFrameAvailable which
    // can run on any thread, and cause failure.
    std::mutex mLayerHistoryLock;
    LayerHistory mLayerHistory GUARDED_BY(mLayerHistoryLock);

    // Timer that records time between requests for next vsync. If the time is higher than a given
    // interval, a callback is fired. Set this variable to >0 to use this feature.
    int64_t mSetIdleTimerMs = 0;
    std::unique_ptr<scheduler::IdleTimer> mIdleTimer;

    std::mutex mCallbackLock;
    ExpiredIdleTimerCallback mExpiredTimerCallback GUARDED_BY(mCallbackLock);
    ExpiredIdleTimerCallback mResetTimerCallback GUARDED_BY(mCallbackLock);
};

} // namespace android
