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

#include <gui/ISurfaceComposer.h>
#include <ui/DisplayStatInfo.h>

#include "DispSync.h"
#include "EventControlThread.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"

namespace android {

class EventControlThread;

class Scheduler {
public:
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
        Connection(sp<ConnectionHandle> handle, sp<BnDisplayEventConnection> eventConnection,
                   std::unique_ptr<EventThread> eventThread)
              : handle(handle), eventConnection(eventConnection), thread(std::move(eventThread)) {}

        ~Connection() = default;

        sp<ConnectionHandle> handle;
        sp<BnDisplayEventConnection> eventConnection;
        const std::unique_ptr<EventThread> thread;
    };

    explicit Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function);

    virtual ~Scheduler();

    /** Creates an EventThread connection. */
    sp<ConnectionHandle> createConnection(
            const std::string& connectionName, int64_t phaseOffsetNs,
            impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
            impl::EventThread::InterceptVSyncsCallback interceptCallback);

    sp<IDisplayEventConnection> createDisplayEventConnection(const sp<ConnectionHandle>& handle);

    // Getter methods.
    EventThread* getEventThread(const sp<ConnectionHandle>& handle);

    sp<BnDisplayEventConnection> getEventConnection(const sp<ConnectionHandle>& handle);

    // Should be called when receiving a hotplug event.
    void hotplugReceived(const sp<ConnectionHandle>& handle, EventThread::DisplayType displayType,
                         bool connected);

    // Should be called after the screen is turned on.
    void onScreenAcquired(const sp<ConnectionHandle>& handle);

    // Should be called before the screen is turned off.
    void onScreenReleased(const sp<ConnectionHandle>& handle);

    // Should be called when dumpsys command is received.
    void dump(const sp<ConnectionHandle>& handle, String8& result) const;

    // Offers ability to modify phase offset in the event thread.
    void setPhaseOffset(const sp<ConnectionHandle>& handle, nsecs_t phaseOffset);

    void getDisplayStatInfo(DisplayStatInfo* stats);

    void enableHardwareVsync();
    void disableHardwareVsync(bool makeUnavailable);
    void setVsyncPeriod(const nsecs_t period);
    void addResyncSample(const nsecs_t timestamp);
    void addPresentFence(const std::shared_ptr<FenceTime>& fenceTime);
    void setIgnorePresentFences(bool ignore);
    void makeHWSyncAvailable(bool makeAvailable);
    void addNewFrameTimestamp(const nsecs_t newFrameTimestamp, bool isAutoTimestamp);

protected:
    virtual std::unique_ptr<EventThread> makeEventThread(
            const std::string& connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
            impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
            impl::EventThread::InterceptVSyncsCallback interceptCallback);

private:
    nsecs_t calculateAverage() const;
    void updateFrameSkipping(const int64_t skipCount);

    // TODO(b/113612090): Instead of letting BufferQueueLayer to access mDispSync directly, it
    // should make request to Scheduler to compute next refresh.
    friend class BufferQueueLayer;

    // If fences from sync Framework are supported.
    const bool mHasSyncFramework;

    // The offset in nanoseconds to use, when DispSync timestamps present fence
    // signaling time.
    const nsecs_t mDispSyncPresentTimeOffset;

    // Each connection has it's own ID. This variable keeps track of the count.
    static std::atomic<int64_t> sNextId;

    // Connections are stored in a map <connection ID, connection> for easy retrieval.
    std::unordered_map<int64_t, std::unique_ptr<Connection>> mConnections;

    std::mutex mHWVsyncLock;
    bool mPrimaryHWVsyncEnabled GUARDED_BY(mHWVsyncLock);
    bool mHWVsyncAvailable GUARDED_BY(mHWVsyncLock);

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
    static constexpr size_t ARRAY_SIZE = 30;
    std::array<int64_t, ARRAY_SIZE> mTimeDifferences;
    size_t mCounter = 0;
};

} // namespace android
