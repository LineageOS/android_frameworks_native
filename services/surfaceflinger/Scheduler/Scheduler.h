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

#include "DispSync.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"

namespace android {

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

    Scheduler() = default;
    virtual ~Scheduler();

    /** Creates an EventThread connection. */
    sp<ConnectionHandle> createConnection(
            const std::string& connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
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

protected:
    virtual std::unique_ptr<EventThread> makeEventThread(
            const std::string& connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
            impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
            impl::EventThread::InterceptVSyncsCallback interceptCallback);

private:
    static std::atomic<int64_t> sNextId;
    std::unordered_map<int64_t, std::unique_ptr<Connection>> mConnections;
};

} // namespace android