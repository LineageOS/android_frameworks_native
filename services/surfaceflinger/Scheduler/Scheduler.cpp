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

#include "Scheduler.h"

#include <cinttypes>
#include <cstdint>
#include <memory>

#include <gui/ISurfaceComposer.h>

#include "DispSync.h"
#include "DispSyncSource.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"

namespace android {

#define RETURN_VALUE_IF_INVALID(value) \
    if (handle == nullptr || mConnections.count(handle->id) == 0) return value
#define RETURN_IF_INVALID() \
    if (handle == nullptr || mConnections.count(handle->id) == 0) return

std::atomic<int64_t> Scheduler::sNextId = 0;

Scheduler::~Scheduler() = default;

sp<Scheduler::ConnectionHandle> Scheduler::createConnection(
        const std::string& connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
        impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const int64_t id = sNextId++;
    ALOGV("Creating a connection handle with ID: %" PRId64 "\n", id);

    std::unique_ptr<EventThread> eventThread =
            makeEventThread(connectionName, dispSync, phaseOffsetNs, resyncCallback,
                            interceptCallback);
    auto connection = std::make_unique<Connection>(new ConnectionHandle(id),
                                                   eventThread->createEventConnection(),
                                                   std::move(eventThread));
    mConnections.insert(std::make_pair(id, std::move(connection)));
    return mConnections[id]->handle;
}

std::unique_ptr<EventThread> Scheduler::makeEventThread(
        const std::string& connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
        impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const std::string sourceName = connectionName + "Source";
    std::unique_ptr<VSyncSource> eventThreadSource =
            std::make_unique<DispSyncSource>(dispSync, phaseOffsetNs, true, sourceName.c_str());
    const std::string threadName = connectionName + "Thread";
    return std::make_unique<impl::EventThread>(std::move(eventThreadSource), resyncCallback,
                                               interceptCallback, threadName.c_str());
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->thread->createEventConnection();
}

EventThread* Scheduler::getEventThread(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->thread.get();
}

sp<BnDisplayEventConnection> Scheduler::getEventConnection(const sp<ConnectionHandle>& handle) {
    RETURN_VALUE_IF_INVALID(nullptr);
    return mConnections[handle->id]->eventConnection;
}

void Scheduler::hotplugReceived(const sp<Scheduler::ConnectionHandle>& handle,
                                EventThread::DisplayType displayType, bool connected) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onHotplugReceived(displayType, connected);
}

void Scheduler::onScreenAcquired(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onScreenAcquired();
}

void Scheduler::onScreenReleased(const sp<Scheduler::ConnectionHandle>& handle) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->onScreenReleased();
}

void Scheduler::dump(const sp<Scheduler::ConnectionHandle>& handle, String8& result) const {
    RETURN_IF_INVALID();
    mConnections.at(handle->id)->thread->dump(result);
}

void Scheduler::setPhaseOffset(const sp<Scheduler::ConnectionHandle>& handle, nsecs_t phaseOffset) {
    RETURN_IF_INVALID();
    mConnections[handle->id]->thread->setPhaseOffset(phaseOffset);
}
} // namespace android
