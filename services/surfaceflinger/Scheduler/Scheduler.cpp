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

std::atomic<int64_t> Scheduler::sNextId = 0;

sp<Scheduler::ConnectionHandle> Scheduler::createConnection(
        const char* connectionName, DispSync* dispSync, int64_t phaseOffsetNs,
        impl::EventThread::ResyncWithRateLimitCallback resyncCallback,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    const int64_t id = sNextId++;
    ALOGV("Creating a connection handle with ID: %" PRId64 "\n", id);

    std::unique_ptr<VSyncSource> eventThreadSource =
            std::make_unique<DispSyncSource>(dispSync, phaseOffsetNs, true, connectionName);
    std::unique_ptr<EventThread> eventThread =
            std::make_unique<impl::EventThread>(std::move(eventThreadSource), resyncCallback,
                                                interceptCallback, connectionName);
    auto connection = std::make_unique<Connection>(new ConnectionHandle(id),
                                                   eventThread->createEventConnection(),
                                                   std::move(eventThread));
    mConnections.insert(std::make_pair(id, std::move(connection)));
    return mConnections[id]->handle;
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        const sp<Scheduler::ConnectionHandle>& handle) {
    if (mConnections.count(handle->id) != 0) {
        return mConnections[handle->id]->thread->createEventConnection();
    }
    return nullptr;
}

EventThread* Scheduler::getEventThread(const sp<Scheduler::ConnectionHandle>& handle) {
    if (mConnections.count(handle->id) != 0) {
        return mConnections[handle->id]->thread.get();
    }
    return nullptr;
}

sp<BnDisplayEventConnection> Scheduler::getEventConnection(const sp<ConnectionHandle>& handle) {
    if (mConnections.find(handle->id) != mConnections.end()) {
        return mConnections[handle->id]->eventConnection;
    }
    return nullptr;
}

void Scheduler::hotplugReceived(const sp<Scheduler::ConnectionHandle>& handle,
                                EventThread::DisplayType displayType, bool connected) {
    if (mConnections.find(handle->id) != mConnections.end()) {
        mConnections[handle->id]->thread->onHotplugReceived(displayType, connected);
    }
}

void Scheduler::onScreenAcquired(const sp<Scheduler::ConnectionHandle>& handle) {
    if (mConnections.find(handle->id) != mConnections.end()) {
        mConnections[handle->id]->thread->onScreenAcquired();
    }
}

void Scheduler::onScreenReleased(const sp<Scheduler::ConnectionHandle>& handle) {
    if (mConnections.find(handle->id) != mConnections.end()) {
        mConnections[handle->id]->thread->onScreenReleased();
    }
}

void Scheduler::dump(const sp<Scheduler::ConnectionHandle>& handle, String8& result) const {
    if (mConnections.find(handle->id) != mConnections.end()) {
        mConnections.at(handle->id)->thread->dump(result);
    }
}

void Scheduler::setPhaseOffset(const sp<Scheduler::ConnectionHandle>& handle, nsecs_t phaseOffset) {
    if (mConnections.find(handle->id) != mConnections.end()) {
        mConnections[handle->id]->thread->setPhaseOffset(phaseOffset);
    }
}
} // namespace android
