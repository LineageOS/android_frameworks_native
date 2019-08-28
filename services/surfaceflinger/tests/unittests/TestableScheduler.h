/*
 * Copyright 2019 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gui/ISurfaceComposer.h>

#include "Scheduler/DispSync.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/Scheduler.h"

namespace android {

class TestableScheduler : public Scheduler {
public:
    explicit TestableScheduler(const scheduler::RefreshRateConfigs& configs)
          : Scheduler([](bool) {}, configs) {}

    TestableScheduler(std::unique_ptr<DispSync> primaryDispSync,
                      std::unique_ptr<EventControlThread> eventControlThread,
                      const scheduler::RefreshRateConfigs& configs)
          : Scheduler(std::move(primaryDispSync), std::move(eventControlThread), configs) {}

    // Used to inject mock event thread.
    ConnectionHandle createConnection(std::unique_ptr<EventThread> eventThread) {
        return Scheduler::createConnection(std::move(eventThread));
    }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */
    auto& mutablePrimaryHWVsyncEnabled() { return mPrimaryHWVsyncEnabled; }
    auto& mutableEventControlThread() { return mEventControlThread; }
    auto& mutablePrimaryDispSync() { return mPrimaryDispSync; }
    auto& mutableHWVsyncAvailable() { return mHWVsyncAvailable; }

    ~TestableScheduler() {
        // All these pointer and container clears help ensure that GMock does
        // not report a leaked object, since the Scheduler instance may
        // still be referenced by something despite our best efforts to destroy
        // it after each test is done.
        mutableEventControlThread().reset();
        mutablePrimaryDispSync().reset();
        mConnections.clear();
    }
};

} // namespace android
