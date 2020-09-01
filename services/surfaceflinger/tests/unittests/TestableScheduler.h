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
#include "Scheduler/LayerHistory.h"
#include "Scheduler/Scheduler.h"

namespace android {

class TestableScheduler : public Scheduler, private ISchedulerCallback {
public:
    TestableScheduler(const scheduler::RefreshRateConfigs& configs, bool useContentDetectionV2)
          : Scheduler([](bool) {}, configs, *this, useContentDetectionV2, true) {
        if (mUseContentDetectionV2) {
            mLayerHistory = std::make_unique<scheduler::impl::LayerHistoryV2>(configs);
        } else {
            mLayerHistory = std::make_unique<scheduler::impl::LayerHistory>();
        }
    }

    TestableScheduler(std::unique_ptr<DispSync> primaryDispSync,
                      std::unique_ptr<EventControlThread> eventControlThread,
                      const scheduler::RefreshRateConfigs& configs, bool useContentDetectionV2)
          : Scheduler(std::move(primaryDispSync), std::move(eventControlThread), configs, *this,
                      useContentDetectionV2, true) {
        if (mUseContentDetectionV2) {
            mLayerHistory = std::make_unique<scheduler::impl::LayerHistoryV2>(configs);
        } else {
            mLayerHistory = std::make_unique<scheduler::impl::LayerHistory>();
        }
    }

    // Used to inject mock event thread.
    ConnectionHandle createConnection(std::unique_ptr<EventThread> eventThread) {
        return Scheduler::createConnection(std::move(eventThread));
    }

    size_t layerHistorySize() const NO_THREAD_SAFETY_ANALYSIS {
        if (mUseContentDetectionV2) {
            return static_cast<scheduler::impl::LayerHistoryV2*>(mLayerHistory.get())
                    ->mLayerInfos.size();
        } else {
            return static_cast<scheduler::impl::LayerHistory*>(mLayerHistory.get())
                    ->mLayerInfos.size();
        }
    }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */
    auto& mutablePrimaryHWVsyncEnabled() { return mPrimaryHWVsyncEnabled; }
    auto& mutableEventControlThread() { return mEventControlThread; }
    auto& mutablePrimaryDispSync() { return mPrimaryDispSync; }
    auto& mutableHWVsyncAvailable() { return mHWVsyncAvailable; }
    auto mutableLayerHistory() {
        return static_cast<scheduler::impl::LayerHistory*>(mLayerHistory.get());
    }
    auto mutableLayerHistoryV2() {
        return static_cast<scheduler::impl::LayerHistoryV2*>(mLayerHistory.get());
    }

    ~TestableScheduler() {
        // All these pointer and container clears help ensure that GMock does
        // not report a leaked object, since the Scheduler instance may
        // still be referenced by something despite our best efforts to destroy
        // it after each test is done.
        mutableEventControlThread().reset();
        mutablePrimaryDispSync().reset();
        mConnections.clear();
    }

private:
    void changeRefreshRate(const RefreshRate&, ConfigEvent) override {}
    void repaintEverythingForHWC() override {}
    void kernelTimerChanged(bool /*expired*/) override {}
};

} // namespace android
