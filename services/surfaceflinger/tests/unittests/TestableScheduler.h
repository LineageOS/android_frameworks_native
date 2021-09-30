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

#include <Scheduler/Scheduler.h>
#include <gmock/gmock.h>
#include <gui/ISurfaceComposer.h>

#include "Scheduler/EventThread.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VSyncTracker.h"
#include "Scheduler/VsyncController.h"
#include "mock/MockVSyncTracker.h"
#include "mock/MockVsyncController.h"

namespace android {

class TestableScheduler : public Scheduler {
public:
    TestableScheduler(const std::shared_ptr<scheduler::RefreshRateConfigs>& refreshRateConfigs,
                      ISchedulerCallback& callback)
          : TestableScheduler(std::make_unique<mock::VsyncController>(),
                              std::make_unique<mock::VSyncTracker>(), refreshRateConfigs,
                              callback) {}

    TestableScheduler(std::unique_ptr<scheduler::VsyncController> vsyncController,
                      std::unique_ptr<scheduler::VSyncTracker> vsyncTracker,
                      const std::shared_ptr<scheduler::RefreshRateConfigs>& refreshRateConfigs,
                      ISchedulerCallback& callback)
          : Scheduler({std::move(vsyncController), std::move(vsyncTracker), nullptr},
                      refreshRateConfigs, callback, createLayerHistory(),
                      {.useContentDetection = true}) {}

    // Used to inject mock event thread.
    ConnectionHandle createConnection(std::unique_ptr<EventThread> eventThread) {
        return Scheduler::createConnection(std::move(eventThread));
    }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */
    auto& mutablePrimaryHWVsyncEnabled() { return mPrimaryHWVsyncEnabled; }
    auto& mutableHWVsyncAvailable() { return mHWVsyncAvailable; }

    bool hasLayerHistory() const { return static_cast<bool>(mLayerHistory); }

    auto* mutableLayerHistory() { return mLayerHistory.get(); }

    size_t layerHistorySize() NO_THREAD_SAFETY_ANALYSIS {
        if (!mLayerHistory) return 0;
        return mutableLayerHistory()->mLayerInfos.size();
    }

    auto refreshRateConfigs() { return holdRefreshRateConfigs(); }

    size_t getNumActiveLayers() NO_THREAD_SAFETY_ANALYSIS {
        if (!mLayerHistory) return 0;
        return mutableLayerHistory()->mActiveLayersEnd;
    }

    void replaceTouchTimer(int64_t millis) {
        if (mTouchTimer) {
            mTouchTimer.reset();
        }
        mTouchTimer.emplace(
                "Testable Touch timer", std::chrono::milliseconds(millis),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    bool isTouchActive() {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        return mFeatures.touch == Scheduler::TouchState::Active;
    }

    void dispatchCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        return Scheduler::dispatchCachedReportedMode();
    }

    void clearOptionalFieldsInFeatures() {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        mFeatures.cachedModeChangedParams.reset();
    }

    void onNonPrimaryDisplayModeChanged(ConnectionHandle handle, DisplayModePtr mode) {
        return Scheduler::onNonPrimaryDisplayModeChanged(handle, mode);
    }

    ~TestableScheduler() {
        // All these pointer and container clears help ensure that GMock does
        // not report a leaked object, since the Scheduler instance may
        // still be referenced by something despite our best efforts to destroy
        // it after each test is done.
        mVsyncSchedule.controller.reset();
        mConnections.clear();
    }
};

} // namespace android
