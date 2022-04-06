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

namespace android::scheduler {

class TestableScheduler : public Scheduler, private ICompositor {
public:
    TestableScheduler(std::shared_ptr<RefreshRateConfigs> configs, ISchedulerCallback& callback)
          : TestableScheduler(std::make_unique<mock::VsyncController>(),
                              std::make_unique<mock::VSyncTracker>(), std::move(configs),
                              callback) {}

    TestableScheduler(std::unique_ptr<VsyncController> controller,
                      std::unique_ptr<VSyncTracker> tracker,
                      std::shared_ptr<RefreshRateConfigs> configs, ISchedulerCallback& callback)
          : Scheduler(*this, callback, Feature::kContentDetection) {
        mVsyncSchedule.emplace(VsyncSchedule(std::move(tracker), nullptr, std::move(controller)));
        setRefreshRateConfigs(std::move(configs));

        ON_CALL(*this, postMessage).WillByDefault([](sp<MessageHandler>&& handler) {
            // Execute task to prevent broken promise exception on destruction.
            handler->handleMessage(Message());
        });
    }

    MOCK_METHOD(void, scheduleFrame, (), (override));
    MOCK_METHOD(void, postMessage, (sp<MessageHandler>&&), (override));

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

    auto& mutableLayerHistory() { return mLayerHistory; }

    size_t layerHistorySize() NO_THREAD_SAFETY_ANALYSIS {
        return mLayerHistory.mActiveLayerInfos.size() + mLayerHistory.mInactiveLayerInfos.size();
    }

    auto refreshRateConfigs() { return holdRefreshRateConfigs(); }

    size_t getNumActiveLayers() NO_THREAD_SAFETY_ANALYSIS {
        return mLayerHistory.mActiveLayerInfos.size();
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
        std::lock_guard<std::mutex> lock(mPolicyLock);
        return mPolicy.touch == Scheduler::TouchState::Active;
    }

    void dispatchCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        return Scheduler::dispatchCachedReportedMode();
    }

    void clearCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.cachedModeChangedParams.reset();
    }

    void onNonPrimaryDisplayModeChanged(ConnectionHandle handle, DisplayModePtr mode) {
        return Scheduler::onNonPrimaryDisplayModeChanged(handle, mode);
    }

private:
    // ICompositor overrides:
    bool commit(nsecs_t, int64_t, nsecs_t) override { return false; }
    void composite(nsecs_t, int64_t) override {}
    void sample() override {}
};

} // namespace android::scheduler
