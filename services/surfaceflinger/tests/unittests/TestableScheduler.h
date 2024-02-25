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

#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <gui/ISurfaceComposer.h>

#include <scheduler/interface/ICompositor.h>

#include "Scheduler/EventThread.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VSyncTracker.h"
#include "Scheduler/VsyncController.h"
#include "Scheduler/VsyncSchedule.h"
#include "mock/MockVSyncDispatch.h"
#include "mock/MockVSyncTracker.h"
#include "mock/MockVsyncController.h"

namespace android {
class TestableSurfaceFlinger;
} // namespace android

namespace android::scheduler {

class TestableScheduler : public Scheduler, private ICompositor {
public:
    TestableScheduler(RefreshRateSelectorPtr selectorPtr,
                      TestableSurfaceFlinger& testableSurfaceFlinger, ISchedulerCallback& callback);

    TestableScheduler(std::unique_ptr<VsyncController> controller,
                      std::shared_ptr<VSyncTracker> tracker, RefreshRateSelectorPtr selectorPtr,
                      surfaceflinger::Factory& factory, TimeStats& timeStats,
                      ISchedulerCallback& schedulerCallback)
          : Scheduler(*this, schedulerCallback,
                      (FeatureFlags)Feature::kContentDetection |
                              Feature::kSmallDirtyContentDetection,
                      factory, selectorPtr->getActiveMode().fps, timeStats) {
        const auto displayId = selectorPtr->getActiveMode().modePtr->getPhysicalDisplayId();
        registerDisplay(displayId, std::move(selectorPtr), std::move(controller),
                        std::move(tracker));

        ON_CALL(*this, postMessage).WillByDefault([](sp<MessageHandler>&& handler) {
            // Execute task to prevent broken promise exception on destruction.
            handler->handleMessage(Message());
        });
    }

    MOCK_METHOD(void, scheduleConfigure, (), (override));
    MOCK_METHOD(void, scheduleFrame, (), (override));
    MOCK_METHOD(void, postMessage, (sp<MessageHandler>&&), (override));

    void doFrameSignal(ICompositor& compositor, VsyncId vsyncId) {
        ftl::FakeGuard guard1(kMainThreadContext);
        ftl::FakeGuard guard2(mDisplayLock);
        Scheduler::onFrameSignal(compositor, vsyncId, TimePoint());
    }

    void setEventThread(Cycle cycle, std::unique_ptr<EventThread> eventThreadPtr) {
        if (cycle == Cycle::Render) {
            mRenderEventThread = std::move(eventThreadPtr);
            mRenderEventConnection = mRenderEventThread->createEventConnection();
        } else {
            mLastCompositeEventThread = std::move(eventThreadPtr);
            mLastCompositeEventConnection = mLastCompositeEventThread->createEventConnection();
        }
    }

    auto refreshRateSelector() { return pacesetterSelectorPtr(); }

    void registerDisplay(
            PhysicalDisplayId displayId, RefreshRateSelectorPtr selectorPtr,
            std::shared_ptr<VSyncTracker> vsyncTracker = std::make_shared<mock::VSyncTracker>()) {
        registerDisplay(displayId, std::move(selectorPtr),
                        std::make_unique<mock::VsyncController>(), vsyncTracker);
    }

    void registerDisplay(PhysicalDisplayId displayId, RefreshRateSelectorPtr selectorPtr,
                         std::unique_ptr<VsyncController> controller,
                         std::shared_ptr<VSyncTracker> tracker) {
        ftl::FakeGuard guard(kMainThreadContext);
        Scheduler::registerDisplayInternal(displayId, std::move(selectorPtr),
                                           std::shared_ptr<VsyncSchedule>(
                                                   new VsyncSchedule(displayId, std::move(tracker),
                                                                     std::make_shared<
                                                                             mock::VSyncDispatch>(),
                                                                     std::move(controller),
                                                                     mockRequestHardwareVsync
                                                                             .AsStdFunction())));
    }

    testing::MockFunction<void(PhysicalDisplayId, bool)> mockRequestHardwareVsync;

    void unregisterDisplay(PhysicalDisplayId displayId) {
        ftl::FakeGuard guard(kMainThreadContext);
        Scheduler::unregisterDisplay(displayId);
    }

    std::optional<PhysicalDisplayId> pacesetterDisplayId() const NO_THREAD_SAFETY_ANALYSIS {
        return mPacesetterDisplayId;
    }

    void setPacesetterDisplay(PhysicalDisplayId displayId) {
        ftl::FakeGuard guard(kMainThreadContext);
        Scheduler::setPacesetterDisplay(displayId);
    }

    std::optional<hal::PowerMode> getDisplayPowerMode(PhysicalDisplayId id) {
        ftl::FakeGuard guard1(kMainThreadContext);
        ftl::FakeGuard guard2(mDisplayLock);
        return mDisplays.get(id).transform(
                [](const Display& display) { return display.powerMode; });
    }

    using Scheduler::resyncAllToHardwareVsync;

    auto& mutableLayerHistory() { return mLayerHistory; }
    auto& mutableAttachedChoreographers() { return mAttachedChoreographers; }

    size_t layerHistorySize() NO_THREAD_SAFETY_ANALYSIS {
        return mLayerHistory.mActiveLayerInfos.size() + mLayerHistory.mInactiveLayerInfos.size();
    }

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

    void setTouchStateAndIdleTimerPolicy(GlobalSignals globalSignals) {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.touch = globalSignals.touch ? TouchState::Active : TouchState::Inactive;
        mPolicy.idleTimer = globalSignals.idle ? TimerState::Expired : TimerState::Reset;
    }

    void setContentRequirements(std::vector<RefreshRateSelector::LayerRequirement> layers) {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.contentRequirements = std::move(layers);
    }

    using Scheduler::DisplayModeChoice;
    using Scheduler::DisplayModeChoiceMap;

    DisplayModeChoiceMap chooseDisplayModes() NO_THREAD_SAFETY_ANALYSIS {
        return Scheduler::chooseDisplayModes();
    }

    void dispatchCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        Scheduler::dispatchCachedReportedMode();
    }

    void clearCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.cachedModeChangedParams.reset();
    }

    void setInitialHwVsyncEnabled(PhysicalDisplayId id, bool enabled) {
        auto schedule = getVsyncSchedule(id);
        std::lock_guard<std::mutex> lock(schedule->mHwVsyncLock);
        schedule->mHwVsyncState = enabled ? VsyncSchedule::HwVsyncState::Enabled
                                          : VsyncSchedule::HwVsyncState::Disabled;
    }

    void updateAttachedChoreographers(
            const surfaceflinger::frontend::LayerHierarchy& layerHierarchy,
            Fps displayRefreshRate) {
        Scheduler::updateAttachedChoreographers(layerHierarchy, displayRefreshRate);
    }

    using Scheduler::onHardwareVsyncRequest;

private:
    // ICompositor overrides:
    void configure() override {}
    bool commit(PhysicalDisplayId, const scheduler::FrameTargets&) override { return false; }
    CompositeResultsPerDisplay composite(PhysicalDisplayId,
                                         const scheduler::FrameTargeters&) override {
        return {};
    }
    void sample() override {}
    void sendNotifyExpectedPresentHint(PhysicalDisplayId) override {}
};

} // namespace android::scheduler
