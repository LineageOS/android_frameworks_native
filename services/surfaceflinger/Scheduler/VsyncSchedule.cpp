/*
 * Copyright 2021 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <common/FlagManager.h>

#include <ftl/fake_guard.h>
#include <gui/TraceUtils.h>
#include <scheduler/Fps.h>
#include <scheduler/Timer.h>

#include "VsyncSchedule.h"

#include "Utils/Dumper.h"
#include "VSyncDispatchTimerQueue.h"
#include "VSyncPredictor.h"
#include "VSyncReactor.h"

#include "../TracedOrdinal.h"

namespace android::scheduler {

class VsyncSchedule::PredictedVsyncTracer {
    // Invoked from the thread of the VsyncDispatch owned by this VsyncSchedule.
    constexpr auto makeVsyncCallback() {
        return [this](nsecs_t, nsecs_t, nsecs_t) {
            mParity = !mParity;
            schedule();
        };
    }

public:
    explicit PredictedVsyncTracer(std::shared_ptr<VsyncDispatch> dispatch)
          : mRegistration(std::move(dispatch), makeVsyncCallback(), __func__) {
        schedule();
    }

private:
    void schedule() { mRegistration.schedule({0, 0, 0}); }

    TracedOrdinal<bool> mParity = {"VSYNC-predicted", 0};
    VSyncCallbackRegistration mRegistration;
};

VsyncSchedule::VsyncSchedule(ftl::NonNull<DisplayModePtr> modePtr, FeatureFlags features,
                             RequestHardwareVsync requestHardwareVsync)
      : mId(modePtr->getPhysicalDisplayId()),
        mRequestHardwareVsync(std::move(requestHardwareVsync)),
        mTracker(createTracker(modePtr)),
        mDispatch(createDispatch(mTracker)),
        mController(createController(modePtr->getPhysicalDisplayId(), *mTracker, features)),
        mTracer(features.test(Feature::kTracePredictedVsync)
                        ? std::make_unique<PredictedVsyncTracer>(mDispatch)
                        : nullptr) {}

VsyncSchedule::VsyncSchedule(PhysicalDisplayId id, TrackerPtr tracker, DispatchPtr dispatch,
                             ControllerPtr controller, RequestHardwareVsync requestHardwareVsync)
      : mId(id),
        mRequestHardwareVsync(std::move(requestHardwareVsync)),
        mTracker(std::move(tracker)),
        mDispatch(std::move(dispatch)),
        mController(std::move(controller)) {}

VsyncSchedule::~VsyncSchedule() = default;

Period VsyncSchedule::period() const {
    return Period::fromNs(mTracker->currentPeriod());
}

Period VsyncSchedule::minFramePeriod() const {
    if (FlagManager::getInstance().vrr_config()) {
        return mTracker->minFramePeriod();
    }
    return period();
}

TimePoint VsyncSchedule::vsyncDeadlineAfter(TimePoint timePoint,
                                            ftl::Optional<TimePoint> lastVsyncOpt) const {
    return TimePoint::fromNs(
            mTracker->nextAnticipatedVSyncTimeFrom(timePoint.ns(),
                                                   lastVsyncOpt.transform(
                                                           [](TimePoint t) { return t.ns(); })));
}

void VsyncSchedule::dump(std::string& out) const {
    utils::Dumper dumper(out);
    {
        std::lock_guard<std::mutex> lock(mHwVsyncLock);
        dumper.dump("hwVsyncState", ftl::enum_string(mHwVsyncState));

        ftl::FakeGuard guard(kMainThreadContext);
        dumper.dump("pendingHwVsyncState", ftl::enum_string(mPendingHwVsyncState));
        dumper.eol();
    }

    out.append("VsyncController:\n");
    mController->dump(out);

    out.append("VsyncDispatch:\n");
    mDispatch->dump(out);
}

VsyncSchedule::TrackerPtr VsyncSchedule::createTracker(ftl::NonNull<DisplayModePtr> modePtr) {
    // TODO(b/144707443): Tune constants.
    constexpr size_t kHistorySize = 20;
    constexpr size_t kMinSamplesForPrediction = 6;
    constexpr uint32_t kDiscardOutlierPercent = 20;

    return std::make_unique<VSyncPredictor>(modePtr, kHistorySize, kMinSamplesForPrediction,
                                            kDiscardOutlierPercent);
}

VsyncSchedule::DispatchPtr VsyncSchedule::createDispatch(TrackerPtr tracker) {
    using namespace std::chrono_literals;

    // TODO(b/144707443): Tune constants.
    constexpr std::chrono::nanoseconds kGroupDispatchWithin = 500us;
    constexpr std::chrono::nanoseconds kSnapToSameVsyncWithin = 3ms;

    return std::make_unique<VSyncDispatchTimerQueue>(std::make_unique<Timer>(), std::move(tracker),
                                                     kGroupDispatchWithin.count(),
                                                     kSnapToSameVsyncWithin.count());
}

VsyncSchedule::ControllerPtr VsyncSchedule::createController(PhysicalDisplayId id,
                                                             VsyncTracker& tracker,
                                                             FeatureFlags features) {
    // TODO(b/144707443): Tune constants.
    constexpr size_t kMaxPendingFences = 20;
    const bool hasKernelIdleTimer = features.test(Feature::kKernelIdleTimer);

    auto reactor = std::make_unique<VSyncReactor>(id, std::make_unique<SystemClock>(), tracker,
                                                  kMaxPendingFences, hasKernelIdleTimer);

    reactor->setIgnorePresentFences(!features.test(Feature::kPresentFences));
    return reactor;
}

void VsyncSchedule::onDisplayModeChanged(ftl::NonNull<DisplayModePtr> modePtr, bool force) {
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    mController->onDisplayModeChanged(modePtr, force);
    enableHardwareVsyncLocked();
}

bool VsyncSchedule::addResyncSample(TimePoint timestamp, ftl::Optional<Period> hwcVsyncPeriod) {
    bool needsHwVsync = false;
    bool periodFlushed = false;
    {
        std::lock_guard<std::mutex> lock(mHwVsyncLock);
        if (mHwVsyncState == HwVsyncState::Enabled) {
            needsHwVsync = mController->addHwVsyncTimestamp(timestamp.ns(),
                                                            hwcVsyncPeriod.transform(&Period::ns),
                                                            &periodFlushed);
        }
    }
    if (needsHwVsync) {
        enableHardwareVsync();
    } else {
        constexpr bool kDisallow = false;
        disableHardwareVsync(kDisallow);
    }
    return periodFlushed;
}

void VsyncSchedule::enableHardwareVsync() {
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    enableHardwareVsyncLocked();
}

void VsyncSchedule::enableHardwareVsyncLocked() {
    ATRACE_CALL();
    if (mHwVsyncState == HwVsyncState::Disabled) {
        getTracker().resetModel();
        mRequestHardwareVsync(mId, true);
        mHwVsyncState = HwVsyncState::Enabled;
    }
}

void VsyncSchedule::disableHardwareVsync(bool disallow) {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    switch (mHwVsyncState) {
        case HwVsyncState::Enabled:
            mRequestHardwareVsync(mId, false);
            [[fallthrough]];
        case HwVsyncState::Disabled:
            mHwVsyncState = disallow ? HwVsyncState::Disallowed : HwVsyncState::Disabled;
            break;
        case HwVsyncState::Disallowed:
            break;
    }
}

bool VsyncSchedule::isHardwareVsyncAllowed(bool makeAllowed) {
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    if (makeAllowed && mHwVsyncState == HwVsyncState::Disallowed) {
        mHwVsyncState = HwVsyncState::Disabled;
    }
    return mHwVsyncState != HwVsyncState::Disallowed;
}

void VsyncSchedule::setPendingHardwareVsyncState(bool enabled) {
    mPendingHwVsyncState = enabled ? HwVsyncState::Enabled : HwVsyncState::Disabled;
}

bool VsyncSchedule::getPendingHardwareVsyncState() const {
    return mPendingHwVsyncState == HwVsyncState::Enabled;
}

} // namespace android::scheduler
