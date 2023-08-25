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

#include <ftl/fake_guard.h>
#include <scheduler/Fps.h>
#include <scheduler/Timer.h>

#include "VsyncSchedule.h"

#include "ISchedulerCallback.h"
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

VsyncSchedule::VsyncSchedule(PhysicalDisplayId id, FeatureFlags features)
      : mId(id),
        mTracker(createTracker(id)),
        mDispatch(createDispatch(mTracker)),
        mController(createController(id, *mTracker, features)),
        mTracer(features.test(Feature::kTracePredictedVsync)
                        ? std::make_unique<PredictedVsyncTracer>(mDispatch)
                        : nullptr) {}

VsyncSchedule::VsyncSchedule(PhysicalDisplayId id, TrackerPtr tracker, DispatchPtr dispatch,
                             ControllerPtr controller)
      : mId(id),
        mTracker(std::move(tracker)),
        mDispatch(std::move(dispatch)),
        mController(std::move(controller)) {}

VsyncSchedule::~VsyncSchedule() = default;

Period VsyncSchedule::period() const {
    return Period::fromNs(mTracker->currentPeriod());
}

TimePoint VsyncSchedule::vsyncDeadlineAfter(TimePoint timePoint) const {
    return TimePoint::fromNs(mTracker->nextAnticipatedVSyncTimeFrom(timePoint.ns()));
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

VsyncSchedule::TrackerPtr VsyncSchedule::createTracker(PhysicalDisplayId id) {
    // TODO(b/144707443): Tune constants.
    constexpr nsecs_t kInitialPeriod = (60_Hz).getPeriodNsecs();
    constexpr size_t kHistorySize = 20;
    constexpr size_t kMinSamplesForPrediction = 6;
    constexpr uint32_t kDiscardOutlierPercent = 20;

    return std::make_unique<VSyncPredictor>(id, kInitialPeriod, kHistorySize,
                                            kMinSamplesForPrediction, kDiscardOutlierPercent);
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

void VsyncSchedule::startPeriodTransition(ISchedulerCallback& callback, Period period, bool force) {
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    mController->startPeriodTransition(period.ns(), force);
    enableHardwareVsyncLocked(callback);
}

bool VsyncSchedule::addResyncSample(ISchedulerCallback& callback, TimePoint timestamp,
                                    ftl::Optional<Period> hwcVsyncPeriod) {
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
        enableHardwareVsync(callback);
    } else {
        disableHardwareVsync(callback, false /* disallow */);
    }
    return periodFlushed;
}

void VsyncSchedule::enableHardwareVsync(ISchedulerCallback& callback) {
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    enableHardwareVsyncLocked(callback);
}

void VsyncSchedule::enableHardwareVsyncLocked(ISchedulerCallback& callback) {
    if (mHwVsyncState == HwVsyncState::Disabled) {
        getTracker().resetModel();
        callback.setVsyncEnabled(mId, true);
        mHwVsyncState = HwVsyncState::Enabled;
    }
}

void VsyncSchedule::disableHardwareVsync(ISchedulerCallback& callback, bool disallow) {
    std::lock_guard<std::mutex> lock(mHwVsyncLock);
    switch (mHwVsyncState) {
        case HwVsyncState::Enabled:
            callback.setVsyncEnabled(mId, false);
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
