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

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <android-base/thread_annotations.h>
#include <ThreadContext.h>
#include <ftl/enum.h>
#include <ftl/optional.h>
#include <ui/DisplayId.h>

#include <scheduler/Features.h>
#include <scheduler/IVsyncSource.h>
#include <scheduler/Time.h>

#include "ThreadContext.h"
#include "VSyncTracker.h"

namespace android {
class EventThreadTest;
class VsyncScheduleTest;
}

namespace android::fuzz {
class SchedulerFuzzer;
}

namespace android::scheduler {

// TODO(b/185535769): Rename classes, and remove aliases.
class VSyncDispatch;
class VSyncTracker;

class VsyncController;
using VsyncDispatch = VSyncDispatch;
using VsyncTracker = VSyncTracker;

// Schedule that synchronizes to hardware VSYNC of a physical display.
class VsyncSchedule final : public IVsyncSource {
public:
    using RequestHardwareVsync = std::function<void(PhysicalDisplayId, bool enabled)>;

    VsyncSchedule(ftl::NonNull<DisplayModePtr> modePtr, FeatureFlags, RequestHardwareVsync);
    ~VsyncSchedule();

    // IVsyncSource overrides:
    Period period() const override;
    TimePoint vsyncDeadlineAfter(TimePoint,
                                 ftl::Optional<TimePoint> lastVsyncOpt = {}) const override;
    Period minFramePeriod() const override;

    // Inform the schedule that the display mode changed the schedule needs to recalibrate
    // itself to the new vsync period. The schedule will end the period transition internally.
    // This will enable hardware VSYNCs in order to calibrate.
    //
    // \param [in] DisplayModePtr  The mode that the display is changing to.
    // \param [in] force    True to force a transition even if it is not a
    //                      change.
    void onDisplayModeChanged(ftl::NonNull<DisplayModePtr>, bool force);

    // Pass a VSYNC sample to VsyncController. Return true if
    // VsyncController detected that the VSYNC period changed. Enable or disable
    // hardware VSYNCs depending on whether more samples are needed.
    bool addResyncSample(TimePoint timestamp, ftl::Optional<Period> hwcVsyncPeriod);

    // TODO(b/185535769): Hide behind API.
    VsyncTracker& getTracker() const { return *mTracker; }
    VsyncTracker& getTracker() { return *mTracker; }
    VsyncController& getController() { return *mController; }

    // TODO(b/185535769): Once these are hidden behind the API, they may no
    // longer need to be shared_ptrs.
    using DispatchPtr = std::shared_ptr<VsyncDispatch>;
    using TrackerPtr = std::shared_ptr<VsyncTracker>;

    // TODO(b/185535769): Remove once VsyncSchedule owns all registrations.
    DispatchPtr getDispatch() { return mDispatch; }

    void dump(std::string&) const;

    // Turn on hardware VSYNCs, unless mHwVsyncState is Disallowed, in which
    // case this call is ignored.
    void enableHardwareVsync() EXCLUDES(mHwVsyncLock);

    // Disable hardware VSYNCs. If `disallow` is true, future calls to
    // enableHardwareVsync are ineffective until isHardwareVsyncAllowed is
    // called with `makeAllowed` set to true.
    void disableHardwareVsync(bool disallow) EXCLUDES(mHwVsyncLock);

    // If true, enableHardwareVsync can enable hardware VSYNC (if not already
    // enabled). If false, enableHardwareVsync does nothing.
    bool isHardwareVsyncAllowed(bool makeAllowed) EXCLUDES(mHwVsyncLock);

    void setPendingHardwareVsyncState(bool enabled) REQUIRES(kMainThreadContext);

    bool getPendingHardwareVsyncState() const REQUIRES(kMainThreadContext);

protected:
    using ControllerPtr = std::unique_ptr<VsyncController>;

    static void NoOpRequestHardwareVsync(PhysicalDisplayId, bool) {}

    // For tests.
    VsyncSchedule(PhysicalDisplayId, TrackerPtr, DispatchPtr, ControllerPtr,
                  RequestHardwareVsync = NoOpRequestHardwareVsync);

private:
    friend class TestableScheduler;
    friend class android::EventThreadTest;
    friend class android::VsyncScheduleTest;
    friend class android::fuzz::SchedulerFuzzer;

    static TrackerPtr createTracker(ftl::NonNull<DisplayModePtr> modePtr);
    static DispatchPtr createDispatch(TrackerPtr);
    static ControllerPtr createController(PhysicalDisplayId, VsyncTracker&, FeatureFlags);

    void enableHardwareVsyncLocked() REQUIRES(mHwVsyncLock);

    mutable std::mutex mHwVsyncLock;
    enum class HwVsyncState {
        // Hardware VSYNCs are currently enabled.
        Enabled,

        // Hardware VSYNCs are currently disabled. They can be enabled by a call
        // to `enableHardwareVsync`.
        Disabled,

        // Hardware VSYNCs are not currently allowed (e.g. because the display
        // is off).
        Disallowed,

        ftl_last = Disallowed,
    };
    HwVsyncState mHwVsyncState GUARDED_BY(mHwVsyncLock) = HwVsyncState::Disallowed;

    // Pending state, in case an attempt is made to set the state while the
    // device is off.
    HwVsyncState mPendingHwVsyncState GUARDED_BY(kMainThreadContext) = HwVsyncState::Disabled;

    class PredictedVsyncTracer;
    using TracerPtr = std::unique_ptr<PredictedVsyncTracer>;

    const PhysicalDisplayId mId;
    const RequestHardwareVsync mRequestHardwareVsync;
    const TrackerPtr mTracker;
    const DispatchPtr mDispatch;
    const ControllerPtr mController;
    const TracerPtr mTracer;
};

} // namespace android::scheduler
