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

#include <memory>
#include <string>

#include <android-base/thread_annotations.h>
#include <ThreadContext.h>
#include <ftl/enum.h>
#include <ftl/optional.h>
#include <scheduler/Features.h>
#include <scheduler/Time.h>

namespace android {
class EventThreadTest;
class VsyncScheduleTest;
}

namespace android::fuzz {
class SchedulerFuzzer;
}

namespace android::scheduler {

struct ISchedulerCallback;

// TODO(b/185535769): Rename classes, and remove aliases.
class VSyncDispatch;
class VSyncTracker;

class VsyncController;
using VsyncDispatch = VSyncDispatch;
using VsyncTracker = VSyncTracker;

// Schedule that synchronizes to hardware VSYNC of a physical display.
class VsyncSchedule {
public:
    explicit VsyncSchedule(FeatureFlags);
    ~VsyncSchedule();

    Period period() const;
    TimePoint vsyncDeadlineAfter(TimePoint) const;

    // Inform the schedule that the period is changing and the schedule needs to recalibrate
    // itself. The schedule will end the period transition internally. This will
    // enable hardware VSYNCs in order to calibrate.
    //
    // \param [in] period   The period that the system is changing into.
    void startPeriodTransition(ISchedulerCallback&, Period period);

    // Pass a VSYNC sample to VsyncController. Return true if
    // VsyncController detected that the VSYNC period changed. Enable or disable
    // hardware VSYNCs depending on whether more samples are needed.
    bool addResyncSample(ISchedulerCallback&, TimePoint timestamp,
                         ftl::Optional<Period> hwcVsyncPeriod);

    // TODO(b/185535769): Hide behind API.
    const VsyncTracker& getTracker() const { return *mTracker; }
    VsyncTracker& getTracker() { return *mTracker; }
    VsyncController& getController() { return *mController; }

    // TODO(b/185535769): Remove once VsyncSchedule owns all registrations.
    VsyncDispatch& getDispatch() { return *mDispatch; }

    void dump(std::string&) const;

    // Turn on hardware VSYNCs, unless mHwVsyncState is Disallowed, in which
    // case this call is ignored.
    void enableHardwareVsync(ISchedulerCallback&) EXCLUDES(mHwVsyncLock);

    // Disable hardware VSYNCs. If `disallow` is true, future calls to
    // enableHardwareVsync are ineffective until allowHardwareVsync is called.
    void disableHardwareVsync(ISchedulerCallback&, bool disallow) EXCLUDES(mHwVsyncLock);

    // If true, enableHardwareVsync can enable hardware VSYNC (if not already
    // enabled). If false, enableHardwareVsync does nothing.
    bool isHardwareVsyncAllowed(bool makeAllowed) EXCLUDES(mHwVsyncLock);

    void setPendingHardwareVsyncState(bool enabled) REQUIRES(kMainThreadContext);

    bool getPendingHardwareVsyncState() const REQUIRES(kMainThreadContext);

private:
    friend class TestableScheduler;
    friend class android::EventThreadTest;
    friend class android::VsyncScheduleTest;
    friend class android::fuzz::SchedulerFuzzer;

    using TrackerPtr = std::unique_ptr<VsyncTracker>;
    using DispatchPtr = std::unique_ptr<VsyncDispatch>;
    using ControllerPtr = std::unique_ptr<VsyncController>;

    // For tests.
    VsyncSchedule(TrackerPtr, DispatchPtr, ControllerPtr);

    static TrackerPtr createTracker();
    static DispatchPtr createDispatch(VsyncTracker&);
    static ControllerPtr createController(VsyncTracker&, FeatureFlags);

    void enableHardwareVsyncLocked(ISchedulerCallback&) REQUIRES(mHwVsyncLock);

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

    const TrackerPtr mTracker;
    const DispatchPtr mDispatch;
    const ControllerPtr mController;
    const TracerPtr mTracer;
};

} // namespace android::scheduler
