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

#include <ftl/enum.h>
#include <scheduler/Features.h>
#include <scheduler/Time.h>
#include <ui/DisplayId.h>

namespace android {
class EventThreadTest;
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
    VsyncSchedule(PhysicalDisplayId, FeatureFlags);
    ~VsyncSchedule();

    Period period() const;
    TimePoint vsyncDeadlineAfter(TimePoint) const;

    // TODO(b/185535769): Hide behind API.
    const VsyncTracker& getTracker() const { return *mTracker; }
    VsyncTracker& getTracker() { return *mTracker; }
    VsyncController& getController() { return *mController; }

    // TODO(b/185535769): Once these are hidden behind the API, they may no
    // longer need to be shared_ptrs.
    using DispatchPtr = std::shared_ptr<VsyncDispatch>;
    using TrackerPtr = std::shared_ptr<VsyncTracker>;

    // TODO(b/185535769): Remove once VsyncSchedule owns all registrations.
    DispatchPtr getDispatch() { return mDispatch; }

    void dump(std::string&) const;

    // Turn on hardware vsyncs, unless mHwVsyncState is Disallowed, in which
    // case this call is ignored.
    void enableHardwareVsync(ISchedulerCallback&) EXCLUDES(mHwVsyncLock);

    // Disable hardware vsyncs. If `disallow` is true, future calls to
    // enableHardwareVsync are ineffective until allowHardwareVsync is called.
    void disableHardwareVsync(ISchedulerCallback&, bool disallow) EXCLUDES(mHwVsyncLock);

    // Restore the ability to enable hardware vsync.
    void allowHardwareVsync() EXCLUDES(mHwVsyncLock);

    // If true, enableHardwareVsync can enable hardware vsync (if not already
    // enabled). If false, enableHardwareVsync does nothing.
    bool isHardwareVsyncAllowed() const EXCLUDES(mHwVsyncLock);

protected:
    using ControllerPtr = std::unique_ptr<VsyncController>;

    // For tests.
    VsyncSchedule(PhysicalDisplayId, TrackerPtr, DispatchPtr, ControllerPtr);

private:
    friend class TestableScheduler;
    friend class android::EventThreadTest;
    friend class android::fuzz::SchedulerFuzzer;

    static TrackerPtr createTracker(PhysicalDisplayId);
    static DispatchPtr createDispatch(TrackerPtr);
    static ControllerPtr createController(PhysicalDisplayId, VsyncTracker&, FeatureFlags);

    mutable std::mutex mHwVsyncLock;
    enum class HwVsyncState {
        // Hardware vsyncs are currently enabled.
        Enabled,

        // Hardware vsyncs are currently disabled. They can be enabled by a call
        // to `enableHardwareVsync`.
        Disabled,

        // Hardware vsyncs are not currently allowed (e.g. because the display
        // is off).
        Disallowed,

        ftl_last = Disallowed,
    };
    HwVsyncState mHwVsyncState GUARDED_BY(mHwVsyncLock) = HwVsyncState::Disallowed;

    // The last state, which may be the current state, or the state prior to setting to Disallowed.
    HwVsyncState mLastHwVsyncState GUARDED_BY(mHwVsyncLock) = HwVsyncState::Disabled;

    class PredictedVsyncTracer;
    using TracerPtr = std::unique_ptr<PredictedVsyncTracer>;

    const PhysicalDisplayId mId;

    // Effectively const except in move constructor.
    TrackerPtr mTracker;
    DispatchPtr mDispatch;
    ControllerPtr mController;
    TracerPtr mTracer;
};

} // namespace android::scheduler
