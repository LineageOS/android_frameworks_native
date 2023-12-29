/*
 * Copyright 2023 The Android Open Source Project
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

#include <array>
#include <atomic>
#include <memory>
#include <optional>

#include <ui/DisplayId.h>
#include <ui/Fence.h>
#include <ui/FenceTime.h>

#include <scheduler/Features.h>
#include <scheduler/Time.h>
#include <scheduler/VsyncId.h>
#include <scheduler/interface/CompositeResult.h>

// TODO(b/185536303): Pull to FTL.
#include "../../../TracedOrdinal.h"
#include "../../../Utils/Dumper.h"

namespace android::scheduler {

struct IVsyncSource;

// Read-only interface to the metrics computed by FrameTargeter for the latest frame.
class FrameTarget {
public:
    VsyncId vsyncId() const { return mVsyncId; }

    // The time when the frame actually began, as opposed to when it had been scheduled to begin.
    TimePoint frameBeginTime() const { return mFrameBeginTime; }

    // Relative to when the frame actually began, as opposed to when it had been scheduled to begin.
    Duration expectedFrameDuration() const { return mExpectedPresentTime - mFrameBeginTime; }

    TimePoint expectedPresentTime() const { return mExpectedPresentTime; }

    std::optional<TimePoint> earliestPresentTime() const { return mEarliestPresentTime; }

    // The time of the VSYNC that preceded this frame. See `presentFenceForPastVsync` for details.
    TimePoint pastVsyncTime(Period minFramePeriod) const;

    // The present fence for the frame that had targeted the most recent VSYNC before this frame.
    // If the target VSYNC for any given frame is more than `vsyncPeriod` in the future, then the
    // VSYNC of at least one previous frame has not yet passed. In other words, this is NOT the
    // `presentFenceForPreviousFrame` if running N VSYNCs ahead, but the one that should have been
    // signaled by now (unless that frame missed).
    const FenceTimePtr& presentFenceForPastVsync(Period minFramePeriod) const;

    // Equivalent to `presentFenceForPastVsync` unless running N VSYNCs ahead.
    const FenceTimePtr& presentFenceForPreviousFrame() const {
        return mPresentFences.front().fenceTime;
    }

    bool isFramePending() const { return mFramePending; }
    bool didMissFrame() const { return mFrameMissed; }
    bool didMissHwcFrame() const { return mHwcFrameMissed && !mGpuFrameMissed; }

protected:
    explicit FrameTarget(const std::string& displayLabel);
    ~FrameTarget() = default;

    bool wouldPresentEarly(Period minFramePeriod) const;

    // Equivalent to `pastVsyncTime` unless running N VSYNCs ahead.
    TimePoint previousFrameVsyncTime(Period minFramePeriod) const {
        return mExpectedPresentTime - minFramePeriod;
    }

    VsyncId mVsyncId;
    TimePoint mFrameBeginTime;
    TimePoint mExpectedPresentTime;
    std::optional<TimePoint> mEarliestPresentTime;

    TracedOrdinal<bool> mFramePending;
    TracedOrdinal<bool> mFrameMissed;
    TracedOrdinal<bool> mHwcFrameMissed;
    TracedOrdinal<bool> mGpuFrameMissed;

    struct FenceWithFenceTime {
        sp<Fence> fence = Fence::NO_FENCE;
        FenceTimePtr fenceTime = FenceTime::NO_FENCE;
    };
    std::array<FenceWithFenceTime, 2> mPresentFences;

private:
    friend class FrameTargeterTestBase;

    template <int N>
    inline bool targetsVsyncsAhead(Period minFramePeriod) const {
        static_assert(N > 1);
        return expectedFrameDuration() > (N - 1) * minFramePeriod;
    }
};

// Computes a display's per-frame metrics about past/upcoming targeting of present deadlines.
class FrameTargeter final : private FrameTarget {
public:
    FrameTargeter(PhysicalDisplayId displayId, FeatureFlags flags)
          : FrameTarget(to_string(displayId)),
            mBackpressureGpuComposition(flags.test(Feature::kBackpressureGpuComposition)),
            mSupportsExpectedPresentTime(flags.test(Feature::kExpectedPresentTime)) {}

    const FrameTarget& target() const { return *this; }

    struct BeginFrameArgs {
        TimePoint frameBeginTime;
        VsyncId vsyncId;
        TimePoint expectedVsyncTime;
        Duration sfWorkDuration;
        Duration hwcMinWorkDuration;
    };

    void beginFrame(const BeginFrameArgs&, const IVsyncSource&);

    std::optional<TimePoint> computeEarliestPresentTime(Period minFramePeriod,
                                                        Duration hwcMinWorkDuration);

    // TODO(b/241285191): Merge with FrameTargeter::endFrame.
    FenceTimePtr setPresentFence(sp<Fence>);

    void endFrame(const CompositeResult&);

    void dump(utils::Dumper&) const;

private:
    friend class FrameTargeterTestBase;

    // For tests.
    using IsFencePendingFuncPtr = bool (*)(const FenceTimePtr&, int graceTimeMs);
    void beginFrame(const BeginFrameArgs&, const IVsyncSource&, IsFencePendingFuncPtr);
    FenceTimePtr setPresentFence(sp<Fence>, FenceTimePtr);

    static bool isFencePending(const FenceTimePtr&, int graceTimeMs);

    const bool mBackpressureGpuComposition;
    const bool mSupportsExpectedPresentTime;

    TimePoint mScheduledPresentTime;
    CompositionCoverageFlags mCompositionCoverage;

    std::atomic_uint mFrameMissedCount = 0;
    std::atomic_uint mHwcFrameMissedCount = 0;
    std::atomic_uint mGpuFrameMissedCount = 0;
};

} // namespace android::scheduler
