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

#include <gui/TraceUtils.h>

#include <scheduler/FrameTargeter.h>
#include <scheduler/IVsyncSource.h>

namespace android::scheduler {

FrameTarget::FrameTarget(const std::string& displayLabel)
      : mFramePending("PrevFramePending " + displayLabel, false),
        mFrameMissed("PrevFrameMissed " + displayLabel, false),
        mHwcFrameMissed("PrevHwcFrameMissed " + displayLabel, false),
        mGpuFrameMissed("PrevGpuFrameMissed " + displayLabel, false) {}

TimePoint FrameTarget::pastVsyncTime(Period minFramePeriod) const {
    // TODO(b/267315508): Generalize to N VSYNCs.
    const int shift = static_cast<int>(targetsVsyncsAhead<2>(minFramePeriod));
    return mExpectedPresentTime - Period::fromNs(minFramePeriod.ns() << shift);
}

const FenceTimePtr& FrameTarget::presentFenceForPastVsync(Period minFramePeriod) const {
    // TODO(b/267315508): Generalize to N VSYNCs.
    const size_t i = static_cast<size_t>(targetsVsyncsAhead<2>(minFramePeriod));
    return mPresentFences[i].fenceTime;
}

bool FrameTarget::wouldPresentEarly(Period minFramePeriod) const {
    // TODO(b/241285475): Since this is called during `composite`, the calls to `targetsVsyncsAhead`
    // should use `TimePoint::now()` in case of delays since `mFrameBeginTime`.

    // TODO(b/267315508): Generalize to N VSYNCs.
    if (targetsVsyncsAhead<3>(minFramePeriod)) {
        return true;
    }

    const auto fence = presentFenceForPastVsync(minFramePeriod);
    return fence->isValid() && fence->getSignalTime() != Fence::SIGNAL_TIME_PENDING;
}

void FrameTargeter::beginFrame(const BeginFrameArgs& args, const IVsyncSource& vsyncSource) {
    return beginFrame(args, vsyncSource, &FrameTargeter::isFencePending);
}

void FrameTargeter::beginFrame(const BeginFrameArgs& args, const IVsyncSource& vsyncSource,
                               IsFencePendingFuncPtr isFencePendingFuncPtr) {
    mVsyncId = args.vsyncId;
    mFrameBeginTime = args.frameBeginTime;

    // The `expectedVsyncTime`, which was predicted when this frame was scheduled, is normally in
    // the future relative to `frameBeginTime`, but may not be for delayed frames. Adjust
    // `mExpectedPresentTime` accordingly, but not `mScheduledPresentTime`.
    const TimePoint lastScheduledPresentTime = mScheduledPresentTime;
    mScheduledPresentTime = args.expectedVsyncTime;

    const Period vsyncPeriod = vsyncSource.period();
    const Period minFramePeriod = vsyncSource.minFramePeriod();

    // Calculate the expected present time once and use the cached value throughout this frame to
    // make sure all layers are seeing this same value.
    if (args.expectedVsyncTime >= args.frameBeginTime) {
        mExpectedPresentTime = args.expectedVsyncTime;
    } else {
        mExpectedPresentTime = vsyncSource.vsyncDeadlineAfter(args.frameBeginTime);
        if (args.sfWorkDuration > vsyncPeriod) {
            // Inflate the expected present time if we're targeting the next VSYNC.
            mExpectedPresentTime += vsyncPeriod;
        }
    }

    if (!mSupportsExpectedPresentTime) {
        mEarliestPresentTime = computeEarliestPresentTime(minFramePeriod, args.hwcMinWorkDuration);
    }

    ATRACE_FORMAT("%s %" PRId64 " vsyncIn %.2fms%s", __func__, ftl::to_underlying(args.vsyncId),
                  ticks<std::milli, float>(mExpectedPresentTime - TimePoint::now()),
                  mExpectedPresentTime == args.expectedVsyncTime ? "" : " (adjusted)");

    const FenceTimePtr& pastPresentFence = presentFenceForPastVsync(minFramePeriod);

    // In cases where the present fence is about to fire, give it a small grace period instead of
    // giving up on the frame.
    //
    // TODO(b/280667110): The grace period should depend on `sfWorkDuration` and `vsyncPeriod` being
    // approximately equal, not whether backpressure propagation is enabled.
    const int graceTimeForPresentFenceMs = static_cast<int>(
            mBackpressureGpuComposition || !mCompositionCoverage.test(CompositionCoverage::Gpu));

    // Pending frames may trigger backpressure propagation.
    const auto& isFencePending = *isFencePendingFuncPtr;
    mFramePending = pastPresentFence != FenceTime::NO_FENCE &&
            isFencePending(pastPresentFence, graceTimeForPresentFenceMs);

    // A frame is missed if the prior frame is still pending. If no longer pending, then we still
    // count the frame as missed if the predicted present time was further in the past than when the
    // fence actually fired. Add some slop to correct for drift. This should generally be smaller
    // than a typical frame duration, but should not be so small that it reports reasonable drift as
    // a missed frame.
    mFrameMissed = mFramePending || [&] {
        const nsecs_t pastPresentTime = pastPresentFence->getSignalTime();
        if (pastPresentTime < 0) return false;
        const nsecs_t frameMissedSlop = vsyncPeriod.ns() / 2;
        return lastScheduledPresentTime.ns() < pastPresentTime - frameMissedSlop;
    }();

    mHwcFrameMissed = mFrameMissed && mCompositionCoverage.test(CompositionCoverage::Hwc);
    mGpuFrameMissed = mFrameMissed && mCompositionCoverage.test(CompositionCoverage::Gpu);

    if (mFrameMissed) mFrameMissedCount++;
    if (mHwcFrameMissed) mHwcFrameMissedCount++;
    if (mGpuFrameMissed) mGpuFrameMissedCount++;
}

std::optional<TimePoint> FrameTargeter::computeEarliestPresentTime(Period minFramePeriod,
                                                                   Duration hwcMinWorkDuration) {
    if (wouldPresentEarly(minFramePeriod)) {
        return previousFrameVsyncTime(minFramePeriod) - hwcMinWorkDuration;
    }
    return {};
}

void FrameTargeter::endFrame(const CompositeResult& result) {
    mCompositionCoverage = result.compositionCoverage;
}

FenceTimePtr FrameTargeter::setPresentFence(sp<Fence> presentFence) {
    auto presentFenceTime = std::make_shared<FenceTime>(presentFence);
    return setPresentFence(std::move(presentFence), std::move(presentFenceTime));
}

FenceTimePtr FrameTargeter::setPresentFence(sp<Fence> presentFence, FenceTimePtr presentFenceTime) {
    mPresentFences[1] = mPresentFences[0];
    mPresentFences[0] = {std::move(presentFence), presentFenceTime};
    return presentFenceTime;
}

void FrameTargeter::dump(utils::Dumper& dumper) const {
    // There are scripts and tests that expect this (rather than "name=value") format.
    dumper.dump({}, "Total missed frame count: " + std::to_string(mFrameMissedCount));
    dumper.dump({}, "HWC missed frame count: " + std::to_string(mHwcFrameMissedCount));
    dumper.dump({}, "GPU missed frame count: " + std::to_string(mGpuFrameMissedCount));
}

bool FrameTargeter::isFencePending(const FenceTimePtr& fence, int graceTimeMs) {
    ATRACE_CALL();
    const status_t status = fence->wait(graceTimeMs);

    // This is the same as Fence::Status::Unsignaled, but it saves a call to getStatus,
    // which calls wait(0) again internally.
    return status == -ETIME;
}

} // namespace android::scheduler
