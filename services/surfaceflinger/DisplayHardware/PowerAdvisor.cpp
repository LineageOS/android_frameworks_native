/*
 * Copyright 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#undef LOG_TAG
#define LOG_TAG "PowerAdvisor"

#include <unistd.h>
#include <cinttypes>
#include <cstdint>
#include <optional>

#include <android-base/properties.h>
#include <utils/Log.h>
#include <utils/Mutex.h>
#include <utils/Trace.h>

#include <binder/IServiceManager.h>

#include "../SurfaceFlingerProperties.h"

#include "PowerAdvisor.h"
#include "SurfaceFlinger.h"

namespace android {
namespace Hwc2 {

PowerAdvisor::~PowerAdvisor() = default;

namespace impl {

using aidl::android::hardware::power::Boost;
using aidl::android::hardware::power::Mode;
using aidl::android::hardware::power::SessionHint;
using aidl::android::hardware::power::WorkDuration;

PowerAdvisor::~PowerAdvisor() = default;

namespace {
std::chrono::milliseconds getUpdateTimeout() {
    // Default to a timeout of 80ms if nothing else is specified
    static std::chrono::milliseconds timeout =
            std::chrono::milliseconds(sysprop::display_update_imminent_timeout_ms(80));
    return timeout;
}

void traceExpensiveRendering(bool enabled) {
    if (enabled) {
        ATRACE_ASYNC_BEGIN("ExpensiveRendering", 0);
    } else {
        ATRACE_ASYNC_END("ExpensiveRendering", 0);
    }
}

} // namespace

PowerAdvisor::PowerAdvisor(SurfaceFlinger& flinger)
      : mPowerHal(std::make_unique<power::PowerHalController>()), mFlinger(flinger) {
    if (getUpdateTimeout() > 0ms) {
        mScreenUpdateTimer.emplace("UpdateImminentTimer", getUpdateTimeout(),
                                   /* resetCallback */ nullptr,
                                   /* timeoutCallback */
                                   [this] {
                                       while (true) {
                                           auto timeSinceLastUpdate = std::chrono::nanoseconds(
                                                   systemTime() - mLastScreenUpdatedTime.load());
                                           if (timeSinceLastUpdate >= getUpdateTimeout()) {
                                               break;
                                           }
                                           // We may try to disable expensive rendering and allow
                                           // for sending DISPLAY_UPDATE_IMMINENT hints too early if
                                           // we idled very shortly after updating the screen, so
                                           // make sure we wait enough time.
                                           std::this_thread::sleep_for(getUpdateTimeout() -
                                                                       timeSinceLastUpdate);
                                       }
                                       mSendUpdateImminent.store(true);
                                       mFlinger.disableExpensiveRendering();
                                   });
    }
}

void PowerAdvisor::init() {
    // Defer starting the screen update timer until SurfaceFlinger finishes construction.
    if (mScreenUpdateTimer) {
        mScreenUpdateTimer->start();
    }
}

void PowerAdvisor::onBootFinished() {
    mBootFinished.store(true);
}

void PowerAdvisor::setExpensiveRenderingExpected(DisplayId displayId, bool expected) {
    if (!mHasExpensiveRendering) {
        ALOGV("Skipped sending EXPENSIVE_RENDERING because HAL doesn't support it");
        return;
    }
    if (expected) {
        mExpensiveDisplays.insert(displayId);
    } else {
        mExpensiveDisplays.erase(displayId);
    }

    const bool expectsExpensiveRendering = !mExpensiveDisplays.empty();
    if (mNotifiedExpensiveRendering != expectsExpensiveRendering) {
        auto ret = getPowerHal().setMode(Mode::EXPENSIVE_RENDERING, expectsExpensiveRendering);
        if (!ret.isOk()) {
            if (ret.isUnsupported()) {
                mHasExpensiveRendering = false;
            }
            return;
        }

        mNotifiedExpensiveRendering = expectsExpensiveRendering;
        traceExpensiveRendering(mNotifiedExpensiveRendering);
    }
}

void PowerAdvisor::notifyCpuLoadUp() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }
    if (usePowerHintSession()) {
        std::lock_guard lock(mHintSessionMutex);
        if (ensurePowerHintSessionRunning()) {
            auto ret = mHintSession->sendHint(SessionHint::CPU_LOAD_UP);
            if (!ret.isOk()) {
                mHintSession = nullptr;
            }
        }
    }
}

void PowerAdvisor::notifyDisplayUpdateImminentAndCpuReset() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }

    if (mSendUpdateImminent.exchange(false)) {
        ALOGV("AIDL notifyDisplayUpdateImminentAndCpuReset");
        if (usePowerHintSession()) {
            std::lock_guard lock(mHintSessionMutex);
            if (ensurePowerHintSessionRunning()) {
                auto ret = mHintSession->sendHint(SessionHint::CPU_LOAD_RESET);
                if (!ret.isOk()) {
                    mHintSession = nullptr;
                }
            }
        }

        if (!mHasDisplayUpdateImminent) {
            ALOGV("Skipped sending DISPLAY_UPDATE_IMMINENT because HAL doesn't support it");
        } else {
            auto ret = getPowerHal().setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 0);
            if (ret.isUnsupported()) {
                mHasDisplayUpdateImminent = false;
            }
        }

        if (mScreenUpdateTimer) {
            mScreenUpdateTimer->reset();
        } else {
            // If we don't have a screen update timer, then we don't throttle power hal calls so
            // flip this bit back to allow for calling into power hal again.
            mSendUpdateImminent.store(true);
        }
    }

    if (mScreenUpdateTimer) {
        mLastScreenUpdatedTime.store(systemTime());
    }
}

bool PowerAdvisor::usePowerHintSession() {
    // uses cached value since the underlying support and flag are unlikely to change at runtime
    return mHintSessionEnabled.value_or(false) && supportsPowerHintSession();
}

bool PowerAdvisor::supportsPowerHintSession() {
    if (!mSupportsHintSession.has_value()) {
        mSupportsHintSession = getPowerHal().getHintSessionPreferredRate().isOk();
    }
    return *mSupportsHintSession;
}

bool PowerAdvisor::ensurePowerHintSessionRunning() {
    if (mHintSession == nullptr && !mHintSessionThreadIds.empty() && usePowerHintSession()) {
        auto ret = getPowerHal().createHintSession(getpid(), static_cast<int32_t>(getuid()),
                                                   mHintSessionThreadIds, mTargetDuration.ns());

        if (ret.isOk()) {
            mHintSession = ret.value();
        }
    }
    return mHintSession != nullptr;
}

void PowerAdvisor::updateTargetWorkDuration(Duration targetDuration) {
    if (!usePowerHintSession()) {
        ALOGV("Power hint session target duration cannot be set, skipping");
        return;
    }
    ATRACE_CALL();
    {
        mTargetDuration = targetDuration;
        if (sTraceHintSessionData) ATRACE_INT64("Time target", targetDuration.ns());
        if (targetDuration == mLastTargetDurationSent) return;
        std::lock_guard lock(mHintSessionMutex);
        if (ensurePowerHintSessionRunning()) {
            ALOGV("Sending target time: %" PRId64 "ns", targetDuration.ns());
            mLastTargetDurationSent = targetDuration;
            auto ret = mHintSession->updateTargetWorkDuration(targetDuration.ns());
            if (!ret.isOk()) {
                ALOGW("Failed to set power hint target work duration with error: %s",
                      ret.getDescription().c_str());
                mHintSession = nullptr;
            }
        }
    }
}

void PowerAdvisor::reportActualWorkDuration() {
    if (!mBootFinished || !sUseReportActualDuration || !usePowerHintSession()) {
        ALOGV("Actual work duration power hint cannot be sent, skipping");
        return;
    }
    ATRACE_CALL();
    std::optional<Duration> actualDuration = estimateWorkDuration();
    if (!actualDuration.has_value() || actualDuration < 0ns) {
        ALOGV("Failed to send actual work duration, skipping");
        return;
    }
    actualDuration = std::make_optional(*actualDuration + sTargetSafetyMargin);
    mActualDuration = actualDuration;

    if (sTraceHintSessionData) {
        ATRACE_INT64("Measured duration", actualDuration->ns());
        ATRACE_INT64("Target error term", Duration{*actualDuration - mTargetDuration}.ns());
        ATRACE_INT64("Reported duration", actualDuration->ns());
        ATRACE_INT64("Reported target", mLastTargetDurationSent.ns());
        ATRACE_INT64("Reported target error term",
                     Duration{*actualDuration - mLastTargetDurationSent}.ns());
    }

    ALOGV("Sending actual work duration of: %" PRId64 " on reported target: %" PRId64
          " with error: %" PRId64,
          actualDuration->ns(), mLastTargetDurationSent.ns(),
          Duration{*actualDuration - mLastTargetDurationSent}.ns());

    if (mTimingTestingMode) {
        mDelayReportActualMutexAcquisitonPromise.get_future().wait();
        mDelayReportActualMutexAcquisitonPromise = std::promise<bool>{};
    }

    {
        std::lock_guard lock(mHintSessionMutex);
        if (!ensurePowerHintSessionRunning()) {
            ALOGV("Hint session not running and could not be started, skipping");
            return;
        }

        WorkDuration duration{
                .timeStampNanos = TimePoint::now().ns(),
                // TODO(b/284324521): Correctly calculate total duration.
                .durationNanos = actualDuration->ns(),
                .workPeriodStartTimestampNanos = mCommitStartTimes[0].ns(),
                .cpuDurationNanos = actualDuration->ns(),
                // TODO(b/284324521): Calculate RenderEngine GPU time.
                .gpuDurationNanos = 0,
        };
        mHintSessionQueue.push_back(duration);

        auto ret = mHintSession->reportActualWorkDuration(mHintSessionQueue);
        if (!ret.isOk()) {
            ALOGW("Failed to report actual work durations with error: %s",
                  ret.getDescription().c_str());
            mHintSession = nullptr;
            return;
        }
    }
    mHintSessionQueue.clear();
}

void PowerAdvisor::enablePowerHintSession(bool enabled) {
    mHintSessionEnabled = enabled;
}

bool PowerAdvisor::startPowerHintSession(std::vector<int32_t>&& threadIds) {
    mHintSessionThreadIds = threadIds;
    if (!mBootFinished.load()) {
        return false;
    }
    if (!usePowerHintSession()) {
        ALOGI("Cannot start power hint session: disabled or unsupported");
        return false;
    }
    LOG_ALWAYS_FATAL_IF(mHintSessionThreadIds.empty(),
                        "No thread IDs provided to power hint session!");
    std::lock_guard lock(mHintSessionMutex);
    if (mHintSession != nullptr) {
        ALOGE("Cannot start power hint session: already running");
        return false;
    }
    return ensurePowerHintSessionRunning();
}

void PowerAdvisor::setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    if (displayData.gpuEndFenceTime) {
        nsecs_t signalTime = displayData.gpuEndFenceTime->getSignalTime();
        if (signalTime != Fence::SIGNAL_TIME_INVALID && signalTime != Fence::SIGNAL_TIME_PENDING) {
            for (auto&& [_, otherDisplayData] : mDisplayTimingData) {
                // If the previous display started before us but ended after we should have
                // started, then it likely delayed our start time and we must compensate for that.
                // Displays finishing earlier should have already made their way through this call
                // and swapped their timing into "lastValid" from "latest", so we check that here.
                if (!otherDisplayData.lastValidGpuStartTime.has_value()) continue;
                if ((*otherDisplayData.lastValidGpuStartTime < *displayData.gpuStartTime) &&
                    (*otherDisplayData.lastValidGpuEndTime > *displayData.gpuStartTime)) {
                    displayData.lastValidGpuStartTime = *otherDisplayData.lastValidGpuEndTime;
                    break;
                }
            }
            displayData.lastValidGpuStartTime = displayData.gpuStartTime;
            displayData.lastValidGpuEndTime = TimePoint::fromNs(signalTime);
        }
    }
    displayData.gpuEndFenceTime = std::move(fenceTime);
    displayData.gpuStartTime = TimePoint::now();
}

void PowerAdvisor::setHwcValidateTiming(DisplayId displayId, TimePoint validateStartTime,
                                        TimePoint validateEndTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    displayData.hwcValidateStartTime = validateStartTime;
    displayData.hwcValidateEndTime = validateEndTime;
}

void PowerAdvisor::setHwcPresentTiming(DisplayId displayId, TimePoint presentStartTime,
                                       TimePoint presentEndTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    displayData.hwcPresentStartTime = presentStartTime;
    displayData.hwcPresentEndTime = presentEndTime;
}

void PowerAdvisor::setSkippedValidate(DisplayId displayId, bool skipped) {
    mDisplayTimingData[displayId].skippedValidate = skipped;
}

void PowerAdvisor::setRequiresClientComposition(DisplayId displayId,
                                                bool requiresClientComposition) {
    mDisplayTimingData[displayId].usedClientComposition = requiresClientComposition;
}

void PowerAdvisor::setExpectedPresentTime(TimePoint expectedPresentTime) {
    mExpectedPresentTimes.append(expectedPresentTime);
}

void PowerAdvisor::setSfPresentTiming(TimePoint presentFenceTime, TimePoint presentEndTime) {
    mLastSfPresentEndTime = presentEndTime;
    mLastPresentFenceTime = presentFenceTime;
}

void PowerAdvisor::setFrameDelay(Duration frameDelayDuration) {
    mFrameDelayDuration = frameDelayDuration;
}

void PowerAdvisor::setHwcPresentDelayedTime(DisplayId displayId, TimePoint earliestFrameStartTime) {
    mDisplayTimingData[displayId].hwcPresentDelayedTime = earliestFrameStartTime;
}

void PowerAdvisor::setCommitStart(TimePoint commitStartTime) {
    mCommitStartTimes.append(commitStartTime);
}

void PowerAdvisor::setCompositeEnd(TimePoint compositeEndTime) {
    mLastPostcompDuration = compositeEndTime - mLastSfPresentEndTime;
}

void PowerAdvisor::setDisplays(std::vector<DisplayId>& displayIds) {
    mDisplayIds = displayIds;
}

void PowerAdvisor::setTotalFrameTargetWorkDuration(Duration targetDuration) {
    mTotalFrameTargetDuration = targetDuration;
}

std::vector<DisplayId> PowerAdvisor::getOrderedDisplayIds(
        std::optional<TimePoint> DisplayTimingData::*sortBy) {
    std::vector<DisplayId> sortedDisplays;
    std::copy_if(mDisplayIds.begin(), mDisplayIds.end(), std::back_inserter(sortedDisplays),
                 [&](DisplayId id) {
                     return mDisplayTimingData.count(id) &&
                             (mDisplayTimingData[id].*sortBy).has_value();
                 });
    std::sort(sortedDisplays.begin(), sortedDisplays.end(), [&](DisplayId idA, DisplayId idB) {
        return *(mDisplayTimingData[idA].*sortBy) < *(mDisplayTimingData[idB].*sortBy);
    });
    return sortedDisplays;
}

std::optional<Duration> PowerAdvisor::estimateWorkDuration() {
    if (!mExpectedPresentTimes.isFull() || !mCommitStartTimes.isFull()) {
        return std::nullopt;
    }

    // Tracks when we finish presenting to hwc
    TimePoint estimatedHwcEndTime = mCommitStartTimes[0];

    // How long we spent this frame not doing anything, waiting for fences or vsync
    Duration idleDuration = 0ns;

    // Most recent previous gpu end time in the current frame, probably from a prior display, used
    // as the start time for the next gpu operation if it ran over time since it probably blocked
    std::optional<TimePoint> previousValidGpuEndTime;

    // The currently estimated gpu end time for the frame,
    // used to accumulate gpu time as we iterate over the active displays
    std::optional<TimePoint> estimatedGpuEndTime;

    // The timing info for the previously calculated display, if there was one
    std::optional<DisplayTimeline> previousDisplayTiming;
    std::vector<DisplayId>&& displayIds =
            getOrderedDisplayIds(&DisplayTimingData::hwcPresentStartTime);
    DisplayTimeline displayTiming;

    // Iterate over the displays that use hwc in the same order they are presented
    for (DisplayId displayId : displayIds) {
        if (mDisplayTimingData.count(displayId) == 0) {
            continue;
        }

        auto& displayData = mDisplayTimingData.at(displayId);

        displayTiming = displayData.calculateDisplayTimeline(mLastPresentFenceTime);

        // If this is the first display, include the duration before hwc present starts
        if (!previousDisplayTiming.has_value()) {
            estimatedHwcEndTime += displayTiming.hwcPresentStartTime - mCommitStartTimes[0];
        } else { // Otherwise add the time since last display's hwc present finished
            estimatedHwcEndTime +=
                    displayTiming.hwcPresentStartTime - previousDisplayTiming->hwcPresentEndTime;
        }

        // Update predicted present finish time with this display's present time
        estimatedHwcEndTime = displayTiming.hwcPresentEndTime;

        // Track how long we spent waiting for the fence, can be excluded from the timing estimate
        idleDuration += displayTiming.probablyWaitsForPresentFence
                ? mLastPresentFenceTime - displayTiming.presentFenceWaitStartTime
                : 0ns;

        // Track how long we spent waiting to present, can be excluded from the timing estimate
        idleDuration += displayTiming.hwcPresentDelayDuration;

        // Estimate the reference frame's gpu timing
        auto gpuTiming = displayData.estimateGpuTiming(previousValidGpuEndTime);
        if (gpuTiming.has_value()) {
            previousValidGpuEndTime = gpuTiming->startTime + gpuTiming->duration;

            // Estimate the prediction frame's gpu end time from the reference frame
            estimatedGpuEndTime = std::max(displayTiming.hwcPresentStartTime,
                                           estimatedGpuEndTime.value_or(TimePoint{0ns})) +
                    gpuTiming->duration;
        }
        previousDisplayTiming = displayTiming;
    }
    ATRACE_INT64("Idle duration", idleDuration.ns());

    TimePoint estimatedFlingerEndTime = mLastSfPresentEndTime;

    // Don't count time spent idly waiting in the estimate as we could do more work in that time
    estimatedHwcEndTime -= idleDuration;
    estimatedFlingerEndTime -= idleDuration;

    // We finish the frame when both present and the gpu are done, so wait for the later of the two
    // Also add the frame delay duration since the target did not move while we were delayed
    Duration totalDuration = mFrameDelayDuration +
            std::max(estimatedHwcEndTime, estimatedGpuEndTime.value_or(TimePoint{0ns})) -
            mCommitStartTimes[0];

    // We finish SurfaceFlinger when post-composition finishes, so add that in here
    Duration flingerDuration =
            estimatedFlingerEndTime + mLastPostcompDuration - mCommitStartTimes[0];

    // Combine the two timings into a single normalized one
    Duration combinedDuration = combineTimingEstimates(totalDuration, flingerDuration);

    return std::make_optional(combinedDuration);
}

Duration PowerAdvisor::combineTimingEstimates(Duration totalDuration, Duration flingerDuration) {
    Duration targetDuration{0ns};
    targetDuration = mTargetDuration;
    if (!mTotalFrameTargetDuration.has_value()) return flingerDuration;

    // Normalize total to the flinger target (vsync period) since that's how often we actually send
    // hints
    Duration normalizedTotalDuration = Duration::fromNs((targetDuration.ns() * totalDuration.ns()) /
                                                        mTotalFrameTargetDuration->ns());
    return std::max(flingerDuration, normalizedTotalDuration);
}

PowerAdvisor::DisplayTimeline PowerAdvisor::DisplayTimingData::calculateDisplayTimeline(
        TimePoint fenceTime) {
    DisplayTimeline timeline;
    // How long between calling hwc present and trying to wait on the fence
    const Duration fenceWaitStartDelay =
            (skippedValidate ? kFenceWaitStartDelaySkippedValidate : kFenceWaitStartDelayValidated);

    // Did our reference frame wait for an appropriate vsync before calling into hwc
    const bool waitedOnHwcPresentTime = hwcPresentDelayedTime.has_value() &&
            *hwcPresentDelayedTime > *hwcPresentStartTime &&
            *hwcPresentDelayedTime < *hwcPresentEndTime;

    // Use validate start here if we skipped it because we did validate + present together
    timeline.hwcPresentStartTime = skippedValidate ? *hwcValidateStartTime : *hwcPresentStartTime;

    // Use validate end here if we skipped it because we did validate + present together
    timeline.hwcPresentEndTime = skippedValidate ? *hwcValidateEndTime : *hwcPresentEndTime;

    // How long hwc present was delayed waiting for the next appropriate vsync
    timeline.hwcPresentDelayDuration =
            (waitedOnHwcPresentTime ? *hwcPresentDelayedTime - *hwcPresentStartTime : 0ns);
    // When we started waiting for the present fence after calling into hwc present
    timeline.presentFenceWaitStartTime =
            timeline.hwcPresentStartTime + timeline.hwcPresentDelayDuration + fenceWaitStartDelay;
    timeline.probablyWaitsForPresentFence = fenceTime > timeline.presentFenceWaitStartTime &&
            fenceTime < timeline.hwcPresentEndTime;

    // How long we ran after we finished waiting for the fence but before hwc present finished
    timeline.postPresentFenceHwcPresentDuration = timeline.hwcPresentEndTime -
            (timeline.probablyWaitsForPresentFence ? fenceTime
                                                   : timeline.presentFenceWaitStartTime);
    return timeline;
}

std::optional<PowerAdvisor::GpuTimeline> PowerAdvisor::DisplayTimingData::estimateGpuTiming(
        std::optional<TimePoint> previousEndTime) {
    if (!(usedClientComposition && lastValidGpuStartTime.has_value() && gpuEndFenceTime)) {
        return std::nullopt;
    }
    const TimePoint latestGpuStartTime =
            std::max(previousEndTime.value_or(TimePoint{0ns}), *gpuStartTime);
    const nsecs_t gpuEndFenceSignal = gpuEndFenceTime->getSignalTime();
    Duration gpuDuration{0ns};
    if (gpuEndFenceSignal != Fence::SIGNAL_TIME_INVALID &&
        gpuEndFenceSignal != Fence::SIGNAL_TIME_PENDING) {
        const TimePoint latestGpuEndTime = TimePoint::fromNs(gpuEndFenceSignal);

        // If we know how long the most recent gpu duration was, use that
        gpuDuration = latestGpuEndTime - latestGpuStartTime;
    } else if (lastValidGpuEndTime.has_value()) {
        // If we don't have the fence data, use the most recent information we do have
        gpuDuration = *lastValidGpuEndTime - *lastValidGpuStartTime;
        if (gpuEndFenceSignal == Fence::SIGNAL_TIME_PENDING) {
            // If pending but went over the previous duration, use current time as the end
            gpuDuration = std::max(gpuDuration, Duration{TimePoint::now() - latestGpuStartTime});
        }
    }
    return GpuTimeline{.duration = gpuDuration, .startTime = latestGpuStartTime};
}

const bool PowerAdvisor::sTraceHintSessionData =
        base::GetBoolProperty(std::string("debug.sf.trace_hint_sessions"), false);

const Duration PowerAdvisor::sTargetSafetyMargin = std::chrono::microseconds(
        base::GetIntProperty<int64_t>("debug.sf.hint_margin_us",
                                      ticks<std::micro>(PowerAdvisor::kDefaultTargetSafetyMargin)));

const bool PowerAdvisor::sUseReportActualDuration =
        base::GetBoolProperty(std::string("debug.adpf.use_report_actual_duration"), true);

power::PowerHalController& PowerAdvisor::getPowerHal() {
    static std::once_flag halFlag;
    std::call_once(halFlag, [this] { mPowerHal->init(); });
    return *mPowerHal;
}

} // namespace impl
} // namespace Hwc2
} // namespace android
