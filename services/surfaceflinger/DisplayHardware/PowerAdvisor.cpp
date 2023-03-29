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

#include <android/hardware/power/1.3/IPower.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <android/hardware/power/WorkDuration.h>

#include <binder/IServiceManager.h>

#include "../SurfaceFlingerProperties.h"

#include "PowerAdvisor.h"
#include "SurfaceFlinger.h"

namespace android {
namespace Hwc2 {

PowerAdvisor::~PowerAdvisor() = default;

namespace impl {

namespace V1_0 = android::hardware::power::V1_0;
namespace V1_3 = android::hardware::power::V1_3;
using V1_3::PowerHint;

using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::IPowerHintSession;
using android::hardware::power::Mode;
using android::hardware::power::SessionHint;
using android::hardware::power::WorkDuration;

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

PowerAdvisor::PowerAdvisor(SurfaceFlinger& flinger) : mFlinger(flinger) {
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
    if (expected) {
        mExpensiveDisplays.insert(displayId);
    } else {
        mExpensiveDisplays.erase(displayId);
    }

    const bool expectsExpensiveRendering = !mExpensiveDisplays.empty();
    if (mNotifiedExpensiveRendering != expectsExpensiveRendering) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->setExpensiveRendering(expectsExpensiveRendering)) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
        }

        mNotifiedExpensiveRendering = expectsExpensiveRendering;
    }
}

void PowerAdvisor::notifyDisplayUpdateImminentAndCpuReset() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }

    if (mSendUpdateImminent.exchange(false)) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->notifyDisplayUpdateImminentAndCpuReset()) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
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

// checks both if it supports and if it's enabled
bool PowerAdvisor::usePowerHintSession() {
    // uses cached value since the underlying support and flag are unlikely to change at runtime
    return mPowerHintEnabled.value_or(false) && supportsPowerHintSession();
}

bool PowerAdvisor::supportsPowerHintSession() {
    // cache to avoid needing lock every time
    if (!mSupportsPowerHint.has_value()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        mSupportsPowerHint = halWrapper && halWrapper->supportsPowerHintSession();
    }
    return *mSupportsPowerHint;
}

bool PowerAdvisor::isPowerHintSessionRunning() {
    return mPowerHintSessionRunning;
}

void PowerAdvisor::setTargetWorkDuration(Duration targetDuration) {
    if (!usePowerHintSession()) {
        ALOGV("Power hint session target duration cannot be set, skipping");
        return;
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->setTargetWorkDuration(targetDuration);
        }
    }
}

void PowerAdvisor::sendActualWorkDuration() {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Actual work duration power hint cannot be sent, skipping");
        return;
    }
    const std::optional<Duration> actualDuration = estimateWorkDuration(false);
    if (actualDuration.has_value()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->sendActualWorkDuration(*actualDuration + sTargetSafetyMargin,
                                               TimePoint::now());
        }
    }
}

void PowerAdvisor::sendPredictedWorkDuration() {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Actual work duration power hint cannot be sent, skipping");
        return;
    }

    const std::optional<Duration> predictedDuration = estimateWorkDuration(true);
    if (predictedDuration.has_value()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->sendActualWorkDuration(*predictedDuration + sTargetSafetyMargin,
                                               TimePoint::now());
        }
    }
}

void PowerAdvisor::enablePowerHint(bool enabled) {
    mPowerHintEnabled = enabled;
}

bool PowerAdvisor::startPowerHintSession(const std::vector<int32_t>& threadIds) {
    if (!usePowerHintSession()) {
        ALOGI("Power hint session cannot be started, skipping");
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* halWrapper = getPowerHal();
        if (halWrapper != nullptr && usePowerHintSession()) {
            halWrapper->setPowerHintSessionThreadIds(threadIds);
            mPowerHintSessionRunning = halWrapper->startPowerHintSession();
        }
    }
    return mPowerHintSessionRunning;
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

std::optional<Duration> PowerAdvisor::estimateWorkDuration(bool earlyHint) {
    if (earlyHint && (!mExpectedPresentTimes.isFull() || !mCommitStartTimes.isFull())) {
        return std::nullopt;
    }

    // Tracks when we finish presenting to hwc
    TimePoint estimatedEndTime = mCommitStartTimes[0];

    // How long we spent this frame not doing anything, waiting for fences or vsync
    Duration idleDuration = 0ns;

    // Most recent previous gpu end time in the current frame, probably from a prior display, used
    // as the start time for the next gpu operation if it ran over time since it probably blocked
    std::optional<TimePoint> previousValidGpuEndTime;

    // The currently estimated gpu end time for the frame,
    // used to accumulate gpu time as we iterate over the active displays
    std::optional<TimePoint> estimatedGpuEndTime;

    // If we're predicting at the start of the frame, we use last frame as our reference point
    // If we're predicting at the end of the frame, we use the current frame as a reference point
    TimePoint referenceFrameStartTime = (earlyHint ? mCommitStartTimes[-1] : mCommitStartTimes[0]);

    // When the prior frame should be presenting to the display
    // If we're predicting at the start of the frame, we use last frame's expected present time
    // If we're predicting at the end of the frame, the present fence time is already known
    TimePoint lastFramePresentTime =
            (earlyHint ? mExpectedPresentTimes[-1] : mLastPresentFenceTime);

    // The timing info for the previously calculated display, if there was one
    std::optional<DisplayTimeline> previousDisplayReferenceTiming;
    std::vector<DisplayId>&& displayIds =
            getOrderedDisplayIds(&DisplayTimingData::hwcPresentStartTime);
    DisplayTimeline referenceTiming, estimatedTiming;

    // Iterate over the displays that use hwc in the same order they are presented
    for (DisplayId displayId : displayIds) {
        if (mDisplayTimingData.count(displayId) == 0) {
            continue;
        }

        auto& displayData = mDisplayTimingData.at(displayId);

        // mLastPresentFenceTime should always be the time of the reference frame, since it will be
        // the previous frame's present fence if called at the start, and current frame's if called
        // at the end
        referenceTiming = displayData.calculateDisplayTimeline(mLastPresentFenceTime);

        // If this is the first display, include the duration before hwc present starts
        if (!previousDisplayReferenceTiming.has_value()) {
            estimatedEndTime += referenceTiming.hwcPresentStartTime - referenceFrameStartTime;
        } else { // Otherwise add the time since last display's hwc present finished
            estimatedEndTime += referenceTiming.hwcPresentStartTime -
                    previousDisplayReferenceTiming->hwcPresentEndTime;
        }

        // Late hint can re-use reference timing here since it's estimating its own reference frame
        estimatedTiming = earlyHint
                ? referenceTiming.estimateTimelineFromReference(lastFramePresentTime,
                                                                estimatedEndTime)
                : referenceTiming;

        // Update predicted present finish time with this display's present time
        estimatedEndTime = estimatedTiming.hwcPresentEndTime;

        // Track how long we spent waiting for the fence, can be excluded from the timing estimate
        idleDuration += estimatedTiming.probablyWaitsForPresentFence
                ? lastFramePresentTime - estimatedTiming.presentFenceWaitStartTime
                : 0ns;

        // Track how long we spent waiting to present, can be excluded from the timing estimate
        idleDuration += earlyHint ? 0ns : referenceTiming.hwcPresentDelayDuration;

        // Estimate the reference frame's gpu timing
        auto gpuTiming = displayData.estimateGpuTiming(previousValidGpuEndTime);
        if (gpuTiming.has_value()) {
            previousValidGpuEndTime = gpuTiming->startTime + gpuTiming->duration;

            // Estimate the prediction frame's gpu end time from the reference frame
            estimatedGpuEndTime = std::max(estimatedTiming.hwcPresentStartTime,
                                           estimatedGpuEndTime.value_or(TimePoint{0ns})) +
                    gpuTiming->duration;
        }
        previousDisplayReferenceTiming = referenceTiming;
    }
    ATRACE_INT64("Idle duration", idleDuration.ns());

    TimePoint estimatedFlingerEndTime = earlyHint ? estimatedEndTime : mLastSfPresentEndTime;

    // Don't count time spent idly waiting in the estimate as we could do more work in that time
    estimatedEndTime -= idleDuration;
    estimatedFlingerEndTime -= idleDuration;

    // We finish the frame when both present and the gpu are done, so wait for the later of the two
    // Also add the frame delay duration since the target did not move while we were delayed
    Duration totalDuration = mFrameDelayDuration +
            std::max(estimatedEndTime, estimatedGpuEndTime.value_or(TimePoint{0ns})) -
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
    {
        std::lock_guard lock(mPowerHalMutex);
        targetDuration = *getPowerHal()->getTargetWorkDuration();
    }
    if (!mTotalFrameTargetDuration.has_value()) return flingerDuration;

    // Normalize total to the flinger target (vsync period) since that's how often we actually send
    // hints
    Duration normalizedTotalDuration = Duration::fromNs((targetDuration.ns() * totalDuration.ns()) /
                                                        mTotalFrameTargetDuration->ns());
    return std::max(flingerDuration, normalizedTotalDuration);
}

PowerAdvisor::DisplayTimeline PowerAdvisor::DisplayTimeline::estimateTimelineFromReference(
        TimePoint fenceTime, TimePoint displayStartTime) {
    DisplayTimeline estimated;
    estimated.hwcPresentStartTime = displayStartTime;

    // We don't predict waiting for vsync alignment yet
    estimated.hwcPresentDelayDuration = 0ns;

    // How long we expect to run before we start waiting for the fence
    // For now just re-use last frame's post-present duration and assume it will not change much
    // Excludes time spent waiting for vsync since that's not going to be consistent
    estimated.presentFenceWaitStartTime = estimated.hwcPresentStartTime +
            (presentFenceWaitStartTime - (hwcPresentStartTime + hwcPresentDelayDuration));
    estimated.probablyWaitsForPresentFence = fenceTime > estimated.presentFenceWaitStartTime;
    estimated.hwcPresentEndTime = postPresentFenceHwcPresentDuration +
            (estimated.probablyWaitsForPresentFence ? fenceTime
                                                    : estimated.presentFenceWaitStartTime);
    return estimated;
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

class HidlPowerHalWrapper : public PowerAdvisor::HalWrapper {
public:
    HidlPowerHalWrapper(sp<V1_3::IPower> powerHal) : mPowerHal(std::move(powerHal)) {}

    ~HidlPowerHalWrapper() override = default;

    static std::unique_ptr<HalWrapper> connect() {
        // Power HAL 1.3 is not guaranteed to be available, thus we need to query
        // Power HAL 1.0 first and try to cast it to Power HAL 1.3.
        sp<V1_3::IPower> powerHal = nullptr;
        sp<V1_0::IPower> powerHal_1_0 = V1_0::IPower::getService();
        if (powerHal_1_0 != nullptr) {
            // Try to cast to Power HAL 1.3
            powerHal = V1_3::IPower::castFrom(powerHal_1_0);
            if (powerHal == nullptr) {
                ALOGW("No Power HAL 1.3 service in system, disabling PowerAdvisor");
            } else {
                ALOGI("Loaded Power HAL 1.3 service");
            }
        } else {
            ALOGW("No Power HAL found, disabling PowerAdvisor");
        }

        if (powerHal == nullptr) {
            return nullptr;
        }

        return std::make_unique<HidlPowerHalWrapper>(std::move(powerHal));
    }

    bool setExpensiveRendering(bool enabled) override {
        ALOGV("HIDL setExpensiveRendering %s", enabled ? "T" : "F");
        auto ret = mPowerHal->powerHintAsync_1_3(PowerHint::EXPENSIVE_RENDERING, enabled);
        if (ret.isOk()) {
            traceExpensiveRendering(enabled);
        }
        return ret.isOk();
    }

    bool notifyDisplayUpdateImminentAndCpuReset() override {
        // Power HAL 1.x doesn't have a notification for this
        ALOGV("HIDL notifyUpdateImminent received but can't send");
        return true;
    }

    bool supportsPowerHintSession() override { return false; }

    bool isPowerHintSessionRunning() override { return false; }

    void restartPowerHintSession() override {}

    void setPowerHintSessionThreadIds(const std::vector<int32_t>&) override {}

    bool startPowerHintSession() override { return false; }

    void setTargetWorkDuration(Duration) override {}

    void sendActualWorkDuration(Duration, TimePoint) override {}

    bool shouldReconnectHAL() override { return false; }

    std::vector<int32_t> getPowerHintSessionThreadIds() override { return std::vector<int32_t>{}; }

    std::optional<Duration> getTargetWorkDuration() override { return std::nullopt; }

private:
    const sp<V1_3::IPower> mPowerHal = nullptr;
};

AidlPowerHalWrapper::AidlPowerHalWrapper(sp<IPower> powerHal) : mPowerHal(std::move(powerHal)) {
    auto ret = mPowerHal->isModeSupported(Mode::EXPENSIVE_RENDERING, &mHasExpensiveRendering);
    if (!ret.isOk()) {
        mHasExpensiveRendering = false;
    }

    ret = mPowerHal->isBoostSupported(Boost::DISPLAY_UPDATE_IMMINENT, &mHasDisplayUpdateImminent);
    if (!ret.isOk()) {
        mHasDisplayUpdateImminent = false;
    }

    mSupportsPowerHint = checkPowerHintSessionSupported();
}

AidlPowerHalWrapper::~AidlPowerHalWrapper() {
    if (mPowerHintSession != nullptr) {
        mPowerHintSession->close();
        mPowerHintSession = nullptr;
    }
}

std::unique_ptr<PowerAdvisor::HalWrapper> AidlPowerHalWrapper::connect() {
    // This only waits if the service is actually declared
    sp<IPower> powerHal = waitForVintfService<IPower>();
    if (powerHal == nullptr) {
        return nullptr;
    }
    ALOGI("Loaded AIDL Power HAL service");

    return std::make_unique<AidlPowerHalWrapper>(std::move(powerHal));
}

bool AidlPowerHalWrapper::setExpensiveRendering(bool enabled) {
    ALOGV("AIDL setExpensiveRendering %s", enabled ? "T" : "F");
    if (!mHasExpensiveRendering) {
        ALOGV("Skipped sending EXPENSIVE_RENDERING because HAL doesn't support it");
        return true;
    }

    auto ret = mPowerHal->setMode(Mode::EXPENSIVE_RENDERING, enabled);
    if (ret.isOk()) {
        traceExpensiveRendering(enabled);
    }
    return ret.isOk();
}

bool AidlPowerHalWrapper::notifyDisplayUpdateImminentAndCpuReset() {
    ALOGV("AIDL notifyDisplayUpdateImminentAndCpuReset");
    if (isPowerHintSessionRunning()) {
        mPowerHintSession->sendHint(SessionHint::CPU_LOAD_RESET);
    }

    if (!mHasDisplayUpdateImminent) {
        ALOGV("Skipped sending DISPLAY_UPDATE_IMMINENT because HAL doesn't support it");
        return true;
    }

    auto ret = mPowerHal->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 0);
    return ret.isOk();
}

// Only version 2+ of the aidl supports power hint sessions, hidl has no support
bool AidlPowerHalWrapper::supportsPowerHintSession() {
    return mSupportsPowerHint;
}

bool AidlPowerHalWrapper::checkPowerHintSessionSupported() {
    int64_t unused;
    // Try to get preferred rate to determine if hint sessions are supported
    // We check for isOk not EX_UNSUPPORTED_OPERATION to lump together errors
    return mPowerHal->getHintSessionPreferredRate(&unused).isOk();
}

bool AidlPowerHalWrapper::isPowerHintSessionRunning() {
    return mPowerHintSession != nullptr;
}

void AidlPowerHalWrapper::closePowerHintSession() {
    if (mPowerHintSession != nullptr) {
        mPowerHintSession->close();
        mPowerHintSession = nullptr;
    }
}

void AidlPowerHalWrapper::restartPowerHintSession() {
    closePowerHintSession();
    startPowerHintSession();
}

void AidlPowerHalWrapper::setPowerHintSessionThreadIds(const std::vector<int32_t>& threadIds) {
    if (threadIds != mPowerHintThreadIds) {
        mPowerHintThreadIds = threadIds;
        if (isPowerHintSessionRunning()) {
            restartPowerHintSession();
        }
    }
}

bool AidlPowerHalWrapper::startPowerHintSession() {
    if (mPowerHintSession != nullptr || mPowerHintThreadIds.empty()) {
        ALOGV("Cannot start power hint session, skipping");
        return false;
    }
    auto ret = mPowerHal->createHintSession(getpid(), static_cast<int32_t>(getuid()),
                                            mPowerHintThreadIds, mTargetDuration.ns(),
                                            &mPowerHintSession);
    if (!ret.isOk()) {
        ALOGW("Failed to start power hint session with error: %s",
              ret.exceptionToString(ret.exceptionCode()).c_str());
    } else {
        mLastTargetDurationSent = mTargetDuration;
    }
    return isPowerHintSessionRunning();
}

void AidlPowerHalWrapper::setTargetWorkDuration(Duration targetDuration) {
    ATRACE_CALL();
    mTargetDuration = targetDuration;
    if (sTraceHintSessionData) ATRACE_INT64("Time target", targetDuration.ns());
    if (isPowerHintSessionRunning() && (targetDuration != mLastTargetDurationSent)) {
        ALOGV("Sending target time: %" PRId64 "ns", targetDuration.ns());
        mLastTargetDurationSent = targetDuration;
        auto ret = mPowerHintSession->updateTargetWorkDuration(targetDuration.ns());
        if (!ret.isOk()) {
            ALOGW("Failed to set power hint target work duration with error: %s",
                  ret.exceptionMessage().c_str());
            mShouldReconnectHal = true;
        }
    }
}

void AidlPowerHalWrapper::sendActualWorkDuration(Duration actualDuration, TimePoint timestamp) {
    ATRACE_CALL();
    if (actualDuration < 0ns || !isPowerHintSessionRunning()) {
        ALOGV("Failed to send actual work duration, skipping");
        return;
    }
    mActualDuration = actualDuration;
    WorkDuration duration;
    duration.durationNanos = actualDuration.ns();
    duration.timeStampNanos = timestamp.ns();
    mPowerHintQueue.push_back(duration);

    if (sTraceHintSessionData) {
        ATRACE_INT64("Measured duration", actualDuration.ns());
        ATRACE_INT64("Target error term", Duration{actualDuration - mTargetDuration}.ns());

        ATRACE_INT64("Reported duration", actualDuration.ns());
        ATRACE_INT64("Reported target", mLastTargetDurationSent.ns());
        ATRACE_INT64("Reported target error term",
                     Duration{actualDuration - mLastTargetDurationSent}.ns());
    }

    ALOGV("Sending actual work duration of: %" PRId64 " on reported target: %" PRId64
          " with error: %" PRId64,
          actualDuration.ns(), mLastTargetDurationSent.ns(),
          Duration{actualDuration - mLastTargetDurationSent}.ns());

    auto ret = mPowerHintSession->reportActualWorkDuration(mPowerHintQueue);
    if (!ret.isOk()) {
        ALOGW("Failed to report actual work durations with error: %s",
              ret.exceptionMessage().c_str());
        mShouldReconnectHal = true;
    }
    mPowerHintQueue.clear();
}

bool AidlPowerHalWrapper::shouldReconnectHAL() {
    return mShouldReconnectHal;
}

std::vector<int32_t> AidlPowerHalWrapper::getPowerHintSessionThreadIds() {
    return mPowerHintThreadIds;
}

std::optional<Duration> AidlPowerHalWrapper::getTargetWorkDuration() {
    return mTargetDuration;
}

const bool AidlPowerHalWrapper::sTraceHintSessionData =
        base::GetBoolProperty(std::string("debug.sf.trace_hint_sessions"), false);

const Duration PowerAdvisor::sTargetSafetyMargin = std::chrono::microseconds(
        base::GetIntProperty<int64_t>("debug.sf.hint_margin_us",
                                      ticks<std::micro>(PowerAdvisor::kDefaultTargetSafetyMargin)));

PowerAdvisor::HalWrapper* PowerAdvisor::getPowerHal() {
    if (!mHasHal) {
        return nullptr;
    }

    // Grab old hint session values before we destroy any existing wrapper
    std::vector<int32_t> oldPowerHintSessionThreadIds;
    std::optional<Duration> oldTargetWorkDuration;

    if (mHalWrapper != nullptr) {
        oldPowerHintSessionThreadIds = mHalWrapper->getPowerHintSessionThreadIds();
        oldTargetWorkDuration = mHalWrapper->getTargetWorkDuration();
    }

    // If we used to have a HAL, but it stopped responding, attempt to reconnect
    if (mReconnectPowerHal) {
        mHalWrapper = nullptr;
        mReconnectPowerHal = false;
    }

    if (mHalWrapper != nullptr) {
        auto wrapper = mHalWrapper.get();
        // If the wrapper is fine, return it, but if it indicates a reconnect, remake it
        if (!wrapper->shouldReconnectHAL()) {
            return wrapper;
        }
        ALOGD("Reconnecting Power HAL");
        mHalWrapper = nullptr;
    }

    // At this point, we know for sure there is no running session
    mPowerHintSessionRunning = false;

    // First attempt to connect to the AIDL Power HAL
    mHalWrapper = AidlPowerHalWrapper::connect();

    // If that didn't succeed, attempt to connect to the HIDL Power HAL
    if (mHalWrapper == nullptr) {
        mHalWrapper = HidlPowerHalWrapper::connect();
    } else {
        ALOGD("Successfully connecting AIDL Power HAL");
        // If AIDL, pass on any existing hint session values
        mHalWrapper->setPowerHintSessionThreadIds(oldPowerHintSessionThreadIds);
        // Only set duration and start if duration is defined
        if (oldTargetWorkDuration.has_value()) {
            mHalWrapper->setTargetWorkDuration(*oldTargetWorkDuration);
            // Only start if possible to run and both threadids and duration are defined
            if (usePowerHintSession() && !oldPowerHintSessionThreadIds.empty()) {
                mPowerHintSessionRunning = mHalWrapper->startPowerHintSession();
            }
        }
    }

    // If we make it to this point and still don't have a HAL, it's unlikely we
    // will, so stop trying
    if (mHalWrapper == nullptr) {
        mHasHal = false;
    }

    return mHalWrapper.get();
}

} // namespace impl
} // namespace Hwc2
} // namespace android
