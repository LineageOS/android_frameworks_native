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

// #define LOG_NDEBUG 0

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <unistd.h>
#include <cinttypes>
#include <cstdint>
#include <functional>
#include <optional>

#include <android-base/properties.h>
#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_libbinder.h>
#include <android/binder_manager.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <common/WorkloadTracer.h>
#include <common/trace.h>
#include <ftl/concat.h>
#include <utils/Log.h>
#include <utils/Mutex.h>

#include <binder/IServiceManager.h>

#include <powermanager/PowerHalController.h>
#include <powermanager/PowerHintSessionWrapper.h>

#include <common/FlagManager.h>
#include "PowerAdvisor.h"
#include "SessionManager.h"

namespace android::adpf::impl {

using namespace android::ftl::flag_operators;
using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using android::hardware::EventFlag;

using ChannelMessageContents = hal::ChannelMessage::ChannelMessageContents;
using MsgQueue = android::AidlMessageQueue<hal::ChannelMessage, SynchronizedReadWrite>;
using FlagQueue = android::AidlMessageQueue<int8_t, SynchronizedReadWrite>;

PowerAdvisor::~PowerAdvisor() {
    {
        std::lock_guard lock(mRefreshRateMutex);
        mRefreshRateStopped = true;
    }
    mRefreshRateCv.notify_one();
    if (mRefreshRateThread.joinable()) {
        mRefreshRateThread.join();
    }
}

namespace {
void traceExpensiveRendering(bool enabled) {
    if (enabled) {
        SFTRACE_ASYNC_BEGIN("ExpensiveRendering", 0);
    } else {
        SFTRACE_ASYNC_END("ExpensiveRendering", 0);
    }
}

static constexpr ftl::Flags<Workload> TRIGGER_LOAD_CHANGE_HINTS = Workload::EFFECTS |
        Workload::VISIBLE_REGION | Workload::DISPLAY_CHANGES | Workload::SCREENSHOT;

constexpr const char* kPowerHalInstance = "android.hardware.power.IPower/default";
constexpr const char* kPowerExtDescriptor = "google.hardware.power.extension.pixel.IPowerExt";
constexpr const char* kRefreshRateHintProperty = "debug.sf.adpf_refresh_rate_hint";

// IPowerExt is a vendor AIDL, so call it over raw binder instead of linking it.
AIBinder_Class* getPowerExtClass() {
    static AIBinder_Class* const clazz = AIBinder_Class_define(
            kPowerExtDescriptor, [](void*) -> void* { return nullptr; }, [](void*) {},
            [](AIBinder*, transaction_code_t, const AParcel*, AParcel*) -> binder_status_t {
                return STATUS_UNKNOWN_TRANSACTION;
            });
    return clazz;
}

constexpr std::chrono::seconds kRefreshRateRetryDelay{1};
constexpr int32_t kHintedRefreshRates[] = {60, 90, 120};

std::string refreshRateHint(int32_t refreshRate) {
    return "REFRESH_" + std::to_string(refreshRate) + "HZ";
}
} // namespace

PowerAdvisor::PowerAdvisor(std::function<void()>&& sfDisableExpensiveFn,
                           std::chrono::milliseconds timeout)
      : mPowerHal(std::make_unique<power::PowerHalController>()) {
    if (timeout > 0ms) {
        mScreenUpdateTimer.emplace("UpdateImminentTimer", timeout,
                                   /* resetCallback */ nullptr,
                                   /* timeoutCallback */
                                   [this, disableExpensiveFn = std::move(sfDisableExpensiveFn),
                                    timeout] {
                                       while (true) {
                                           auto timeSinceLastUpdate = std::chrono::nanoseconds(
                                                   systemTime() - mLastScreenUpdatedTime.load());
                                           if (timeSinceLastUpdate >= timeout) {
                                               break;
                                           }
                                           // We may try to disable expensive rendering and allow
                                           // for sending DISPLAY_UPDATE_IMMINENT hints too early if
                                           // we idled very shortly after updating the screen, so
                                           // make sure we wait enough time.
                                           std::this_thread::sleep_for(timeout -
                                                                       timeSinceLastUpdate);
                                       }
                                       mSendUpdateImminent.store(true);
                                       disableExpensiveFn();
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

void PowerAdvisor::setOptimizeForPerformance(bool enabled) {
    mOptimizeForPerformance.store(enabled);
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
        auto ret = getPowerHal().setMode(hal::Mode::EXPENSIVE_RENDERING, expectsExpensiveRendering);
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
    sendHintSessionHint(hal::SessionHint::CPU_LOAD_UP);
}

void PowerAdvisor::notifyDisplayUpdateImminentAndCpuReset() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }

    if (mSendUpdateImminent.exchange(false)) {
        ALOGV("AIDL notifyDisplayUpdateImminentAndCpuReset");
        sendHintSessionHint(hal::SessionHint::CPU_LOAD_RESET);

        if (!mHasDisplayUpdateImminent) {
            ALOGV("Skipped sending DISPLAY_UPDATE_IMMINENT because HAL doesn't support it");
        } else {
            auto ret = getPowerHal().setBoost(hal::Boost::DISPLAY_UPDATE_IMMINENT, 0);
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
    return mHintSessionEnabled.value_or(false) && supportsPowerHintSession() &&
            mOptimizeForPerformance.load();
}

bool PowerAdvisor::supportsPowerHintSession() {
    if (!mSupportsHintSession.has_value()) {
        mSupportsHintSession = getPowerHal().getHintSessionPreferredRate().isOk();
    }
    return *mSupportsHintSession;
}

bool PowerAdvisor::shouldCreateSessionWithConfig() {
    return mSessionConfigSupported && mBootFinished;
}

void PowerAdvisor::sendHintSessionHint(hal::SessionHint hint) {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Power hint session is not enabled, skip sending session hint");
        return;
    }
    SFTRACE_CALL();
    SFTRACE_INT("Session hint", static_cast<int>(hint));
    {
        std::scoped_lock lock(mHintSessionMutex);
        if (!ensurePowerHintSessionRunning()) {
            ALOGV("Hint session not running and could not be started, skip sending session hint");
            return;
        }
        ALOGV("Sending session hint: %d", static_cast<int>(hint));
        if (!writeHintSessionMessage<ChannelMessageContents::Tag::hint>(&hint, 1)) {
            auto ret = mHintSession->sendHint(hint);
            if (!ret.isOk()) {
                ALOGW("Failed to send session hint with error: %s", ret.errorMessage());
                mHintSession = nullptr;
            }
        }
    }
}

bool PowerAdvisor::ensurePowerHintSessionRunning() {
    if (mHintSession == nullptr && !mHintSessionThreadIds.empty() && usePowerHintSession()) {
        if (shouldCreateSessionWithConfig()) {
            auto ret = getPowerHal().createHintSessionWithConfig(getpid(),
                                                                 static_cast<int32_t>(getuid()),
                                                                 mHintSessionThreadIds,
                                                                 mTargetDuration.ns(),
                                                                 hal::SessionTag::SURFACEFLINGER,
                                                                 &mSessionConfig);
            if (ret.isOk()) {
                mHintSession = ret.value();
                setUpFmq();
            }
            // If it fails the first time we try, or ever returns unsupported, assume unsupported
            else if (mFirstConfigSupportCheck || ret.isUnsupported()) {
                ALOGI("Hint session with config is unsupported, falling back to a legacy session");
                mSessionConfigSupported = false;
            }
            mFirstConfigSupportCheck = false;
        }
        // Immediately try original method after, in case the first way returned unsupported
        if (mHintSession == nullptr && !shouldCreateSessionWithConfig()) {
            auto ret = getPowerHal().createHintSession(getpid(), static_cast<int32_t>(getuid()),
                                                       mHintSessionThreadIds, mTargetDuration.ns());
            if (ret.isOk()) {
                mHintSession = ret.value();
            }
        }
    }
    return mHintSession != nullptr;
}

void PowerAdvisor::setUpFmq() {
    auto&& channelRet = getPowerHal().getSessionChannel(getpid(), static_cast<int32_t>(getuid()));
    if (!channelRet.isOk()) {
        ALOGE("Failed to get session channel with error: %s", channelRet.errorMessage());
        return;
    }
    auto& channelConfig = channelRet.value();
    mMsgQueue = std::make_unique<MsgQueue>(std::move(channelConfig.channelDescriptor), true);
    LOG_ALWAYS_FATAL_IF(!mMsgQueue->isValid(), "Failed to set up hint session msg queue");
    LOG_ALWAYS_FATAL_IF(channelConfig.writeFlagBitmask <= 0,
                        "Invalid flag bit masks found in channel config: writeBitMask(%d)",
                        channelConfig.writeFlagBitmask);
    mFmqWriteMask = static_cast<uint32_t>(channelConfig.writeFlagBitmask);
    if (!channelConfig.eventFlagDescriptor.has_value()) {
        // For FMQ v1 in Android 15 we will force using shared event flag since the default
        // no-op FMQ impl in Power HAL v5 will always return a valid channel config with
        // non-zero masks but no shared flag.
        mMsgQueue = nullptr;
        ALOGE("No event flag descriptor found in channel config");
        return;
    }
    mFlagQueue = std::make_unique<FlagQueue>(std::move(*channelConfig.eventFlagDescriptor), true);
    LOG_ALWAYS_FATAL_IF(!mFlagQueue->isValid(), "Failed to set up hint session flag queue");
    auto status = EventFlag::createEventFlag(mFlagQueue->getEventFlagWord(), &mEventFlag);
    LOG_ALWAYS_FATAL_IF(status != OK, "Failed to set up hint session event flag");
}

void PowerAdvisor::updateTargetWorkDuration(Duration targetDuration) {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Power hint session is not enabled, skipping target update");
        return;
    }
    SFTRACE_CALL();
    {
        mTargetDuration = targetDuration;
        SFTRACE_INT64("Target Work Duration", targetDuration.ns());
        if (targetDuration == mLastTargetDurationSent) return;
        std::scoped_lock lock(mHintSessionMutex);
        if (!ensurePowerHintSessionRunning()) {
            ALOGV("Hint session not running and could not be started, skip updating target");
            return;
        }
        ALOGV("Sending target time: %" PRId64 "ns", targetDuration.ns());
        mLastTargetDurationSent = targetDuration;
        auto target = targetDuration.ns();
        if (!writeHintSessionMessage<ChannelMessageContents::Tag::targetDuration>(&target, 1)) {
            auto ret = mHintSession->updateTargetWorkDuration(targetDuration.ns());
            if (!ret.isOk()) {
                ALOGW("Failed to set power hint target work duration with error: %s",
                      ret.errorMessage());
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
    SFTRACE_CALL();
    std::optional<hal::WorkDuration> actualDuration = estimateWorkDuration();
    if (!actualDuration.has_value() || actualDuration->durationNanos < 0) {
        ALOGV("Failed to send actual work duration, skipping");
        return;
    }
    actualDuration->durationNanos += sTargetSafetyMargin.ns();
    SFTRACE_INT64("Reported Work Duration", actualDuration->durationNanos);
    if (supportsGpuReporting()) {
        SFTRACE_INT64("Reported cpu duration", actualDuration->cpuDurationNanos);
        SFTRACE_INT64("Reported gpu duration", actualDuration->gpuDurationNanos);
    }

    if (sTraceHintSessionData) {
        SFTRACE_INT64("Measured duration", actualDuration->durationNanos);
        SFTRACE_INT64("Target error term", actualDuration->durationNanos - mTargetDuration.ns());
        SFTRACE_INT64("Reported target", mLastTargetDurationSent.ns());
        SFTRACE_INT64("Reported target error term",
                      actualDuration->durationNanos - mLastTargetDurationSent.ns());
    }

    ALOGV("Sending actual work duration of: %" PRId64 " with cpu: %" PRId64 " and gpu: %" PRId64
          " on reported target: %" PRId64 " with error: %" PRId64,
          actualDuration->durationNanos, actualDuration->cpuDurationNanos,
          actualDuration->gpuDurationNanos, mLastTargetDurationSent.ns(),
          actualDuration->durationNanos - mLastTargetDurationSent.ns());

    if (mTimingTestingMode) {
        mDelayReportActualMutexAcquisitonPromise.get_future().wait();
        mDelayReportActualMutexAcquisitonPromise = std::promise<bool>{};
    }

    {
        std::scoped_lock lock(mHintSessionMutex);
        if (!ensurePowerHintSessionRunning()) {
            ALOGV("Hint session not running and could not be started, skip reporting durations");
            return;
        }
        mHintSessionQueue.push_back(*actualDuration);
        if (!writeHintSessionMessage<
                    ChannelMessageContents::Tag::workDuration>(mHintSessionQueue.data(),
                                                               mHintSessionQueue.size())) {
            auto ret = mHintSession->reportActualWorkDuration(mHintSessionQueue);
            if (!ret.isOk()) {
                ALOGW("Failed to report actual work durations with error: %s", ret.errorMessage());
                mHintSession = nullptr;
                return;
            }
        }
    }
    mHintSessionQueue.clear();
}

template <hal::ChannelMessage::ChannelMessageContents::Tag T, class In>
bool PowerAdvisor::writeHintSessionMessage(In* contents, size_t count) {
    if (!mMsgQueue) {
        ALOGV("Skip using FMQ with message tag %hhd as it's not supported", T);
        return false;
    }
    auto availableSize = mMsgQueue->availableToWrite();
    if (availableSize < count) {
        ALOGW("Skip using FMQ with message tag %hhd as there isn't enough space", T);
        return false;
    }
    MsgQueue::MemTransaction tx;
    if (!mMsgQueue->beginWrite(count, &tx)) {
        ALOGW("Failed to begin writing message with tag %hhd", T);
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        if constexpr (T == ChannelMessageContents::Tag::workDuration) {
            const hal::WorkDuration& duration = contents[i];
            new (tx.getSlot(i)) hal::ChannelMessage{
                    .sessionID = static_cast<int32_t>(mSessionConfig.id),
                    .timeStampNanos =
                            (i == count - 1) ? ::android::uptimeNanos() : duration.timeStampNanos,
                    .data = ChannelMessageContents::make<ChannelMessageContents::Tag::workDuration,
                                                         hal::WorkDurationFixedV1>({
                            .durationNanos = duration.durationNanos,
                            .workPeriodStartTimestampNanos = duration.workPeriodStartTimestampNanos,
                            .cpuDurationNanos = duration.cpuDurationNanos,
                            .gpuDurationNanos = duration.gpuDurationNanos,
                    }),
            };
        } else {
            new (tx.getSlot(i)) hal::ChannelMessage{
                    .sessionID = static_cast<int32_t>(mSessionConfig.id),
                    .timeStampNanos = ::android::uptimeNanos(),
                    .data = ChannelMessageContents::make<T, In>(std::move(contents[i])),
            };
        }
    }
    if (!mMsgQueue->commitWrite(count)) {
        ALOGW("Failed to send message with tag %hhd, fall back to binder call", T);
        return false;
    }
    mEventFlag->wake(mFmqWriteMask);
    return true;
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
    {
        std::scoped_lock lock(mHintSessionMutex);
        if (mHintSession != nullptr) {
            ALOGE("Cannot start power hint session: already running");
            return false;
        }
        return ensurePowerHintSessionRunning();
    }
}

bool PowerAdvisor::supportsGpuReporting() {
    return mBootFinished && FlagManager::getInstance().adpf_gpu_sf();
}

void PowerAdvisor::setGpuStartTime(DisplayId displayId, TimePoint startTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    if (displayData.gpuEndFenceTime) {
        nsecs_t signalTime = displayData.gpuEndFenceTime->getSignalTime();
        if (signalTime != Fence::SIGNAL_TIME_INVALID && signalTime != Fence::SIGNAL_TIME_PENDING) {
            displayData.lastValidGpuStartTime = displayData.gpuStartTime;
            displayData.lastValidGpuEndTime = TimePoint::fromNs(signalTime);
            for (auto&& [_, otherDisplayData] : mDisplayTimingData) {
                if (!otherDisplayData.lastValidGpuStartTime.has_value() ||
                    !otherDisplayData.lastValidGpuEndTime.has_value())
                    continue;
                if ((*otherDisplayData.lastValidGpuStartTime < *displayData.gpuStartTime) &&
                    (*otherDisplayData.lastValidGpuEndTime > *displayData.gpuStartTime)) {
                    displayData.lastValidGpuStartTime = *otherDisplayData.lastValidGpuEndTime;
                    break;
                }
            }
        }
        displayData.gpuEndFenceTime = nullptr;
    }
    displayData.gpuStartTime = startTime;
}

void PowerAdvisor::setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    if (displayData.gpuEndFenceTime && !supportsGpuReporting()) {
        nsecs_t signalTime = displayData.gpuEndFenceTime->getSignalTime();
        if (signalTime != Fence::SIGNAL_TIME_INVALID && signalTime != Fence::SIGNAL_TIME_PENDING) {
            displayData.lastValidGpuStartTime = displayData.gpuStartTime;
            displayData.lastValidGpuEndTime = TimePoint::fromNs(signalTime);
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
        }
    }
    displayData.gpuEndFenceTime = std::move(fenceTime);
    if (!supportsGpuReporting()) {
        displayData.gpuStartTime = TimePoint::now();
    }
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

void PowerAdvisor::setRequiresRenderEngine(DisplayId displayId, bool requiresRenderEngine) {
    mDisplayTimingData[displayId].requiresRenderEngine = requiresRenderEngine;
}

void PowerAdvisor::setExpectedPresentTime(TimePoint expectedPresentTime) {
    mExpectedPresentTimes.next() = expectedPresentTime;
}

void PowerAdvisor::setSfPresentTiming(TimePoint presentFenceTime, TimePoint presentEndTime) {
    mLastPresentFenceTime = presentFenceTime;
    mLastSfPresentEndTime = presentEndTime;
}

void PowerAdvisor::setFrameDelay(Duration frameDelayDuration) {
    mFrameDelayDuration = frameDelayDuration;
}

void PowerAdvisor::setHwcPresentDelayedTime(DisplayId displayId, TimePoint earliestFrameStartTime) {
    mDisplayTimingData[displayId].hwcPresentDelayedTime = earliestFrameStartTime;
}

void PowerAdvisor::setCommitStart(TimePoint commitStartTime) {
    mCommitStartTimes.next() = commitStartTime;
}

void PowerAdvisor::setCompositeEnd(TimePoint compositeEndTime) {
    mLastPostcompDuration = compositeEndTime - mLastSfPresentEndTime;
}

void PowerAdvisor::notifyRefreshRate(int32_t refreshRate) {
    if (refreshRate <= 0 || !base::GetBoolProperty(kRefreshRateHintProperty, false)) {
        return;
    }

    std::lock_guard lock(mRefreshRateMutex);
    if (refreshRate == mLastNotifiedRefreshRate) {
        return;
    }

    mLastNotifiedRefreshRate = refreshRate;
    mPendingRefreshRate = refreshRate;
    if (!mRefreshRateThread.joinable()) {
        mRefreshRateThread = std::thread([this] { refreshRateHintLoop(); });
    }
    mRefreshRateCv.notify_one();
}

void PowerAdvisor::refreshRateHintLoop() {
    pthread_setname_np(pthread_self(), "RefreshRateHint");

    std::unique_lock lock(mRefreshRateMutex);
    while (true) {
        mRefreshRateCv.wait(lock, [this] { return mRefreshRateStopped || mPendingRefreshRate; });
        if (mRefreshRateStopped) {
            return;
        }

        const int32_t refreshRate = *mPendingRefreshRate;
        mPendingRefreshRate.reset();

        lock.unlock();
        const bool applied = applyRefreshRateHint(refreshRate);
        lock.lock();

        if (!applied && !mPendingRefreshRate) {
            // HAL might not be up yet, try again in a bit.
            mRefreshRateCv.wait_for(lock, kRefreshRateRetryDelay,
                                    [this] { return mRefreshRateStopped || mPendingRefreshRate; });
            if (!mRefreshRateStopped && !mPendingRefreshRate) {
                mPendingRefreshRate = refreshRate;
            }
        }
    }
}

bool PowerAdvisor::applyRefreshRateHint(int32_t refreshRate) {
    // Turn the new rate on first, then every other rate off.
    if (!setPowerExtMode(refreshRateHint(refreshRate), true)) {
        return false;
    }
    for (const int32_t rate : kHintedRefreshRates) {
        if (rate != refreshRate) {
            setPowerExtMode(refreshRateHint(rate), false);
        }
    }
    return true;
}

bool PowerAdvisor::setPowerExtMode(const std::string& mode, bool enabled) {
    SFTRACE_FORMAT("PowerExt setMode %s %d", mode.c_str(), enabled);

    if (!mPowerExtBinder.get()) {
        ndk::SpAIBinder power(AServiceManager_checkService(kPowerHalInstance));
        AIBinder* ext = nullptr;
        if (!power.get() || AIBinder_getExtension(power.get(), &ext) != STATUS_OK || !ext) {
            return false;
        }
        ndk::SpAIBinder binder(ext);
        if (!AIBinder_associateClass(binder.get(), getPowerExtClass())) {
            return false;
        }
        mPowerExtBinder = std::move(binder);
    }

    AParcel* in = nullptr;
    if (AIBinder_prepareTransaction(mPowerExtBinder.get(), &in) != STATUS_OK) {
        return false;
    }
    AParcel_writeString(in, mode.c_str(), static_cast<int32_t>(mode.size()));
    AParcel_writeBool(in, enabled);

    // setMode is the first method in IPowerExt, so it's code 1.
    AParcel* out = nullptr;
    const binder_status_t status =
            AIBinder_transact(mPowerExtBinder.get(), FIRST_CALL_TRANSACTION, &in, &out, 0);
    ndk::ScopedAParcel outParcel(out);
    if (status != STATUS_OK) {
        // HAL probably died, reconnect next time.
        mPowerExtBinder.set(nullptr);
        return false;
    }
    return true;
}

void PowerAdvisor::setDisplays(std::vector<DisplayId>& displayIds) {
    mDisplayIds = displayIds;
}

void PowerAdvisor::setTotalFrameTargetWorkDuration(Duration targetDuration) {
    mTotalFrameTargetDuration = targetDuration;
}

std::shared_ptr<SessionManager> PowerAdvisor::getSessionManager() {
    return mSessionManager;
}

sp<IBinder> PowerAdvisor::getOrCreateSessionManagerForBinder(uid_t uid) {
    // Flag guards the creation of SessionManager
    if (mSessionManager == nullptr) {
        mSessionManager = ndk::SharedRefBase::make<SessionManager>(uid);
    }
    return AIBinder_toPlatformBinder(mSessionManager->asBinder().get());
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

std::optional<hal::WorkDuration> PowerAdvisor::estimateWorkDuration() {
    if (!mExpectedPresentTimes.isFull() || !mCommitStartTimes.isFull()) {
        return std::nullopt;
    }

    // Tracks when we finish presenting to hwc
    TimePoint estimatedHwcEndTime = mCommitStartTimes.back();

    // How long we spent this frame not doing anything, waiting for fences or vsync
    Duration idleDuration = 0ns;

    // Most recent previous gpu end time in the current frame, probably from a prior display, used
    // as the start time for the next gpu operation if it ran over time since it probably blocked
    std::optional<TimePoint> previousValidGpuEndTime;

    // The currently estimated gpu end time for the frame,
    // used to accumulate gpu time as we iterate over the active displays
    std::optional<TimePoint> estimatedGpuEndTime;

    std::vector<DisplayId>&& displayIds =
            getOrderedDisplayIds(&DisplayTimingData::hwcPresentStartTime);
    DisplayTimeline displayTiming;
    std::optional<GpuTimeline> firstGpuTimeline;

    // Iterate over the displays that use hwc in the same order they are presented
    for (DisplayId displayId : displayIds) {
        if (mDisplayTimingData.count(displayId) == 0) {
            continue;
        }

        auto& displayData = mDisplayTimingData.at(displayId);

        displayTiming = displayData.calculateDisplayTimeline(mLastPresentFenceTime);

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
            if (!firstGpuTimeline.has_value()) {
                firstGpuTimeline = gpuTiming;
            }
            previousValidGpuEndTime = gpuTiming->startTime + gpuTiming->duration;

            // Estimate the prediction frame's gpu end time from the reference frame
            estimatedGpuEndTime = std::max(displayTiming.hwcPresentStartTime,
                                           estimatedGpuEndTime.value_or(TimePoint{0ns})) +
                    gpuTiming->duration;
        }
    }

    TimePoint estimatedFlingerEndTime = mLastSfPresentEndTime;

    // Don't count time spent idly waiting in the estimate as we could do more work in that time
    estimatedHwcEndTime -= idleDuration;
    estimatedFlingerEndTime -= idleDuration;

    // We finish the frame when both present and the gpu are done, so wait for the later of the two
    // Also add the frame delay duration since the target did not move while we were delayed
    Duration totalDuration = mFrameDelayDuration +
            std::max(estimatedHwcEndTime, estimatedGpuEndTime.value_or(TimePoint{0ns})) -
            mCommitStartTimes.back();
    Duration totalDurationWithoutGpu =
            mFrameDelayDuration + estimatedHwcEndTime - mCommitStartTimes.back();

    // We finish SurfaceFlinger when post-composition finishes, so add that in here
    Duration flingerDuration =
            estimatedFlingerEndTime + mLastPostcompDuration - mCommitStartTimes.back();
    Duration estimatedGpuDuration = firstGpuTimeline.has_value()
            ? estimatedGpuEndTime.value_or(TimePoint{0ns}) - firstGpuTimeline->startTime
            : Duration::fromNs(0);

    // Combine the two timings into a single normalized one
    Duration combinedDuration = combineTimingEstimates(totalDuration, flingerDuration);
    Duration cpuDuration = combineTimingEstimates(totalDurationWithoutGpu, flingerDuration);

    hal::WorkDuration duration{
            .timeStampNanos = TimePoint::now().ns(),
            .durationNanos = combinedDuration.ns(),
            .workPeriodStartTimestampNanos = mCommitStartTimes.back().ns(),
            .cpuDurationNanos = supportsGpuReporting() ? cpuDuration.ns() : 0,
            .gpuDurationNanos = supportsGpuReporting() ? estimatedGpuDuration.ns() : 0,
    };
    if (sTraceHintSessionData) {
        SFTRACE_INT64("Idle duration", idleDuration.ns());
        SFTRACE_INT64("Total duration", totalDuration.ns());
        SFTRACE_INT64("Flinger duration", flingerDuration.ns());
    }
    return std::make_optional(duration);
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
    if (!(requiresRenderEngine && lastValidGpuStartTime.has_value() && gpuEndFenceTime)) {
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

void PowerAdvisor::setQueuedWorkload(ftl::Flags<Workload> queued) {
    queued &= TRIGGER_LOAD_CHANGE_HINTS;
    if (!(queued).get()) return;
    uint32_t previousQueuedWorkload = mQueuedWorkload.fetch_or(queued.get());

    uint32_t newHints = (previousQueuedWorkload ^ queued.get()) & queued.get();
    if (newHints) {
        SFTRACE_INSTANT_FOR_TRACK(WorkloadTracer::TRACK_NAME,
                                  ftl::Concat("QueuedWorkload: ",
                                              ftl::truncated<20>(ftl::Flags<Workload>(newHints)
                                                                         .string()
                                                                         .c_str()))
                                          .c_str());
    }
    if (!previousQueuedWorkload) {
        // TODO(b/385028458) maybe load up hint if close to wake up
    }
}

void PowerAdvisor::setScreenshotWorkload() {
    mCommittedWorkload |= Workload::SCREENSHOT;
}

void PowerAdvisor::setCommittedWorkload(ftl::Flags<Workload> workload) {
    workload &= TRIGGER_LOAD_CHANGE_HINTS;
    uint32_t queued = mQueuedWorkload.exchange(0);
    mCommittedWorkload |= workload;

    bool cancelLoadupHint = queued && !mCommittedWorkload.get();
    if (cancelLoadupHint) {
        SFTRACE_INSTANT_FOR_TRACK(WorkloadTracer::TRACK_NAME,
                                  ftl::Concat("UncommittedQueuedWorkload: ",
                                              ftl::truncated<20>(ftl::Flags<Workload>(queued)
                                                                         .string()
                                                                         .c_str()))
                                          .c_str());
        // TODO(b/385028458) cancel load up hint
    }

    bool increasedWorkload = queued == 0 && mCommittedWorkload.get() != 0;
    if (increasedWorkload) {
        SFTRACE_INSTANT_FOR_TRACK(WorkloadTracer::TRACK_NAME,
                                  ftl::Concat("CommittedWorkload: ",
                                              ftl::truncated<20>(mCommittedWorkload.string()))
                                          .c_str());

        // TODO(b/385028458) load up hint for other increased workloads.

        // Provides a load up hint only for effects that require client
        // composition, such as blur or shadows.
        if (mCommittedWorkload.any(adpf::Workload::EFFECTS)) {
            notifyCpuLoadUp();
        }
    }
}

void PowerAdvisor::setCompositedWorkload(ftl::Flags<Workload> composited) {
    composited &= TRIGGER_LOAD_CHANGE_HINTS;
    mCommittedWorkload = composited;
}
} // namespace android::adpf::impl
