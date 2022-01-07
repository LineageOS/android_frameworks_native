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

#undef LOG_TAG
#define LOG_TAG "PowerAdvisor"

#include <unistd.h>
#include <cinttypes>
#include <cstdint>
#include <optional>

#include <android-base/properties.h>
#include <utils/Log.h>
#include <utils/Mutex.h>

#include <android/hardware/power/1.3/IPower.h>
#include <android/hardware/power/IPower.h>
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
using android::hardware::power::WorkDuration;

using scheduler::OneShotTimer;

class AidlPowerHalWrapper;

PowerAdvisor::~PowerAdvisor() = default;

namespace {
int32_t getUpdateTimeout() {
    // Default to a timeout of 80ms if nothing else is specified
    static int32_t timeout = sysprop::display_update_imminent_timeout_ms(80);
    return timeout;
}

} // namespace

PowerAdvisor::PowerAdvisor(SurfaceFlinger& flinger)
      : mFlinger(flinger),
        mUseScreenUpdateTimer(getUpdateTimeout() > 0),
        mScreenUpdateTimer(
                "UpdateImminentTimer", OneShotTimer::Interval(getUpdateTimeout()),
                /* resetCallback */ [this] { mSendUpdateImminent.store(false); },
                /* timeoutCallback */
                [this] {
                    mSendUpdateImminent.store(true);
                    mFlinger.disableExpensiveRendering();
                }) {}

void PowerAdvisor::init() {
    // Defer starting the screen update timer until SurfaceFlinger finishes construction.
    if (mUseScreenUpdateTimer) {
        mScreenUpdateTimer.start();
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

void PowerAdvisor::notifyDisplayUpdateImminent() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }

    if (mSendUpdateImminent.load()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->notifyDisplayUpdateImminent()) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
        }
    }

    if (mUseScreenUpdateTimer) {
        mScreenUpdateTimer.reset();
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
        mSupportsPowerHint = halWrapper->supportsPowerHintSession();
    }
    return *mSupportsPowerHint;
}

bool PowerAdvisor::isPowerHintSessionRunning() {
    return mPowerHintSessionRunning;
}

void PowerAdvisor::setTargetWorkDuration(int64_t targetDurationNanos) {
    if (!usePowerHintSession()) {
        ALOGV("Power hint session target duration cannot be set, skipping");
        return;
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->setTargetWorkDuration(targetDurationNanos - kTargetSafetyMargin.count());
        }
    }
}

void PowerAdvisor::sendActualWorkDuration(int64_t actualDurationNanos, nsecs_t timeStampNanos) {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Actual work duration power hint cannot be sent, skipping");
        return;
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->sendActualWorkDuration(actualDurationNanos, timeStampNanos);
        }
    }
}

// needs to be set after the flag is known but before PowerAdvisor enters onBootFinished
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
        return ret.isOk();
    }

    bool notifyDisplayUpdateImminent() override {
        // Power HAL 1.x doesn't have a notification for this
        ALOGV("HIDL notifyUpdateImminent received but can't send");
        return true;
    }

    bool supportsPowerHintSession() override { return false; }

    bool isPowerHintSessionRunning() override { return false; }

    void restartPowerHintSession() override {}

    void setPowerHintSessionThreadIds(const std::vector<int32_t>&) override {}

    bool startPowerHintSession() override { return false; }

    void setTargetWorkDuration(int64_t) override {}

    void sendActualWorkDuration(int64_t, nsecs_t) override {}

    bool shouldReconnectHAL() override { return false; }

    std::vector<int32_t> getPowerHintSessionThreadIds() override { return std::vector<int32_t>{}; }

    std::optional<int64_t> getTargetWorkDuration() override { return std::nullopt; }

private:
    const sp<V1_3::IPower> mPowerHal = nullptr;
};

class AidlPowerHalWrapper : public PowerAdvisor::HalWrapper {
public:
    AidlPowerHalWrapper(sp<IPower> powerHal) : mPowerHal(std::move(powerHal)) {
        auto ret = mPowerHal->isModeSupported(Mode::EXPENSIVE_RENDERING, &mHasExpensiveRendering);
        if (!ret.isOk()) {
            mHasExpensiveRendering = false;
        }

        ret = mPowerHal->isBoostSupported(Boost::DISPLAY_UPDATE_IMMINENT,
                                          &mHasDisplayUpdateImminent);
        if (!ret.isOk()) {
            mHasDisplayUpdateImminent = false;
        }

        mSupportsPowerHint = checkPowerHintSessionSupported();

        if (mSupportsPowerHint) {
            mPowerHintQueue.reserve(kMaxQueueSize);
        }
    }

    ~AidlPowerHalWrapper() override {
        if (mPowerHintSession != nullptr) {
            mPowerHintSession->close();
            mPowerHintSession = nullptr;
        }
    };

    static std::unique_ptr<HalWrapper> connect() {
        // This only waits if the service is actually declared
        sp<IPower> powerHal = waitForVintfService<IPower>();
        if (powerHal == nullptr) {
            return nullptr;
        }
        ALOGI("Loaded AIDL Power HAL service");

        return std::make_unique<AidlPowerHalWrapper>(std::move(powerHal));
    }

    bool setExpensiveRendering(bool enabled) override {
        ALOGV("AIDL setExpensiveRendering %s", enabled ? "T" : "F");
        if (!mHasExpensiveRendering) {
            ALOGV("Skipped sending EXPENSIVE_RENDERING because HAL doesn't support it");
            return true;
        }

        auto ret = mPowerHal->setMode(Mode::EXPENSIVE_RENDERING, enabled);
        return ret.isOk();
    }

    bool notifyDisplayUpdateImminent() override {
        ALOGV("AIDL notifyDisplayUpdateImminent");
        if (!mHasDisplayUpdateImminent) {
            ALOGV("Skipped sending DISPLAY_UPDATE_IMMINENT because HAL doesn't support it");
            return true;
        }

        auto ret = mPowerHal->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 0);
        return ret.isOk();
    }

    // only version 2+ of the aidl supports power hint sessions, hidl has no support
    bool supportsPowerHintSession() override { return mSupportsPowerHint; }

    bool checkPowerHintSessionSupported() {
        int64_t unused;
        // Try to get preferred rate to determine if hint sessions are supported
        // We check for isOk not EX_UNSUPPORTED_OPERATION to lump other errors
        return mPowerHal->getHintSessionPreferredRate(&unused).isOk();
    }

    bool isPowerHintSessionRunning() override { return mPowerHintSession != nullptr; }

    void closePowerHintSession() {
        if (mPowerHintSession != nullptr) {
            mPowerHintSession->close();
            mPowerHintSession = nullptr;
        }
    }

    void restartPowerHintSession() {
        closePowerHintSession();
        startPowerHintSession();
    }

    void setPowerHintSessionThreadIds(const std::vector<int32_t>& threadIds) override {
        if (threadIds != mPowerHintThreadIds) {
            mPowerHintThreadIds = threadIds;
            if (isPowerHintSessionRunning()) {
                restartPowerHintSession();
            }
        }
    }

    bool startPowerHintSession() override {
        if (mPowerHintSession != nullptr || mPowerHintThreadIds.empty()) {
            ALOGV("Cannot start power hint session, skipping");
            return false;
        }
        auto ret = mPowerHal->createHintSession(getpid(), static_cast<int32_t>(getuid()),
                                                mPowerHintThreadIds, mTargetDuration,
                                                &mPowerHintSession);
        if (!ret.isOk()) {
            ALOGW("Failed to start power hint session with error: %s",
                  ret.exceptionToString(ret.exceptionCode()).c_str());
        } else {
            mLastTargetDurationSent = mTargetDuration;
        }
        return isPowerHintSessionRunning();
    }

    bool shouldSetTargetDuration(int64_t targetDurationNanos) {
        // report if the change in target from our last submission to now exceeds the threshold
        return abs(1.0 -
                   static_cast<double>(mLastTargetDurationSent) /
                           static_cast<double>(targetDurationNanos)) >=
                kAllowedTargetDeviationPercent;
    }

    void setTargetWorkDuration(int64_t targetDurationNanos) override {
        ATRACE_CALL();
        mTargetDuration = targetDurationNanos;
        if (sTraceHintSessionData) ATRACE_INT64("Time target", targetDurationNanos);
        if (!sNormalizeTarget && shouldSetTargetDuration(targetDurationNanos) &&
            isPowerHintSessionRunning()) {
            if (mLastActualDurationSent.has_value()) {
                // update the error term here since we are actually sending an update to powerhal
                if (sTraceHintSessionData)
                    ATRACE_INT64("Target error term",
                                 targetDurationNanos - *mLastActualDurationSent);
            }
            ALOGV("Sending target time: %lld ns", static_cast<long long>(targetDurationNanos));
            mLastTargetDurationSent = targetDurationNanos;
            auto ret = mPowerHintSession->updateTargetWorkDuration(targetDurationNanos);
            if (!ret.isOk()) {
                ALOGW("Failed to set power hint target work duration with error: %s",
                      ret.exceptionMessage().c_str());
                mShouldReconnectHal = true;
            }
        }
    }

    bool shouldReportActualDurationsNow() {
        // report if we have never reported before or have exceeded the max queue size
        if (!mLastActualDurationSent.has_value() || mPowerHintQueue.size() >= kMaxQueueSize) {
            return true;
        }

        if (!mActualDuration.has_value()) {
            return false;
        }

        // duration of most recent timing
        const double mostRecentActualDuration = static_cast<double>(*mActualDuration);
        // duration of the last timing actually reported to the powerhal
        const double lastReportedActualDuration = static_cast<double>(*mLastActualDurationSent);

        // report if the change in duration from then to now exceeds the threshold
        return abs(1.0 - mostRecentActualDuration / lastReportedActualDuration) >=
                kAllowedActualDeviationPercent;
    }

    void sendActualWorkDuration(int64_t actualDurationNanos, nsecs_t timeStampNanos) override {
        ATRACE_CALL();

        if (actualDurationNanos < 0 || !isPowerHintSessionRunning()) {
            ALOGV("Failed to send actual work duration, skipping");
            return;
        }

        WorkDuration duration;
        duration.durationNanos = actualDurationNanos;
        mActualDuration = actualDurationNanos;

        // normalize the sent values to a pre-set target
        if (sNormalizeTarget) {
            duration.durationNanos += mLastTargetDurationSent - mTargetDuration;
        }
        duration.timeStampNanos = timeStampNanos;
        mPowerHintQueue.push_back(duration);

        long long targetNsec = mTargetDuration;
        long long durationNsec = actualDurationNanos;

        if (sTraceHintSessionData) {
            ATRACE_INT64("Measured duration", durationNsec);
            ATRACE_INT64("Target error term", targetNsec - durationNsec);
        }

        ALOGV("Sending actual work duration of: %lld on target: %lld with error: %lld",
              durationNsec, targetNsec, targetNsec - durationNsec);

        // This rate limiter queues similar duration reports to the powerhal into
        // batches to avoid excessive binder calls. The criteria to send a given batch
        // are outlined in shouldReportActualDurationsNow()
        if (shouldReportActualDurationsNow()) {
            ALOGV("Sending hint update batch");
            auto ret = mPowerHintSession->reportActualWorkDuration(mPowerHintQueue);
            if (!ret.isOk()) {
                ALOGW("Failed to report actual work durations with error: %s",
                      ret.exceptionMessage().c_str());
                mShouldReconnectHal = true;
            }
            mPowerHintQueue.clear();
            // we save the non-normalized value here to detect % changes
            mLastActualDurationSent = actualDurationNanos;
        }
    }

    bool shouldReconnectHAL() override { return mShouldReconnectHal; }

    std::vector<int32_t> getPowerHintSessionThreadIds() override { return mPowerHintThreadIds; }

    std::optional<int64_t> getTargetWorkDuration() override { return mTargetDuration; }

private:
    const sp<IPower> mPowerHal = nullptr;
    bool mHasExpensiveRendering = false;
    bool mHasDisplayUpdateImminent = false;
    // Used to indicate an error state and need for reconstruction
    bool mShouldReconnectHal = false;
    // This is not thread safe, but is currently protected by mPowerHalMutex so it needs no lock
    sp<IPowerHintSession> mPowerHintSession = nullptr;
    // Queue of actual durations saved to report
    std::vector<WorkDuration> mPowerHintQueue;
    // The latest un-normalized values we have received for target and actual
    int64_t mTargetDuration = kDefaultTarget;
    std::optional<int64_t> mActualDuration;
    // The list of thread ids, stored so we can restart the session from this class if needed
    std::vector<int32_t> mPowerHintThreadIds;
    bool mSupportsPowerHint;
    // Keep track of the last messages sent for rate limiter change detection
    std::optional<int64_t> mLastActualDurationSent;
    int64_t mLastTargetDurationSent = kDefaultTarget;
    // Whether to normalize all the actual values as error terms relative to a constant target
    // This saves a binder call by not setting the target, and should not affect the pid values
    static const bool sNormalizeTarget;
    // Whether we should emit ATRACE_INT data for hint sessions
    static const bool sTraceHintSessionData;
    // Max number of messages allowed in mPowerHintQueue before reporting is forced
    static constexpr int32_t kMaxQueueSize = 15;
    // Max percent the actual duration can vary without causing a report (eg: 0.1 = 10%)
    static constexpr double kAllowedActualDeviationPercent = 0.1;
    // Max percent the target duration can vary without causing a report (eg: 0.05 = 5%)
    static constexpr double kAllowedTargetDeviationPercent = 0.05;
    // Target used for init and normalization, the actual value does not really matter
    static constexpr int64_t kDefaultTarget = 50000000;
};

const bool AidlPowerHalWrapper::sTraceHintSessionData =
        base::GetBoolProperty(std::string("debug.sf.trace_hint_sessions"), false);

const bool AidlPowerHalWrapper::sNormalizeTarget =
        base::GetBoolProperty(std::string("debug.sf.normalize_hint_session_durations"), true);

PowerAdvisor::HalWrapper* PowerAdvisor::getPowerHal() {
    static std::unique_ptr<HalWrapper> sHalWrapper = nullptr;
    static bool sHasHal = true;

    if (!sHasHal) {
        return nullptr;
    }

    // grab old hint session values before we destroy any existing wrapper
    std::vector<int32_t> oldPowerHintSessionThreadIds;
    std::optional<int64_t> oldTargetWorkDuration;

    if (sHalWrapper != nullptr) {
        oldPowerHintSessionThreadIds = sHalWrapper->getPowerHintSessionThreadIds();
        oldTargetWorkDuration = sHalWrapper->getTargetWorkDuration();
    }

    // If we used to have a HAL, but it stopped responding, attempt to reconnect
    if (mReconnectPowerHal) {
        sHalWrapper = nullptr;
        mReconnectPowerHal = false;
    }

    if (sHalWrapper != nullptr) {
        auto wrapper = sHalWrapper.get();
        // if the wrapper is fine, return it, but if it indicates a reconnect, remake it
        if (!wrapper->shouldReconnectHAL()) {
            return wrapper;
        }
        sHalWrapper = nullptr;
    }

    // at this point, we know for sure there is no running session
    mPowerHintSessionRunning = false;

    // First attempt to connect to the AIDL Power HAL
    sHalWrapper = AidlPowerHalWrapper::connect();

    // If that didn't succeed, attempt to connect to the HIDL Power HAL
    if (sHalWrapper == nullptr) {
        sHalWrapper = HidlPowerHalWrapper::connect();
    } else { // if AIDL, pass on any existing hint session values
        // thread ids always safe to set
        sHalWrapper->setPowerHintSessionThreadIds(oldPowerHintSessionThreadIds);
        // only set duration and start if duration is defined
        if (oldTargetWorkDuration.has_value()) {
            sHalWrapper->setTargetWorkDuration(*oldTargetWorkDuration);
            // only start if possible to run and both threadids and duration are defined
            if (usePowerHintSession() && !oldPowerHintSessionThreadIds.empty()) {
                mPowerHintSessionRunning = sHalWrapper->startPowerHintSession();
            }
        }
    }

    // If we make it to this point and still don't have a HAL, it's unlikely we
    // will, so stop trying
    if (sHalWrapper == nullptr) {
        sHasHal = false;
    }

    return sHalWrapper.get();
}

} // namespace impl
} // namespace Hwc2
} // namespace android
