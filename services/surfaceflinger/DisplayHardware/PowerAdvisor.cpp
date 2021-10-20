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
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* halWrapper = getPowerHal();
        if (halWrapper != nullptr && usePowerHintSession()) {
            mPowerHintSessionRunning = halWrapper->startPowerHintSession();
        }
    }
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
    ALOGE_IF(!mPowerHintEnabled.has_value(), "Power hint session cannot be used before boot!");
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
    // we check "supports" here not "usePowerHintSession" because this needs to work
    // before the session is actually running, and "use" will always fail before boot
    // we store the values passed in before boot to start the session with during onBootFinished
    if (!supportsPowerHintSession()) {
        ALOGV("Power hint session target duration cannot be set, skipping");
        return;
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->setTargetWorkDuration(targetDurationNanos);
        }
    }
}

void PowerAdvisor::setPowerHintSessionThreadIds(const std::vector<int32_t>& threadIds) {
    // we check "supports" here not "usePowerHintSession" because this needs to wsork
    // before the session is actually running, and "use" will always fail before boot.
    // we store the values passed in before boot to start the session with during onBootFinished
    if (!supportsPowerHintSession()) {
        ALOGV("Power hint session thread ids cannot be set, skipping");
        return;
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->setPowerHintSessionThreadIds(const_cast<std::vector<int32_t>&>(threadIds));
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

        // This just gives a number not a binder status, so no .isOk()
        mSupportsPowerHints = mPowerHal->getInterfaceVersion() >= 2;

        if (mSupportsPowerHints) {
            mPowerHintQueue.reserve(MAX_QUEUE_SIZE);
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
    bool supportsPowerHintSession() override { return mSupportsPowerHints; }

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
        if (mPowerHintSession != nullptr || !mPowerHintTargetDuration.has_value() ||
            mPowerHintThreadIds.empty()) {
            ALOGV("Cannot start power hint session, skipping");
            return false;
        }
        auto ret = mPowerHal->createHintSession(getpid(), static_cast<int32_t>(getuid()),
                                                mPowerHintThreadIds, *mPowerHintTargetDuration,
                                                &mPowerHintSession);
        if (!ret.isOk()) {
            ALOGW("Failed to start power hint session with error: %s",
                  ret.exceptionToString(ret.exceptionCode()).c_str());
            // Indicate to the poweradvisor that this wrapper likely needs to be remade
            mShouldReconnectHal = true;
        }
        return isPowerHintSessionRunning();
    }

    bool shouldSetTargetDuration(int64_t targetDurationNanos) {
        if (!mLastTargetDurationSent.has_value()) {
            return true;
        }

        // report if the change in target from our last submission to now exceeds the threshold
        return abs(1.0 -
                   static_cast<double>(*mLastTargetDurationSent) /
                           static_cast<double>(targetDurationNanos)) >=
                ALLOWED_TARGET_DEVIATION_PERCENT;
    }

    void setTargetWorkDuration(int64_t targetDurationNanos) override {
        mPowerHintTargetDuration = targetDurationNanos;
        if (shouldSetTargetDuration(targetDurationNanos) && isPowerHintSessionRunning()) {
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
        if (!mLastMessageReported.has_value() || mPowerHintQueue.size() >= MAX_QUEUE_SIZE) {
            return true;
        }

        // duration of most recent timing
        const double mostRecentActualDuration =
                static_cast<double>(mPowerHintQueue.back().durationNanos);
        // duration of the last timing actually reported to the powerhal
        const double lastReportedActualDuration =
                static_cast<double>(mLastMessageReported->durationNanos);

        // report if the change in duration from then to now exceeds the threshold
        return abs(1.0 - mostRecentActualDuration / lastReportedActualDuration) >=
                ALLOWED_ACTUAL_DEVIATION_PERCENT;
    }

    void sendActualWorkDuration(int64_t actualDurationNanos, nsecs_t timeStampNanos) override {
        if (actualDurationNanos < 0 || !isPowerHintSessionRunning()) {
            ALOGV("Failed to send actual work duration, skipping");
            return;
        }

        WorkDuration duration;
        duration.durationNanos = actualDurationNanos;
        duration.timeStampNanos = timeStampNanos;
        mPowerHintQueue.push_back(duration);

        // This rate limiter queues similar duration reports to the powerhal into
        // batches to avoid excessive binder calls. The criteria to send a given batch
        // are outlined in shouldReportActualDurationsNow()
        if (shouldReportActualDurationsNow()) {
            auto ret = mPowerHintSession->reportActualWorkDuration(mPowerHintQueue);
            if (!ret.isOk()) {
                ALOGW("Failed to report actual work durations with error: %s",
                      ret.exceptionMessage().c_str());
                mShouldReconnectHal = true;
            }
            mPowerHintQueue.clear();
            mLastMessageReported = duration;
        }
    }

    bool shouldReconnectHAL() override { return mShouldReconnectHal; }

    std::vector<int32_t> getPowerHintSessionThreadIds() override { return mPowerHintThreadIds; }

    std::optional<int64_t> getTargetWorkDuration() override { return mPowerHintTargetDuration; }

private:
    // max number of messages allowed in mPowerHintQueue before reporting is forced
    static constexpr int32_t MAX_QUEUE_SIZE = 15;
    // max percent the actual duration can vary without causing a report (eg: 0.1 = 10%)
    static constexpr double ALLOWED_ACTUAL_DEVIATION_PERCENT = 0.1;
    // max percent the target duration can vary without causing a report (eg: 0.05 = 5%)
    static constexpr double ALLOWED_TARGET_DEVIATION_PERCENT = 0.05;

    const sp<IPower> mPowerHal = nullptr;
    bool mHasExpensiveRendering = false;
    bool mHasDisplayUpdateImminent = false;
    bool mShouldReconnectHal = false; // used to indicate an error state and need for reconstruction
    // This is not thread safe, but is currently protected by mPowerHalMutex so it needs no lock
    sp<IPowerHintSession> mPowerHintSession = nullptr;
    std::vector<WorkDuration> mPowerHintQueue;
    // halwrapper owns these values so we can init when we want and reconnect if broken
    std::optional<int64_t> mPowerHintTargetDuration;
    std::vector<int32_t> mPowerHintThreadIds;
    // keep track of the last messages sent for rate limiter change detection
    std::optional<WorkDuration> mLastMessageReported;
    std::optional<int64_t> mLastTargetDurationSent;
    bool mSupportsPowerHints;
};

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
