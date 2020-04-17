/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "PowerHalWrapper"
#include <utils/Log.h>

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/Mode.h>

#include <powermanager/PowerHalWrapper.h>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::PowerHint;

namespace android {

// -------------------------------------------------------------------------------------------------

PowerHalResult EmptyPowerHalWrapper::setBoost(Boost boost, int32_t durationMs) {
    ALOGV("Skipped setBoost %s with duration %dms because Power HAL not available",
        toString(boost).c_str(), durationMs);
    return PowerHalResult::UNSUPPORTED;
}

PowerHalResult EmptyPowerHalWrapper::setMode(Mode mode, bool enabled) {
    ALOGV("Skipped setMode %s to %s because Power HAL not available",
        toString(mode).c_str(), enabled ? "true" : "false");
    return PowerHalResult::UNSUPPORTED;
}

// -------------------------------------------------------------------------------------------------

PowerHalResult HidlPowerHalWrapperV1_0::setBoost(Boost boost, int32_t durationMs) {
    if (boost == Boost::INTERACTION) {
        return sendPowerHint(PowerHint::INTERACTION, durationMs);
    } else {
        ALOGV("Skipped setBoost %s because Power HAL AIDL not available",
            toString(boost).c_str());
        return PowerHalResult::UNSUPPORTED;
    }
}

PowerHalResult HidlPowerHalWrapperV1_0::setMode(Mode mode, bool enabled) {
    uint32_t data = enabled ? 1 : 0;
    switch (mode) {
        case Mode::LAUNCH:
            return sendPowerHint(PowerHint::LAUNCH, data);
        case Mode::LOW_POWER:
            return sendPowerHint(PowerHint::LOW_POWER, data);
        case Mode::SUSTAINED_PERFORMANCE:
            return sendPowerHint(PowerHint::SUSTAINED_PERFORMANCE, data);
        case Mode::VR:
            return sendPowerHint(PowerHint::VR_MODE, data);
        case Mode::INTERACTIVE:
            return setInteractive(enabled);
        case Mode::DOUBLE_TAP_TO_WAKE:
            return setFeature(Feature::POWER_FEATURE_DOUBLE_TAP_TO_WAKE, enabled);
        default:
            ALOGV("Skipped setMode %s because Power HAL AIDL not available",
                toString(mode).c_str());
            return PowerHalResult::UNSUPPORTED;
    }
}

PowerHalResult HidlPowerHalWrapperV1_0::sendPowerHint(PowerHint hintId, uint32_t data) {
    auto ret = handleV1_0->powerHint(hintId, data);
    return ret.isOk() ? PowerHalResult::SUCCESSFUL : PowerHalResult::FAILED;
}

PowerHalResult HidlPowerHalWrapperV1_0::setInteractive(bool enabled) {
    auto ret = handleV1_0->setInteractive(enabled);
    return ret.isOk() ? PowerHalResult::SUCCESSFUL : PowerHalResult::FAILED;
}

PowerHalResult HidlPowerHalWrapperV1_0::setFeature(Feature feature, bool enabled) {
    auto ret = handleV1_0->setFeature(feature, enabled);
    return ret.isOk() ? PowerHalResult::SUCCESSFUL : PowerHalResult::FAILED;
}

// -------------------------------------------------------------------------------------------------

PowerHalResult HidlPowerHalWrapperV1_1::sendPowerHint(PowerHint hintId, uint32_t data) {
    auto ret = handleV1_1->powerHintAsync(hintId, data);
    return ret.isOk() ? PowerHalResult::SUCCESSFUL : PowerHalResult::FAILED;
}

// -------------------------------------------------------------------------------------------------

PowerHalResult AidlPowerHalWrapper::setBoost(Boost boost, int32_t durationMs) {
    std::unique_lock<std::mutex> lock(mBoostMutex);
    // Quick return if boost is not supported by HAL
    if (boost > Boost::DISPLAY_UPDATE_IMMINENT ||
        boostSupportedArray[static_cast<int32_t>(boost)] == PowerHalSupport::OFF) {
        ALOGV("Skipped setBoost %s because Power HAL doesn't support it",
            toString(boost).c_str());
        return PowerHalResult::UNSUPPORTED;
    }

    if (boostSupportedArray[static_cast<int32_t>(boost)] == PowerHalSupport::UNKNOWN) {
        bool isSupported = false;
        auto isSupportedRet = handle->isBoostSupported(boost, &isSupported);
        if (!isSupportedRet.isOk()) {
            ALOGV("Skipped setBoost %s because Power HAL is not available to check support",
                toString(boost).c_str());
            return PowerHalResult::FAILED;
        }

        boostSupportedArray[static_cast<int32_t>(boost)] =
            isSupported ? PowerHalSupport::ON : PowerHalSupport::OFF;
        if (!isSupported) {
            ALOGV("Skipped setBoost %s because Power HAL doesn't support it",
                toString(boost).c_str());
            return PowerHalResult::UNSUPPORTED;
        }
    }
    lock.unlock();

    auto ret = handle->setBoost(boost, durationMs);
    return ret.isOk() ? PowerHalResult::SUCCESSFUL : PowerHalResult::FAILED;
}

PowerHalResult AidlPowerHalWrapper::setMode(Mode mode, bool enabled) {
    std::unique_lock<std::mutex> lock(mModeMutex);
    // Quick return if mode is not supported by HAL
    if (mode > Mode::DISPLAY_INACTIVE ||
        modeSupportedArray[static_cast<int32_t>(mode)] == PowerHalSupport::OFF) {
        ALOGV("Skipped setMode %s because Power HAL doesn't support it",
            toString(mode).c_str());
        return PowerHalResult::UNSUPPORTED;
    }

    if (modeSupportedArray[static_cast<int32_t>(mode)] == PowerHalSupport::UNKNOWN) {
        bool isSupported = false;
        auto isSupportedRet = handle->isModeSupported(mode, &isSupported);
        if (!isSupportedRet.isOk()) {
            ALOGV("Skipped setMode %s because Power HAL is not available to check support",
                toString(mode).c_str());
            return PowerHalResult::FAILED;
        }

        modeSupportedArray[static_cast<int32_t>(mode)] =
            isSupported ? PowerHalSupport::ON : PowerHalSupport::OFF;
        if (!isSupported) {
                ALOGV("Skipped setMode %s because Power HAL doesn't support it",
                    toString(mode).c_str());
                return PowerHalResult::UNSUPPORTED;
        }
    }
    lock.unlock();

    auto ret = handle->setMode(mode, enabled);
    return ret.isOk() ? PowerHalResult::SUCCESSFUL : PowerHalResult::FAILED;
}

// -------------------------------------------------------------------------------------------------

}; // namespace android
