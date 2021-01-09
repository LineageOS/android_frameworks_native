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

#define LOG_TAG "HalWrapper"
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/Mode.h>
#include <powermanager/PowerHalWrapper.h>
#include <utils/Log.h>

using namespace android::hardware::power;

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

inline HalResult toHalResult(const binder::Status& result) {
    if (result.isOk()) {
        return HalResult::SUCCESSFUL;
    }
    ALOGE("Power HAL request failed: %s", result.toString8().c_str());
    return HalResult::FAILED;
}

template <typename T>
inline HalResult toHalResult(const hardware::Return<T>& result) {
    if (result.isOk()) {
        return HalResult::SUCCESSFUL;
    }
    ALOGE("Power HAL request failed: %s", result.description().c_str());
    return HalResult::FAILED;
}

// -------------------------------------------------------------------------------------------------

HalResult EmptyHalWrapper::setBoost(Boost boost, int32_t durationMs) {
    ALOGV("Skipped setBoost %s with duration %dms because Power HAL not available",
          toString(boost).c_str(), durationMs);
    return HalResult::UNSUPPORTED;
}

HalResult EmptyHalWrapper::setMode(Mode mode, bool enabled) {
    ALOGV("Skipped setMode %s to %s because Power HAL not available", toString(mode).c_str(),
          enabled ? "true" : "false");
    return HalResult::UNSUPPORTED;
}

// -------------------------------------------------------------------------------------------------

HalResult HidlHalWrapperV1_0::setBoost(Boost boost, int32_t durationMs) {
    if (boost == Boost::INTERACTION) {
        return sendPowerHint(V1_0::PowerHint::INTERACTION, durationMs);
    } else {
        ALOGV("Skipped setBoost %s because Power HAL AIDL not available", toString(boost).c_str());
        return HalResult::UNSUPPORTED;
    }
}

HalResult HidlHalWrapperV1_0::setMode(Mode mode, bool enabled) {
    uint32_t data = enabled ? 1 : 0;
    switch (mode) {
        case Mode::LAUNCH:
            return sendPowerHint(V1_0::PowerHint::LAUNCH, data);
        case Mode::LOW_POWER:
            return sendPowerHint(V1_0::PowerHint::LOW_POWER, data);
        case Mode::SUSTAINED_PERFORMANCE:
            return sendPowerHint(V1_0::PowerHint::SUSTAINED_PERFORMANCE, data);
        case Mode::VR:
            return sendPowerHint(V1_0::PowerHint::VR_MODE, data);
        case Mode::INTERACTIVE:
            return setInteractive(enabled);
        case Mode::DOUBLE_TAP_TO_WAKE:
            return setFeature(V1_0::Feature::POWER_FEATURE_DOUBLE_TAP_TO_WAKE, enabled);
        default:
            ALOGV("Skipped setMode %s because Power HAL AIDL not available",
                  toString(mode).c_str());
            return HalResult::UNSUPPORTED;
    }
}

HalResult HidlHalWrapperV1_0::sendPowerHint(V1_0::PowerHint hintId, uint32_t data) {
    return toHalResult(mHandleV1_0->powerHint(hintId, data));
}

HalResult HidlHalWrapperV1_0::setInteractive(bool enabled) {
    return toHalResult(mHandleV1_0->setInteractive(enabled));
}

HalResult HidlHalWrapperV1_0::setFeature(V1_0::Feature feature, bool enabled) {
    return toHalResult(mHandleV1_0->setFeature(feature, enabled));
}

// -------------------------------------------------------------------------------------------------

HalResult HidlHalWrapperV1_1::sendPowerHint(V1_0::PowerHint hintId, uint32_t data) {
    return toHalResult(mHandleV1_1->powerHintAsync(hintId, data));
}

// -------------------------------------------------------------------------------------------------

HalResult AidlHalWrapper::setBoost(Boost boost, int32_t durationMs) {
    std::unique_lock<std::mutex> lock(mBoostMutex);
    size_t idx = static_cast<size_t>(boost);

    // Quick return if boost is not supported by HAL
    if (idx >= mBoostSupportedArray.size() || mBoostSupportedArray[idx] == HalSupport::OFF) {
        ALOGV("Skipped setBoost %s because Power HAL doesn't support it", toString(boost).c_str());
        return HalResult::UNSUPPORTED;
    }

    if (mBoostSupportedArray[idx] == HalSupport::UNKNOWN) {
        bool isSupported = false;
        auto isSupportedRet = mHandle->isBoostSupported(boost, &isSupported);
        if (!isSupportedRet.isOk()) {
            ALOGE("Skipped setBoost %s because check support failed with: %s",
                  toString(boost).c_str(), isSupportedRet.toString8().c_str());
            return HalResult::FAILED;
        }

        mBoostSupportedArray[idx] = isSupported ? HalSupport::ON : HalSupport::OFF;
        if (!isSupported) {
            ALOGV("Skipped setBoost %s because Power HAL doesn't support it",
                  toString(boost).c_str());
            return HalResult::UNSUPPORTED;
        }
    }
    lock.unlock();

    return toHalResult(mHandle->setBoost(boost, durationMs));
}

HalResult AidlHalWrapper::setMode(Mode mode, bool enabled) {
    std::unique_lock<std::mutex> lock(mModeMutex);
    size_t idx = static_cast<size_t>(mode);

    // Quick return if mode is not supported by HAL
    if (idx >= mModeSupportedArray.size() || mModeSupportedArray[idx] == HalSupport::OFF) {
        ALOGV("Skipped setMode %s because Power HAL doesn't support it", toString(mode).c_str());
        return HalResult::UNSUPPORTED;
    }

    if (mModeSupportedArray[idx] == HalSupport::UNKNOWN) {
        bool isSupported = false;
        auto isSupportedRet = mHandle->isModeSupported(mode, &isSupported);
        if (!isSupportedRet.isOk()) {
            ALOGE("Skipped setMode %s because check support failed with: %s",
                  toString(mode).c_str(), isSupportedRet.toString8().c_str());
            return HalResult::FAILED;
        }

        mModeSupportedArray[idx] = isSupported ? HalSupport::ON : HalSupport::OFF;
        if (!isSupported) {
            ALOGV("Skipped setMode %s because Power HAL doesn't support it",
                  toString(mode).c_str());
            return HalResult::UNSUPPORTED;
        }
    }
    lock.unlock();

    return toHalResult(mHandle->setMode(mode, enabled));
}

// -------------------------------------------------------------------------------------------------

} // namespace power

} // namespace android
