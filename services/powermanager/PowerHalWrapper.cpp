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
#include <aidl/android/hardware/power/Boost.h>
#include <aidl/android/hardware/power/IPowerHintSession.h>
#include <aidl/android/hardware/power/Mode.h>
#include <powermanager/HalResult.h>
#include <powermanager/PowerHalWrapper.h>
#include <utils/Log.h>

using namespace android::hardware::power;
namespace Aidl = aidl::android::hardware::power;

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

HalResult<void> EmptyHalWrapper::setBoost(Aidl::Boost boost, int32_t durationMs) {
    ALOGV("Skipped setBoost %s with duration %dms because %s", toString(boost).c_str(), durationMs,
          getUnsupportedMessage());
    return HalResult<void>::unsupported();
}

HalResult<void> EmptyHalWrapper::setMode(Aidl::Mode mode, bool enabled) {
    ALOGV("Skipped setMode %s to %s because %s", toString(mode).c_str(), enabled ? "true" : "false",
          getUnsupportedMessage());
    return HalResult<void>::unsupported();
}

HalResult<std::shared_ptr<PowerHintSessionWrapper>> EmptyHalWrapper::createHintSession(
        int32_t, int32_t, const std::vector<int32_t>& threadIds, int64_t) {
    ALOGV("Skipped createHintSession(task num=%zu) because %s", threadIds.size(),
          getUnsupportedMessage());
    return HalResult<std::shared_ptr<PowerHintSessionWrapper>>::unsupported();
}

HalResult<std::shared_ptr<PowerHintSessionWrapper>> EmptyHalWrapper::createHintSessionWithConfig(
        int32_t, int32_t, const std::vector<int32_t>& threadIds, int64_t, Aidl::SessionTag,
        Aidl::SessionConfig*) {
    ALOGV("Skipped createHintSessionWithConfig(task num=%zu) because %s", threadIds.size(),
          getUnsupportedMessage());
    return HalResult<std::shared_ptr<PowerHintSessionWrapper>>::unsupported();
}

HalResult<int64_t> EmptyHalWrapper::getHintSessionPreferredRate() {
    ALOGV("Skipped getHintSessionPreferredRate because %s", getUnsupportedMessage());
    return HalResult<int64_t>::unsupported();
}

HalResult<Aidl::ChannelConfig> EmptyHalWrapper::getSessionChannel(int, int) {
    ALOGV("Skipped getSessionChannel because %s", getUnsupportedMessage());
    return HalResult<Aidl::ChannelConfig>::unsupported();
}

HalResult<void> EmptyHalWrapper::closeSessionChannel(int, int) {
    ALOGV("Skipped closeSessionChannel because %s", getUnsupportedMessage());
    return HalResult<void>::unsupported();
}

const char* EmptyHalWrapper::getUnsupportedMessage() {
    return "Power HAL is not supported";
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HidlHalWrapperV1_0::setBoost(Aidl::Boost boost, int32_t durationMs) {
    if (boost == Aidl::Boost::INTERACTION) {
        return sendPowerHint(V1_3::PowerHint::INTERACTION, durationMs);
    } else {
        return EmptyHalWrapper::setBoost(boost, durationMs);
    }
}

HalResult<void> HidlHalWrapperV1_0::setMode(Aidl::Mode mode, bool enabled) {
    uint32_t data = enabled ? 1 : 0;
    switch (mode) {
        case Aidl::Mode::LAUNCH:
            return sendPowerHint(V1_3::PowerHint::LAUNCH, data);
        case Aidl::Mode::LOW_POWER:
            return sendPowerHint(V1_3::PowerHint::LOW_POWER, data);
        case Aidl::Mode::SUSTAINED_PERFORMANCE:
            return sendPowerHint(V1_3::PowerHint::SUSTAINED_PERFORMANCE, data);
        case Aidl::Mode::VR:
            return sendPowerHint(V1_3::PowerHint::VR_MODE, data);
        case Aidl::Mode::INTERACTIVE:
            return setInteractive(enabled);
        case Aidl::Mode::DOUBLE_TAP_TO_WAKE:
            return setFeature(V1_0::Feature::POWER_FEATURE_DOUBLE_TAP_TO_WAKE, enabled);
        default:
            return EmptyHalWrapper::setMode(mode, enabled);
    }
}

HalResult<void> HidlHalWrapperV1_0::sendPowerHint(V1_3::PowerHint hintId, uint32_t data) {
    auto ret = mHandleV1_0->powerHint(static_cast<V1_0::PowerHint>(hintId), data);
    return HalResult<void>::fromReturn(ret);
}

HalResult<void> HidlHalWrapperV1_0::setInteractive(bool enabled) {
    auto ret = mHandleV1_0->setInteractive(enabled);
    return HalResult<void>::fromReturn(ret);
}

HalResult<void> HidlHalWrapperV1_0::setFeature(V1_0::Feature feature, bool enabled) {
    auto ret = mHandleV1_0->setFeature(feature, enabled);
    return HalResult<void>::fromReturn(ret);
}

const char* HidlHalWrapperV1_0::getUnsupportedMessage() {
    return "Power HAL AIDL is not supported";
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HidlHalWrapperV1_1::sendPowerHint(V1_3::PowerHint hintId, uint32_t data) {
    auto handle = static_cast<V1_1::IPower*>(mHandleV1_0.get());
    auto ret = handle->powerHintAsync(static_cast<V1_0::PowerHint>(hintId), data);
    return HalResult<void>::fromReturn(ret);
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HidlHalWrapperV1_2::sendPowerHint(V1_3::PowerHint hintId, uint32_t data) {
    auto handle = static_cast<V1_2::IPower*>(mHandleV1_0.get());
    auto ret = handle->powerHintAsync_1_2(static_cast<V1_2::PowerHint>(hintId), data);
    return HalResult<void>::fromReturn(ret);
}

HalResult<void> HidlHalWrapperV1_2::setBoost(Aidl::Boost boost, int32_t durationMs) {
    switch (boost) {
        case Aidl::Boost::CAMERA_SHOT:
            return sendPowerHint(V1_3::PowerHint::CAMERA_SHOT, durationMs);
        case Aidl::Boost::CAMERA_LAUNCH:
            return sendPowerHint(V1_3::PowerHint::CAMERA_LAUNCH, durationMs);
        default:
            return HidlHalWrapperV1_1::setBoost(boost, durationMs);
    }
}

HalResult<void> HidlHalWrapperV1_2::setMode(Aidl::Mode mode, bool enabled) {
    uint32_t data = enabled ? 1 : 0;
    switch (mode) {
        case Aidl::Mode::CAMERA_STREAMING_SECURE:
        case Aidl::Mode::CAMERA_STREAMING_LOW:
        case Aidl::Mode::CAMERA_STREAMING_MID:
        case Aidl::Mode::CAMERA_STREAMING_HIGH:
            return sendPowerHint(V1_3::PowerHint::CAMERA_STREAMING, data);
        case Aidl::Mode::AUDIO_STREAMING_LOW_LATENCY:
            return sendPowerHint(V1_3::PowerHint::AUDIO_LOW_LATENCY, data);
        default:
            return HidlHalWrapperV1_1::setMode(mode, enabled);
    }
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HidlHalWrapperV1_3::setMode(Aidl::Mode mode, bool enabled) {
    uint32_t data = enabled ? 1 : 0;
    if (mode == Aidl::Mode::EXPENSIVE_RENDERING) {
        return sendPowerHint(V1_3::PowerHint::EXPENSIVE_RENDERING, data);
    }
    return HidlHalWrapperV1_2::setMode(mode, enabled);
}

HalResult<void> HidlHalWrapperV1_3::sendPowerHint(V1_3::PowerHint hintId, uint32_t data) {
    auto handle = static_cast<V1_3::IPower*>(mHandleV1_0.get());
    auto ret = handle->powerHintAsync_1_3(hintId, data);
    return HalResult<void>::fromReturn(ret);
}

// -------------------------------------------------------------------------------------------------

HalResult<void> AidlHalWrapper::setBoost(Aidl::Boost boost, int32_t durationMs) {
    std::unique_lock<std::mutex> lock(mBoostMutex);
    size_t idx = static_cast<size_t>(boost);

    // Quick return if boost is not supported by HAL
    if (idx >= mBoostSupportedArray.size() || mBoostSupportedArray[idx] == HalSupport::OFF) {
        ALOGV("Skipped setBoost %s because %s", toString(boost).c_str(), getUnsupportedMessage());
        return HalResult<void>::unsupported();
    }

    if (mBoostSupportedArray[idx] == HalSupport::UNKNOWN) {
        bool isSupported = false;
        auto isSupportedRet = mHandle->isBoostSupported(boost, &isSupported);
        if (!isSupportedRet.isOk()) {
            ALOGE("Skipped setBoost %s because check support failed with: %s",
                  toString(boost).c_str(), isSupportedRet.getDescription().c_str());
            // return HalResult::FAILED;
            return HalResult<void>::fromStatus(isSupportedRet);
        }

        mBoostSupportedArray[idx] = isSupported ? HalSupport::ON : HalSupport::OFF;
        if (!isSupported) {
            ALOGV("Skipped setBoost %s because %s", toString(boost).c_str(),
                  getUnsupportedMessage());
            return HalResult<void>::unsupported();
        }
    }
    lock.unlock();

    return HalResult<void>::fromStatus(mHandle->setBoost(boost, durationMs));
}

HalResult<void> AidlHalWrapper::setMode(Aidl::Mode mode, bool enabled) {
    std::unique_lock<std::mutex> lock(mModeMutex);
    size_t idx = static_cast<size_t>(mode);

    // Quick return if mode is not supported by HAL
    if (idx >= mModeSupportedArray.size() || mModeSupportedArray[idx] == HalSupport::OFF) {
        ALOGV("Skipped setMode %s because %s", toString(mode).c_str(), getUnsupportedMessage());
        return HalResult<void>::unsupported();
    }

    if (mModeSupportedArray[idx] == HalSupport::UNKNOWN) {
        bool isSupported = false;
        auto isSupportedRet = mHandle->isModeSupported(mode, &isSupported);
        if (!isSupportedRet.isOk()) {
            return HalResult<void>::failed(isSupportedRet.getDescription());
        }

        mModeSupportedArray[idx] = isSupported ? HalSupport::ON : HalSupport::OFF;
        if (!isSupported) {
            ALOGV("Skipped setMode %s because %s", toString(mode).c_str(), getUnsupportedMessage());
            return HalResult<void>::unsupported();
        }
    }
    lock.unlock();

    return HalResult<void>::fromStatus(mHandle->setMode(mode, enabled));
}

HalResult<std::shared_ptr<PowerHintSessionWrapper>> AidlHalWrapper::createHintSession(
        int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos) {
    std::shared_ptr<Aidl::IPowerHintSession> appSession;
    return HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
            fromStatus(mHandle->createHintSession(tgid, uid, threadIds, durationNanos, &appSession),
                       std::make_shared<PowerHintSessionWrapper>(std::move(appSession)));
}

HalResult<std::shared_ptr<PowerHintSessionWrapper>> AidlHalWrapper::createHintSessionWithConfig(
        int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos,
        Aidl::SessionTag tag, Aidl::SessionConfig* config) {
    std::shared_ptr<Aidl::IPowerHintSession> appSession;
    return HalResult<std::shared_ptr<PowerHintSessionWrapper>>::
            fromStatus(mHandle->createHintSessionWithConfig(tgid, uid, threadIds, durationNanos,
                                                            tag, config, &appSession),
                       std::make_shared<PowerHintSessionWrapper>(std::move(appSession)));
}

HalResult<int64_t> AidlHalWrapper::getHintSessionPreferredRate() {
    int64_t rate = -1;
    auto result = mHandle->getHintSessionPreferredRate(&rate);
    return HalResult<int64_t>::fromStatus(result, rate);
}

HalResult<Aidl::ChannelConfig> AidlHalWrapper::getSessionChannel(int tgid, int uid) {
    Aidl::ChannelConfig config;
    auto result = mHandle->getSessionChannel(tgid, uid, &config);
    return HalResult<Aidl::ChannelConfig>::fromStatus(result, std::move(config));
}

HalResult<void> AidlHalWrapper::closeSessionChannel(int tgid, int uid) {
    return HalResult<void>::fromStatus(mHandle->closeSessionChannel(tgid, uid));
}

const char* AidlHalWrapper::getUnsupportedMessage() {
    return "Power HAL doesn't support it";
}

// -------------------------------------------------------------------------------------------------

} // namespace power

} // namespace android
