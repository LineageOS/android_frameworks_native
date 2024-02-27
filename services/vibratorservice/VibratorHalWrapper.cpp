/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "VibratorHalWrapper"

#include <android/hardware/vibrator/1.3/IVibrator.h>
#include <android/hardware/vibrator/IVibrator.h>
#include <hardware/vibrator.h>
#include <cmath>

#include <utils/Log.h>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalWrapper.h>

using android::hardware::vibrator::Braking;
using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;
using android::hardware::vibrator::PrimitivePwle;

using std::chrono::milliseconds;

namespace V1_0 = android::hardware::vibrator::V1_0;
namespace V1_1 = android::hardware::vibrator::V1_1;
namespace V1_2 = android::hardware::vibrator::V1_2;
namespace V1_3 = android::hardware::vibrator::V1_3;
namespace Aidl = android::hardware::vibrator;

namespace android {

namespace vibrator {

// -------------------------------------------------------------------------------------------------

template <class T>
bool isStaticCastValid(Effect effect) {
    T castEffect = static_cast<T>(effect);
    auto iter = hardware::hidl_enum_range<T>();
    return castEffect >= *iter.begin() && castEffect <= *std::prev(iter.end());
}

// -------------------------------------------------------------------------------------------------

Info HalWrapper::getInfo() {
    getCapabilities();
    getPrimitiveDurations();
    std::lock_guard<std::mutex> lock(mInfoMutex);
    if (mInfoCache.mSupportedEffects.isFailed()) {
        mInfoCache.mSupportedEffects = getSupportedEffectsInternal();
    }
    if (mInfoCache.mSupportedBraking.isFailed()) {
        mInfoCache.mSupportedBraking = getSupportedBrakingInternal();
    }
    if (mInfoCache.mPrimitiveDelayMax.isFailed()) {
        mInfoCache.mPrimitiveDelayMax = getPrimitiveDelayMaxInternal();
    }
    if (mInfoCache.mPwlePrimitiveDurationMax.isFailed()) {
        mInfoCache.mPwlePrimitiveDurationMax = getPrimitiveDurationMaxInternal();
    }
    if (mInfoCache.mCompositionSizeMax.isFailed()) {
        mInfoCache.mCompositionSizeMax = getCompositionSizeMaxInternal();
    }
    if (mInfoCache.mPwleSizeMax.isFailed()) {
        mInfoCache.mPwleSizeMax = getPwleSizeMaxInternal();
    }
    if (mInfoCache.mMinFrequency.isFailed()) {
        mInfoCache.mMinFrequency = getMinFrequencyInternal();
    }
    if (mInfoCache.mResonantFrequency.isFailed()) {
        mInfoCache.mResonantFrequency = getResonantFrequencyInternal();
    }
    if (mInfoCache.mFrequencyResolution.isFailed()) {
        mInfoCache.mFrequencyResolution = getFrequencyResolutionInternal();
    }
    if (mInfoCache.mQFactor.isFailed()) {
        mInfoCache.mQFactor = getQFactorInternal();
    }
    if (mInfoCache.mMaxAmplitudes.isFailed()) {
        mInfoCache.mMaxAmplitudes = getMaxAmplitudesInternal();
    }
    return mInfoCache.get();
}

HalResult<milliseconds> HalWrapper::performComposedEffect(const std::vector<CompositeEffect>&,
                                                          const std::function<void()>&) {
    ALOGV("Skipped performComposedEffect because it's not available in Vibrator HAL");
    return HalResult<milliseconds>::unsupported();
}

HalResult<void> HalWrapper::performPwleEffect(const std::vector<PrimitivePwle>&,
                                              const std::function<void()>&) {
    ALOGV("Skipped performPwleEffect because it's not available in Vibrator HAL");
    return HalResult<void>::unsupported();
}

HalResult<Capabilities> HalWrapper::getCapabilities() {
    std::lock_guard<std::mutex> lock(mInfoMutex);
    if (mInfoCache.mCapabilities.isFailed()) {
        mInfoCache.mCapabilities = getCapabilitiesInternal();
    }
    return mInfoCache.mCapabilities;
}

HalResult<std::vector<milliseconds>> HalWrapper::getPrimitiveDurations() {
    std::lock_guard<std::mutex> lock(mInfoMutex);
    if (mInfoCache.mSupportedPrimitives.isFailed()) {
        mInfoCache.mSupportedPrimitives = getSupportedPrimitivesInternal();
        if (mInfoCache.mSupportedPrimitives.isUnsupported()) {
            mInfoCache.mPrimitiveDurations = HalResult<std::vector<milliseconds>>::unsupported();
        }
    }
    if (mInfoCache.mPrimitiveDurations.isFailed() && mInfoCache.mSupportedPrimitives.isOk()) {
        mInfoCache.mPrimitiveDurations =
                getPrimitiveDurationsInternal(mInfoCache.mSupportedPrimitives.value());
    }
    return mInfoCache.mPrimitiveDurations;
}

HalResult<std::vector<Effect>> HalWrapper::getSupportedEffectsInternal() {
    ALOGV("Skipped getSupportedEffects because it's not available in Vibrator HAL");
    return HalResult<std::vector<Effect>>::unsupported();
}

HalResult<std::vector<Braking>> HalWrapper::getSupportedBrakingInternal() {
    ALOGV("Skipped getSupportedBraking because it's not available in Vibrator HAL");
    return HalResult<std::vector<Braking>>::unsupported();
}

HalResult<std::vector<CompositePrimitive>> HalWrapper::getSupportedPrimitivesInternal() {
    ALOGV("Skipped getSupportedPrimitives because it's not available in Vibrator HAL");
    return HalResult<std::vector<CompositePrimitive>>::unsupported();
}

HalResult<std::vector<milliseconds>> HalWrapper::getPrimitiveDurationsInternal(
        const std::vector<CompositePrimitive>&) {
    ALOGV("Skipped getPrimitiveDurations because it's not available in Vibrator HAL");
    return HalResult<std::vector<milliseconds>>::unsupported();
}

HalResult<milliseconds> HalWrapper::getPrimitiveDelayMaxInternal() {
    ALOGV("Skipped getPrimitiveDelayMaxInternal because it's not available in Vibrator HAL");
    return HalResult<milliseconds>::unsupported();
}

HalResult<milliseconds> HalWrapper::getPrimitiveDurationMaxInternal() {
    ALOGV("Skipped getPrimitiveDurationMaxInternal because it's not available in Vibrator HAL");
    return HalResult<milliseconds>::unsupported();
}

HalResult<int32_t> HalWrapper::getCompositionSizeMaxInternal() {
    ALOGV("Skipped getCompositionSizeMaxInternal because it's not available in Vibrator HAL");
    return HalResult<int32_t>::unsupported();
}

HalResult<int32_t> HalWrapper::getPwleSizeMaxInternal() {
    ALOGV("Skipped getPwleSizeMaxInternal because it's not available in Vibrator HAL");
    return HalResult<int32_t>::unsupported();
}

HalResult<float> HalWrapper::getMinFrequencyInternal() {
    ALOGV("Skipped getMinFrequency because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<float> HalWrapper::getResonantFrequencyInternal() {
    ALOGV("Skipped getResonantFrequency because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<float> HalWrapper::getFrequencyResolutionInternal() {
    ALOGV("Skipped getFrequencyResolution because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<float> HalWrapper::getQFactorInternal() {
    ALOGV("Skipped getQFactor because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<std::vector<float>> HalWrapper::getMaxAmplitudesInternal() {
    ALOGV("Skipped getMaxAmplitudes because it's not available in Vibrator HAL");
    return HalResult<std::vector<float>>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<void> AidlHalWrapper::ping() {
    return HalResultFactory::fromStatus(IInterface::asBinder(getHal())->pingBinder());
}

void AidlHalWrapper::tryReconnect() {
    auto result = mReconnectFn();
    if (!result.isOk()) {
        return;
    }
    sp<Aidl::IVibrator> newHandle = result.value();
    if (newHandle) {
        std::lock_guard<std::mutex> lock(mHandleMutex);
        mHandle = std::move(newHandle);
    }
}

HalResult<void> AidlHalWrapper::on(milliseconds timeout,
                                   const std::function<void()>& completionCallback) {
    HalResult<Capabilities> capabilities = getCapabilities();
    bool supportsCallback = capabilities.isOk() &&
            static_cast<int32_t>(capabilities.value() & Capabilities::ON_CALLBACK);
    auto cb = supportsCallback ? new HalCallbackWrapper(completionCallback) : nullptr;

    auto ret = HalResultFactory::fromStatus(getHal()->on(timeout.count(), cb));
    if (!supportsCallback && ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, timeout);
    }

    return ret;
}

HalResult<void> AidlHalWrapper::off() {
    return HalResultFactory::fromStatus(getHal()->off());
}

HalResult<void> AidlHalWrapper::setAmplitude(float amplitude) {
    return HalResultFactory::fromStatus(getHal()->setAmplitude(amplitude));
}

HalResult<void> AidlHalWrapper::setExternalControl(bool enabled) {
    return HalResultFactory::fromStatus(getHal()->setExternalControl(enabled));
}

HalResult<void> AidlHalWrapper::alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) {
    return HalResultFactory::fromStatus(getHal()->alwaysOnEnable(id, effect, strength));
}

HalResult<void> AidlHalWrapper::alwaysOnDisable(int32_t id) {
    return HalResultFactory::fromStatus(getHal()->alwaysOnDisable(id));
}

HalResult<milliseconds> AidlHalWrapper::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    HalResult<Capabilities> capabilities = getCapabilities();
    bool supportsCallback = capabilities.isOk() &&
            static_cast<int32_t>(capabilities.value() & Capabilities::PERFORM_CALLBACK);
    auto cb = supportsCallback ? new HalCallbackWrapper(completionCallback) : nullptr;

    int32_t lengthMs;
    auto result = getHal()->perform(effect, strength, cb, &lengthMs);
    milliseconds length = milliseconds(lengthMs);

    auto ret = HalResultFactory::fromStatus<milliseconds>(result, length);
    if (!supportsCallback && ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, length);
    }

    return ret;
}

HalResult<milliseconds> AidlHalWrapper::performComposedEffect(
        const std::vector<CompositeEffect>& primitives,
        const std::function<void()>& completionCallback) {
    // This method should always support callbacks, so no need to double check.
    auto cb = new HalCallbackWrapper(completionCallback);

    auto durations = getPrimitiveDurations().valueOr({});
    milliseconds duration(0);
    for (const auto& effect : primitives) {
        auto primitiveIdx = static_cast<size_t>(effect.primitive);
        if (primitiveIdx < durations.size()) {
            duration += durations[primitiveIdx];
        } else {
            // Make sure the returned duration is positive to indicate successful vibration.
            duration += milliseconds(1);
        }
        duration += milliseconds(effect.delayMs);
    }

    return HalResultFactory::fromStatus<milliseconds>(getHal()->compose(primitives, cb), duration);
}

HalResult<void> AidlHalWrapper::performPwleEffect(const std::vector<PrimitivePwle>& primitives,
                                                  const std::function<void()>& completionCallback) {
    // This method should always support callbacks, so no need to double check.
    auto cb = new HalCallbackWrapper(completionCallback);
    return HalResultFactory::fromStatus(getHal()->composePwle(primitives, cb));
}

HalResult<Capabilities> AidlHalWrapper::getCapabilitiesInternal() {
    int32_t capabilities = 0;
    auto result = getHal()->getCapabilities(&capabilities);
    return HalResultFactory::fromStatus<Capabilities>(result,
                                                      static_cast<Capabilities>(capabilities));
}

HalResult<std::vector<Effect>> AidlHalWrapper::getSupportedEffectsInternal() {
    std::vector<Effect> supportedEffects;
    auto result = getHal()->getSupportedEffects(&supportedEffects);
    return HalResultFactory::fromStatus<std::vector<Effect>>(result, supportedEffects);
}

HalResult<std::vector<Braking>> AidlHalWrapper::getSupportedBrakingInternal() {
    std::vector<Braking> supportedBraking;
    auto result = getHal()->getSupportedBraking(&supportedBraking);
    return HalResultFactory::fromStatus<std::vector<Braking>>(result, supportedBraking);
}

HalResult<std::vector<CompositePrimitive>> AidlHalWrapper::getSupportedPrimitivesInternal() {
    std::vector<CompositePrimitive> supportedPrimitives;
    auto result = getHal()->getSupportedPrimitives(&supportedPrimitives);
    return HalResultFactory::fromStatus<std::vector<CompositePrimitive>>(result,
                                                                         supportedPrimitives);
}

HalResult<std::vector<milliseconds>> AidlHalWrapper::getPrimitiveDurationsInternal(
        const std::vector<CompositePrimitive>& supportedPrimitives) {
    std::vector<milliseconds> durations;
    constexpr auto primitiveRange = enum_range<CompositePrimitive>();
    constexpr auto primitiveCount = std::distance(primitiveRange.begin(), primitiveRange.end());
    durations.resize(primitiveCount);

    for (auto primitive : supportedPrimitives) {
        auto primitiveIdx = static_cast<size_t>(primitive);
        if (primitiveIdx >= durations.size()) {
            // Safety check, should not happen if enum_range is correct.
            ALOGE("Supported primitive %zu is outside range [0,%zu), skipping load duration",
                  primitiveIdx, durations.size());
            continue;
        }
        int32_t duration = 0;
        auto result = getHal()->getPrimitiveDuration(primitive, &duration);
        auto halResult = HalResultFactory::fromStatus<int32_t>(result, duration);
        if (halResult.isUnsupported()) {
            // Should not happen, supported primitives should always support requesting duration.
            ALOGE("Supported primitive %zu returned unsupported for getPrimitiveDuration",
                  primitiveIdx);
        }
        if (halResult.isFailed()) {
            // Fail entire request if one request has failed.
            return HalResult<std::vector<milliseconds>>::failed(result.toString8().c_str());
        }
        durations[primitiveIdx] = milliseconds(duration);
    }

    return HalResult<std::vector<milliseconds>>::ok(durations);
}

HalResult<milliseconds> AidlHalWrapper::getPrimitiveDelayMaxInternal() {
    int32_t delay = 0;
    auto result = getHal()->getCompositionDelayMax(&delay);
    return HalResultFactory::fromStatus<milliseconds>(result, milliseconds(delay));
}

HalResult<milliseconds> AidlHalWrapper::getPrimitiveDurationMaxInternal() {
    int32_t delay = 0;
    auto result = getHal()->getPwlePrimitiveDurationMax(&delay);
    return HalResultFactory::fromStatus<milliseconds>(result, milliseconds(delay));
}

HalResult<int32_t> AidlHalWrapper::getCompositionSizeMaxInternal() {
    int32_t size = 0;
    auto result = getHal()->getCompositionSizeMax(&size);
    return HalResultFactory::fromStatus<int32_t>(result, size);
}

HalResult<int32_t> AidlHalWrapper::getPwleSizeMaxInternal() {
    int32_t size = 0;
    auto result = getHal()->getPwleCompositionSizeMax(&size);
    return HalResultFactory::fromStatus<int32_t>(result, size);
}

HalResult<float> AidlHalWrapper::getMinFrequencyInternal() {
    float minFrequency = 0;
    auto result = getHal()->getFrequencyMinimum(&minFrequency);
    return HalResultFactory::fromStatus<float>(result, minFrequency);
}

HalResult<float> AidlHalWrapper::getResonantFrequencyInternal() {
    float f0 = 0;
    auto result = getHal()->getResonantFrequency(&f0);
    return HalResultFactory::fromStatus<float>(result, f0);
}

HalResult<float> AidlHalWrapper::getFrequencyResolutionInternal() {
    float frequencyResolution = 0;
    auto result = getHal()->getFrequencyResolution(&frequencyResolution);
    return HalResultFactory::fromStatus<float>(result, frequencyResolution);
}

HalResult<float> AidlHalWrapper::getQFactorInternal() {
    float qFactor = 0;
    auto result = getHal()->getQFactor(&qFactor);
    return HalResultFactory::fromStatus<float>(result, qFactor);
}

HalResult<std::vector<float>> AidlHalWrapper::getMaxAmplitudesInternal() {
    std::vector<float> amplitudes;
    auto result = getHal()->getBandwidthAmplitudeMap(&amplitudes);
    return HalResultFactory::fromStatus<std::vector<float>>(result, amplitudes);
}

sp<Aidl::IVibrator> AidlHalWrapper::getHal() {
    std::lock_guard<std::mutex> lock(mHandleMutex);
    return mHandle;
}

// -------------------------------------------------------------------------------------------------

template <typename I>
HalResult<void> HidlHalWrapper<I>::ping() {
    auto result = getHal()->ping();
    return HalResultFactory::fromReturn(result);
}

template <typename I>
void HidlHalWrapper<I>::tryReconnect() {
    sp<I> newHandle = I::tryGetService();
    if (newHandle) {
        std::lock_guard<std::mutex> lock(mHandleMutex);
        mHandle = std::move(newHandle);
    }
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::on(milliseconds timeout,
                                      const std::function<void()>& completionCallback) {
    auto result = getHal()->on(timeout.count());
    auto ret = HalResultFactory::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
    if (ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, timeout);
    }
    return ret;
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::off() {
    auto result = getHal()->off();
    return HalResultFactory::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::setAmplitude(float amplitude) {
    uint8_t amp = static_cast<uint8_t>(amplitude * std::numeric_limits<uint8_t>::max());
    auto result = getHal()->setAmplitude(amp);
    return HalResultFactory::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::setExternalControl(bool) {
    ALOGV("Skipped setExternalControl because Vibrator HAL does not support it");
    return HalResult<void>::unsupported();
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::alwaysOnEnable(int32_t, Effect, EffectStrength) {
    ALOGV("Skipped alwaysOnEnable because Vibrator HAL AIDL is not available");
    return HalResult<void>::unsupported();
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::alwaysOnDisable(int32_t) {
    ALOGV("Skipped alwaysOnDisable because Vibrator HAL AIDL is not available");
    return HalResult<void>::unsupported();
}

template <typename I>
HalResult<Capabilities> HidlHalWrapper<I>::getCapabilitiesInternal() {
    hardware::Return<bool> result = getHal()->supportsAmplitudeControl();
    Capabilities capabilities =
            result.withDefault(false) ? Capabilities::AMPLITUDE_CONTROL : Capabilities::NONE;
    return HalResultFactory::fromReturn<Capabilities>(result, capabilities);
}

template <typename I>
template <typename T>
HalResult<milliseconds> HidlHalWrapper<I>::performInternal(
        perform_fn<T> performFn, sp<I> handle, T effect, EffectStrength strength,
        const std::function<void()>& completionCallback) {
    V1_0::Status status;
    int32_t lengthMs;
    auto effectCallback = [&status, &lengthMs](V1_0::Status retStatus, uint32_t retLengthMs) {
        status = retStatus;
        lengthMs = retLengthMs;
    };

    V1_0::EffectStrength effectStrength = static_cast<V1_0::EffectStrength>(strength);
    auto result = std::invoke(performFn, handle, effect, effectStrength, effectCallback);
    milliseconds length = milliseconds(lengthMs);

    auto ret = HalResultFactory::fromReturn<milliseconds>(result, status, length);
    if (ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, length);
    }

    return ret;
}

template <typename I>
sp<I> HidlHalWrapper<I>::getHal() {
    std::lock_guard<std::mutex> lock(mHandleMutex);
    return mHandle;
}

// -------------------------------------------------------------------------------------------------

HalResult<milliseconds> HidlHalWrapperV1_0::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_0::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<milliseconds> HidlHalWrapperV1_1::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_1::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_1::Effect_1_1>(effect)) {
        return performInternal(&V1_1::IVibrator::perform_1_1, getHal(),
                               static_cast<V1_1::Effect_1_1>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<milliseconds> HidlHalWrapperV1_2::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_2::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_1::Effect_1_1>(effect)) {
        return performInternal(&V1_2::IVibrator::perform_1_1, getHal(),
                               static_cast<V1_1::Effect_1_1>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_2::Effect>(effect)) {
        return performInternal(&V1_2::IVibrator::perform_1_2, getHal(),
                               static_cast<V1_2::Effect>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HidlHalWrapperV1_3::setExternalControl(bool enabled) {
    auto result = getHal()->setExternalControl(static_cast<uint32_t>(enabled));
    return HalResultFactory::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
}

HalResult<milliseconds> HidlHalWrapperV1_3::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_3::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_1::Effect_1_1>(effect)) {
        return performInternal(&V1_3::IVibrator::perform_1_1, getHal(),
                               static_cast<V1_1::Effect_1_1>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_2::Effect>(effect)) {
        return performInternal(&V1_3::IVibrator::perform_1_2, getHal(),
                               static_cast<V1_2::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_3::Effect>(effect)) {
        return performInternal(&V1_3::IVibrator::perform_1_3, getHal(),
                               static_cast<V1_3::Effect>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

HalResult<Capabilities> HidlHalWrapperV1_3::getCapabilitiesInternal() {
    Capabilities capabilities = Capabilities::NONE;

    sp<V1_3::IVibrator> hal = getHal();
    auto amplitudeResult = hal->supportsAmplitudeControl();
    if (!amplitudeResult.isOk()) {
        return HalResultFactory::fromReturn<Capabilities>(amplitudeResult, capabilities);
    }

    auto externalControlResult = hal->supportsExternalControl();
    if (amplitudeResult.withDefault(false)) {
        capabilities |= Capabilities::AMPLITUDE_CONTROL;
    }
    if (externalControlResult.withDefault(false)) {
        capabilities |= Capabilities::EXTERNAL_CONTROL;

        if (amplitudeResult.withDefault(false)) {
            capabilities |= Capabilities::EXTERNAL_AMPLITUDE_CONTROL;
        }
    }

    return HalResultFactory::fromReturn<Capabilities>(externalControlResult, capabilities);
}

// -------------------------------------------------------------------------------------------------

}; // namespace vibrator

}; // namespace android
