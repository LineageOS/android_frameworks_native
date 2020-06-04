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

#ifndef ANDROID_OS_VIBRATORHALWRAPPER_H
#define ANDROID_OS_VIBRATORHALWRAPPER_H

#include <android-base/thread_annotations.h>
#include <android/hardware/vibrator/1.3/IVibrator.h>
#include <android/hardware/vibrator/IVibrator.h>

#include <vibratorservice/VibratorCallbackScheduler.h>

namespace android {

namespace vibrator {

// -------------------------------------------------------------------------------------------------

// Result of a call to the Vibrator HAL wrapper, holding data if successful.
template <typename T>
class HalResult {
public:
    static HalResult<T> ok(T value) { return HalResult(value); }
    static HalResult<T> failed() { return HalResult(/* unsupported= */ false); }
    static HalResult<T> unsupported() { return HalResult(/* unsupported= */ true); }

    static HalResult<T> fromStatus(binder::Status status, T data);
    static HalResult<T> fromStatus(hardware::vibrator::V1_0::Status status, T data);

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret, T data);

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret,
                                   hardware::vibrator::V1_0::Status status, T data);

    // This will throw std::bad_optional_access if this result is not ok.
    const T& value() const { return mValue.value(); }
    bool isOk() const { return !mUnsupported && mValue.has_value(); }
    bool isFailed() const { return !mUnsupported && !mValue.has_value(); }
    bool isUnsupported() const { return mUnsupported; }

private:
    std::optional<T> mValue;
    bool mUnsupported;

    explicit HalResult(T value) : mValue(std::make_optional(value)), mUnsupported(false) {}
    explicit HalResult(bool unsupported) : mValue(), mUnsupported(unsupported) {}
};

// Empty result of a call to the Vibrator HAL wrapper.
template <>
class HalResult<void> {
public:
    static HalResult<void> ok() { return HalResult(); }
    static HalResult<void> failed() { return HalResult(/* failed= */ true); }
    static HalResult<void> unsupported() {
        return HalResult(/* failed= */ false, /* unsupported= */ true);
    }

    static HalResult<void> fromStatus(binder::Status status);
    static HalResult<void> fromStatus(hardware::vibrator::V1_0::Status status);

    template <typename R>
    static HalResult<void> fromReturn(hardware::Return<R>& ret);

    bool isOk() const { return !mUnsupported && !mFailed; }
    bool isFailed() const { return !mUnsupported && mFailed; }
    bool isUnsupported() const { return mUnsupported; }

private:
    bool mFailed;
    bool mUnsupported;

    explicit HalResult(bool failed = false, bool unsupported = false)
          : mFailed(failed), mUnsupported(unsupported) {}
};

// -------------------------------------------------------------------------------------------------

// Vibrator HAL capabilities.
enum class Capabilities : int32_t {
    NONE = 0,
    ON_CALLBACK = hardware::vibrator::IVibrator::CAP_ON_CALLBACK,
    PERFORM_CALLBACK = hardware::vibrator::IVibrator::CAP_PERFORM_CALLBACK,
    AMPLITUDE_CONTROL = hardware::vibrator::IVibrator::CAP_AMPLITUDE_CONTROL,
    EXTERNAL_CONTROL = hardware::vibrator::IVibrator::CAP_EXTERNAL_CONTROL,
    EXTERNAL_AMPLITUDE_CONTROL = hardware::vibrator::IVibrator::CAP_EXTERNAL_AMPLITUDE_CONTROL,
    COMPOSE_EFFECTS = hardware::vibrator::IVibrator::CAP_COMPOSE_EFFECTS,
    ALWAYS_ON_CONTROL = hardware::vibrator::IVibrator::CAP_ALWAYS_ON_CONTROL
};

inline Capabilities operator|(Capabilities lhs, Capabilities rhs) {
    using underlying = typename std::underlying_type<Capabilities>::type;
    return static_cast<Capabilities>(static_cast<underlying>(lhs) | static_cast<underlying>(rhs));
}

inline Capabilities& operator|=(Capabilities& lhs, Capabilities rhs) {
    return lhs = lhs | rhs;
}

inline Capabilities operator&(Capabilities lhs, Capabilities rhs) {
    using underlying = typename std::underlying_type<Capabilities>::type;
    return static_cast<Capabilities>(static_cast<underlying>(lhs) & static_cast<underlying>(rhs));
}

inline Capabilities& operator&=(Capabilities& lhs, Capabilities rhs) {
    return lhs = lhs & rhs;
}

// -------------------------------------------------------------------------------------------------

// Wrapper for Vibrator HAL handlers.
class HalWrapper {
public:
    explicit HalWrapper(std::shared_ptr<CallbackScheduler> scheduler)
          : mCallbackScheduler(std::move(scheduler)) {}
    virtual ~HalWrapper() = default;

    virtual HalResult<void> ping() = 0;

    virtual HalResult<void> on(std::chrono::milliseconds timeout,
                               const std::function<void()>& completionCallback) = 0;
    virtual HalResult<void> off() = 0;

    virtual HalResult<void> setAmplitude(int32_t amplitude) = 0;
    virtual HalResult<void> setExternalControl(bool enabled) = 0;

    virtual HalResult<void> alwaysOnEnable(int32_t id, hardware::vibrator::Effect effect,
                                           hardware::vibrator::EffectStrength strength) = 0;
    virtual HalResult<void> alwaysOnDisable(int32_t id) = 0;

    virtual HalResult<Capabilities> getCapabilities() = 0;
    virtual HalResult<std::vector<hardware::vibrator::Effect>> getSupportedEffects() = 0;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) = 0;

    virtual HalResult<void> performComposedEffect(
            const std::vector<hardware::vibrator::CompositeEffect>& primitiveEffects,
            const std::function<void()>& completionCallback) = 0;

protected:
    // Shared pointer to allow CallbackScheduler to outlive this wrapper.
    const std::shared_ptr<CallbackScheduler> mCallbackScheduler;
};

// Wrapper for the AIDL Vibrator HAL.
class AidlHalWrapper : public HalWrapper {
public:
    AidlHalWrapper(std::shared_ptr<CallbackScheduler> scheduler,
                   sp<hardware::vibrator::IVibrator> handle)
          : HalWrapper(std::move(scheduler)), mHandle(std::move(handle)) {}
    virtual ~AidlHalWrapper() = default;

    virtual HalResult<void> ping() override;

    virtual HalResult<void> on(std::chrono::milliseconds timeout,
                               const std::function<void()>& completionCallback) override;
    virtual HalResult<void> off() override;

    virtual HalResult<void> setAmplitude(int32_t amplitude) override;
    virtual HalResult<void> setExternalControl(bool enabled) override;

    virtual HalResult<void> alwaysOnEnable(int32_t id, hardware::vibrator::Effect effect,
                                           hardware::vibrator::EffectStrength strength) override;
    virtual HalResult<void> alwaysOnDisable(int32_t id) override;

    virtual HalResult<Capabilities> getCapabilities() override;
    virtual HalResult<std::vector<hardware::vibrator::Effect>> getSupportedEffects() override;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

    virtual HalResult<void> performComposedEffect(
            const std::vector<hardware::vibrator::CompositeEffect>& primitiveEffects,
            const std::function<void()>& completionCallback) override;

private:
    const sp<hardware::vibrator::IVibrator> mHandle;
    std::mutex mCapabilitiesMutex;
    std::mutex mSupportedEffectsMutex;
    std::optional<Capabilities> mCapabilities GUARDED_BY(mCapabilitiesMutex);
    std::optional<std::vector<hardware::vibrator::Effect>> mSupportedEffects
            GUARDED_BY(mSupportedEffectsMutex);

    // Loads directly from IVibrator handle, skipping caches.
    HalResult<Capabilities> getCapabilitiesInternal();
    HalResult<std::vector<hardware::vibrator::Effect>> getSupportedEffectsInternal();
};

// Wrapper for the HDIL Vibrator HAL v1.0.
class HidlHalWrapperV1_0 : public HalWrapper {
public:
    HidlHalWrapperV1_0(std::shared_ptr<CallbackScheduler> scheduler,
                       sp<hardware::vibrator::V1_0::IVibrator> handle)
          : HalWrapper(std::move(scheduler)), mHandleV1_0(std::move(handle)) {}
    virtual ~HidlHalWrapperV1_0() = default;

    virtual HalResult<void> ping() override;

    virtual HalResult<void> on(std::chrono::milliseconds timeout,
                               const std::function<void()>& completionCallback) override;
    virtual HalResult<void> off() override;

    virtual HalResult<void> setAmplitude(int32_t amplitude) override;
    virtual HalResult<void> setExternalControl(bool enabled) override;

    virtual HalResult<void> alwaysOnEnable(int32_t id, hardware::vibrator::Effect effect,
                                           hardware::vibrator::EffectStrength strength) override;
    virtual HalResult<void> alwaysOnDisable(int32_t id) override;

    virtual HalResult<Capabilities> getCapabilities() override;
    virtual HalResult<std::vector<hardware::vibrator::Effect>> getSupportedEffects() override;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

    virtual HalResult<void> performComposedEffect(
            const std::vector<hardware::vibrator::CompositeEffect>& primitiveEffects,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_0::IVibrator> mHandleV1_0;
    std::mutex mCapabilitiesMutex;
    std::optional<Capabilities> mCapabilities GUARDED_BY(mCapabilitiesMutex);

    // Loads directly from IVibrator handle, skipping the mCapabilities cache.
    virtual HalResult<Capabilities> getCapabilitiesInternal();

    template <class I, class T>
    using perform_fn =
            hardware::Return<void> (I::*)(T, hardware::vibrator::V1_0::EffectStrength,
                                          hardware::vibrator::V1_0::IVibrator::perform_cb);

    template <class I, class T>
    HalResult<std::chrono::milliseconds> performInternal(
            perform_fn<I, T> performFn, sp<I> handle, T effect,
            hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback);

    HalResult<std::chrono::milliseconds> performInternalV1_0(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback);
};

// Wrapper for the HDIL Vibrator HAL v1.1.
class HidlHalWrapperV1_1 : public HidlHalWrapperV1_0 {
public:
    HidlHalWrapperV1_1(std::shared_ptr<CallbackScheduler> scheduler,
                       sp<hardware::vibrator::V1_1::IVibrator> handle)
          : HidlHalWrapperV1_0(std::move(scheduler), handle), mHandleV1_1(handle) {}
    virtual ~HidlHalWrapperV1_1() = default;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_1::IVibrator> mHandleV1_1;

    HalResult<std::chrono::milliseconds> performInternalV1_1(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback);
};

// Wrapper for the HDIL Vibrator HAL v1.2.
class HidlHalWrapperV1_2 : public HidlHalWrapperV1_1 {
public:
    HidlHalWrapperV1_2(std::shared_ptr<CallbackScheduler> scheduler,
                       sp<hardware::vibrator::V1_2::IVibrator> handle)
          : HidlHalWrapperV1_1(std::move(scheduler), handle), mHandleV1_2(handle) {}
    virtual ~HidlHalWrapperV1_2() = default;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_2::IVibrator> mHandleV1_2;

    HalResult<std::chrono::milliseconds> performInternalV1_2(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback);
};

// Wrapper for the HDIL Vibrator HAL v1.3.
class HidlHalWrapperV1_3 : public HidlHalWrapperV1_2 {
public:
    HidlHalWrapperV1_3(std::shared_ptr<CallbackScheduler> scheduler,
                       sp<hardware::vibrator::V1_3::IVibrator> handle)
          : HidlHalWrapperV1_2(std::move(scheduler), handle), mHandleV1_3(handle) {}
    virtual ~HidlHalWrapperV1_3() = default;

    virtual HalResult<void> setExternalControl(bool enabled) override;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_3::IVibrator> mHandleV1_3;

    virtual HalResult<Capabilities> getCapabilitiesInternal() override;
    HalResult<std::chrono::milliseconds> performInternalV1_3(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback);
};

// -------------------------------------------------------------------------------------------------

}; // namespace vibrator

}; // namespace android

#endif // ANDROID_OS_VIBRATORHALWRAPPER_H
