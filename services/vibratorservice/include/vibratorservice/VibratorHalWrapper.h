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

namespace android {

namespace vibrator {

// -------------------------------------------------------------------------------------------------

// Result of a call to the Vibrator HAL wrapper, holding data if successful.
template <typename T>
class HalResult {
public:
    static HalResult<T> ok(T value);
    static HalResult<T> failed();
    static HalResult<T> unsupported();

    static HalResult<T> fromStatus(binder::Status status, T data);
    static HalResult<T> fromStatus(hardware::vibrator::V1_0::Status status, T data);

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret, T data);

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret,
                                   hardware::vibrator::V1_0::Status status, T data);

    // This will throw std::bad_optional_access if this result is not ok.
    T value() const { return mValue.value(); }
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
    static HalResult<void> ok();
    static HalResult<void> failed();
    static HalResult<void> unsupported();

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
};

// Wrapper for the AIDL Vibrator HAL.
class AidlHalWrapper : public HalWrapper {
public:
    explicit AidlHalWrapper(sp<hardware::vibrator::IVibrator> handle)
          : mHandle(std::move(handle)) {}

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
};

// Wrapper for the HDIL Vibrator HAL v1.0.
class HidlHalWrapperV1_0 : public HalWrapper {
public:
    explicit HidlHalWrapperV1_0(sp<hardware::vibrator::V1_0::IVibrator> handle)
          : mHandleV1_0(std::move(handle)) {}

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
};

// Wrapper for the HDIL Vibrator HAL v1.1.
class HidlHalWrapperV1_1 : public HidlHalWrapperV1_0 {
public:
    explicit HidlHalWrapperV1_1(sp<hardware::vibrator::V1_0::IVibrator> handleV1_0)
          : HidlHalWrapperV1_0(handleV1_0),
            mHandleV1_1(hardware::vibrator::V1_1::IVibrator::castFrom(handleV1_0)) {}

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_1::IVibrator> mHandleV1_1;
};

// Wrapper for the HDIL Vibrator HAL v1.2.
class HidlHalWrapperV1_2 : public HidlHalWrapperV1_1 {
public:
    explicit HidlHalWrapperV1_2(sp<hardware::vibrator::V1_0::IVibrator> handleV1_0)
          : HidlHalWrapperV1_1(handleV1_0),
            mHandleV1_2(hardware::vibrator::V1_2::IVibrator::castFrom(handleV1_0)) {}

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_2::IVibrator> mHandleV1_2;
};

// Wrapper for the HDIL Vibrator HAL v1.3.
class HidlHalWrapperV1_3 : public HidlHalWrapperV1_2 {
public:
    explicit HidlHalWrapperV1_3(sp<hardware::vibrator::V1_0::IVibrator> handleV1_0)
          : HidlHalWrapperV1_2(handleV1_0),
            mHandleV1_3(hardware::vibrator::V1_3::IVibrator::castFrom(handleV1_0)) {}

    virtual HalResult<void> setExternalControl(bool enabled) override;
    virtual HalResult<Capabilities> getCapabilities() override;

    virtual HalResult<std::chrono::milliseconds> performEffect(
            hardware::vibrator::Effect effect, hardware::vibrator::EffectStrength strength,
            const std::function<void()>& completionCallback) override;

protected:
    const sp<hardware::vibrator::V1_3::IVibrator> mHandleV1_3;
};

// -------------------------------------------------------------------------------------------------

}; // namespace vibrator

}; // namespace android

#endif // ANDROID_OS_VIBRATORHALWRAPPER_H
