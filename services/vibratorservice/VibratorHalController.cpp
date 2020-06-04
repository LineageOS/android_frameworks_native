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

#define LOG_TAG "VibratorHalController"

#include <android/hardware/vibrator/1.3/IVibrator.h>
#include <android/hardware/vibrator/IVibrator.h>
#include <binder/IServiceManager.h>
#include <hardware/vibrator.h>

#include <utils/Log.h>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalController.h>
#include <vibratorservice/VibratorHalWrapper.h>

using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;

using std::chrono::milliseconds;

namespace V1_0 = android::hardware::vibrator::V1_0;
namespace V1_1 = android::hardware::vibrator::V1_1;
namespace V1_2 = android::hardware::vibrator::V1_2;
namespace V1_3 = android::hardware::vibrator::V1_3;
namespace Aidl = android::hardware::vibrator;

namespace android {

namespace vibrator {

// -------------------------------------------------------------------------------------------------

template <typename T>
using hal_connect_fn = std::function<sp<T>()>;

template <typename T>
sp<T> connectToHal(bool* halExists, const hal_connect_fn<T>& connectFn, const char* halName) {
    if (!*halExists) {
        return nullptr;
    }
    sp<T> hal = connectFn();
    if (hal) {
        ALOGV("Successfully connected to Vibrator HAL %s service.", halName);
    } else {
        ALOGV("Vibrator HAL %s service not available.", halName);
        *halExists = false;
    }
    return hal;
}

sp<Aidl::IVibrator> connectToAidl() {
    static bool gHalExists = true;
    static hal_connect_fn<Aidl::IVibrator> connectFn = []() {
        return waitForVintfService<Aidl::IVibrator>();
    };
    return connectToHal(&gHalExists, connectFn, "AIDL");
}

sp<V1_0::IVibrator> connectToHidl() {
    static bool gHalExists = true;
    static hal_connect_fn<V1_0::IVibrator> connectFn = []() {
        return V1_0::IVibrator::getService();
    };
    return connectToHal(&gHalExists, connectFn, "v1.0");
}

// -------------------------------------------------------------------------------------------------

std::shared_ptr<HalWrapper> HalConnector::connect(std::shared_ptr<CallbackScheduler> scheduler) {
    sp<Aidl::IVibrator> aidlHal = connectToAidl();
    if (aidlHal) {
        return std::make_shared<AidlHalWrapper>(std::move(scheduler), aidlHal);
    }
    sp<V1_0::IVibrator> halV1_0 = connectToHidl();
    if (halV1_0 == nullptr) {
        // No Vibrator HAL service available.
        return nullptr;
    }
    sp<V1_3::IVibrator> halV1_3 = V1_3::IVibrator::castFrom(halV1_0);
    if (halV1_3) {
        ALOGV("Successfully converted to Vibrator HAL v1.3 service.");
        return std::make_shared<HidlHalWrapperV1_3>(std::move(scheduler), halV1_3);
    }
    sp<V1_2::IVibrator> halV1_2 = V1_2::IVibrator::castFrom(halV1_0);
    if (halV1_2) {
        ALOGV("Successfully converted to Vibrator HAL v1.2 service.");
        return std::make_shared<HidlHalWrapperV1_2>(std::move(scheduler), halV1_2);
    }
    sp<V1_1::IVibrator> halV1_1 = V1_1::IVibrator::castFrom(halV1_0);
    if (halV1_1) {
        ALOGV("Successfully converted to Vibrator HAL v1.1 service.");
        return std::make_shared<HidlHalWrapperV1_1>(std::move(scheduler), halV1_1);
    }
    return std::make_shared<HidlHalWrapperV1_0>(std::move(scheduler), halV1_0);
}

// -------------------------------------------------------------------------------------------------

template <typename T>
HalResult<T> HalController::processHalResult(HalResult<T> result, const char* functionName) {
    if (result.isFailed()) {
        ALOGE("%s failed: Vibrator HAL not available", functionName);
        std::lock_guard<std::mutex> lock(mConnectedHalMutex);
        // Drop HAL handle. This will force future api calls to reconnect.
        mConnectedHal = nullptr;
    }
    return result;
}

template <typename T>
HalResult<T> HalController::apply(HalController::hal_fn<T>& halFn, const char* functionName) {
    std::shared_ptr<HalWrapper> hal = nullptr;
    {
        std::lock_guard<std::mutex> lock(mConnectedHalMutex);
        if (mConnectedHal == nullptr) {
            mConnectedHal = mHalConnector->connect(mCallbackScheduler);
        }
        hal = mConnectedHal;
    }
    if (hal) {
        return processHalResult(halFn(hal), functionName);
    }

    ALOGV("Skipped %s because Vibrator HAL is not available", functionName);
    return HalResult<T>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HalController::ping() {
    hal_fn<void> pingFn = [](std::shared_ptr<HalWrapper> hal) { return hal->ping(); };
    return apply(pingFn, "ping");
}

HalResult<void> HalController::on(milliseconds timeout,
                                  const std::function<void()>& completionCallback) {
    hal_fn<void> onFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->on(timeout, completionCallback);
    };
    return apply(onFn, "on");
}

HalResult<void> HalController::off() {
    hal_fn<void> offFn = [](std::shared_ptr<HalWrapper> hal) { return hal->off(); };
    return apply(offFn, "off");
}

HalResult<void> HalController::setAmplitude(int32_t amplitude) {
    hal_fn<void> setAmplitudeFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->setAmplitude(amplitude);
    };
    return apply(setAmplitudeFn, "setAmplitude");
}

HalResult<void> HalController::setExternalControl(bool enabled) {
    hal_fn<void> setExternalControlFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->setExternalControl(enabled);
    };
    return apply(setExternalControlFn, "setExternalControl");
}

HalResult<void> HalController::alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) {
    hal_fn<void> alwaysOnEnableFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->alwaysOnEnable(id, effect, strength);
    };
    return apply(alwaysOnEnableFn, "alwaysOnEnable");
}

HalResult<void> HalController::alwaysOnDisable(int32_t id) {
    hal_fn<void> alwaysOnDisableFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->alwaysOnDisable(id);
    };
    return apply(alwaysOnDisableFn, "alwaysOnDisable");
}

HalResult<Capabilities> HalController::getCapabilities() {
    hal_fn<Capabilities> getCapabilitiesFn = [](std::shared_ptr<HalWrapper> hal) {
        return hal->getCapabilities();
    };
    return apply(getCapabilitiesFn, "getCapabilities");
}

HalResult<std::vector<Effect>> HalController::getSupportedEffects() {
    hal_fn<std::vector<Effect>> getSupportedEffectsFn = [](std::shared_ptr<HalWrapper> hal) {
        return hal->getSupportedEffects();
    };
    return apply(getSupportedEffectsFn, "getSupportedEffects");
}

HalResult<milliseconds> HalController::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    hal_fn<milliseconds> performEffectFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->performEffect(effect, strength, completionCallback);
    };
    return apply(performEffectFn, "performEffect");
}

HalResult<void> HalController::performComposedEffect(
        const std::vector<CompositeEffect>& primitiveEffects,
        const std::function<void()>& completionCallback) {
    hal_fn<void> performComposedEffectFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->performComposedEffect(primitiveEffects, completionCallback);
    };
    return apply(performComposedEffectFn, "performComposedEffect");
}

}; // namespace vibrator

}; // namespace android
