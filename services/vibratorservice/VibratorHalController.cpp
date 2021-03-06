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
using android::hardware::vibrator::CompositePrimitive;
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

std::shared_ptr<HalWrapper> connectHal(std::shared_ptr<CallbackScheduler> scheduler) {
    static bool gHalExists = true;
    if (!gHalExists) {
        // We already tried to connect to all of the vibrator HAL versions and none was available.
        return nullptr;
    }

    sp<Aidl::IVibrator> aidlHal = waitForVintfService<Aidl::IVibrator>();
    if (aidlHal) {
        ALOGV("Successfully connected to Vibrator HAL AIDL service.");
        return std::make_shared<AidlHalWrapper>(std::move(scheduler), aidlHal);
    }

    sp<V1_0::IVibrator> halV1_0 = V1_0::IVibrator::getService();
    if (halV1_0 == nullptr) {
        ALOGV("Vibrator HAL service not available.");
        gHalExists = false;
        return nullptr;
    }

    sp<V1_3::IVibrator> halV1_3 = V1_3::IVibrator::castFrom(halV1_0);
    if (halV1_3) {
        ALOGV("Successfully connected to Vibrator HAL v1.3 service.");
        return std::make_shared<HidlHalWrapperV1_3>(std::move(scheduler), halV1_3);
    }
    sp<V1_2::IVibrator> halV1_2 = V1_2::IVibrator::castFrom(halV1_0);
    if (halV1_2) {
        ALOGV("Successfully connected to Vibrator HAL v1.2 service.");
        return std::make_shared<HidlHalWrapperV1_2>(std::move(scheduler), halV1_2);
    }
    sp<V1_1::IVibrator> halV1_1 = V1_1::IVibrator::castFrom(halV1_0);
    if (halV1_1) {
        ALOGV("Successfully connected to Vibrator HAL v1.1 service.");
        return std::make_shared<HidlHalWrapperV1_1>(std::move(scheduler), halV1_1);
    }
    ALOGV("Successfully connected to Vibrator HAL v1.0 service.");
    return std::make_shared<HidlHalWrapperV1_0>(std::move(scheduler), halV1_0);
}

// -------------------------------------------------------------------------------------------------

static constexpr int MAX_RETRIES = 1;

template <typename T>
HalResult<T> HalController::processHalResult(HalResult<T> result, const char* functionName) {
    if (result.isFailed()) {
        ALOGE("%s failed: %s", functionName, result.errorMessage());
        std::lock_guard<std::mutex> lock(mConnectedHalMutex);
        mConnectedHal->tryReconnect();
    }
    return result;
}

template <typename T>
HalResult<T> HalController::apply(HalController::hal_fn<T>& halFn, const char* functionName) {
    std::shared_ptr<HalWrapper> hal = nullptr;
    {
        std::lock_guard<std::mutex> lock(mConnectedHalMutex);
        if (mConnectedHal == nullptr) {
            // Init was never called, so connect to HAL for the first time during this call.
            mConnectedHal = mConnector(mCallbackScheduler);

            if (mConnectedHal == nullptr) {
                ALOGV("Skipped %s because Vibrator HAL is not available", functionName);
                return HalResult<T>::unsupported();
            }
        }
        hal = mConnectedHal;
    }

    HalResult<T> ret = processHalResult(halFn(hal), functionName);
    for (int i = 0; i < MAX_RETRIES && ret.isFailed(); i++) {
        ret = processHalResult(halFn(hal), functionName);
    }

    return ret;
}

// -------------------------------------------------------------------------------------------------

bool HalController::init() {
    std::lock_guard<std::mutex> lock(mConnectedHalMutex);
    if (mConnectedHal == nullptr) {
        mConnectedHal = mConnector(mCallbackScheduler);
    }
    return mConnectedHal != nullptr;
}

HalResult<void> HalController::ping() {
    hal_fn<void> pingFn = [](std::shared_ptr<HalWrapper> hal) { return hal->ping(); };
    return apply(pingFn, "ping");
}

void HalController::tryReconnect() {
    std::lock_guard<std::mutex> lock(mConnectedHalMutex);
    if (mConnectedHal == nullptr) {
        mConnectedHal = mConnector(mCallbackScheduler);
    } else {
        mConnectedHal->tryReconnect();
    }
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

HalResult<std::vector<CompositePrimitive>> HalController::getSupportedPrimitives() {
    hal_fn<std::vector<CompositePrimitive>> getSupportedPrimitivesFn =
            [](std::shared_ptr<HalWrapper> hal) { return hal->getSupportedPrimitives(); };
    return apply(getSupportedPrimitivesFn, "getSupportedPrimitives");
}

HalResult<milliseconds> HalController::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    hal_fn<milliseconds> performEffectFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->performEffect(effect, strength, completionCallback);
    };
    return apply(performEffectFn, "performEffect");
}

HalResult<milliseconds> HalController::performComposedEffect(
        const std::vector<CompositeEffect>& primitiveEffects,
        const std::function<void()>& completionCallback) {
    hal_fn<milliseconds> performComposedEffectFn = [&](std::shared_ptr<HalWrapper> hal) {
        return hal->performComposedEffect(primitiveEffects, completionCallback);
    };
    return apply(performComposedEffectFn, "performComposedEffect");
}

}; // namespace vibrator

}; // namespace android
