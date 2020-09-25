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

#define LOG_TAG "VibratorManagerHalWrapper"

#include <utils/Log.h>

#include <vibratorservice/VibratorManagerHalWrapper.h>

namespace android {

namespace vibrator {

constexpr int32_t SINGLE_VIBRATOR_ID = 0;

HalResult<void> LegacyManagerHalWrapper::ping() {
    return mController->ping();
}

void LegacyManagerHalWrapper::tryReconnect() {
    mController->tryReconnect();
}

HalResult<std::vector<int32_t>> LegacyManagerHalWrapper::getVibratorIds() {
    if (mController->init()) {
        return HalResult<std::vector<int32_t>>::ok(std::vector<int32_t>(1, SINGLE_VIBRATOR_ID));
    }
    // Controller.init did not connect to any vibrator HAL service, so the device has no vibrator.
    return HalResult<std::vector<int32_t>>::ok(std::vector<int32_t>());
}

HalResult<std::shared_ptr<HalController>> LegacyManagerHalWrapper::getVibrator(int32_t id) {
    if (id == SINGLE_VIBRATOR_ID && mController->init()) {
        return HalResult<std::shared_ptr<HalController>>::ok(mController);
    }
    // Controller.init did not connect to any vibrator HAL service, so the device has no vibrator.
    return HalResult<std::shared_ptr<HalController>>::failed("No vibrator with id = " +
                                                             std::to_string(id));
}

HalResult<void> LegacyManagerHalWrapper::prepareSynced(const std::vector<int32_t>&) {
    return HalResult<void>::unsupported();
}

HalResult<void> LegacyManagerHalWrapper::triggerSynced(const std::function<void()>&) {
    return HalResult<void>::unsupported();
}

HalResult<void> LegacyManagerHalWrapper::cancelSynced() {
    return HalResult<void>::unsupported();
}

}; // namespace vibrator

}; // namespace android
