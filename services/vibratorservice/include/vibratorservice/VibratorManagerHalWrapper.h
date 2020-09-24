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

#ifndef ANDROID_OS_VIBRATOR_MANAGER_HAL_WRAPPER_H
#define ANDROID_OS_VIBRATOR_MANAGER_HAL_WRAPPER_H

#include <vibratorservice/VibratorHalController.h>

namespace android {

namespace vibrator {

// Wrapper for VibratorManager HAL handlers.
class ManagerHalWrapper {
public:
    ManagerHalWrapper() = default;
    virtual ~ManagerHalWrapper() = default;

    virtual HalResult<void> ping() = 0;

    /* reloads wrapped HAL service instance without waiting. This can be used to reconnect when the
     * service restarts, to rapidly retry after a failure.
     */
    virtual void tryReconnect() = 0;

    virtual HalResult<std::vector<int32_t>> getVibratorIds() = 0;
    virtual HalResult<std::shared_ptr<HalController>> getVibrator(int32_t id) = 0;

    virtual HalResult<void> prepareSynced(const std::vector<int32_t>& ids) = 0;
    virtual HalResult<void> triggerSynced(const std::function<void()>& completionCallback) = 0;
    virtual HalResult<void> cancelSynced() = 0;
};

// Wrapper for the VibratorManager over single Vibrator HAL.
class LegacyManagerHalWrapper : public ManagerHalWrapper {
public:
    LegacyManagerHalWrapper() : LegacyManagerHalWrapper(std::make_shared<HalController>()) {}
    explicit LegacyManagerHalWrapper(std::shared_ptr<HalController> controller)
          : mController(std::move(controller)) {}
    virtual ~LegacyManagerHalWrapper() = default;

    HalResult<void> ping() override final;
    void tryReconnect() override final;

    HalResult<std::vector<int32_t>> getVibratorIds() override final;
    HalResult<std::shared_ptr<HalController>> getVibrator(int32_t id) override final;

    HalResult<void> prepareSynced(const std::vector<int32_t>& ids) override final;
    HalResult<void> triggerSynced(const std::function<void()>& completionCallback) override final;
    HalResult<void> cancelSynced() override final;

private:
    const std::shared_ptr<HalController> mController;
};

}; // namespace vibrator

}; // namespace android

#endif // ANDROID_OS_VIBRATOR_MANAGER_HAL_WRAPPER_H
