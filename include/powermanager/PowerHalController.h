/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *                        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_POWERHALCONTROLLER_H
#define ANDROID_POWERHALCONTROLLER_H

#include <android-base/thread_annotations.h>
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/Mode.h>

#include <powermanager/PowerHalWrapper.h>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::PowerHint;

namespace android {

// -------------------------------------------------------------------------------------------------

// Connects to underlying Power HAL handles.
class PowerHalConnector {
public:
    PowerHalConnector() = default;
    virtual ~PowerHalConnector() = default;

    virtual std::unique_ptr<PowerHalWrapper> connect();
    virtual void reset();
};

// -------------------------------------------------------------------------------------------------

// Controller for Power HAL handle.
// This relies on PowerHalConnector to connect to the underlying Power HAL service and reconnects to
// it after each failed api call. This also ensures connecting to the service is thread-safe.
class PowerHalController : public PowerHalWrapper {
public:
    PowerHalController() : PowerHalController(std::make_unique<PowerHalConnector>()) {}
    explicit PowerHalController(std::unique_ptr<PowerHalConnector> connector)
        : mHalConnector(std::move(connector)) {}

    void init();

    PowerHalResult setBoost(Boost boost, int32_t durationMs) override;
    PowerHalResult setMode(Mode mode, bool enabled) override;

private:
    std::mutex mConnectedHalMutex;
    std::unique_ptr<PowerHalConnector> mHalConnector;

    // Shared pointers to keep global pointer and allow local copies to be used in different threads
    std::shared_ptr<PowerHalWrapper> mConnectedHal GUARDED_BY(mConnectedHalMutex) = nullptr;
    const std::shared_ptr<PowerHalWrapper> mDefaultHal = std::make_shared<EmptyPowerHalWrapper>();

    std::shared_ptr<PowerHalWrapper> initHal();
    PowerHalResult processHalResult(PowerHalResult result, const char* functionName);
};

// -------------------------------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_POWERHALCONTROLLER_H
