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

#ifndef ANDROID_POWERHALWRAPPER_H
#define ANDROID_POWERHALWRAPPER_H

#include <android-base/thread_annotations.h>

#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/Mode.h>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::PowerHint;
using IPowerV1_1 = android::hardware::power::V1_1::IPower;
using IPowerV1_0 = android::hardware::power::V1_0::IPower;
using IPowerAidl = android::hardware::power::IPower;

namespace android {

// State of Power HAL support for individual apis.
enum class PowerHalSupport {
    UNKNOWN = 0,
    ON = 1,
    OFF = 2,
};

// State of the Power HAL api call result.
enum class PowerHalResult {
    SUCCESSFUL = 0,
    FAILED = 1,
    UNSUPPORTED = 2,
};

// Wrapper for Power HAL handlers.
class PowerHalWrapper {
public:
    virtual ~PowerHalWrapper() = default;

    virtual PowerHalResult setBoost(Boost boost, int32_t durationMs) = 0;
    virtual PowerHalResult setMode(Mode mode, bool enabled) = 0;
};

// Empty Power HAL wrapper that ignores all api calls.
class EmptyPowerHalWrapper : public PowerHalWrapper {
public:
    EmptyPowerHalWrapper() = default;
    ~EmptyPowerHalWrapper() = default;

    PowerHalResult setBoost(Boost boost, int32_t durationMs) override;
    PowerHalResult setMode(Mode mode, bool enabled) override;
};

// Wrapper for the HIDL Power HAL v1.0.
class HidlPowerHalWrapperV1_0 : public PowerHalWrapper {
public:
    explicit HidlPowerHalWrapperV1_0(sp<IPowerV1_0> powerHal) : handleV1_0(std::move(powerHal)) {}
    virtual ~HidlPowerHalWrapperV1_0() = default;

    PowerHalResult setBoost(Boost boost, int32_t durationMs) override;
    PowerHalResult setMode(Mode mode, bool enabled) override;

protected:
    virtual PowerHalResult sendPowerHint(PowerHint hintId, uint32_t data);

private:
    sp<IPowerV1_0> handleV1_0;
    PowerHalResult setInteractive(bool enabled);
    PowerHalResult setFeature(Feature feature, bool enabled);
};

// Wrapper for the HIDL Power HAL v1.1.
class HidlPowerHalWrapperV1_1 : public HidlPowerHalWrapperV1_0 {
public:
    HidlPowerHalWrapperV1_1(sp<IPowerV1_0> powerHalV1_0, sp<IPowerV1_1> powerHalV1_1)
        : HidlPowerHalWrapperV1_0(powerHalV1_0), handleV1_1(std::move(powerHalV1_1)) {}
    ~HidlPowerHalWrapperV1_1() = default;

protected:
    virtual PowerHalResult sendPowerHint(PowerHint hintId, uint32_t data) override;

private:
    sp<IPowerV1_1> handleV1_1;
};

// Wrapper for the AIDL Power HAL.
class AidlPowerHalWrapper : public PowerHalWrapper {
public:
    explicit AidlPowerHalWrapper(sp<IPowerAidl> powerHal) : handle(std::move(powerHal)) {}
    ~AidlPowerHalWrapper() = default;

    PowerHalResult setBoost(Boost boost, int32_t durationMs) override;
    PowerHalResult setMode(Mode mode, bool enabled) override;

private:
    // Control access to the boost and mode supported arrays.
    std::mutex mBoostMutex;
    std::mutex mModeMutex;
    sp<IPowerAidl> handle;
    // Android framework only sends boost upto DISPLAY_UPDATE_IMMINENT.
    // Need to increase the array size if more boost supported.
    std::array<std::atomic<PowerHalSupport>, static_cast<int32_t>(Boost::DISPLAY_UPDATE_IMMINENT)+1>
        boostSupportedArray GUARDED_BY(mBoostMutex) = {PowerHalSupport::UNKNOWN};
    // Android framework only sends mode upto DISPLAY_INACTIVE.
    // Need to increase the array if more mode supported.
    std::array<std::atomic<PowerHalSupport>, static_cast<int32_t>(Mode::DISPLAY_INACTIVE)+1>
        modeSupportedArray GUARDED_BY(mModeMutex) = {PowerHalSupport::UNKNOWN};
};

}; // namespace android

#endif // ANDROID_POWERHALWRAPPER_H
