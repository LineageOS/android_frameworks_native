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

namespace android {

namespace power {

// State of Power HAL support for individual apis.
enum class HalSupport {
    UNKNOWN = 0,
    ON = 1,
    OFF = 2,
};

// State of the Power HAL api call result.
enum class HalResult {
    SUCCESSFUL = 0,
    FAILED = 1,
    UNSUPPORTED = 2,
};

// Wrapper for Power HAL handlers.
class HalWrapper {
public:
    virtual ~HalWrapper() = default;

    virtual HalResult setBoost(hardware::power::Boost boost, int32_t durationMs) = 0;
    virtual HalResult setMode(hardware::power::Mode mode, bool enabled) = 0;
};

// Empty Power HAL wrapper that ignores all api calls.
class EmptyHalWrapper : public HalWrapper {
public:
    EmptyHalWrapper() = default;
    ~EmptyHalWrapper() = default;

    virtual HalResult setBoost(hardware::power::Boost boost, int32_t durationMs) override;
    virtual HalResult setMode(hardware::power::Mode mode, bool enabled) override;
};

// Wrapper for the HIDL Power HAL v1.0.
class HidlHalWrapperV1_0 : public HalWrapper {
public:
    explicit HidlHalWrapperV1_0(sp<hardware::power::V1_0::IPower> Hal)
          : mHandleV1_0(std::move(Hal)) {}
    virtual ~HidlHalWrapperV1_0() = default;

    virtual HalResult setBoost(hardware::power::Boost boost, int32_t durationMs) override;
    virtual HalResult setMode(hardware::power::Mode mode, bool enabled) override;

protected:
    virtual HalResult sendPowerHint(hardware::power::V1_0::PowerHint hintId, uint32_t data);

private:
    sp<hardware::power::V1_0::IPower> mHandleV1_0;
    HalResult setInteractive(bool enabled);
    HalResult setFeature(hardware::power::V1_0::Feature feature, bool enabled);
};

// Wrapper for the HIDL Power HAL v1.1.
class HidlHalWrapperV1_1 : public HidlHalWrapperV1_0 {
public:
    HidlHalWrapperV1_1(sp<hardware::power::V1_0::IPower> handleV1_0,
                       sp<hardware::power::V1_1::IPower> handleV1_1)
          : HidlHalWrapperV1_0(std::move(handleV1_0)), mHandleV1_1(std::move(handleV1_1)) {}
    virtual ~HidlHalWrapperV1_1() = default;

protected:
    virtual HalResult sendPowerHint(hardware::power::V1_0::PowerHint hintId,
                                    uint32_t data) override;

private:
    sp<hardware::power::V1_1::IPower> mHandleV1_1;
};

// Wrapper for the AIDL Power HAL.
class AidlHalWrapper : public HalWrapper {
public:
    explicit AidlHalWrapper(sp<hardware::power::IPower> handle) : mHandle(std::move(handle)) {}
    virtual ~AidlHalWrapper() = default;

    virtual HalResult setBoost(hardware::power::Boost boost, int32_t durationMs) override;
    virtual HalResult setMode(hardware::power::Mode mode, bool enabled) override;

private:
    // Control access to the boost and mode supported arrays.
    std::mutex mBoostMutex;
    std::mutex mModeMutex;
    sp<hardware::power::IPower> mHandle;
    // Android framework only sends boost upto DISPLAY_UPDATE_IMMINENT.
    // Need to increase the array size if more boost supported.
    std::array<std::atomic<HalSupport>,
               static_cast<int32_t>(hardware::power::Boost::DISPLAY_UPDATE_IMMINENT) + 1>
            mBoostSupportedArray GUARDED_BY(mBoostMutex) = {HalSupport::UNKNOWN};
    // Android framework only sends mode upto DISPLAY_INACTIVE.
    // Need to increase the array if more mode supported.
    std::array<std::atomic<HalSupport>,
               static_cast<int32_t>(hardware::power::Mode::DISPLAY_INACTIVE) + 1>
            mModeSupportedArray GUARDED_BY(mModeMutex) = {HalSupport::UNKNOWN};
};

}; // namespace power

}; // namespace android

#endif // ANDROID_POWERHALWRAPPER_H
