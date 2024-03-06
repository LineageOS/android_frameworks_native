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

#define LOG_TAG "PowerHalController"
#include <aidl/android/hardware/power/Boost.h>
#include <aidl/android/hardware/power/IPower.h>
#include <aidl/android/hardware/power/IPowerHintSession.h>
#include <aidl/android/hardware/power/Mode.h>
#include <android/hardware/power/1.1/IPower.h>
#include <powermanager/PowerHalController.h>
#include <powermanager/PowerHalLoader.h>
#include <utils/Log.h>

using namespace android::hardware::power;

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

std::unique_ptr<HalWrapper> HalConnector::connect() {
    if (std::shared_ptr<aidl::android::hardware::power::IPower> halAidl =
                PowerHalLoader::loadAidl()) {
        return std::make_unique<AidlHalWrapper>(halAidl);
    }
    // If V1_0 isn't defined, none of them are
    if (sp<V1_0::IPower> halHidlV1_0 = PowerHalLoader::loadHidlV1_0()) {
        if (sp<V1_3::IPower> halHidlV1_3 = PowerHalLoader::loadHidlV1_3()) {
            return std::make_unique<HidlHalWrapperV1_3>(halHidlV1_3);
        }
        if (sp<V1_2::IPower> halHidlV1_2 = PowerHalLoader::loadHidlV1_2()) {
            return std::make_unique<HidlHalWrapperV1_2>(halHidlV1_2);
        }
        if (sp<V1_1::IPower> halHidlV1_1 = PowerHalLoader::loadHidlV1_1()) {
            return std::make_unique<HidlHalWrapperV1_1>(halHidlV1_1);
        }
        return std::make_unique<HidlHalWrapperV1_0>(halHidlV1_0);
    }
    return nullptr;
}

void HalConnector::reset() {
    PowerHalLoader::unloadAll();
}

int32_t HalConnector::getAidlVersion() {
    return PowerHalLoader::getAidlVersion();
}

// -------------------------------------------------------------------------------------------------

void PowerHalController::init() {
    initHal();
}

// Check validity of current handle to the power HAL service, and create a new
// one if necessary.
std::shared_ptr<HalWrapper> PowerHalController::initHal() {
    std::lock_guard<std::mutex> lock(mConnectedHalMutex);
    if (mConnectedHal == nullptr) {
        mConnectedHal = mHalConnector->connect();
        if (mConnectedHal == nullptr) {
            // Unable to connect to Power HAL service. Fallback to default.
            return mDefaultHal;
        }
    }
    return mConnectedHal;
}

// Using statement expression macro instead of a method lets the static be
// scoped to the outer method while dodging the need for a support lookup table
// This only works for AIDL methods that do not vary supported/unsupported depending
// on their arguments (not setBoost, setMode) which do their own support checks
#define CACHE_SUPPORT(version, method)                                    \
    ({                                                                    \
        static bool support = mHalConnector->getAidlVersion() >= version; \
        !support ? decltype(method)::unsupported() : ({                   \
            auto result = method;                                         \
            if (result.isUnsupported()) {                                 \
                support = false;                                          \
            }                                                             \
            std::move(result);                                            \
        });                                                               \
    })

// Check if a call to Power HAL function failed; if so, log the failure and
// invalidate the current Power HAL handle.
template <typename T>
HalResult<T> PowerHalController::processHalResult(HalResult<T>&& result, const char* fnName) {
    if (result.isFailed()) {
        ALOGE("%s failed: %s", fnName, result.errorMessage());
        std::lock_guard<std::mutex> lock(mConnectedHalMutex);
        // Drop Power HAL handle. This will force future api calls to reconnect.
        mConnectedHal = nullptr;
        mHalConnector->reset();
    }
    return std::move(result);
}

HalResult<void> PowerHalController::setBoost(aidl::android::hardware::power::Boost boost,
                                             int32_t durationMs) {
    std::shared_ptr<HalWrapper> handle = initHal();
    return processHalResult(handle->setBoost(boost, durationMs), "setBoost");
}

HalResult<void> PowerHalController::setMode(aidl::android::hardware::power::Mode mode,
                                            bool enabled) {
    std::shared_ptr<HalWrapper> handle = initHal();
    return processHalResult(handle->setMode(mode, enabled), "setMode");
}

// Aidl-only methods

HalResult<std::shared_ptr<PowerHintSessionWrapper>> PowerHalController::createHintSession(
        int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos) {
    std::shared_ptr<HalWrapper> handle = initHal();
    return CACHE_SUPPORT(2,
                         processHalResult(handle->createHintSession(tgid, uid, threadIds,
                                                                    durationNanos),
                                          "createHintSession"));
}

HalResult<std::shared_ptr<PowerHintSessionWrapper>> PowerHalController::createHintSessionWithConfig(
        int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos,
        aidl::android::hardware::power::SessionTag tag,
        aidl::android::hardware::power::SessionConfig* config) {
    std::shared_ptr<HalWrapper> handle = initHal();
    return CACHE_SUPPORT(5,
                         processHalResult(handle->createHintSessionWithConfig(tgid, uid, threadIds,
                                                                              durationNanos, tag,
                                                                              config),
                                          "createHintSessionWithConfig"));
}

HalResult<int64_t> PowerHalController::getHintSessionPreferredRate() {
    std::shared_ptr<HalWrapper> handle = initHal();
    return CACHE_SUPPORT(2,
                         processHalResult(handle->getHintSessionPreferredRate(),
                                          "getHintSessionPreferredRate"));
}

HalResult<aidl::android::hardware::power::ChannelConfig> PowerHalController::getSessionChannel(
        int tgid, int uid) {
    std::shared_ptr<HalWrapper> handle = initHal();
    return CACHE_SUPPORT(5,
                         processHalResult(handle->getSessionChannel(tgid, uid),
                                          "getSessionChannel"));
}

HalResult<void> PowerHalController::closeSessionChannel(int tgid, int uid) {
    std::shared_ptr<HalWrapper> handle = initHal();
    return CACHE_SUPPORT(5,
                         processHalResult(handle->closeSessionChannel(tgid, uid),
                                          "closeSessionChannel"));
}

} // namespace power

} // namespace android
