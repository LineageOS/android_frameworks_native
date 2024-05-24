/*
 * Copyright 2022 The Android Open Source Project
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

#pragma once

#include "binder/Status.h"

// FMQ library in IPower does questionable conversions
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <aidl/android/hardware/power/IPower.h>
#pragma clang diagnostic pop

#include <gmock/gmock.h>

using aidl::android::hardware::power::Boost;
using aidl::android::hardware::power::ChannelConfig;
using aidl::android::hardware::power::IPower;
using aidl::android::hardware::power::IPowerHintSession;
using aidl::android::hardware::power::SessionConfig;
using aidl::android::hardware::power::SessionTag;

using aidl::android::hardware::power::Mode;
using android::binder::Status;

namespace android::Hwc2::mock {

class MockIPower : public IPower {
public:
    MockIPower();

    MOCK_METHOD(ndk::ScopedAStatus, isBoostSupported, (Boost boost, bool* ret), (override));
    MOCK_METHOD(ndk::ScopedAStatus, setBoost, (Boost boost, int32_t durationMs), (override));
    MOCK_METHOD(ndk::ScopedAStatus, isModeSupported, (Mode mode, bool* ret), (override));
    MOCK_METHOD(ndk::ScopedAStatus, setMode, (Mode mode, bool enabled), (override));
    MOCK_METHOD(ndk::ScopedAStatus, createHintSession,
                (int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                 int64_t durationNanos, std::shared_ptr<IPowerHintSession>* session),
                (override));
    MOCK_METHOD(ndk::ScopedAStatus, getHintSessionPreferredRate, (int64_t * rate), (override));
    MOCK_METHOD(ndk::ScopedAStatus, createHintSessionWithConfig,
                (int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                 int64_t durationNanos, SessionTag tag, SessionConfig* config,
                 std::shared_ptr<IPowerHintSession>* _aidl_return),
                (override));
    MOCK_METHOD(ndk::ScopedAStatus, getSessionChannel,
                (int32_t tgid, int32_t uid, ChannelConfig* _aidl_return), (override));
    MOCK_METHOD(ndk::ScopedAStatus, closeSessionChannel, (int32_t tgid, int32_t uid), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getInterfaceVersion, (int32_t * version), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getInterfaceHash, (std::string * hash), (override));
    MOCK_METHOD(ndk::SpAIBinder, asBinder, (), (override));
    MOCK_METHOD(bool, isRemote, (), (override));
};

} // namespace android::Hwc2::mock
