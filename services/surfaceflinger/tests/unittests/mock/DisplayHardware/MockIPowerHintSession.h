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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <aidl/android/hardware/power/IPower.h>
#pragma clang diagnostic pop

#include <gmock/gmock.h>

using aidl::android::hardware::power::IPowerHintSession;
using aidl::android::hardware::power::SessionConfig;
using aidl::android::hardware::power::SessionHint;
using aidl::android::hardware::power::SessionMode;
using android::binder::Status;

using namespace aidl::android::hardware::power;

namespace android::Hwc2::mock {

class MockIPowerHintSession : public IPowerHintSession {
public:
    MockIPowerHintSession();

    MOCK_METHOD(ndk::SpAIBinder, asBinder, (), (override));
    MOCK_METHOD(ndk::ScopedAStatus, pause, (), (override));
    MOCK_METHOD(ndk::ScopedAStatus, resume, (), (override));
    MOCK_METHOD(ndk::ScopedAStatus, close, (), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getInterfaceVersion, (int32_t * version), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getInterfaceHash, (std::string * hash), (override));
    MOCK_METHOD(bool, isRemote, (), (override));
    MOCK_METHOD(ndk::ScopedAStatus, updateTargetWorkDuration, (int64_t), (override));
    MOCK_METHOD(ndk::ScopedAStatus, reportActualWorkDuration, (const ::std::vector<WorkDuration>&),
                (override));
    MOCK_METHOD(ndk::ScopedAStatus, sendHint, (SessionHint), (override));
    MOCK_METHOD(ndk::ScopedAStatus, setThreads, (const ::std::vector<int32_t>&), (override));
    MOCK_METHOD(ndk::ScopedAStatus, setMode, (SessionMode, bool), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getSessionConfig, (SessionConfig * _aidl_return), (override));
};

} // namespace android::Hwc2::mock
