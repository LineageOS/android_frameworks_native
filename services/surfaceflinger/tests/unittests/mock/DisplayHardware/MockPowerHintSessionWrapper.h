/*
 * Copyright 2024 The Android Open Source Project
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
#include <powermanager/PowerHintSessionWrapper.h>
#pragma clang diagnostic pop

#include <gmock/gmock.h>

using aidl::android::hardware::power::IPowerHintSession;
using aidl::android::hardware::power::SessionConfig;
using aidl::android::hardware::power::SessionHint;
using aidl::android::hardware::power::SessionMode;
using android::binder::Status;

using namespace aidl::android::hardware::power;

namespace android::Hwc2::mock {

class MockPowerHintSessionWrapper : public power::PowerHintSessionWrapper {
public:
    MockPowerHintSessionWrapper();

    MOCK_METHOD(power::HalResult<void>, updateTargetWorkDuration, (int64_t), (override));
    MOCK_METHOD(power::HalResult<void>, reportActualWorkDuration,
                (const ::std::vector<WorkDuration>&), (override));
    MOCK_METHOD(power::HalResult<void>, pause, (), (override));
    MOCK_METHOD(power::HalResult<void>, resume, (), (override));
    MOCK_METHOD(power::HalResult<void>, close, (), (override));
    MOCK_METHOD(power::HalResult<void>, sendHint, (SessionHint), (override));
    MOCK_METHOD(power::HalResult<void>, setThreads, (const ::std::vector<int32_t>&), (override));
    MOCK_METHOD(power::HalResult<void>, setMode, (SessionMode, bool), (override));
    MOCK_METHOD(power::HalResult<SessionConfig>, getSessionConfig, (), (override));
};

} // namespace android::Hwc2::mock
