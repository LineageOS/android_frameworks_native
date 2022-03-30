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

#include <android/hardware/power/IPower.h>
#include <gmock/gmock.h>

using android::binder::Status;
using android::hardware::power::IPowerHintSession;

using namespace android::hardware::power;

namespace android::Hwc2::mock {

class MockIPowerHintSession : public IPowerHintSession {
public:
    MockIPowerHintSession();

    MOCK_METHOD(IBinder*, onAsBinder, (), (override));
    MOCK_METHOD(Status, pause, (), (override));
    MOCK_METHOD(Status, resume, (), (override));
    MOCK_METHOD(Status, close, (), (override));
    MOCK_METHOD(int32_t, getInterfaceVersion, (), (override));
    MOCK_METHOD(std::string, getInterfaceHash, (), (override));
    MOCK_METHOD(Status, updateTargetWorkDuration, (int64_t), (override));
    MOCK_METHOD(Status, reportActualWorkDuration, (const ::std::vector<WorkDuration>&), (override));
};

} // namespace android::Hwc2::mock
