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
using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::IPowerHintSession;
using android::hardware::power::Mode;

namespace android::Hwc2::mock {

class MockIPower : public IPower {
public:
    MockIPower();

    MOCK_METHOD(Status, isBoostSupported, (Boost boost, bool* ret), (override));
    MOCK_METHOD(Status, setBoost, (Boost boost, int32_t durationMs), (override));
    MOCK_METHOD(Status, isModeSupported, (Mode mode, bool* ret), (override));
    MOCK_METHOD(Status, setMode, (Mode mode, bool enabled), (override));
    MOCK_METHOD(Status, createHintSession,
                (int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                 int64_t durationNanos, sp<IPowerHintSession>* session),
                (override));
    MOCK_METHOD(Status, getHintSessionPreferredRate, (int64_t * rate), (override));
    MOCK_METHOD(int32_t, getInterfaceVersion, (), (override));
    MOCK_METHOD(std::string, getInterfaceHash, (), (override));
    MOCK_METHOD(IBinder*, onAsBinder, (), (override));
};

} // namespace android::Hwc2::mock
