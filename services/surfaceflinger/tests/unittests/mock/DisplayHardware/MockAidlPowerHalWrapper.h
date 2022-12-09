/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <gmock/gmock.h>

#include "DisplayHardware/PowerAdvisor.h"

namespace android {
namespace hardware {
namespace power {
class IPower;
}
} // namespace hardware
} // namespace android

namespace android::Hwc2::mock {

class MockAidlPowerHalWrapper : public Hwc2::impl::AidlPowerHalWrapper {
public:
    MockAidlPowerHalWrapper();
    ~MockAidlPowerHalWrapper() override;
    MOCK_METHOD(bool, setExpensiveRendering, (bool enabled), (override));
    MOCK_METHOD(bool, notifyDisplayUpdateImminent, (), (override));
    MOCK_METHOD(bool, supportsPowerHintSession, (), (override));
    MOCK_METHOD(bool, isPowerHintSessionRunning, (), (override));
    MOCK_METHOD(void, restartPowerHintSession, (), (override));
    MOCK_METHOD(void, setPowerHintSessionThreadIds, (const std::vector<int32_t>& threadIds),
                (override));
    MOCK_METHOD(bool, startPowerHintSession, (), (override));
    MOCK_METHOD(void, setTargetWorkDuration, (nsecs_t targetDuration), (override));
    MOCK_METHOD(void, sendActualWorkDuration, (nsecs_t actualDuration, nsecs_t timestamp),
                (override));
    MOCK_METHOD(bool, shouldReconnectHAL, (), (override));
};

} // namespace android::Hwc2::mock