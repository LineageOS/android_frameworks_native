/*
 * Copyright 2018 The Android Open Source Project
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

namespace android::Hwc2::mock {

class PowerAdvisor : public android::Hwc2::PowerAdvisor {
public:
    PowerAdvisor();
    ~PowerAdvisor() override;

    MOCK_METHOD(void, init, (), (override));
    MOCK_METHOD(void, onBootFinished, (), (override));
    MOCK_METHOD(void, setExpensiveRenderingExpected, (DisplayId displayId, bool expected),
                (override));
    MOCK_METHOD(bool, isUsingExpensiveRendering, (), (override));
    MOCK_METHOD(void, notifyDisplayUpdateImminent, (), (override));
    MOCK_METHOD(bool, usePowerHintSession, (), (override));
    MOCK_METHOD(bool, supportsPowerHintSession, (), (override));
    MOCK_METHOD(bool, isPowerHintSessionRunning, (), (override));
    MOCK_METHOD(void, setTargetWorkDuration, (int64_t targetDurationNanos), (override));
    MOCK_METHOD(void, setPowerHintSessionThreadIds, (const std::vector<int32_t>& threadIds),
                (override));
    MOCK_METHOD(void, sendActualWorkDuration, (int64_t actualDurationNanos, nsecs_t timestamp),
                (override));
    MOCK_METHOD(void, enablePowerHint, (bool enabled), (override));
};

} // namespace android::Hwc2::mock
