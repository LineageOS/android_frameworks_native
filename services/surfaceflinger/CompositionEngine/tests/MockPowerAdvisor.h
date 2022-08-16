/*
 * Copyright 2019 The Android Open Source Project

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
namespace Hwc2 {
namespace mock {

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
    MOCK_METHOD(void, setTargetWorkDuration, (int64_t targetDuration), (override));
    MOCK_METHOD(void, sendActualWorkDuration, (), (override));
    MOCK_METHOD(void, sendPredictedWorkDuration, (), (override));
    MOCK_METHOD(void, enablePowerHint, (bool enabled), (override));
    MOCK_METHOD(bool, startPowerHintSession, (const std::vector<int32_t>& threadIds), (override));
    MOCK_METHOD(void, setGpuFenceTime,
                (DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime), (override));
    MOCK_METHOD(void, setHwcValidateTiming,
                (DisplayId displayId, nsecs_t valiateStartTime, nsecs_t validateEndTime),
                (override));
    MOCK_METHOD(void, setHwcPresentTiming,
                (DisplayId displayId, nsecs_t presentStartTime, nsecs_t presentEndTime),
                (override));
    MOCK_METHOD(void, setSkippedValidate, (DisplayId displayId, bool skipped), (override));
    MOCK_METHOD(void, setRequiresClientComposition,
                (DisplayId displayId, bool requiresClientComposition), (override));
    MOCK_METHOD(void, setExpectedPresentTime, (nsecs_t expectedPresentTime), (override));
    MOCK_METHOD(void, setSfPresentTiming, (nsecs_t presentFenceTime, nsecs_t presentEndTime),
                (override));
    MOCK_METHOD(void, setHwcPresentDelayedTime,
                (DisplayId displayId,
                 std::chrono::steady_clock::time_point earliestFrameStartTime));
    MOCK_METHOD(void, setFrameDelay, (nsecs_t frameDelayDuration), (override));
    MOCK_METHOD(void, setCommitStart, (nsecs_t commitStartTime), (override));
    MOCK_METHOD(void, setCompositeEnd, (nsecs_t compositeEndtime), (override));
    MOCK_METHOD(void, setDisplays, (std::vector<DisplayId> & displayIds), (override));
    MOCK_METHOD(void, setTotalFrameTargetWorkDuration, (int64_t targetDuration), (override));
};

} // namespace mock
} // namespace Hwc2
} // namespace android
