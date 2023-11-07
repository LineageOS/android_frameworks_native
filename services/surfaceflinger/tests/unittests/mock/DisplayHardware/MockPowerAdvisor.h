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
    MOCK_METHOD(void, notifyCpuLoadUp, (), (override));
    MOCK_METHOD(void, notifyDisplayUpdateImminentAndCpuReset, (), (override));
    MOCK_METHOD(bool, usePowerHintSession, (), (override));
    MOCK_METHOD(bool, supportsPowerHintSession, (), (override));
    MOCK_METHOD(bool, ensurePowerHintSessionRunning, (), (override));
    MOCK_METHOD(void, updateTargetWorkDuration, (Duration targetDuration), (override));
    MOCK_METHOD(void, reportActualWorkDuration, (), (override));
    MOCK_METHOD(void, enablePowerHintSession, (bool enabled), (override));
    MOCK_METHOD(bool, startPowerHintSession, (const std::vector<int32_t>& threadIds), (override));
    MOCK_METHOD(void, setGpuFenceTime,
                (DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime), (override));
    MOCK_METHOD(void, setHwcValidateTiming,
                (DisplayId displayId, TimePoint validateStartTime, TimePoint validateEndTime),
                (override));
    MOCK_METHOD(void, setHwcPresentTiming,
                (DisplayId displayId, TimePoint presentStartTime, TimePoint presentEndTime),
                (override));
    MOCK_METHOD(void, setSkippedValidate, (DisplayId displayId, bool skipped), (override));
    MOCK_METHOD(void, setRequiresClientComposition,
                (DisplayId displayId, bool requiresClientComposition), (override));
    MOCK_METHOD(void, setExpectedPresentTime, (TimePoint expectedPresentTime), (override));
    MOCK_METHOD(void, setSfPresentTiming, (TimePoint presentFenceTime, TimePoint presentEndTime),
                (override));
    MOCK_METHOD(void, setHwcPresentDelayedTime,
                (DisplayId displayId, TimePoint earliestFrameStartTime));
    MOCK_METHOD(void, setFrameDelay, (Duration frameDelayDuration), (override));
    MOCK_METHOD(void, setCommitStart, (TimePoint commitStartTime), (override));
    MOCK_METHOD(void, setCompositeEnd, (TimePoint compositeEndTime), (override));
    MOCK_METHOD(void, setDisplays, (std::vector<DisplayId> & displayIds), (override));
    MOCK_METHOD(void, setTotalFrameTargetWorkDuration, (Duration targetDuration), (override));
};

} // namespace android::Hwc2::mock
