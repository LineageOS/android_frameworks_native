/*
 * Copyright 2020 The Android Open Source Project
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

#include "Scheduler/VSyncTracker.h"

namespace android::mock {

class VSyncTracker : public android::scheduler::VSyncTracker {
public:
    VSyncTracker();
    ~VSyncTracker() override;

    MOCK_METHOD(bool, addVsyncTimestamp, (nsecs_t), (override));
    MOCK_METHOD(nsecs_t, nextAnticipatedVSyncTimeFrom, (nsecs_t, std::optional<nsecs_t>),
                (const, override));
    MOCK_METHOD(nsecs_t, currentPeriod, (), (const, override));
    MOCK_METHOD(Period, minFramePeriod, (), (const, override));
    MOCK_METHOD(void, resetModel, (), (override));
    MOCK_METHOD(bool, needsMoreSamples, (), (const, override));
    MOCK_METHOD(bool, isVSyncInPhase, (nsecs_t, Fps), (const, override));
    MOCK_METHOD(void, setDisplayModePtr, (ftl::NonNull<DisplayModePtr>), (override));
    MOCK_METHOD(void, setRenderRate, (Fps), (override));
    MOCK_METHOD(void, onFrameBegin, (TimePoint, TimePoint), (override));
    MOCK_METHOD(void, onFrameMissed, (TimePoint), (override));
    MOCK_METHOD(void, dump, (std::string&), (const, override));
};

} // namespace android::mock
