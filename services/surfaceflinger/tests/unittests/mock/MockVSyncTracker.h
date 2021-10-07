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

    MOCK_METHOD1(addVsyncTimestamp, bool(nsecs_t));
    MOCK_CONST_METHOD1(nextAnticipatedVSyncTimeFrom, nsecs_t(nsecs_t));
    MOCK_CONST_METHOD0(currentPeriod, nsecs_t());
    MOCK_METHOD1(setPeriod, void(nsecs_t));
    MOCK_METHOD0(resetModel, void());
    MOCK_CONST_METHOD0(needsMoreSamples, bool());
    MOCK_CONST_METHOD2(isVSyncInPhase, bool(nsecs_t, Fps));
    MOCK_CONST_METHOD1(dump, void(std::string&));
};

} // namespace android::mock
