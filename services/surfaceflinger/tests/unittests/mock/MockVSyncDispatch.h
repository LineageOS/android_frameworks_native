/*
 * Copyright 2023 The Android Open Source Project
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

#include "Scheduler/VSyncDispatch.h"

namespace android::mock {

class VSyncDispatch : public android::scheduler::VSyncDispatch {
public:
    VSyncDispatch();
    ~VSyncDispatch() override;

    MOCK_METHOD(CallbackToken, registerCallback, (Callback, std::string), (override));
    MOCK_METHOD(void, unregisterCallback, (CallbackToken), (override));
    MOCK_METHOD(std::optional<scheduler::ScheduleResult>, schedule, (CallbackToken, ScheduleTiming),
                (override));
    MOCK_METHOD(std::optional<scheduler::ScheduleResult>, update, (CallbackToken, ScheduleTiming),
                (override));
    MOCK_METHOD(scheduler::CancelResult, cancel, (CallbackToken token), (override));
    MOCK_METHOD(void, dump, (std::string&), (const, override));
};

} // namespace android::mock
