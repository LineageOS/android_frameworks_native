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

#include "Scheduler/Scheduler.h"

namespace android::mock {

struct SchedulerCallback final : ISchedulerCallback {
    MOCK_METHOD1(setVsyncEnabled, void(bool));
    MOCK_METHOD2(changeRefreshRate,
                 void(const scheduler::RefreshRateConfigs::RefreshRate&,
                      scheduler::RefreshRateConfigEvent));
    MOCK_METHOD0(repaintEverythingForHWC, void());
    MOCK_METHOD1(kernelTimerChanged, void(bool));
    MOCK_METHOD0(triggerOnFrameRateOverridesChanged, void());
};

struct NoOpSchedulerCallback final : ISchedulerCallback {
    void setVsyncEnabled(bool) override {}
    void changeRefreshRate(const scheduler::RefreshRateConfigs::RefreshRate&,
                           scheduler::RefreshRateConfigEvent) override {}
    void repaintEverythingForHWC() override {}
    void kernelTimerChanged(bool) override {}
    void triggerOnFrameRateOverridesChanged() {}
};

} // namespace android::mock
