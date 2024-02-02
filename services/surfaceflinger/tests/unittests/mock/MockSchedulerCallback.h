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

#include "Scheduler/ISchedulerCallback.h"

namespace android::scheduler::mock {

struct SchedulerCallback final : ISchedulerCallback {
    MOCK_METHOD(void, requestHardwareVsync, (PhysicalDisplayId, bool), (override));
    MOCK_METHOD(void, requestDisplayModes, (std::vector<display::DisplayModeRequest>), (override));
    MOCK_METHOD(void, kernelTimerChanged, (bool), (override));
    MOCK_METHOD(void, triggerOnFrameRateOverridesChanged, (), (override));
    MOCK_METHOD(void, onChoreographerAttached, (), (override));
    MOCK_METHOD(void, onExpectedPresentTimePosted, (TimePoint, ftl::NonNull<DisplayModePtr>, Fps),
                (override));
};

struct NoOpSchedulerCallback final : ISchedulerCallback {
    void requestHardwareVsync(PhysicalDisplayId, bool) override {}
    void requestDisplayModes(std::vector<display::DisplayModeRequest>) override {}
    void kernelTimerChanged(bool) override {}
    void triggerOnFrameRateOverridesChanged() override {}
    void onChoreographerAttached() override {}
    void onExpectedPresentTimePosted(TimePoint, ftl::NonNull<DisplayModePtr>, Fps) override {}
};

} // namespace android::scheduler::mock
