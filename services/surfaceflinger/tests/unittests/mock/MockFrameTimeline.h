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

#include "FrameTimeline/FrameTimeline.h"

namespace android::mock {

class FrameTimeline : public android::frametimeline::impl::FrameTimeline {
    // No need to create mocks for SurfaceFrame and TokenManager yet. They are very small components
    // and do not have external dependencies like perfetto.
public:
    FrameTimeline(std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid);
    ~FrameTimeline();

    MOCK_METHOD0(onBootFinished, void());
    MOCK_METHOD1(addSurfaceFrame, void(std::shared_ptr<frametimeline::SurfaceFrame>));
    MOCK_METHOD3(setSfWakeUp, void(int64_t, nsecs_t, nsecs_t));
    MOCK_METHOD2(setSfPresent, void(nsecs_t, const std::shared_ptr<FenceTime>&));
};

} // namespace android::mock
