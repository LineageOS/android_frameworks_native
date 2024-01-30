/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "Scheduler/VsyncController.h"

namespace android::mock {

class VsyncController : public android::scheduler::VsyncController {
public:
    VsyncController();
    ~VsyncController() override;

    MOCK_METHOD(bool, addPresentFence, (std::shared_ptr<FenceTime>), (override));
    MOCK_METHOD(bool, addHwVsyncTimestamp, (nsecs_t, std::optional<nsecs_t>, bool*), (override));
    MOCK_METHOD(void, onDisplayModeChanged, (ftl::NonNull<DisplayModePtr>, bool), (override));
    MOCK_METHOD(void, setIgnorePresentFences, (bool), (override));
    MOCK_METHOD(void, setDisplayPowerMode, (hal::PowerMode), (override));

    MOCK_METHOD(void, dump, (std::string&), (const, override));
};

} // namespace android::mock
