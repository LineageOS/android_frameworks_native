/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <aidl/android/hardware/power/Boost.h>
#include <aidl/android/hardware/power/ChannelConfig.h>
#include <aidl/android/hardware/power/IPower.h>
#include <aidl/android/hardware/power/IPowerHintSession.h>
#include <aidl/android/hardware/power/Mode.h>
#include <aidl/android/hardware/power/SessionConfig.h>
#include <android-base/thread_annotations.h>
#include "HalResult.h"

namespace android::power {

// Wrapper for power hint sessions, which allows for better mocking,
// support checking, and failure handling than using hint sessions directly
class PowerHintSessionWrapper {
public:
    virtual ~PowerHintSessionWrapper() = default;
    PowerHintSessionWrapper(
            std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>&& session);
    virtual HalResult<void> updateTargetWorkDuration(int64_t in_targetDurationNanos);
    virtual HalResult<void> reportActualWorkDuration(
            const std::vector<::aidl::android::hardware::power::WorkDuration>& in_durations);
    virtual HalResult<void> pause();
    virtual HalResult<void> resume();
    virtual HalResult<void> close();
    virtual HalResult<void> sendHint(::aidl::android::hardware::power::SessionHint in_hint);
    virtual HalResult<void> setThreads(const std::vector<int32_t>& in_threadIds);
    virtual HalResult<void> setMode(::aidl::android::hardware::power::SessionMode in_type,
                                    bool in_enabled);
    virtual HalResult<aidl::android::hardware::power::SessionConfig> getSessionConfig();

private:
    std::shared_ptr<aidl::android::hardware::power::IPowerHintSession> mSession;
    int32_t mInterfaceVersion;
};

} // namespace android::power