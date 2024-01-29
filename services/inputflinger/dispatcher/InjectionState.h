/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdint.h>
#include "InputDispatcherInterface.h"

namespace android {

namespace inputdispatcher {

struct InjectionState {
    const std::optional<gui::Uid> targetUid;
    const bool injectionIsAsync; // set to true if injection is not waiting for the result
    android::os::InputEventInjectionResult injectionResult; // initially PENDING
    int32_t pendingForegroundDispatches; // the number of foreground dispatches in progress

    explicit InjectionState(const std::optional<gui::Uid>& targetUid, bool isAsync);
};

} // namespace inputdispatcher
} // namespace android
