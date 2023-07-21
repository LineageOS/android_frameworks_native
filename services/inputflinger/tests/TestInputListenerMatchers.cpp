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

#include "TestInputListenerMatchers.h"

namespace android {

WithKeyActionMatcher WithKeyAction(int32_t action) {
    return WithKeyActionMatcher(action);
}

WithMotionActionMatcher WithMotionAction(int32_t action) {
    return WithMotionActionMatcher(action);
}

WithDisplayIdMatcher WithDisplayId(int32_t displayId) {
    return WithDisplayIdMatcher(displayId);
}

WithDeviceIdMatcher WithDeviceId(int32_t deviceId) {
    return WithDeviceIdMatcher(deviceId);
}

} // namespace android
