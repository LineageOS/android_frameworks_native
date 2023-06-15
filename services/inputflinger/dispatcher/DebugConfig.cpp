/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "DebugConfig.h"

#include <android-base/properties.h>

namespace android::inputdispatcher {

const bool IS_DEBUGGABLE_BUILD =
#if defined(__ANDROID__)
        android::base::GetBoolProperty("ro.debuggable", false);
#else
        true;
#endif

bool debugInboundEventDetails() {
    if (!IS_DEBUGGABLE_BUILD) {
        static const bool DEBUG_INBOUND_EVENT_DETAILS =
                android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "InboundEvent");
        return DEBUG_INBOUND_EVENT_DETAILS;
    }
    return android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "InboundEvent");
}

} // namespace android::inputdispatcher
