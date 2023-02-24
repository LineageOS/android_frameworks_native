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

#include "Macros.h"

#include <android-base/properties.h>

namespace {

const bool IS_DEBUGGABLE_BUILD =
#if defined(__ANDROID__)
        android::base::GetBoolProperty("ro.debuggable", false);
#else
        true;
#endif

} // namespace

namespace android {

bool debugRawEvents() {
    if (!IS_DEBUGGABLE_BUILD) {
        static const bool DEBUG_RAW_EVENTS =
                __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "RawEvents", ANDROID_LOG_INFO);
        return DEBUG_RAW_EVENTS;
    }
    return __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "RawEvents", ANDROID_LOG_INFO);
}

} // namespace android
