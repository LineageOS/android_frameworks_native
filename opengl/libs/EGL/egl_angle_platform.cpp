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

#if defined(__ANDROID__)

#include "egl_angle_platform.h"
#include <time.h>

#include <log/log.h>

namespace angle {

GetDisplayPlatformFunc AnglePlatformImpl::angleGetDisplayPlatform = nullptr;
ResetDisplayPlatformFunc AnglePlatformImpl::angleResetDisplayPlatform = nullptr;
// Initialize start time
time_t AnglePlatformImpl::startTime = time(nullptr);

void AnglePlatformImpl::assignAnglePlatformMethods(PlatformMethods* platformMethods) {
    platformMethods->addTraceEvent = addTraceEvent;
    platformMethods->getTraceCategoryEnabledFlag = getTraceCategoryEnabledFlag;
    platformMethods->monotonicallyIncreasingTime = monotonicallyIncreasingTime;
    platformMethods->logError = logError;
    platformMethods->logWarning = logWarning;
    platformMethods->logInfo = logInfo;
}

const unsigned char* AnglePlatformImpl::getTraceCategoryEnabledFlag(PlatformMethods* /*platform*/,
                                                                    const char* /*categoryName*/) {
    // Returning ptr to 'g' (non-zero) to ALWAYS enable tracing initially.
    // This ptr is what will be passed into "category_group_enabled" of addTraceEvent
    static const unsigned char traceEnabled = 'g';
    return &traceEnabled;
}

double AnglePlatformImpl::monotonicallyIncreasingTime(PlatformMethods* /*platform*/) {
    return difftime(time(nullptr), startTime);
}

void AnglePlatformImpl::logError(PlatformMethods* /*platform*/, const char* errorMessage) {
    ALOGE("ANGLE Error:%s", errorMessage);
}

void AnglePlatformImpl::logWarning(PlatformMethods* /*platform*/, const char* warningMessage) {
    ALOGW("ANGLE Warn:%s", warningMessage);
}

void AnglePlatformImpl::logInfo(PlatformMethods* /*platform*/, const char* infoMessage) {
    ALOGD("ANGLE Info:%s", infoMessage);
}

TraceEventHandle AnglePlatformImpl::addTraceEvent(
        PlatformMethods* /**platform*/, char phase, const unsigned char* /*category_group_enabled*/,
        const char* name, unsigned long long /*id*/, double /*timestamp*/, int /*num_args*/,
        const char** /*arg_names*/, const unsigned char* /*arg_types*/,
        const unsigned long long* /*arg_values*/, unsigned char /*flags*/) {
    switch (phase) {
        case 'B': {
            ATRACE_BEGIN(name);
            break;
        }
        case 'E': {
            ATRACE_END();
            break;
        }
        case 'I': {
            ATRACE_NAME(name);
            break;
        }
        default:
            // Could handle other event types here
            break;
    }
    // Return any non-zero handle to avoid assert in ANGLE
    TraceEventHandle result = 1.0;
    return result;
}

}; // namespace angle

#endif // __ANDROID__
