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

#if defined(__ANDROID__)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <EGL/Platform.h>
#pragma GCC diagnostic pop

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "egl_trace.h"

namespace angle {

class AnglePlatformImpl {
public:
    static void assignAnglePlatformMethods(PlatformMethods* platformMethods);
    static GetDisplayPlatformFunc angleGetDisplayPlatform;
    static ResetDisplayPlatformFunc angleResetDisplayPlatform;

private:
    static time_t startTime;
    static const unsigned char* getTraceCategoryEnabledFlag(PlatformMethods* /*platform*/,
                                                            const char* /*categoryName*/);
    static double monotonicallyIncreasingTime(PlatformMethods* /*platform*/);
    static void logError(PlatformMethods* /*platform*/, const char* errorMessage);
    static void logWarning(PlatformMethods* /*platform*/, const char* warningMessage);
    static void logInfo(PlatformMethods* /*platform*/, const char* infoMessage);
    static TraceEventHandle addTraceEvent(PlatformMethods* /**platform*/, char phase,
                                          const unsigned char* /*category_group_enabled*/,
                                          const char* name, unsigned long long /*id*/,
                                          double /*timestamp*/, int /*num_args*/,
                                          const char** /*arg_names*/,
                                          const unsigned char* /*arg_types*/,
                                          const unsigned long long* /*arg_values*/,
                                          unsigned char /*flags*/);
};

}; // namespace angle

#endif // __ANDROID__
