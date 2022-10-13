/*
 * Copyright 2021 The Android Open Source Project
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

#include <stdarg.h>

#include <cutils/trace.h>
#include <utils/Trace.h>

#define ATRACE_FORMAT(fmt, ...)                                                 \
    TraceUtils::TraceEnder traceEnder =                                         \
            (CC_UNLIKELY(ATRACE_ENABLED()) &&                                   \
                     (TraceUtils::atraceFormatBegin(fmt, ##__VA_ARGS__), true), \
             TraceUtils::TraceEnder())

#define ATRACE_FORMAT_INSTANT(fmt, ...) \
    (CC_UNLIKELY(ATRACE_ENABLED()) && (TraceUtils::instantFormat(fmt, ##__VA_ARGS__), true))

#define ALOGE_AND_TRACE(fmt, ...)                  \
    do {                                           \
        ALOGE(fmt, ##__VA_ARGS__);                 \
        ATRACE_FORMAT_INSTANT(fmt, ##__VA_ARGS__); \
    } while (false)

namespace android {

class TraceUtils {
public:
    class TraceEnder {
    public:
        ~TraceEnder() { ATRACE_END(); }
    };

    static void atraceFormatBegin(const char* fmt, ...) {
        const int BUFFER_SIZE = 256;
        va_list ap;
        char buf[BUFFER_SIZE];

        va_start(ap, fmt);
        vsnprintf(buf, BUFFER_SIZE, fmt, ap);
        va_end(ap);

        ATRACE_BEGIN(buf);
    }

    static void instantFormat(const char* fmt, ...) {
        const int BUFFER_SIZE = 256;
        va_list ap;
        char buf[BUFFER_SIZE];

        va_start(ap, fmt);
        vsnprintf(buf, BUFFER_SIZE, fmt, ap);
        va_end(ap);

        ATRACE_INSTANT(buf);
    }
};

} // namespace android
