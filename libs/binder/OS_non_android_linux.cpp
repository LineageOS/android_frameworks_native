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

#include "OS.h"

#include <log/log.h>

#include <syscall.h>
#include <cstdarg>

#ifdef __ANDROID__
#error "This module is not intended for Android, just bare Linux"
#endif
#ifdef __APPLE__
#error "This module is not intended for MacOS"
#endif
#ifdef _WIN32
#error "This module is not intended for Windows"
#endif

namespace android::binder::os {

void trace_begin(uint64_t, const char*) {}

void trace_end(uint64_t) {}

uint64_t GetThreadId() {
    return syscall(__NR_gettid);
}

bool report_sysprop_change() {
    return false;
}

} // namespace android::binder::os

int __android_log_print(int /*prio*/, const char* /*tag*/, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    return 1;
}
