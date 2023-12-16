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

#include <android-base/threads.h>
#include <cutils/trace.h>
#include <utils/misc.h>

namespace android::binder {
namespace os {

uint64_t GetThreadId() {
#ifdef BINDER_RPC_SINGLE_THREADED
    return 0;
#else
    return base::GetThreadId();
#endif
}

bool report_sysprop_change() {
    android::report_sysprop_change();
    return true;
}

void trace_begin(uint64_t tag, const char* name) {
    atrace_begin(tag, name);
}

void trace_end(uint64_t tag) {
    atrace_end(tag);
}

} // namespace os

// Legacy trace symbol. To be removed once all of downstream rebuilds.
void atrace_begin(uint64_t tag, const char* name) {
    os::trace_begin(tag, name);
}

// Legacy trace symbol. To be removed once all of downstream rebuilds.
void atrace_end(uint64_t tag) {
    os::trace_end(tag);
}

} // namespace android::binder
