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

#pragma once

#include <cstdio>
#include <cstdlib>

#include <android/log.h>

extern "C" {

#ifndef ANDROID_LOG_STUB_MIN_PRIORITY
#define ANDROID_LOG_STUB_MIN_PRIORITY ANDROID_LOG_INFO
#endif

#ifndef LOG_TAG
#define LOG_TAG ""
#endif

constexpr bool __android_log_stub_is_loggable(android_LogPriority priority) {
    return ANDROID_LOG_STUB_MIN_PRIORITY <= priority;
}

#ifdef ANDROID_LOG_STUB_WEAK_PRINT
#define __ANDROID_LOG_STUB_IS_PRINT_PRESENT __android_log_print
#define __ANDROID_LOG_STUB_PRINT_ATTR __attribute__((weak))
#else
#define __ANDROID_LOG_STUB_IS_PRINT_PRESENT true
#define __ANDROID_LOG_STUB_PRINT_ATTR
#endif

int __android_log_print(int prio, const char* tag, const char* fmt, ...)
        __attribute__((format(printf, 3, 4))) __ANDROID_LOG_STUB_PRINT_ATTR;

#define IF_ALOG(priority, tag) \
    if (__android_log_stub_is_loggable(ANDROID_##priority) && __ANDROID_LOG_STUB_IS_PRINT_PRESENT)
#define IF_ALOGV() IF_ALOG(LOG_VERBOSE, LOG_TAG)
#define IF_ALOGD() IF_ALOG(LOG_DEBUG, LOG_TAG)
#define IF_ALOGI() IF_ALOG(LOG_INFO, LOG_TAG)
#define IF_ALOGW() IF_ALOG(LOG_WARN, LOG_TAG)
#define IF_ALOGE() IF_ALOG(LOG_ERROR, LOG_TAG)

#define ALOG(priority, tag, fmt, ...)                                        \
    do {                                                                     \
        if (false)[[/*VERY*/ unlikely]] { /* ignore unused __VA_ARGS__ */    \
            std::fprintf(stderr, fmt __VA_OPT__(, ) __VA_ARGS__);            \
        }                                                                    \
        IF_ALOG(priority, tag) {                                             \
            __android_log_print(ANDROID_##priority, tag, "%s: " fmt "\n",    \
                                (tag)__VA_OPT__(, ) __VA_ARGS__);            \
        }                                                                    \
        if constexpr (ANDROID_##priority == ANDROID_LOG_FATAL) std::abort(); \
    } while (false)
#define ALOGV(...) ALOG(LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) ALOG(LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) ALOG(LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOG_FATAL(...) ALOG(LOG_FATAL, LOG_TAG, __VA_ARGS__)
#define LOG_ALWAYS_FATAL LOG_FATAL

#define ALOG_IF(cond, priority, tag, ...) \
    if (cond) [[unlikely]]                \
    ALOG(priority, tag, #cond ": " __VA_ARGS__)
#define ALOGV_IF(cond, ...) ALOG_IF(cond, LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define ALOGD_IF(cond, ...) ALOG_IF(cond, LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI_IF(cond, ...) ALOG_IF(cond, LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGW_IF(cond, ...) ALOG_IF(cond, LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGE_IF(cond, ...) ALOG_IF(cond, LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOG_FATAL_IF(cond, ...) ALOG_IF(cond, LOG_FATAL, LOG_TAG, __VA_ARGS__)
#define LOG_ALWAYS_FATAL_IF LOG_FATAL_IF
#define ALOG_ASSERT(cond, ...) LOG_FATAL_IF(!(cond), ##__VA_ARGS__)

inline int android_errorWriteLog(int tag, const char* subTag) {
    ALOGE("android_errorWriteLog(%x, %s)", tag, subTag);
    return 0;
}

} // extern "C"
