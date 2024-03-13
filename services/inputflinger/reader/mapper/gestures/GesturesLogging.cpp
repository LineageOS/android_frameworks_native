/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef LOG_TAG
#define LOG_TAG "Gestures"
#endif

#include <stdio.h>

#include <log/log.h>

#include "include/gestures.h"

extern "C" {

namespace {

/**
 * Log details of each gesture output by the gestures library.
 * Enable this via "adb shell setprop log.tag.TouchpadInputMapperGestures DEBUG" (requires
 * restarting the shell)
 */
const bool DEBUG_TOUCHPAD_GESTURES =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, "TouchpadInputMapperGestures",
                                  ANDROID_LOG_INFO);

} // namespace

void gestures_log(int verb, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (verb == GESTURES_LOG_ERROR) {
        LOG_PRI_VA(ANDROID_LOG_ERROR, LOG_TAG, fmt, args);
    } else if (DEBUG_TOUCHPAD_GESTURES) {
        if (verb == GESTURES_LOG_INFO) {
            LOG_PRI_VA(ANDROID_LOG_INFO, LOG_TAG, fmt, args);
        } else {
            LOG_PRI_VA(ANDROID_LOG_DEBUG, LOG_TAG, fmt, args);
        }
    }
    va_end(args);
}
}
