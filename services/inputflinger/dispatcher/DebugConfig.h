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

#pragma once

#define LOG_TAG "InputDispatcher"

#include <android-base/logging.h>

namespace android::inputdispatcher {

/**
 * Signals whether this is a debuggable Android build.
 * This is populated by reading the value of the "ro.debuggable" property.
 */
extern const bool IS_DEBUGGABLE_BUILD;

/**
 * Log detailed debug messages about each inbound event notification to the dispatcher.
 * Enable this via "adb shell setprop log.tag.InputDispatcherInboundEvent DEBUG".
 * This requires a restart on non-debuggable (e.g. user) builds, but should take effect immediately
 * on debuggable builds (e.g. userdebug).
 */
bool debugInboundEventDetails();

/**
 * Log detailed debug messages about each outbound event processed by the dispatcher.
 * Enable this via "adb shell setprop log.tag.InputDispatcherOutboundEvent DEBUG" (requires restart)
 */
const bool DEBUG_OUTBOUND_EVENT_DETAILS =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "OutboundEvent");

/**
 * Log debug messages about the dispatch cycle.
 * Enable this via "adb shell setprop log.tag.InputDispatcherDispatchCycle DEBUG" (requires restart)
 */
const bool DEBUG_DISPATCH_CYCLE =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "DispatchCycle");

/**
 * Log debug messages about channel creation
 * Enable this via "adb shell setprop log.tag.InputDispatcherChannelCreation DEBUG" (requires
 * restart)
 */
const bool DEBUG_CHANNEL_CREATION =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "ChannelCreation");

/**
 * Log debug messages about input event injection.
 * Enable this via "adb shell setprop log.tag.InputDispatcherInjection DEBUG" (requires restart)
 */
const bool DEBUG_INJECTION =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "Injection");

/**
 * Log debug messages about input focus tracking.
 * Enable this via "adb shell setprop log.tag.InputDispatcherFocus DEBUG" (requires restart)
 */
const bool DEBUG_FOCUS =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "Focus");

/**
 * Log debug messages about touch mode event
 * Enable this via "adb shell setprop log.tag.InputDispatcherTouchMode DEBUG" (requires restart)
 */
const bool DEBUG_TOUCH_MODE =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "TouchMode");

/**
 * Log debug messages about touch occlusion
 */
constexpr bool DEBUG_TOUCH_OCCLUSION = true;

/**
 * Log debug messages about the app switch latency optimization.
 * Enable this via "adb shell setprop log.tag.InputDispatcherAppSwitch DEBUG" (requires restart)
 */
const bool DEBUG_APP_SWITCH =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "AppSwitch");

/**
 * Log debug messages about hover events.
 * Enable this via "adb shell setprop log.tag.InputDispatcherHover DEBUG" (requires restart)
 */
const bool DEBUG_HOVER =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "Hover");

/**
 * Crash if a bad stream from InputListener is detected.
 * Enable this via "adb shell setprop log.tag.InputDispatcherVerifyEvents DEBUG" (requires restart)
 */
const bool DEBUG_VERIFY_EVENTS =
        android::base::ShouldLog(android::base::LogSeverity::DEBUG, LOG_TAG "VerifyEvents");

} // namespace android::inputdispatcher
