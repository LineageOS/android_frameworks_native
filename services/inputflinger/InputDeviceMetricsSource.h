/*
 * Copyright 2023 The Android Open Source Project
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

#include "NotifyArgs.h"

#include <linux/input.h>
#include <statslog.h>

namespace android {

/**
 * Enum representation of the InputDeviceUsageSource.
 */
enum class InputDeviceUsageSource : int32_t {
    UNKNOWN = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__UNKNOWN,
    BUTTONS = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__BUTTONS,
    KEYBOARD = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__KEYBOARD,
    DPAD = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__DPAD,
    GAMEPAD = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__GAMEPAD,
    JOYSTICK = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__JOYSTICK,
    MOUSE = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__MOUSE,
    MOUSE_CAPTURED = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__MOUSE_CAPTURED,
    TOUCHPAD = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__TOUCHPAD,
    TOUCHPAD_CAPTURED = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__TOUCHPAD_CAPTURED,
    ROTARY_ENCODER = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__ROTARY_ENCODER,
    STYLUS_DIRECT = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__STYLUS_DIRECT,
    STYLUS_INDIRECT = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__STYLUS_INDIRECT,
    STYLUS_FUSED = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__STYLUS_FUSED,
    TOUCH_NAVIGATION = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__TOUCH_NAVIGATION,
    TOUCHSCREEN = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__TOUCHSCREEN,
    TRACKBALL = util::INPUT_DEVICE_USAGE_REPORTED__USAGE_SOURCES__TRACKBALL,

    ftl_first = UNKNOWN,
    ftl_last = TRACKBALL,
    // Used by latency fuzzer
    kMaxValue = ftl_last
};

/** Returns the InputDeviceUsageSource that corresponds to the key event. */
InputDeviceUsageSource getUsageSourceForKeyArgs(int32_t keyboardType, const NotifyKeyArgs&);

/** Returns the InputDeviceUsageSources that correspond to the motion event. */
std::set<InputDeviceUsageSource> getUsageSourcesForMotionArgs(const NotifyMotionArgs&);

} // namespace android
