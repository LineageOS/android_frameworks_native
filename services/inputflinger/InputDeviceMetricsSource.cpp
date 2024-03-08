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

#include "InputDeviceMetricsSource.h"

#include "KeyCodeClassifications.h"

#include <android/input.h>
#include <input/Input.h>
#include <linux/input.h>
#include <log/log_main.h>

#include <set>

namespace android {

InputDeviceUsageSource getUsageSourceForKeyArgs(int32_t keyboardType,
                                                const NotifyKeyArgs& keyArgs) {
    if (!isFromSource(keyArgs.source, AINPUT_SOURCE_KEYBOARD)) {
        return InputDeviceUsageSource::UNKNOWN;
    }

    if (isFromSource(keyArgs.source, AINPUT_SOURCE_DPAD) &&
        DPAD_ALL_KEYCODES.count(keyArgs.keyCode) != 0) {
        return InputDeviceUsageSource::DPAD;
    }

    if (isFromSource(keyArgs.source, AINPUT_SOURCE_GAMEPAD) &&
        GAMEPAD_KEYCODES.count(keyArgs.keyCode) != 0) {
        return InputDeviceUsageSource::GAMEPAD;
    }

    if (keyboardType == AINPUT_KEYBOARD_TYPE_ALPHABETIC) {
        return InputDeviceUsageSource::KEYBOARD;
    }

    return InputDeviceUsageSource::BUTTONS;
}

std::set<InputDeviceUsageSource> getUsageSourcesForMotionArgs(const NotifyMotionArgs& motionArgs) {
    LOG_ALWAYS_FATAL_IF(motionArgs.getPointerCount() < 1, "Received motion args without pointers");
    std::set<InputDeviceUsageSource> sources;

    for (uint32_t i = 0; i < motionArgs.getPointerCount(); i++) {
        const auto toolType = motionArgs.pointerProperties[i].toolType;
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_MOUSE)) {
            if (toolType == ToolType::MOUSE) {
                sources.emplace(InputDeviceUsageSource::MOUSE);
                continue;
            }
            if (toolType == ToolType::FINGER) {
                sources.emplace(InputDeviceUsageSource::TOUCHPAD);
                continue;
            }
            if (isStylusToolType(toolType)) {
                sources.emplace(InputDeviceUsageSource::STYLUS_INDIRECT);
                continue;
            }
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_MOUSE_RELATIVE) &&
            toolType == ToolType::MOUSE) {
            sources.emplace(InputDeviceUsageSource::MOUSE_CAPTURED);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TOUCHPAD) &&
            toolType == ToolType::FINGER) {
            sources.emplace(InputDeviceUsageSource::TOUCHPAD_CAPTURED);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_BLUETOOTH_STYLUS) &&
            isStylusToolType(toolType)) {
            sources.emplace(InputDeviceUsageSource::STYLUS_FUSED);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_STYLUS) && isStylusToolType(toolType)) {
            sources.emplace(InputDeviceUsageSource::STYLUS_DIRECT);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TOUCH_NAVIGATION)) {
            sources.emplace(InputDeviceUsageSource::TOUCH_NAVIGATION);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_JOYSTICK)) {
            sources.emplace(InputDeviceUsageSource::JOYSTICK);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_ROTARY_ENCODER)) {
            sources.emplace(InputDeviceUsageSource::ROTARY_ENCODER);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TRACKBALL)) {
            sources.emplace(InputDeviceUsageSource::TRACKBALL);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TOUCHSCREEN)) {
            sources.emplace(InputDeviceUsageSource::TOUCHSCREEN);
            continue;
        }
        sources.emplace(InputDeviceUsageSource::UNKNOWN);
    }

    return sources;
}

} // namespace android
