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

#include <android/input.h>
#include <set>

namespace android {

/** The set of all Android key codes that are required for a device to be classified as a D-pad. */
static const std::set<int32_t> DPAD_REQUIRED_KEYCODES = {
        AKEYCODE_DPAD_UP,    AKEYCODE_DPAD_DOWN,   AKEYCODE_DPAD_LEFT,
        AKEYCODE_DPAD_RIGHT, AKEYCODE_DPAD_CENTER,
};

/** The set of all Android key codes that correspond to D-pad keys. */
static const std::set<int32_t> DPAD_ALL_KEYCODES = {
        AKEYCODE_DPAD_UP,       AKEYCODE_DPAD_DOWN,      AKEYCODE_DPAD_LEFT,
        AKEYCODE_DPAD_RIGHT,    AKEYCODE_DPAD_CENTER,    AKEYCODE_DPAD_UP_LEFT,
        AKEYCODE_DPAD_UP_RIGHT, AKEYCODE_DPAD_DOWN_LEFT, AKEYCODE_DPAD_DOWN_RIGHT,
};

/** The set of all Android key codes that correspond to gamepad buttons. */
static const std::set<int32_t> GAMEPAD_KEYCODES = {
        AKEYCODE_BUTTON_A,      AKEYCODE_BUTTON_B,      AKEYCODE_BUTTON_C,    //
        AKEYCODE_BUTTON_X,      AKEYCODE_BUTTON_Y,      AKEYCODE_BUTTON_Z,    //
        AKEYCODE_BUTTON_L1,     AKEYCODE_BUTTON_R1,                           //
        AKEYCODE_BUTTON_L2,     AKEYCODE_BUTTON_R2,                           //
        AKEYCODE_BUTTON_THUMBL, AKEYCODE_BUTTON_THUMBR,                       //
        AKEYCODE_BUTTON_START,  AKEYCODE_BUTTON_SELECT, AKEYCODE_BUTTON_MODE, //
};

/** The set of all Android key codes that correspond to buttons (bit-switches) on a stylus. */
static const std::set<int32_t> STYLUS_BUTTON_KEYCODES = {
        AKEYCODE_STYLUS_BUTTON_PRIMARY,
        AKEYCODE_STYLUS_BUTTON_SECONDARY,
        AKEYCODE_STYLUS_BUTTON_TERTIARY,
        AKEYCODE_STYLUS_BUTTON_TAIL,
};

} // namespace android
