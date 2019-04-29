/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "InputClassifier"

#include "InputClassifier.h"

#include <algorithm>
#include <android-base/stringprintf.h>
#include <cmath>
#include <inttypes.h>
#include <log/log.h>
#if defined(__linux__)
    #include <pthread.h>
#endif
#include <server_configurable_flags/get_flags.h>
#include <unordered_set>

#include <android/hardware/input/classifier/1.0/IInputClassifier.h>

#define INDENT1 "  "
#define INDENT2 "    "
#define INDENT3 "      "
#define INDENT4 "        "
#define INDENT5 "          "

using android::base::StringPrintf;
using android::hardware::hidl_bitfield;
using android::hardware::hidl_vec;
using android::hardware::Return;
using namespace android::hardware::input;

namespace android {

static constexpr bool DEBUG = false;

// Category (=namespace) name for the input settings that are applied at boot time
static const char* INPUT_NATIVE_BOOT = "input_native_boot";
// Feature flag name for the deep press feature
static const char* DEEP_PRESS_ENABLED = "deep_press_enabled";

//Max number of elements to store in mEvents.
static constexpr size_t MAX_EVENTS = 5;

template<class K, class V>
static V getValueForKey(const std::unordered_map<K, V>& map, K key, V defaultValue) {
    auto it = map.find(key);
    if (it == map.end()) {
        return defaultValue;
    }
    return it->second;
}

static common::V1_0::Source getSource(uint32_t source) {
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_UNKNOWN) ==
            common::V1_0::Source::UNKNOWN, "SOURCE_UNKNOWN mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_KEYBOARD) ==
            common::V1_0::Source::KEYBOARD, "SOURCE_KEYBOARD mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_DPAD) ==
            common::V1_0::Source::DPAD, "SOURCE_DPAD mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_GAMEPAD) ==
            common::V1_0::Source::GAMEPAD, "SOURCE_GAMEPAD mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_TOUCHSCREEN) ==
            common::V1_0::Source::TOUCHSCREEN, "SOURCE_TOUCHSCREEN mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_MOUSE) ==
            common::V1_0::Source::MOUSE, "SOURCE_MOUSE mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_STYLUS) ==
            common::V1_0::Source::STYLUS, "SOURCE_STYLUS mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_BLUETOOTH_STYLUS) ==
            common::V1_0::Source::BLUETOOTH_STYLUS, "SOURCE_BLUETOOTH_STYLUS mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_TRACKBALL) ==
            common::V1_0::Source::TRACKBALL, "SOURCE_TRACKBALL mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_MOUSE_RELATIVE) ==
            common::V1_0::Source::MOUSE_RELATIVE, "SOURCE_MOUSE_RELATIVE mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_TOUCHPAD) ==
            common::V1_0::Source::TOUCHPAD, "SOURCE_TOUCHPAD mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_TOUCH_NAVIGATION) ==
            common::V1_0::Source::TOUCH_NAVIGATION, "SOURCE_TOUCH_NAVIGATION mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_JOYSTICK) ==
            common::V1_0::Source::JOYSTICK, "SOURCE_JOYSTICK mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_ROTARY_ENCODER) ==
            common::V1_0::Source::ROTARY_ENCODER, "SOURCE_ROTARY_ENCODER mismatch");
    static_assert(static_cast<common::V1_0::Source>(AINPUT_SOURCE_ANY) ==
            common::V1_0::Source::ANY, "SOURCE_ANY mismatch");
    return static_cast<common::V1_0::Source>(source);
}

static common::V1_0::Action getAction(int32_t actionMasked) {
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_DOWN) ==
            common::V1_0::Action::DOWN, "ACTION_DOWN mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_UP) ==
            common::V1_0::Action::UP, "ACTION_UP mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_MOVE) ==
            common::V1_0::Action::MOVE, "ACTION_MOVE mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_CANCEL) ==
            common::V1_0::Action::CANCEL, "ACTION_CANCEL mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_OUTSIDE) ==
            common::V1_0::Action::OUTSIDE, "ACTION_OUTSIDE mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_POINTER_DOWN) ==
            common::V1_0::Action::POINTER_DOWN, "ACTION_POINTER_DOWN mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_POINTER_UP) ==
            common::V1_0::Action::POINTER_UP, "ACTION_POINTER_UP mismatch");
    static_assert(static_cast<common::V1_0::Action>( AMOTION_EVENT_ACTION_HOVER_MOVE) ==
            common::V1_0::Action::HOVER_MOVE, "ACTION_HOVER_MOVE mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_SCROLL) ==
            common::V1_0::Action::SCROLL, "ACTION_SCROLL mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_HOVER_ENTER) ==
            common::V1_0::Action::HOVER_ENTER, "ACTION_HOVER_ENTER mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_HOVER_EXIT) ==
            common::V1_0::Action::HOVER_EXIT, "ACTION_HOVER_EXIT mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_BUTTON_PRESS) ==
            common::V1_0::Action::BUTTON_PRESS, "ACTION_BUTTON_PRESS mismatch");
    static_assert(static_cast<common::V1_0::Action>(AMOTION_EVENT_ACTION_BUTTON_RELEASE) ==
            common::V1_0::Action::BUTTON_RELEASE, "ACTION_BUTTON_RELEASE mismatch");
    return static_cast<common::V1_0::Action>(actionMasked);
}

static common::V1_0::Button getActionButton(int32_t actionButton) {
    static_assert(static_cast<common::V1_0::Button>(0) ==
            common::V1_0::Button::NONE, "BUTTON_NONE mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_PRIMARY) ==
            common::V1_0::Button::PRIMARY, "BUTTON_PRIMARY mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_SECONDARY) ==
            common::V1_0::Button::SECONDARY, "BUTTON_SECONDARY mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_TERTIARY) ==
            common::V1_0::Button::TERTIARY, "BUTTON_TERTIARY mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_BACK) ==
            common::V1_0::Button::BACK, "BUTTON_BACK mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_FORWARD) ==
            common::V1_0::Button::FORWARD, "BUTTON_FORWARD mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY) ==
            common::V1_0::Button::STYLUS_PRIMARY, "BUTTON_STYLUS_PRIMARY mismatch");
    static_assert(static_cast<common::V1_0::Button>(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY) ==
            common::V1_0::Button::STYLUS_SECONDARY, "BUTTON_STYLUS_SECONDARY mismatch");
    return static_cast<common::V1_0::Button>(actionButton);
}

static hidl_bitfield<common::V1_0::Flag> getFlags(int32_t flags) {
    static_assert(static_cast<common::V1_0::Flag>(AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED) ==
            common::V1_0::Flag::WINDOW_IS_OBSCURED);
    static_assert(static_cast<common::V1_0::Flag>(AMOTION_EVENT_FLAG_IS_GENERATED_GESTURE) ==
            common::V1_0::Flag::IS_GENERATED_GESTURE);
    static_assert(static_cast<common::V1_0::Flag>(AMOTION_EVENT_FLAG_TAINTED) ==
            common::V1_0::Flag::TAINTED);
    return static_cast<hidl_bitfield<common::V1_0::Flag>>(flags);
}

static hidl_bitfield<common::V1_0::PolicyFlag> getPolicyFlags(int32_t flags) {
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_WAKE) ==
            common::V1_0::PolicyFlag::WAKE);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_VIRTUAL) ==
            common::V1_0::PolicyFlag::VIRTUAL);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_FUNCTION) ==
            common::V1_0::PolicyFlag::FUNCTION);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_GESTURE) ==
            common::V1_0::PolicyFlag::GESTURE);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_INJECTED) ==
            common::V1_0::PolicyFlag::INJECTED);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_TRUSTED) ==
            common::V1_0::PolicyFlag::TRUSTED);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_FILTERED) ==
            common::V1_0::PolicyFlag::FILTERED);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_DISABLE_KEY_REPEAT) ==
            common::V1_0::PolicyFlag::DISABLE_KEY_REPEAT);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_INTERACTIVE) ==
            common::V1_0::PolicyFlag::INTERACTIVE);
    static_assert(static_cast<common::V1_0::PolicyFlag>(POLICY_FLAG_PASS_TO_USER) ==
            common::V1_0::PolicyFlag::PASS_TO_USER);
    return static_cast<hidl_bitfield<common::V1_0::PolicyFlag>>(flags);
}

static hidl_bitfield<common::V1_0::EdgeFlag> getEdgeFlags(int32_t flags) {
    static_assert(static_cast<common::V1_0::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_NONE) ==
            common::V1_0::EdgeFlag::NONE);
    static_assert(static_cast<common::V1_0::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_TOP) ==
            common::V1_0::EdgeFlag::TOP);
    static_assert(static_cast<common::V1_0::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_BOTTOM) ==
            common::V1_0::EdgeFlag::BOTTOM);
    static_assert(static_cast<common::V1_0::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_LEFT) ==
            common::V1_0::EdgeFlag::LEFT);
    static_assert(static_cast<common::V1_0::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_RIGHT) ==
            common::V1_0::EdgeFlag::RIGHT);
    return static_cast<hidl_bitfield<common::V1_0::EdgeFlag>>(flags);
}

static hidl_bitfield<common::V1_0::Meta> getMetastate(int32_t state) {
    static_assert(static_cast<common::V1_0::Meta>(AMETA_NONE) ==
            common::V1_0::Meta::NONE);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_ALT_ON) ==
            common::V1_0::Meta::ALT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_ALT_LEFT_ON) ==
            common::V1_0::Meta::ALT_LEFT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_ALT_RIGHT_ON) ==
            common::V1_0::Meta::ALT_RIGHT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_SHIFT_ON) ==
            common::V1_0::Meta::SHIFT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_SHIFT_LEFT_ON) ==
            common::V1_0::Meta::SHIFT_LEFT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_SHIFT_RIGHT_ON) ==
            common::V1_0::Meta::SHIFT_RIGHT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_SYM_ON) ==
            common::V1_0::Meta::SYM_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_FUNCTION_ON) ==
            common::V1_0::Meta::FUNCTION_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_CTRL_ON) ==
            common::V1_0::Meta::CTRL_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_CTRL_LEFT_ON) ==
            common::V1_0::Meta::CTRL_LEFT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_CTRL_RIGHT_ON) ==
            common::V1_0::Meta::CTRL_RIGHT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_META_ON) ==
            common::V1_0::Meta::META_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_META_LEFT_ON) ==
            common::V1_0::Meta::META_LEFT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_META_RIGHT_ON) ==
            common::V1_0::Meta::META_RIGHT_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_CAPS_LOCK_ON) ==
            common::V1_0::Meta::CAPS_LOCK_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_NUM_LOCK_ON) ==
            common::V1_0::Meta::NUM_LOCK_ON);
    static_assert(static_cast<common::V1_0::Meta>(AMETA_SCROLL_LOCK_ON) ==
            common::V1_0::Meta::SCROLL_LOCK_ON);
    return static_cast<hidl_bitfield<common::V1_0::Meta>>(state);
}

static hidl_bitfield<common::V1_0::Button> getButtonState(int32_t buttonState) {
    // No need for static_assert here.
    // The button values have already been asserted in getActionButton(..) above
    return static_cast<hidl_bitfield<common::V1_0::Button>>(buttonState);
}

static common::V1_0::ToolType getToolType(int32_t toolType) {
    static_assert(static_cast<common::V1_0::ToolType>(AMOTION_EVENT_TOOL_TYPE_UNKNOWN) ==
            common::V1_0::ToolType::UNKNOWN);
    static_assert(static_cast<common::V1_0::ToolType>(AMOTION_EVENT_TOOL_TYPE_FINGER) ==
            common::V1_0::ToolType::FINGER);
    static_assert(static_cast<common::V1_0::ToolType>(AMOTION_EVENT_TOOL_TYPE_STYLUS) ==
            common::V1_0::ToolType::STYLUS);
    static_assert(static_cast<common::V1_0::ToolType>(AMOTION_EVENT_TOOL_TYPE_MOUSE) ==
            common::V1_0::ToolType::MOUSE);
    static_assert(static_cast<common::V1_0::ToolType>(AMOTION_EVENT_TOOL_TYPE_ERASER) ==
            common::V1_0::ToolType::ERASER);
    return static_cast<common::V1_0::ToolType>(toolType);
}

static common::V1_0::Axis getAxis(uint64_t axis) {
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_X) ==
            common::V1_0::Axis::X);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_Y) ==
            common::V1_0::Axis::Y);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_PRESSURE) ==
            common::V1_0::Axis::PRESSURE);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_SIZE) ==
            common::V1_0::Axis::SIZE);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_TOUCH_MAJOR) ==
            common::V1_0::Axis::TOUCH_MAJOR);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_TOUCH_MINOR) ==
            common::V1_0::Axis::TOUCH_MINOR);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_TOOL_MAJOR) ==
            common::V1_0::Axis::TOOL_MAJOR);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_TOOL_MINOR) ==
            common::V1_0::Axis::TOOL_MINOR);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_ORIENTATION) ==
            common::V1_0::Axis::ORIENTATION);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_VSCROLL) ==
            common::V1_0::Axis::VSCROLL);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_HSCROLL) ==
            common::V1_0::Axis::HSCROLL);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_Z) ==
            common::V1_0::Axis::Z);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RX) ==
            common::V1_0::Axis::RX);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RY) ==
            common::V1_0::Axis::RY);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RZ) ==
            common::V1_0::Axis::RZ);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_HAT_X) ==
            common::V1_0::Axis::HAT_X);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_HAT_Y) ==
            common::V1_0::Axis::HAT_Y);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_LTRIGGER) ==
            common::V1_0::Axis::LTRIGGER);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RTRIGGER) ==
            common::V1_0::Axis::RTRIGGER);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_THROTTLE) ==
            common::V1_0::Axis::THROTTLE);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RUDDER) ==
            common::V1_0::Axis::RUDDER);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_WHEEL) ==
            common::V1_0::Axis::WHEEL);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GAS) ==
            common::V1_0::Axis::GAS);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_BRAKE) ==
            common::V1_0::Axis::BRAKE);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_DISTANCE) ==
            common::V1_0::Axis::DISTANCE);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_TILT) ==
            common::V1_0::Axis::TILT);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_SCROLL) ==
            common::V1_0::Axis::SCROLL);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RELATIVE_X) ==
            common::V1_0::Axis::RELATIVE_X);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_RELATIVE_Y) ==
            common::V1_0::Axis::RELATIVE_Y);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_1) ==
            common::V1_0::Axis::GENERIC_1);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_2) ==
            common::V1_0::Axis::GENERIC_2);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_3) ==
            common::V1_0::Axis::GENERIC_3);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_4) ==
            common::V1_0::Axis::GENERIC_4);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_5) ==
            common::V1_0::Axis::GENERIC_5);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_6) ==
            common::V1_0::Axis::GENERIC_6);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_7) ==
            common::V1_0::Axis::GENERIC_7);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_8) ==
            common::V1_0::Axis::GENERIC_8);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_9) ==
            common::V1_0::Axis::GENERIC_9);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_10) ==
            common::V1_0::Axis::GENERIC_10);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_11) ==
            common::V1_0::Axis::GENERIC_11);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_12) ==
            common::V1_0::Axis::GENERIC_12);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_13) ==
            common::V1_0::Axis::GENERIC_13);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_14) ==
            common::V1_0::Axis::GENERIC_14);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_15) ==
            common::V1_0::Axis::GENERIC_15);
    static_assert(static_cast<common::V1_0::Axis>(AMOTION_EVENT_AXIS_GENERIC_16) ==
            common::V1_0::Axis::GENERIC_16);
    return static_cast<common::V1_0::Axis>(axis);
}

static common::V1_0::VideoFrame getHalVideoFrame(const TouchVideoFrame& frame) {
    common::V1_0::VideoFrame out;
    out.width = frame.getWidth();
    out.height = frame.getHeight();
    out.data = frame.getData();
    struct timeval timestamp = frame.getTimestamp();
    out.timestamp = seconds_to_nanoseconds(timestamp.tv_sec) +
             microseconds_to_nanoseconds(timestamp.tv_usec);
    return out;
}

static std::vector<common::V1_0::VideoFrame> convertVideoFrames(
        const std::vector<TouchVideoFrame>& frames) {
    std::vector<common::V1_0::VideoFrame> out;
    for (const TouchVideoFrame& frame : frames) {
        out.push_back(getHalVideoFrame(frame));
    }
    return out;
}

static uint8_t getActionIndex(int32_t action) {
    return (action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK) >>
            AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
}

static void getHidlPropertiesAndCoords(const NotifyMotionArgs& args,
        std::vector<common::V1_0::PointerProperties>* outPointerProperties,
        std::vector<common::V1_0::PointerCoords>* outPointerCoords) {
    outPointerProperties->reserve(args.pointerCount);
    outPointerCoords->reserve(args.pointerCount);
    for (size_t i = 0; i < args.pointerCount; i++) {
        common::V1_0::PointerProperties properties;
        properties.id = args.pointerProperties[i].id;
        properties.toolType = getToolType(args.pointerProperties[i].toolType);
        outPointerProperties->push_back(properties);

        common::V1_0::PointerCoords coords;
        BitSet64 bits (args.pointerCoords[i].bits);
        std::vector<float> values;
        size_t index = 0;
        while (!bits.isEmpty()) {
            uint32_t axis = bits.clearFirstMarkedBit();
            coords.bits |= 1 << static_cast<uint64_t>(getAxis(axis));
            float value = args.pointerCoords[i].values[index++];
            values.push_back(value);
        }
        coords.values = values;
        outPointerCoords->push_back(coords);
    }
}

static common::V1_0::MotionEvent getMotionEvent(const NotifyMotionArgs& args) {
    common::V1_0::MotionEvent event;
    event.deviceId = args.deviceId;
    event.source = getSource(args.source);
    event.displayId = args.displayId;
    event.downTime = args.downTime;
    event.eventTime = args.eventTime;
    event.action = getAction(args.action & AMOTION_EVENT_ACTION_MASK);
    event.actionIndex = getActionIndex(args.action);
    event.actionButton = getActionButton(args.actionButton);
    event.flags = getFlags(args.flags);
    event.policyFlags = getPolicyFlags(args.policyFlags);
    event.edgeFlags = getEdgeFlags(args.edgeFlags);
    event.metaState = getMetastate(args.metaState);
    event.buttonState = getButtonState(args.buttonState);
    event.xPrecision = args.xPrecision;
    event.yPrecision = args.yPrecision;

    std::vector<common::V1_0::PointerProperties> pointerProperties;
    std::vector<common::V1_0::PointerCoords> pointerCoords;
    getHidlPropertiesAndCoords(args, /*out*/&pointerProperties, /*out*/&pointerCoords);
    event.pointerProperties = pointerProperties;
    event.pointerCoords = pointerCoords;

    event.deviceTimestamp = args.deviceTimestamp;
    event.frames = convertVideoFrames(args.videoFrames);

    return event;
}

static MotionClassification getMotionClassification(common::V1_0::Classification classification) {
    static_assert(MotionClassification::NONE ==
            static_cast<MotionClassification>(common::V1_0::Classification::NONE));
    static_assert(MotionClassification::AMBIGUOUS_GESTURE ==
            static_cast<MotionClassification>(common::V1_0::Classification::AMBIGUOUS_GESTURE));
    static_assert(MotionClassification::DEEP_PRESS ==
            static_cast<MotionClassification>(common::V1_0::Classification::DEEP_PRESS));
    return static_cast<MotionClassification>(classification);
}

static bool isTouchEvent(const NotifyMotionArgs& args) {
    return args.source == AINPUT_SOURCE_TOUCHPAD || args.source == AINPUT_SOURCE_TOUCHSCREEN;
}

// Check if the "deep touch" feature is on.
static bool deepPressEnabled() {
    std::string flag_value = server_configurable_flags::GetServerConfigurableFlag(
            INPUT_NATIVE_BOOT, DEEP_PRESS_ENABLED, "true");
    std::transform(flag_value.begin(), flag_value.end(), flag_value.begin(), ::tolower);
    if (flag_value == "1" || flag_value == "true") {
        ALOGI("Deep press feature enabled.");
        return true;
    }
    ALOGI("Deep press feature is not enabled.");
    return false;
}


// --- ClassifierEvent ---

ClassifierEvent::ClassifierEvent(std::unique_ptr<NotifyMotionArgs> args) :
        type(ClassifierEventType::MOTION), args(std::move(args)) { };
ClassifierEvent::ClassifierEvent(std::unique_ptr<NotifyDeviceResetArgs> args) :
        type(ClassifierEventType::DEVICE_RESET), args(std::move(args)) { };
ClassifierEvent::ClassifierEvent(ClassifierEventType type, std::unique_ptr<NotifyArgs> args) :
        type(type), args(std::move(args)) { };

ClassifierEvent::ClassifierEvent(ClassifierEvent&& other) :
        type(other.type), args(std::move(other.args)) { };

ClassifierEvent& ClassifierEvent::operator=(ClassifierEvent&& other) {
    type = other.type;
    args = std::move(other.args);
    return *this;
}

ClassifierEvent ClassifierEvent::createHalResetEvent() {
    return ClassifierEvent(ClassifierEventType::HAL_RESET, nullptr);
}

ClassifierEvent ClassifierEvent::createExitEvent() {
    return ClassifierEvent(ClassifierEventType::EXIT, nullptr);
}

std::optional<int32_t> ClassifierEvent::getDeviceId() const {
    switch (type) {
        case ClassifierEventType::MOTION: {
            NotifyMotionArgs* motionArgs = static_cast<NotifyMotionArgs*>(args.get());
            return motionArgs->deviceId;
        }
        case ClassifierEventType::DEVICE_RESET: {
            NotifyDeviceResetArgs* deviceResetArgs =
                    static_cast<NotifyDeviceResetArgs*>(args.get());
            return deviceResetArgs->deviceId;
        }
        case ClassifierEventType::HAL_RESET: {
            return std::nullopt;
        }
        case ClassifierEventType::EXIT: {
            return std::nullopt;
        }
    }
}

// --- MotionClassifier ---

MotionClassifier::MotionClassifier(sp<android::hardware::hidl_death_recipient> deathRecipient) :
        mDeathRecipient(deathRecipient), mEvents(MAX_EVENTS) {
    mHalThread = std::thread(&MotionClassifier::callInputClassifierHal, this);
#if defined(__linux__)
    // Set the thread name for debugging
    pthread_setname_np(mHalThread.native_handle(), "InputClassifier");
#endif
}

/**
 * This function may block for some time to initialize the HAL, so it should only be called
 * from the "InputClassifier HAL" thread.
 */
bool MotionClassifier::init() {
    ensureHalThread(__func__);
    sp<android::hardware::input::classifier::V1_0::IInputClassifier> service =
            classifier::V1_0::IInputClassifier::getService();
    if (!service) {
        // Not really an error, maybe the device does not have this HAL,
        // but somehow the feature flag is flipped
        ALOGI("Could not obtain InputClassifier HAL");
        return false;
    }

    sp<android::hardware::hidl_death_recipient> recipient = mDeathRecipient.promote();
    if (recipient != nullptr) {
        const bool linked = service->linkToDeath(recipient, 0 /* cookie */).withDefault(false);
        if (!linked) {
            ALOGE("Could not link MotionClassifier to the HAL death");
            return false;
        }
    }

    // Under normal operation, we do not need to reset the HAL here. But in the case where system
    // crashed, but HAL didn't, we may be connecting to an existing HAL process that might already
    // have received events in the past. That means, that HAL could be in an inconsistent state
    // once it receives events from the newly created MotionClassifier.
    mEvents.push(ClassifierEvent::createHalResetEvent());

    {
        std::scoped_lock lock(mLock);
        if (mService) {
            ALOGE("MotionClassifier::%s should only be called once", __func__);
        }
        mService = service;
    }
    return true;
}

MotionClassifier::~MotionClassifier() {
    requestExit();
    mHalThread.join();
}

void MotionClassifier::ensureHalThread(const char* function) {
    if (DEBUG) {
        if (std::this_thread::get_id() != mHalThread.get_id()) {
            LOG_FATAL("Function %s should only be called from InputClassifier thread", function);
        }
    }
}

/**
 * Obtain the classification from the HAL for a given MotionEvent.
 * Should only be called from the InputClassifier thread (mHalThread).
 * Should not be called from the thread that notifyMotion runs on.
 *
 * There is no way to provide a timeout for a HAL call. So if the HAL takes too long
 * to return a classification, this would directly impact the touch latency.
 * To remove any possibility of negatively affecting the touch latency, the HAL
 * is called from a dedicated thread.
 */
void MotionClassifier::callInputClassifierHal() {
    ensureHalThread(__func__);
    const bool initialized = init();
    if (!initialized) {
        // MotionClassifier no longer useful.
        // Deliver death notification from a separate thread
        // because ~MotionClassifier may be invoked, which calls mHalThread.join()
        std::thread([deathRecipient = mDeathRecipient](){
                sp<android::hardware::hidl_death_recipient> recipient = deathRecipient.promote();
                if (recipient != nullptr) {
                    recipient->serviceDied(0 /*cookie*/, nullptr);
                }
        }).detach();
        return;
    }
    // From this point on, mService is guaranteed to be non-null.

    while (true) {
        ClassifierEvent event = mEvents.pop();
        bool halResponseOk = true;
        switch (event.type) {
            case ClassifierEventType::MOTION: {
                NotifyMotionArgs* motionArgs = static_cast<NotifyMotionArgs*>(event.args.get());
                common::V1_0::MotionEvent motionEvent = getMotionEvent(*motionArgs);
                Return<common::V1_0::Classification> response = mService->classify(motionEvent);
                halResponseOk = response.isOk();
                if (halResponseOk) {
                    common::V1_0::Classification halClassification = response;
                    updateClassification(motionArgs->deviceId, motionArgs->eventTime,
                            getMotionClassification(halClassification));
                }
                break;
            }
            case ClassifierEventType::DEVICE_RESET: {
                const int32_t deviceId = *(event.getDeviceId());
                halResponseOk = mService->resetDevice(deviceId).isOk();
                setClassification(deviceId, MotionClassification::NONE);
                break;
            }
            case ClassifierEventType::HAL_RESET: {
                halResponseOk = mService->reset().isOk();
                clearClassifications();
                break;
            }
            case ClassifierEventType::EXIT: {
                clearClassifications();
                return;
            }
        }
        if (!halResponseOk) {
            ALOGE("Error communicating with InputClassifier HAL. "
                    "Exiting MotionClassifier HAL thread");
            clearClassifications();
            return;
        }
    }
}

void MotionClassifier::enqueueEvent(ClassifierEvent&& event) {
    bool eventAdded = mEvents.push(std::move(event));
    if (!eventAdded) {
        // If the queue is full, suspect the HAL is slow in processing the events.
        ALOGE("Dropped event with eventTime %" PRId64, event.args->eventTime);
        reset();
    }
}

void MotionClassifier::requestExit() {
    reset();
    mEvents.push(ClassifierEvent::createExitEvent());
}

void MotionClassifier::updateClassification(int32_t deviceId, nsecs_t eventTime,
        MotionClassification classification) {
    std::scoped_lock lock(mLock);
    const nsecs_t lastDownTime = getValueForKey(mLastDownTimes, deviceId, static_cast<nsecs_t>(0));
    if (eventTime < lastDownTime) {
        // HAL just finished processing an event that belonged to an earlier gesture,
        // but new gesture is already in progress. Drop this classification.
        ALOGW("Received late classification. Late by at least %" PRId64 " ms.",
                nanoseconds_to_milliseconds(lastDownTime - eventTime));
        return;
    }
    mClassifications[deviceId] = classification;
}

void MotionClassifier::setClassification(int32_t deviceId, MotionClassification classification) {
    std::scoped_lock lock(mLock);
    mClassifications[deviceId] = classification;
}

void MotionClassifier::clearClassifications() {
    std::scoped_lock lock(mLock);
    mClassifications.clear();
}

MotionClassification MotionClassifier::getClassification(int32_t deviceId) {
    std::scoped_lock lock(mLock);
    return getValueForKey(mClassifications, deviceId, MotionClassification::NONE);
}

void MotionClassifier::updateLastDownTime(int32_t deviceId, nsecs_t downTime) {
    std::scoped_lock lock(mLock);
    mLastDownTimes[deviceId] = downTime;
    mClassifications[deviceId] = MotionClassification::NONE;
}

MotionClassification MotionClassifier::classify(const NotifyMotionArgs& args) {
    if ((args.action & AMOTION_EVENT_ACTION_MASK) == AMOTION_EVENT_ACTION_DOWN) {
        updateLastDownTime(args.deviceId, args.downTime);
    }

    ClassifierEvent event(std::make_unique<NotifyMotionArgs>(args));
    enqueueEvent(std::move(event));
    return getClassification(args.deviceId);
}

void MotionClassifier::reset() {
    mEvents.clear();
    mEvents.push(ClassifierEvent::createHalResetEvent());
}

/**
 * Per-device reset. Clear the outstanding events that are going to be sent to HAL.
 * Request InputClassifier thread to call resetDevice for this particular device.
 */
void MotionClassifier::reset(const NotifyDeviceResetArgs& args) {
    int32_t deviceId = args.deviceId;
    // Clear the pending events right away, to avoid unnecessary work done by the HAL.
    mEvents.erase([deviceId](const ClassifierEvent& event) {
            std::optional<int32_t> eventDeviceId = event.getDeviceId();
            return eventDeviceId && (*eventDeviceId == deviceId);
    });
    enqueueEvent(std::make_unique<NotifyDeviceResetArgs>(args));
}

const char* MotionClassifier::getServiceStatus() REQUIRES(mLock) {
    if (!mService) {
        return "null";
    }
    if (mService->ping().isOk()) {
        return "running";
    }
    return "not responding";
}

void MotionClassifier::dump(std::string& dump) {
    std::scoped_lock lock(mLock);
    dump += StringPrintf(INDENT2 "mService status: %s\n", getServiceStatus());
    dump += StringPrintf(INDENT2 "mEvents: %zu element(s) (max=%zu)\n",
            mEvents.size(), MAX_EVENTS);
    dump += INDENT2 "mClassifications, mLastDownTimes:\n";
    dump += INDENT3 "Device Id\tClassification\tLast down time";
    // Combine mClassifications and mLastDownTimes into a single table.
    // Create a superset of device ids.
    std::unordered_set<int32_t> deviceIds;
    std::for_each(mClassifications.begin(), mClassifications.end(),
            [&deviceIds](auto pair){ deviceIds.insert(pair.first); });
    std::for_each(mLastDownTimes.begin(), mLastDownTimes.end(),
            [&deviceIds](auto pair){ deviceIds.insert(pair.first); });
    for(int32_t deviceId : deviceIds) {
        const MotionClassification classification =
                getValueForKey(mClassifications, deviceId, MotionClassification::NONE);
        const nsecs_t downTime = getValueForKey(mLastDownTimes, deviceId, static_cast<nsecs_t>(0));
        dump += StringPrintf("\n" INDENT4 "%" PRId32 "\t%s\t%" PRId64,
                deviceId, motionClassificationToString(classification), downTime);
    }
}


// --- InputClassifier ---

InputClassifier::InputClassifier(const sp<InputListenerInterface>& listener) :
        mListener(listener) {
    // The rest of the initialization is done in onFirstRef, because we need to obtain
    // an sp to 'this' in order to register for HAL death notifications
}

void InputClassifier::onFirstRef() {
    if (!deepPressEnabled()) {
        // If feature is not enabled, MotionClassifier should stay null to avoid unnecessary work.
        // When MotionClassifier is null, InputClassifier will forward all events
        // to the next InputListener, unmodified.
        return;
    }
    std::scoped_lock lock(mLock);
    mMotionClassifier = std::make_unique<MotionClassifier>(this);
}

void InputClassifier::notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) {
    // pass through
    mListener->notifyConfigurationChanged(args);
}

void InputClassifier::notifyKey(const NotifyKeyArgs* args) {
    // pass through
    mListener->notifyKey(args);
}

void InputClassifier::notifyMotion(const NotifyMotionArgs* args) {
    std::scoped_lock lock(mLock);
    // MotionClassifier is only used for touch events, for now
    const bool sendToMotionClassifier = mMotionClassifier && isTouchEvent(*args);
    if (!sendToMotionClassifier) {
        mListener->notifyMotion(args);
        return;
    }

    NotifyMotionArgs newArgs(*args);
    newArgs.classification = mMotionClassifier->classify(newArgs);
    mListener->notifyMotion(&newArgs);
}

void InputClassifier::notifySwitch(const NotifySwitchArgs* args) {
    // pass through
    mListener->notifySwitch(args);
}

void InputClassifier::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    std::scoped_lock lock(mLock);
    if (mMotionClassifier) {
        mMotionClassifier->reset(*args);
    }
    // continue to next stage
    mListener->notifyDeviceReset(args);
}

void InputClassifier::serviceDied(uint64_t /*cookie*/,
        const wp<android::hidl::base::V1_0::IBase>& who) {
    std::scoped_lock lock(mLock);
    ALOGE("InputClassifier HAL has died. Setting mMotionClassifier to null");
    mMotionClassifier = nullptr;
    sp<android::hidl::base::V1_0::IBase> service = who.promote();
    if (service) {
        service->unlinkToDeath(this);
    }
}

void InputClassifier::dump(std::string& dump) {
    std::scoped_lock lock(mLock);
    dump += "Input Classifier State:\n";

    dump += INDENT1 "Motion Classifier:\n";
    if (mMotionClassifier) {
        mMotionClassifier->dump(dump);
    } else {
        dump += INDENT2 "<nullptr>";
    }
    dump += "\n";
}

} // namespace android
