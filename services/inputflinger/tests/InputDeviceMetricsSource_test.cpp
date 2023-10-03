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

#include "../InputDeviceMetricsSource.h"

#include <NotifyArgsBuilders.h>

#include <android/input.h>
#include <ftl/enum.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <input/InputEventBuilders.h>
#include <linux/input.h>

#include <set>

namespace android {

namespace {

constexpr auto ALL_USAGE_SOURCES = ftl::enum_range<InputDeviceUsageSource>();
constexpr uint32_t TOUCHSCREEN = AINPUT_SOURCE_TOUCHSCREEN;
constexpr uint32_t STYLUS = AINPUT_SOURCE_STYLUS;
constexpr uint32_t KEY_SOURCES =
        AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_DPAD | AINPUT_SOURCE_GAMEPAD;
constexpr int32_t POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

} // namespace

// --- InputDeviceMetricsSourceDeviceClassificationTest ---

class DeviceClassificationFixture : public ::testing::Test,
                                    public ::testing::WithParamInterface<InputDeviceUsageSource> {};

TEST_P(DeviceClassificationFixture, ValidClassifications) {
    const InputDeviceUsageSource usageSource = GetParam();

    // Use a switch to ensure a test is added for all source classifications.
    switch (usageSource) {
        case InputDeviceUsageSource::UNKNOWN: {
            ASSERT_EQ(InputDeviceUsageSource::UNKNOWN,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_NONE,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, TOUCHSCREEN)
                                                       .build()));

            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::UNKNOWN};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_KEYBOARD)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::PALM)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::BUTTONS: {
            ASSERT_EQ(InputDeviceUsageSource::BUTTONS,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_STYLUS_BUTTON_TAIL)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::KEYBOARD: {
            ASSERT_EQ(InputDeviceUsageSource::KEYBOARD,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_ALPHABETIC,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::DPAD: {
            ASSERT_EQ(InputDeviceUsageSource::DPAD,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_DPAD_CENTER)
                                                       .build()));

            ASSERT_EQ(InputDeviceUsageSource::DPAD,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_ALPHABETIC,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_DPAD_CENTER)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::GAMEPAD: {
            ASSERT_EQ(InputDeviceUsageSource::GAMEPAD,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_BUTTON_A)
                                                       .build()));

            ASSERT_EQ(InputDeviceUsageSource::GAMEPAD,
                      getUsageSourceForKeyArgs(AINPUT_KEYBOARD_TYPE_ALPHABETIC,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_BUTTON_A)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::JOYSTICK: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::JOYSTICK};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_JOYSTICK)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::UNKNOWN)
                                                       .axis(AMOTION_EVENT_AXIS_GAS, 1.f))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::MOUSE: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::MOUSE};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::MOUSE)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::MOUSE_CAPTURED: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::MOUSE_CAPTURED};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE,
                                                AINPUT_SOURCE_MOUSE_RELATIVE)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::MOUSE)
                                                       .x(100)
                                                       .y(200)
                                                       .axis(AMOTION_EVENT_AXIS_RELATIVE_X, 100)
                                                       .axis(AMOTION_EVENT_AXIS_RELATIVE_Y, 200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::TOUCHPAD: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TOUCHPAD};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::TOUCHPAD_CAPTURED: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TOUCHPAD_CAPTURED};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHPAD)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER)
                                                       .x(100)
                                                       .y(200)
                                                       .axis(AMOTION_EVENT_AXIS_RELATIVE_X, 1)
                                                       .axis(AMOTION_EVENT_AXIS_RELATIVE_Y, 2))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::ROTARY_ENCODER: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::ROTARY_ENCODER};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_SCROLL,
                                                AINPUT_SOURCE_ROTARY_ENCODER)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::UNKNOWN)
                                                       .axis(AMOTION_EVENT_AXIS_SCROLL, 10)
                                                       .axis(AMOTION_EVENT_AXIS_VSCROLL, 10))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::STYLUS_DIRECT: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::STYLUS_DIRECT};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                STYLUS | TOUCHSCREEN)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::STYLUS)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::STYLUS_INDIRECT: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::STYLUS_INDIRECT};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                STYLUS | TOUCHSCREEN | AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::STYLUS)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::STYLUS_FUSED: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::STYLUS_FUSED};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                AINPUT_SOURCE_BLUETOOTH_STYLUS | TOUCHSCREEN)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::STYLUS)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::TOUCH_NAVIGATION: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TOUCH_NAVIGATION};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE,
                                                AINPUT_SOURCE_TOUCH_NAVIGATION)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER)
                                                       .x(100)
                                                       .y(200))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::TOUCHSCREEN: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TOUCHSCREEN};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(POINTER_1_DOWN, TOUCHSCREEN)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER)
                                                       .x(100)
                                                       .y(200))
                                      .pointer(PointerBuilder(/*id=*/2, ToolType::FINGER)
                                                       .x(300)
                                                       .y(400))
                                      .build()));
            break;
        }

        case InputDeviceUsageSource::TRACKBALL: {
            std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TRACKBALL};
            ASSERT_EQ(srcs,
                      getUsageSourcesForMotionArgs(
                              MotionArgsBuilder(AMOTION_EVENT_ACTION_SCROLL,
                                                AINPUT_SOURCE_TRACKBALL)
                                      .pointer(PointerBuilder(/*id=*/1, ToolType::UNKNOWN)
                                                       .axis(AMOTION_EVENT_AXIS_VSCROLL, 100)
                                                       .axis(AMOTION_EVENT_AXIS_HSCROLL, 200))
                                      .build()));
            break;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(InputDeviceMetricsSourceDeviceClassificationTest,
                         DeviceClassificationFixture,
                         ::testing::ValuesIn(ALL_USAGE_SOURCES.begin(), ALL_USAGE_SOURCES.end()),
                         [](const testing::TestParamInfo<InputDeviceUsageSource>& testParamInfo) {
                             return ftl::enum_string(testParamInfo.param);
                         });

TEST(InputDeviceMetricsSourceDeviceClassificationTest, MixedClassificationTouchscreenStylus) {
    std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TOUCHSCREEN,
                                          InputDeviceUsageSource::STYLUS_DIRECT};
    ASSERT_EQ(srcs,
              getUsageSourcesForMotionArgs(
                      MotionArgsBuilder(POINTER_1_DOWN, TOUCHSCREEN | STYLUS)
                              .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(100).y(200))
                              .pointer(PointerBuilder(/*id=*/2, ToolType::STYLUS).x(300).y(400))
                              .build()));
}

} // namespace android
