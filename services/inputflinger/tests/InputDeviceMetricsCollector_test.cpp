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

#include "../InputDeviceMetricsCollector.h"

#include <gtest/gtest.h>
#include <gui/constants.h>
#include <input/EventBuilders.h>
#include <linux/input.h>

#include <array>
#include <tuple>

#include "TestInputListener.h"

namespace android {

using std::chrono_literals::operator""ns;
using std::chrono::nanoseconds;

namespace {

constexpr auto USAGE_TIMEOUT = 8765309ns;
constexpr auto TIME = 999999ns;
constexpr auto ALL_USAGE_SOURCES = ftl::enum_range<InputDeviceUsageSource>();

constexpr int32_t DEVICE_ID = 3;
constexpr int32_t DEVICE_ID_2 = 4;
constexpr int32_t VID = 0xFEED;
constexpr int32_t PID = 0xDEAD;
constexpr int32_t VERSION = 0xBEEF;
const std::string DEVICE_NAME = "Half Dome";
const std::string LOCATION = "California";
const std::string UNIQUE_ID = "Yosemite";
constexpr uint32_t TOUCHSCREEN = AINPUT_SOURCE_TOUCHSCREEN;
constexpr uint32_t STYLUS = AINPUT_SOURCE_STYLUS;
constexpr uint32_t KEY_SOURCES =
        AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_DPAD | AINPUT_SOURCE_GAMEPAD;
constexpr int32_t POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

InputDeviceIdentifier getIdentifier(int32_t id = DEVICE_ID) {
    InputDeviceIdentifier identifier;
    identifier.name = DEVICE_NAME + "_" + std::to_string(id);
    identifier.location = LOCATION;
    identifier.uniqueId = UNIQUE_ID;
    identifier.vendor = VID;
    identifier.product = PID;
    identifier.version = VERSION;
    identifier.bus = BUS_USB;
    return identifier;
}

InputDeviceInfo generateTestDeviceInfo(int32_t id = DEVICE_ID,
                                       uint32_t sources = TOUCHSCREEN | STYLUS,
                                       bool isAlphabetic = false) {
    auto info = InputDeviceInfo();
    info.initialize(id, /*generation=*/1, /*controllerNumber=*/1, getIdentifier(id), "alias",
                    /*isExternal=*/false, /*hasMic=*/false, ADISPLAY_ID_NONE);
    info.addSource(sources);
    info.setKeyboardType(isAlphabetic ? AINPUT_KEYBOARD_TYPE_ALPHABETIC
                                      : AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC);
    return info;
}

const InputDeviceInfo ALPHABETIC_KEYBOARD_INFO =
        generateTestDeviceInfo(DEVICE_ID, KEY_SOURCES, /*isAlphabetic=*/true);
const InputDeviceInfo NON_ALPHABETIC_KEYBOARD_INFO =
        generateTestDeviceInfo(DEVICE_ID, KEY_SOURCES, /*isAlphabetic=*/false);

std::set<gui::Uid> uids(std::initializer_list<int32_t> vals) {
    std::set<gui::Uid> set;
    for (const auto val : vals) {
        set.emplace(val);
    }
    return set;
}

} // namespace

// --- InputDeviceMetricsCollectorDeviceClassificationTest ---

class DeviceClassificationFixture : public ::testing::Test,
                                    public ::testing::WithParamInterface<InputDeviceUsageSource> {};

TEST_P(DeviceClassificationFixture, ValidClassifications) {
    const InputDeviceUsageSource usageSource = GetParam();

    // Use a switch to ensure a test is added for all source classifications.
    switch (usageSource) {
        case InputDeviceUsageSource::UNKNOWN: {
            ASSERT_EQ(InputDeviceUsageSource::UNKNOWN,
                      getUsageSourceForKeyArgs(generateTestDeviceInfo(),
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
                      getUsageSourceForKeyArgs(NON_ALPHABETIC_KEYBOARD_INFO,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_STYLUS_BUTTON_TAIL)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::KEYBOARD: {
            ASSERT_EQ(InputDeviceUsageSource::KEYBOARD,
                      getUsageSourceForKeyArgs(ALPHABETIC_KEYBOARD_INFO,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::DPAD: {
            ASSERT_EQ(InputDeviceUsageSource::DPAD,
                      getUsageSourceForKeyArgs(NON_ALPHABETIC_KEYBOARD_INFO,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_DPAD_CENTER)
                                                       .build()));

            ASSERT_EQ(InputDeviceUsageSource::DPAD,
                      getUsageSourceForKeyArgs(ALPHABETIC_KEYBOARD_INFO,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_DPAD_CENTER)
                                                       .build()));
            break;
        }

        case InputDeviceUsageSource::GAMEPAD: {
            ASSERT_EQ(InputDeviceUsageSource::GAMEPAD,
                      getUsageSourceForKeyArgs(NON_ALPHABETIC_KEYBOARD_INFO,
                                               KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, KEY_SOURCES)
                                                       .keyCode(AKEYCODE_BUTTON_A)
                                                       .build()));

            ASSERT_EQ(InputDeviceUsageSource::GAMEPAD,
                      getUsageSourceForKeyArgs(ALPHABETIC_KEYBOARD_INFO,
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

INSTANTIATE_TEST_SUITE_P(InputDeviceMetricsCollectorDeviceClassificationTest,
                         DeviceClassificationFixture,
                         ::testing::ValuesIn(ALL_USAGE_SOURCES.begin(), ALL_USAGE_SOURCES.end()),
                         [](const testing::TestParamInfo<InputDeviceUsageSource>& testParamInfo) {
                             return ftl::enum_string(testParamInfo.param);
                         });

TEST(InputDeviceMetricsCollectorDeviceClassificationTest, MixedClassificationTouchscreenStylus) {
    std::set<InputDeviceUsageSource> srcs{InputDeviceUsageSource::TOUCHSCREEN,
                                          InputDeviceUsageSource::STYLUS_DIRECT};
    ASSERT_EQ(srcs,
              getUsageSourcesForMotionArgs(
                      MotionArgsBuilder(POINTER_1_DOWN, TOUCHSCREEN | STYLUS)
                              .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(100).y(200))
                              .pointer(PointerBuilder(/*id=*/2, ToolType::STYLUS).x(300).y(400))
                              .build()));
}

// --- InputDeviceMetricsCollectorTest ---

class InputDeviceMetricsCollectorTest : public testing::Test, public InputDeviceMetricsLogger {
protected:
    TestInputListener mTestListener;
    InputDeviceMetricsCollector mMetricsCollector{mTestListener, *this, USAGE_TIMEOUT};

    void assertUsageLogged(InputDeviceIdentifier identifier, nanoseconds duration,
                           std::optional<SourceUsageBreakdown> sourceBreakdown = {},
                           std::optional<UidUsageBreakdown> uidBreakdown = {}) {
        ASSERT_GE(mLoggedUsageSessions.size(), 1u);
        const auto& [loggedIdentifier, report] = *mLoggedUsageSessions.begin();
        ASSERT_EQ(identifier, loggedIdentifier);
        ASSERT_EQ(duration, report.usageDuration);
        if (sourceBreakdown) {
            ASSERT_EQ(sourceBreakdown, report.sourceBreakdown);
        }
        if (uidBreakdown) {
            ASSERT_EQ(uidBreakdown, report.uidBreakdown);
        }
        mLoggedUsageSessions.erase(mLoggedUsageSessions.begin());
    }

    void assertUsageNotLogged() { ASSERT_TRUE(mLoggedUsageSessions.empty()); }

    void setCurrentTime(nanoseconds time) { mCurrentTime = time; }

    nsecs_t currentTime() const { return mCurrentTime.count(); }

    NotifyMotionArgs generateMotionArgs(int32_t deviceId,
                                        uint32_t source = AINPUT_SOURCE_TOUCHSCREEN,
                                        std::vector<ToolType> toolTypes = {ToolType::FINGER}) {
        MotionArgsBuilder builder(AMOTION_EVENT_ACTION_MOVE, source);
        for (size_t i = 0; i < toolTypes.size(); i++) {
            builder.pointer(PointerBuilder(i, toolTypes[i]));
        }
        return builder.deviceId(deviceId)
                .eventTime(mCurrentTime.count())
                .downTime(mCurrentTime.count())
                .build();
    }

private:
    std::vector<std::tuple<InputDeviceIdentifier, DeviceUsageReport>> mLoggedUsageSessions;
    nanoseconds mCurrentTime{TIME};

    nanoseconds getCurrentTime() override { return mCurrentTime; }

    void logInputDeviceUsageReported(const InputDeviceIdentifier& identifier,
                                     const DeviceUsageReport& report) override {
        mLoggedUsageSessions.emplace_back(identifier, report);
    }
};

TEST_F(InputDeviceMetricsCollectorTest, DontLogUsageWhenDeviceNotRegistered) {
    // Device was used.
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mTestListener.assertNotifyMotionWasCalled();
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device was used again after the usage timeout expired, but we still don't log usage.
    setCurrentTime(TIME + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mTestListener.assertNotifyMotionWasCalled();
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, DontLogUsageForIgnoredDevices) {
    constexpr static std::array<int32_t, 2> ignoredDevices{
            {INVALID_INPUT_DEVICE_ID, VIRTUAL_KEYBOARD_ID}};

    for (int32_t ignoredDeviceId : ignoredDevices) {
        mMetricsCollector.notifyInputDevicesChanged(
                {/*id=*/0, {generateTestDeviceInfo(ignoredDeviceId)}});

        // Device was used.
        mMetricsCollector.notifyMotion(generateMotionArgs(ignoredDeviceId));
        mTestListener.assertNotifyMotionWasCalled();
        ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

        // Device was used again after the usage timeout expired, but we still don't log usage.
        setCurrentTime(TIME + USAGE_TIMEOUT);
        mMetricsCollector.notifyMotion(generateMotionArgs(ignoredDeviceId));
        mTestListener.assertNotifyMotionWasCalled();
        ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

        // Remove the ignored device, and ensure we still don't log usage.
        mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {}});
        ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
    }
}

TEST_F(InputDeviceMetricsCollectorTest, LogsSingleEventUsageSession) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});

    // Device was used.
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device was used again after the usage timeout.
    setCurrentTime(TIME + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    // The usage session has zero duration because it consisted of only one event.
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(), 0ns));
}

TEST_F(InputDeviceMetricsCollectorTest, LogsMultipleEventUsageSession) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});

    // Device was used.
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device was used again after some time.
    setCurrentTime(TIME + 21ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));

    setCurrentTime(TIME + 42ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));

    // Device was used again after the usage timeout.
    setCurrentTime(TIME + 42ns + 2 * USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(), 42ns));
}

TEST_F(InputDeviceMetricsCollectorTest, RemovingDeviceEndsUsageSession) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});

    // Device was used.
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device was used again after some time.
    setCurrentTime(TIME + 21ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));

    // The device was removed before the usage timeout expired.
    setCurrentTime(TIME + 42ns);
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {}});
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(), 21ns));
}

TEST_F(InputDeviceMetricsCollectorTest, TracksUsageFromDifferentDevicesIndependently) {
    mMetricsCollector.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(), generateTestDeviceInfo(DEVICE_ID_2)}});

    // Device 1 was used.
    setCurrentTime(TIME);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device 2 was used.
    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2));
    setCurrentTime(TIME + 400ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device 1 was used after its usage timeout expired. Its usage session is reported.
    setCurrentTime(TIME + 300ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(DEVICE_ID), 100ns));

    // Device 2 was used.
    setCurrentTime(TIME + 350ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device 1 was used.
    setCurrentTime(TIME + 500ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Device 2 is not used for a while, but Device 1 is used again.
    setCurrentTime(TIME + 400ns + (2 * USAGE_TIMEOUT));
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    // Since Device 2's usage session ended, its usage should be reported.
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(DEVICE_ID_2), 150ns + USAGE_TIMEOUT));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, BreakdownUsageBySource) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});
    InputDeviceMetricsLogger::SourceUsageBreakdown expectedSourceBreakdown;

    // Use touchscreen.
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN));
    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Use a stylus with the same input device.
    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, STYLUS, {ToolType::STYLUS}));
    setCurrentTime(TIME + 400ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, STYLUS, {ToolType::STYLUS}));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Touchscreen was used again after its usage timeout expired.
    // This should be tracked as a separate usage of the source in the breakdown.
    setCurrentTime(TIME + 300ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    expectedSourceBreakdown.emplace_back(InputDeviceUsageSource::TOUCHSCREEN, 100ns);
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Continue stylus and touchscreen usages.
    setCurrentTime(TIME + 350ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, STYLUS, {ToolType::STYLUS}));
    setCurrentTime(TIME + 450ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Touchscreen was used after the stylus's usage timeout expired.
    // The stylus usage should be tracked in the source breakdown.
    setCurrentTime(TIME + 400ns + USAGE_TIMEOUT + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN));
    expectedSourceBreakdown.emplace_back(InputDeviceUsageSource::STYLUS_DIRECT,
                                         150ns + USAGE_TIMEOUT);
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Remove all devices to force the usage session to be logged.
    setCurrentTime(TIME + 500ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyInputDevicesChanged({});
    expectedSourceBreakdown.emplace_back(InputDeviceUsageSource::TOUCHSCREEN,
                                         100ns + USAGE_TIMEOUT);
    // Verify that only one usage session was logged for the device, and that session was broken
    // down by source correctly.
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(),
                                              400ns + USAGE_TIMEOUT + USAGE_TIMEOUT,
                                              expectedSourceBreakdown));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, BreakdownUsageBySource_TrackSourceByDevice) {
    mMetricsCollector.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID), generateTestDeviceInfo(DEVICE_ID_2)}});
    InputDeviceMetricsLogger::SourceUsageBreakdown expectedSourceBreakdown1;
    InputDeviceMetricsLogger::SourceUsageBreakdown expectedSourceBreakdown2;

    // Use both devices, with different sources.
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN));
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2, STYLUS, {ToolType::STYLUS}));
    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN));
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2, STYLUS, {ToolType::STYLUS}));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Remove all devices to force the usage session to be logged.
    mMetricsCollector.notifyInputDevicesChanged({});
    expectedSourceBreakdown1.emplace_back(InputDeviceUsageSource::TOUCHSCREEN, 100ns);
    expectedSourceBreakdown2.emplace_back(InputDeviceUsageSource::STYLUS_DIRECT, 100ns);
    ASSERT_NO_FATAL_FAILURE(
            assertUsageLogged(getIdentifier(DEVICE_ID), 100ns, expectedSourceBreakdown1));
    ASSERT_NO_FATAL_FAILURE(
            assertUsageLogged(getIdentifier(DEVICE_ID_2), 100ns, expectedSourceBreakdown2));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, BreakdownUsageBySource_MultiSourceEvent) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo(DEVICE_ID)}});
    InputDeviceMetricsLogger::SourceUsageBreakdown expectedSourceBreakdown;

    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN | STYLUS, //
                                                      {ToolType::STYLUS}));
    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN | STYLUS, //
                                                      {ToolType::STYLUS, ToolType::FINGER}));
    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN | STYLUS, //
                                                      {ToolType::STYLUS, ToolType::FINGER}));
    setCurrentTime(TIME + 300ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN | STYLUS, //
                                                      {ToolType::FINGER}));
    setCurrentTime(TIME + 400ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID, TOUCHSCREEN | STYLUS, //
                                                      {ToolType::FINGER}));
    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());

    // Remove all devices to force the usage session to be logged.
    mMetricsCollector.notifyInputDevicesChanged({});
    expectedSourceBreakdown.emplace_back(InputDeviceUsageSource::STYLUS_DIRECT, 200ns);
    expectedSourceBreakdown.emplace_back(InputDeviceUsageSource::TOUCHSCREEN, 300ns);
    ASSERT_NO_FATAL_FAILURE(
            assertUsageLogged(getIdentifier(DEVICE_ID), 400ns, expectedSourceBreakdown));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, UidsNotTrackedWhenThereIsNoActiveSession) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});

    // Notify interaction with UIDs before the device is used.
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1}));

    // Use the device.
    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));

    // Notify interaction for the wrong device.
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID_2, currentTime(), uids({42}));

    // Notify interaction after usage session would have expired.
    // This interaction should not be tracked.
    setCurrentTime(TIME + 200ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({2, 3}));

    // Use the device again, by starting a new usage session.
    setCurrentTime(TIME + 300ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));

    // The first usage session is logged.
    static const UidUsageBreakdown emptyBreakdown;
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(), 100ns, /*sourceBreakdown=*/{},
                                              /*uidBreakdown=*/emptyBreakdown));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, BreakdownUsageByUid) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});
    UidUsageBreakdown expectedUidBreakdown;

    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1}));

    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 2}));
    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 2, 3}));

    expectedUidBreakdown.emplace_back(1, 200ns);
    expectedUidBreakdown.emplace_back(2, 100ns);
    expectedUidBreakdown.emplace_back(3, 0ns);

    // Remove the device to force the usage session to be logged.
    mMetricsCollector.notifyInputDevicesChanged({});
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(), 200ns, /*sourceBreakdown=*/{},
                                              expectedUidBreakdown));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, BreakdownUsageByUid_TracksMultipleSessionsForUid) {
    mMetricsCollector.notifyInputDevicesChanged({/*id=*/0, {generateTestDeviceInfo()}});
    UidUsageBreakdown expectedUidBreakdown;

    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 2}));
    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 2}));

    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1}));

    setCurrentTime(TIME + 300ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 3}));
    setCurrentTime(TIME + 400ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 3}));

    setCurrentTime(TIME + 200ns + USAGE_TIMEOUT);
    expectedUidBreakdown.emplace_back(2, 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({4}));

    setCurrentTime(TIME + 300ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 4}));

    setCurrentTime(TIME + 400ns + USAGE_TIMEOUT);
    expectedUidBreakdown.emplace_back(3, 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({2, 3}));

    setCurrentTime(TIME + 500ns + USAGE_TIMEOUT);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({3}));

    // Remove the device to force the usage session to be logged.
    mMetricsCollector.notifyInputDevicesChanged({});
    expectedUidBreakdown.emplace_back(1, 300ns + USAGE_TIMEOUT);
    expectedUidBreakdown.emplace_back(2, 0ns);
    expectedUidBreakdown.emplace_back(3, 100ns);
    expectedUidBreakdown.emplace_back(4, 100ns);
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(), 500ns + USAGE_TIMEOUT,
                                              /*sourceBreakdown=*/{}, expectedUidBreakdown));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

TEST_F(InputDeviceMetricsCollectorTest, BreakdownUsageByUid_TracksUidsByDevice) {
    mMetricsCollector.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID), generateTestDeviceInfo(DEVICE_ID_2)}});
    UidUsageBreakdown expectedUidBreakdown1;
    UidUsageBreakdown expectedUidBreakdown2;

    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 2}));

    setCurrentTime(TIME + 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID_2, currentTime(), uids({1, 3}));

    setCurrentTime(TIME + 200ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID, currentTime(), uids({1, 2}));
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID_2));
    mMetricsCollector.notifyDeviceInteraction(DEVICE_ID_2, currentTime(), uids({1, 3}));

    setCurrentTime(TIME + 200ns + USAGE_TIMEOUT);
    expectedUidBreakdown1.emplace_back(1, 200ns);
    expectedUidBreakdown1.emplace_back(2, 200ns);
    expectedUidBreakdown2.emplace_back(1, 100ns);
    expectedUidBreakdown2.emplace_back(3, 100ns);
    mMetricsCollector.notifyMotion(generateMotionArgs(DEVICE_ID));
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(DEVICE_ID), 200ns,
                                              /*sourceBreakdown=*/{}, expectedUidBreakdown1));
    ASSERT_NO_FATAL_FAILURE(assertUsageLogged(getIdentifier(DEVICE_ID_2), 100ns,
                                              /*sourceBreakdown=*/{}, expectedUidBreakdown2));

    ASSERT_NO_FATAL_FAILURE(assertUsageNotLogged());
}

} // namespace android
