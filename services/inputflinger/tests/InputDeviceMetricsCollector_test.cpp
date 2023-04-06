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

constexpr int32_t DEVICE_ID = 3;
constexpr int32_t DEVICE_ID_2 = 4;
constexpr int32_t VID = 0xFEED;
constexpr int32_t PID = 0xDEAD;
constexpr int32_t VERSION = 0xBEEF;
const std::string DEVICE_NAME = "Half Dome";
const std::string LOCATION = "California";
const std::string UNIQUE_ID = "Yosemite";

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

InputDeviceInfo generateTestDeviceInfo(int32_t id = DEVICE_ID) {
    auto info = InputDeviceInfo();
    info.initialize(id, /*generation=*/1, /*controllerNumber=*/1, getIdentifier(id), "alias",
                    /*isExternal=*/false, /*hasMic=*/false, ADISPLAY_ID_NONE);
    info.addSource(AINPUT_SOURCE_TOUCHSCREEN);
    return info;
}

} // namespace

// --- InputDeviceMetricsCollectorTest ---

class InputDeviceMetricsCollectorTest : public testing::Test, InputDeviceMetricsLogger {
protected:
    TestInputListener mTestListener;
    InputDeviceMetricsCollector mMetricsCollector{mTestListener, *this, USAGE_TIMEOUT};

    void assertUsageLogged(InputDeviceIdentifier identifier, nanoseconds duration) {
        ASSERT_GE(mLoggedUsageSessions.size(), 1u);
        const auto& session = *mLoggedUsageSessions.begin();
        ASSERT_EQ(identifier, std::get<InputDeviceIdentifier>(session));
        ASSERT_EQ(duration, std::get<nanoseconds>(session));
        mLoggedUsageSessions.erase(mLoggedUsageSessions.begin());
    }

    void assertUsageNotLogged() { ASSERT_TRUE(mLoggedUsageSessions.empty()); }

    void setCurrentTime(nanoseconds time) { mCurrentTime = time; }

    NotifyMotionArgs generateMotionArgs(int32_t deviceId) {
        PointerProperties pointerProperties{};
        pointerProperties.id = 0;
        pointerProperties.toolType = ToolType::FINGER;

        PointerCoords pointerCoords{};
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_X, 100);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, 200);

        return {/*id=*/0,
                mCurrentTime.count(),
                /*readTime=*/0,
                deviceId,
                AINPUT_SOURCE_TOUCHSCREEN,
                /*displayId=*/0,
                POLICY_FLAG_PASS_TO_USER,
                AMOTION_EVENT_ACTION_MOVE,
                /*actionButton=*/0,
                /*flags=*/0,
                AMETA_NONE,
                /*buttonState=*/0,
                MotionClassification::NONE,
                AMOTION_EVENT_EDGE_FLAG_NONE,
                /*pointerCount=*/1,
                &pointerProperties,
                &pointerCoords,
                /*xPrecision=*/0,
                /*yPrecision=*/0,
                AMOTION_EVENT_INVALID_CURSOR_POSITION,
                AMOTION_EVENT_INVALID_CURSOR_POSITION,
                mCurrentTime.count(),
                /*videoFrames=*/{}};
    }

private:
    std::vector<std::tuple<InputDeviceIdentifier, nanoseconds>> mLoggedUsageSessions;
    nanoseconds mCurrentTime{TIME};

    nanoseconds getCurrentTime() override { return mCurrentTime; }

    void logInputDeviceUsageReported(const InputDeviceIdentifier& identifier,
                                     nanoseconds duration) override {
        mLoggedUsageSessions.emplace_back(identifier, duration);
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

} // namespace android
