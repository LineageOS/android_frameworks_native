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

#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <EventHub.h>
#include <InputReaderBase.h>
#include <NotifyArgs.h>
#include <PointerControllerInterface.h>
#include <StylusState.h>
#include <VibrationElement.h>
#include <android-base/logging.h>
#include <android-base/result.h>
#include <gmock/gmock.h>
#include <input/InputDevice.h>
#include <input/KeyCharacterMap.h>
#include <input/KeyLayoutMap.h>
#include <input/PropertyMap.h>
#include <input/TouchVideoFrame.h>
#include <input/VirtualKeyMap.h>
#include <utils/Errors.h>
#include <utils/Timers.h>

namespace android {

class MockInputReaderContext : public InputReaderContext {
public:
    MOCK_METHOD(void, updateGlobalMetaState, (), (override));
    MOCK_METHOD(int32_t, getGlobalMetaState, (), (override));

    MOCK_METHOD(void, disableVirtualKeysUntil, (nsecs_t time), (override));
    MOCK_METHOD(bool, shouldDropVirtualKey, (nsecs_t now, int32_t keyCode, int32_t scanCode),
                (override));

    MOCK_METHOD(void, fadePointer, (), (override));
    MOCK_METHOD(std::shared_ptr<PointerControllerInterface>, getPointerController,
                (int32_t deviceId), (override));

    MOCK_METHOD(void, requestTimeoutAtTime, (nsecs_t when), (override));
    int32_t bumpGeneration() override { return ++mGeneration; }

    MOCK_METHOD(void, getExternalStylusDevices, (std::vector<InputDeviceInfo> & outDevices),
                (override));
    MOCK_METHOD(std::list<NotifyArgs>, dispatchExternalStylusState, (const StylusState& outState),
                (override));

    MOCK_METHOD(InputReaderPolicyInterface*, getPolicy, (), (override));
    MOCK_METHOD(EventHubInterface*, getEventHub, (), (override));

    int32_t getNextId() override { return 1; };

    MOCK_METHOD(void, updateLedMetaState, (int32_t metaState), (override));
    MOCK_METHOD(int32_t, getLedMetaState, (), (override));

    MOCK_METHOD(void, setPreventingTouchpadTaps, (bool prevent), (override));
    MOCK_METHOD(bool, isPreventingTouchpadTaps, (), (override));

    MOCK_METHOD(void, setLastKeyDownTimestamp, (nsecs_t when));
    MOCK_METHOD(nsecs_t, getLastKeyDownTimestamp, ());

private:
    int32_t mGeneration = 0;
};

class MockEventHubInterface : public EventHubInterface {
public:
    MOCK_METHOD(ftl::Flags<InputDeviceClass>, getDeviceClasses, (int32_t deviceId), (const));
    MOCK_METHOD(InputDeviceIdentifier, getDeviceIdentifier, (int32_t deviceId), (const));
    MOCK_METHOD(int32_t, getDeviceControllerNumber, (int32_t deviceId), (const));
    MOCK_METHOD(std::optional<PropertyMap>, getConfiguration, (int32_t deviceId), (const));
    MOCK_METHOD(status_t, getAbsoluteAxisInfo,
                (int32_t deviceId, int axis, RawAbsoluteAxisInfo* outAxisInfo), (const));
    MOCK_METHOD(bool, hasRelativeAxis, (int32_t deviceId, int axis), (const));
    MOCK_METHOD(bool, hasInputProperty, (int32_t deviceId, int property), (const));
    MOCK_METHOD(bool, hasMscEvent, (int32_t deviceId, int mscEvent), (const));
    MOCK_METHOD(void, addKeyRemapping, (int32_t deviceId, int fromKeyCode, int toKeyCode), (const));
    MOCK_METHOD(status_t, mapKey,
                (int32_t deviceId, int scanCode, int usageCode, int32_t metaState,
                 int32_t* outKeycode, int32_t* outMetaState, uint32_t* outFlags),
                (const));
    MOCK_METHOD(status_t, mapAxis, (int32_t deviceId, int scanCode, AxisInfo* outAxisInfo),
                (const));
    MOCK_METHOD(void, setExcludedDevices, (const std::vector<std::string>& devices));
    MOCK_METHOD(std::vector<RawEvent>, getEvents, (int timeoutMillis));
    MOCK_METHOD(std::vector<TouchVideoFrame>, getVideoFrames, (int32_t deviceId));
    MOCK_METHOD((base::Result<std::pair<InputDeviceSensorType, int32_t>>), mapSensor,
                (int32_t deviceId, int32_t absCode), (const, override));
    MOCK_METHOD(std::vector<int32_t>, getRawBatteryIds, (int32_t deviceId), (const, override));
    MOCK_METHOD(std::optional<RawBatteryInfo>, getRawBatteryInfo,
                (int32_t deviceId, int32_t BatteryId), (const, override));
    MOCK_METHOD(std::vector<int32_t>, getRawLightIds, (int32_t deviceId), (const, override));
    MOCK_METHOD(std::optional<RawLightInfo>, getRawLightInfo, (int32_t deviceId, int32_t lightId),
                (const, override));
    MOCK_METHOD(std::optional<int32_t>, getLightBrightness, (int32_t deviceId, int32_t lightId),
                (const, override));
    MOCK_METHOD(void, setLightBrightness, (int32_t deviceId, int32_t lightId, int32_t brightness),
                (override));
    MOCK_METHOD((std::optional<std::unordered_map<LightColor, int32_t>>), getLightIntensities,
                (int32_t deviceId, int32_t lightId), (const, override));
    MOCK_METHOD(void, setLightIntensities,
                (int32_t deviceId, int32_t lightId,
                 (std::unordered_map<LightColor, int32_t>)intensities),
                (override));

    MOCK_METHOD(std::optional<RawLayoutInfo>, getRawLayoutInfo, (int32_t deviceId),
                (const, override));
    MOCK_METHOD(int32_t, getScanCodeState, (int32_t deviceId, int32_t scanCode), (const, override));
    MOCK_METHOD(int32_t, getKeyCodeState, (int32_t deviceId, int32_t keyCode), (const, override));
    MOCK_METHOD(int32_t, getSwitchState, (int32_t deviceId, int32_t sw), (const, override));

    MOCK_METHOD(status_t, getAbsoluteAxisValue, (int32_t deviceId, int32_t axis, int32_t* outValue),
                (const, override));
    MOCK_METHOD(base::Result<std::vector<int32_t>>, getMtSlotValues,
                (int32_t deviceId, int32_t axis, size_t slotCount), (const, override));

    MOCK_METHOD(int32_t, getKeyCodeForKeyLocation, (int32_t deviceId, int32_t locationKeyCode),
                (const, override));
    MOCK_METHOD(bool, markSupportedKeyCodes,
                (int32_t deviceId, const std::vector<int32_t>& keyCodes, uint8_t* outFlags),
                (const, override));

    MOCK_METHOD(bool, hasScanCode, (int32_t deviceId, int32_t scanCode), (const, override));

    MOCK_METHOD(bool, hasKeyCode, (int32_t deviceId, int32_t keyCode), (const, override));

    MOCK_METHOD(bool, hasLed, (int32_t deviceId, int32_t led), (const, override));

    MOCK_METHOD(void, setLedState, (int32_t deviceId, int32_t led, bool on), (override));

    MOCK_METHOD(void, getVirtualKeyDefinitions,
                (int32_t deviceId, std::vector<VirtualKeyDefinition>& outVirtualKeys),
                (const, override));

    MOCK_METHOD(const std::shared_ptr<KeyCharacterMap>, getKeyCharacterMap, (int32_t deviceId),
                (const, override));

    MOCK_METHOD(bool, setKeyboardLayoutOverlay,
                (int32_t deviceId, std::shared_ptr<KeyCharacterMap> map), (override));

    MOCK_METHOD(void, vibrate, (int32_t deviceId, const VibrationElement& effect), (override));
    MOCK_METHOD(void, cancelVibrate, (int32_t deviceId), (override));

    MOCK_METHOD(std::vector<int32_t>, getVibratorIds, (int32_t deviceId), (const, override));
    MOCK_METHOD(std::optional<int32_t>, getBatteryCapacity, (int32_t deviceId, int32_t batteryId),
                (const, override));

    MOCK_METHOD(std::optional<int32_t>, getBatteryStatus, (int32_t deviceId, int32_t batteryId),
                (const, override));
    MOCK_METHOD(void, requestReopenDevices, (), (override));
    MOCK_METHOD(void, wake, (), (override));

    MOCK_METHOD(void, dump, (std::string & dump), (const, override));
    MOCK_METHOD(void, monitor, (), (const, override));
    MOCK_METHOD(bool, isDeviceEnabled, (int32_t deviceId), (const, override));
    MOCK_METHOD(status_t, enableDevice, (int32_t deviceId), (override));
    MOCK_METHOD(status_t, disableDevice, (int32_t deviceId), (override));
    MOCK_METHOD(void, sysfsNodeChanged, (const std::string& sysfsNodePath), (override));
};

} // namespace android
