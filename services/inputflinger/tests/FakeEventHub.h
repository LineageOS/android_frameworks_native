/*
 * Copyright 2022 The Android Open Source Project
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

#include <condition_variable>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include <EventHub.h>
#include <InputDevice.h>
#include <ftl/flags.h>
#include <input/PropertyMap.h>
#include <input/VirtualKeyMap.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>

namespace android {

class FakeEventHub : public EventHubInterface {
    struct KeyInfo {
        int32_t keyCode;
        uint32_t flags;
    };

    struct SensorInfo {
        InputDeviceSensorType sensorType;
        int32_t sensorDataIndex;
    };

    struct Device {
        InputDeviceIdentifier identifier;
        ftl::Flags<InputDeviceClass> classes;
        PropertyMap configuration;
        KeyedVector<int, RawAbsoluteAxisInfo> absoluteAxes;
        KeyedVector<int, bool> relativeAxes;
        KeyedVector<int32_t, int32_t> keyCodeStates;
        KeyedVector<int32_t, int32_t> scanCodeStates;
        KeyedVector<int32_t, int32_t> switchStates;
        KeyedVector<int32_t, int32_t> absoluteAxisValue;
        KeyedVector<int32_t, KeyInfo> keysByScanCode;
        KeyedVector<int32_t, KeyInfo> keysByUsageCode;
        std::unordered_map<int32_t, int32_t> keyRemapping;
        KeyedVector<int32_t, bool> leds;
        // fake mapping which would normally come from keyCharacterMap
        std::unordered_map<int32_t, int32_t> keyCodeMapping;
        std::unordered_map<int32_t, SensorInfo> sensorsByAbsCode;
        BitArray<MSC_MAX> mscBitmask;
        std::vector<VirtualKeyDefinition> virtualKeys;
        bool enabled;
        std::optional<RawLayoutInfo> layoutInfo;
        std::string sysfsRootPath;
        std::unordered_map<int32_t, std::vector<int32_t>> mtSlotValues;

        status_t enable() {
            enabled = true;
            return OK;
        }

        status_t disable() {
            enabled = false;
            return OK;
        }

        explicit Device(ftl::Flags<InputDeviceClass> classes) : classes(classes), enabled(true) {}
    };

    std::mutex mLock;
    std::condition_variable mEventsCondition;

    KeyedVector<int32_t, Device*> mDevices;
    std::vector<std::string> mExcludedDevices;
    std::vector<RawEvent> mEvents GUARDED_BY(mLock);
    std::unordered_map<int32_t /*deviceId*/, std::vector<TouchVideoFrame>> mVideoFrames;
    std::vector<int32_t> mVibrators = {0, 1};
    std::unordered_map<int32_t, RawLightInfo> mRawLightInfos;
    // Simulates a device light brightness, from light id to light brightness.
    std::unordered_map<int32_t /* lightId */, int32_t /* brightness*/> mLightBrightness;
    // Simulates a device light intensities, from light id to light intensities map.
    std::unordered_map<int32_t /* lightId */, std::unordered_map<LightColor, int32_t>>
            mLightIntensities;

public:
    static constexpr int32_t DEFAULT_BATTERY = 1;
    static constexpr int32_t BATTERY_STATUS = 4;
    static constexpr int32_t BATTERY_CAPACITY = 66;
    static const std::string BATTERY_DEVPATH;

    virtual ~FakeEventHub();
    FakeEventHub() {}

    void addDevice(int32_t deviceId, const std::string& name, ftl::Flags<InputDeviceClass> classes,
                   int bus = 0);
    void removeDevice(int32_t deviceId);

    bool isDeviceEnabled(int32_t deviceId) const override;
    status_t enableDevice(int32_t deviceId) override;
    status_t disableDevice(int32_t deviceId) override;

    void finishDeviceScan();

    void addConfigurationProperty(int32_t deviceId, const char* key, const char* value);
    void addConfigurationMap(int32_t deviceId, const PropertyMap* configuration);

    void addAbsoluteAxis(int32_t deviceId, int axis, int32_t minValue, int32_t maxValue, int flat,
                         int fuzz, int resolution = 0);
    void addRelativeAxis(int32_t deviceId, int32_t axis);
    void setAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t value);

    void setRawLayoutInfo(int32_t deviceId, RawLayoutInfo info);

    void setKeyCodeState(int32_t deviceId, int32_t keyCode, int32_t state);
    void setScanCodeState(int32_t deviceId, int32_t scanCode, int32_t state);
    void setSwitchState(int32_t deviceId, int32_t switchCode, int32_t state);

    void addKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t keyCode,
                uint32_t flags);
    void addKeyCodeMapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode);
    void addKeyRemapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode) const;
    void addVirtualKeyDefinition(int32_t deviceId, const VirtualKeyDefinition& definition);

    void addSensorAxis(int32_t deviceId, int32_t absCode, InputDeviceSensorType sensorType,
                       int32_t sensorDataIndex);

    void setMscEvent(int32_t deviceId, int32_t mscEvent);

    void addLed(int32_t deviceId, int32_t led, bool initialState);
    void addRawLightInfo(int32_t rawId, RawLightInfo&& info);
    void fakeLightBrightness(int32_t rawId, int32_t brightness);
    void fakeLightIntensities(int32_t rawId,
                              const std::unordered_map<LightColor, int32_t> intensities);
    bool getLedState(int32_t deviceId, int32_t led);

    std::vector<std::string>& getExcludedDevices();

    void setVideoFrames(
            std::unordered_map<int32_t /*deviceId*/, std::vector<TouchVideoFrame>> videoFrames);

    void enqueueEvent(nsecs_t when, nsecs_t readTime, int32_t deviceId, int32_t type, int32_t code,
                      int32_t value);
    void assertQueueIsEmpty();
    void setSysfsRootPath(int32_t deviceId, std::string sysfsRootPath) const;
    // Populate fake slot values to be returned by the getter, size of the values should be equal to
    // the slot count
    void setMtSlotValues(int32_t deviceId, int32_t axis, const std::vector<int32_t>& values);
    base::Result<std::vector<int32_t>> getMtSlotValues(int32_t deviceId, int32_t axis,
                                                       size_t slotCount) const override;

private:
    Device* getDevice(int32_t deviceId) const;

    ftl::Flags<InputDeviceClass> getDeviceClasses(int32_t deviceId) const override;
    InputDeviceIdentifier getDeviceIdentifier(int32_t deviceId) const override;
    int32_t getDeviceControllerNumber(int32_t) const override;
    std::optional<PropertyMap> getConfiguration(int32_t deviceId) const override;
    status_t getAbsoluteAxisInfo(int32_t deviceId, int axis,
                                 RawAbsoluteAxisInfo* outAxisInfo) const override;
    bool hasRelativeAxis(int32_t deviceId, int axis) const override;
    bool hasInputProperty(int32_t, int) const override;
    bool hasMscEvent(int32_t deviceId, int mscEvent) const override final;
    status_t mapKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t metaState,
                    int32_t* outKeycode, int32_t* outMetaState, uint32_t* outFlags) const override;
    const KeyInfo* getKey(Device* device, int32_t scanCode, int32_t usageCode) const;

    status_t mapAxis(int32_t, int32_t, AxisInfo*) const override;
    base::Result<std::pair<InputDeviceSensorType, int32_t>> mapSensor(
            int32_t deviceId, int32_t absCode) const override;
    void setExcludedDevices(const std::vector<std::string>& devices) override;
    std::vector<RawEvent> getEvents(int) override;
    std::vector<TouchVideoFrame> getVideoFrames(int32_t deviceId) override;
    int32_t getScanCodeState(int32_t deviceId, int32_t scanCode) const override;
    std::optional<RawLayoutInfo> getRawLayoutInfo(int32_t deviceId) const override;
    int32_t getKeyCodeState(int32_t deviceId, int32_t keyCode) const override;
    int32_t getSwitchState(int32_t deviceId, int32_t sw) const override;
    status_t getAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t* outValue) const override;
    int32_t getKeyCodeForKeyLocation(int32_t deviceId, int32_t locationKeyCode) const override;

    // Return true if the device has non-empty key layout.
    bool markSupportedKeyCodes(int32_t deviceId, const std::vector<int32_t>& keyCodes,
                               uint8_t* outFlags) const override;
    bool hasScanCode(int32_t deviceId, int32_t scanCode) const override;
    bool hasKeyCode(int32_t deviceId, int32_t keyCode) const override;
    bool hasLed(int32_t deviceId, int32_t led) const override;
    void setLedState(int32_t deviceId, int32_t led, bool on) override;
    void getVirtualKeyDefinitions(int32_t deviceId,
                                  std::vector<VirtualKeyDefinition>& outVirtualKeys) const override;
    const std::shared_ptr<KeyCharacterMap> getKeyCharacterMap(int32_t) const override;
    bool setKeyboardLayoutOverlay(int32_t, std::shared_ptr<KeyCharacterMap>) override;

    void vibrate(int32_t, const VibrationElement&) override {}
    void cancelVibrate(int32_t) override {}
    std::vector<int32_t> getVibratorIds(int32_t deviceId) const override;

    std::optional<int32_t> getBatteryCapacity(int32_t, int32_t) const override;
    std::optional<int32_t> getBatteryStatus(int32_t, int32_t) const override;
    std::vector<int32_t> getRawBatteryIds(int32_t deviceId) const override;
    std::optional<RawBatteryInfo> getRawBatteryInfo(int32_t deviceId,
                                                    int32_t batteryId) const override;

    std::vector<int32_t> getRawLightIds(int32_t deviceId) const override;
    std::optional<RawLightInfo> getRawLightInfo(int32_t deviceId, int32_t lightId) const override;
    void setLightBrightness(int32_t deviceId, int32_t lightId, int32_t brightness) override;
    void setLightIntensities(int32_t deviceId, int32_t lightId,
                             std::unordered_map<LightColor, int32_t> intensities) override;
    std::optional<int32_t> getLightBrightness(int32_t deviceId, int32_t lightId) const override;
    std::optional<std::unordered_map<LightColor, int32_t>> getLightIntensities(
            int32_t deviceId, int32_t lightId) const override;
    void sysfsNodeChanged(const std::string& sysfsNodePath) override;
    void dump(std::string&) const override {}
    void monitor() const override {}
    void requestReopenDevices() override {}
    void wake() override {}
};

} // namespace android
