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

#include "FakeEventHub.h"

#include <android-base/thread_annotations.h>
#include <gtest/gtest.h>
#include <linux/input-event-codes.h>

#include "TestConstants.h"

namespace android {

const std::string FakeEventHub::BATTERY_DEVPATH = "/sys/devices/mydevice/power_supply/mybattery";

FakeEventHub::~FakeEventHub() {
    for (size_t i = 0; i < mDevices.size(); i++) {
        delete mDevices.valueAt(i);
    }
}

void FakeEventHub::addDevice(int32_t deviceId, const std::string& name,
                             ftl::Flags<InputDeviceClass> classes, int bus) {
    Device* device = new Device(classes);
    device->identifier.name = name;
    device->identifier.bus = bus;
    mDevices.add(deviceId, device);

    enqueueEvent(ARBITRARY_TIME, READ_TIME, deviceId, EventHubInterface::DEVICE_ADDED, 0, 0);
}

void FakeEventHub::removeDevice(int32_t deviceId) {
    delete mDevices.valueFor(deviceId);
    mDevices.removeItem(deviceId);

    enqueueEvent(ARBITRARY_TIME, READ_TIME, deviceId, EventHubInterface::DEVICE_REMOVED, 0, 0);
}

bool FakeEventHub::isDeviceEnabled(int32_t deviceId) const {
    Device* device = getDevice(deviceId);
    if (device == nullptr) {
        ALOGE("Incorrect device id=%" PRId32 " provided to %s", deviceId, __func__);
        return false;
    }
    return device->enabled;
}

status_t FakeEventHub::enableDevice(int32_t deviceId) {
    status_t result;
    Device* device = getDevice(deviceId);
    if (device == nullptr) {
        ALOGE("Incorrect device id=%" PRId32 " provided to %s", deviceId, __func__);
        return BAD_VALUE;
    }
    if (device->enabled) {
        ALOGW("Duplicate call to %s, device %" PRId32 " already enabled", __func__, deviceId);
        return OK;
    }
    result = device->enable();
    return result;
}

status_t FakeEventHub::disableDevice(int32_t deviceId) {
    Device* device = getDevice(deviceId);
    if (device == nullptr) {
        ALOGE("Incorrect device id=%" PRId32 " provided to %s", deviceId, __func__);
        return BAD_VALUE;
    }
    if (!device->enabled) {
        ALOGW("Duplicate call to %s, device %" PRId32 " already disabled", __func__, deviceId);
        return OK;
    }
    return device->disable();
}

void FakeEventHub::finishDeviceScan() {
    enqueueEvent(ARBITRARY_TIME, READ_TIME, 0, EventHubInterface::FINISHED_DEVICE_SCAN, 0, 0);
}

void FakeEventHub::addConfigurationProperty(int32_t deviceId, const char* key, const char* value) {
    getDevice(deviceId)->configuration.addProperty(key, value);
}

void FakeEventHub::addConfigurationMap(int32_t deviceId, const PropertyMap* configuration) {
    getDevice(deviceId)->configuration.addAll(configuration);
}

void FakeEventHub::addAbsoluteAxis(int32_t deviceId, int axis, int32_t minValue, int32_t maxValue,
                                   int flat, int fuzz, int resolution) {
    Device* device = getDevice(deviceId);

    RawAbsoluteAxisInfo info;
    info.valid = true;
    info.minValue = minValue;
    info.maxValue = maxValue;
    info.flat = flat;
    info.fuzz = fuzz;
    info.resolution = resolution;
    device->absoluteAxes.add(axis, info);
}

void FakeEventHub::addRelativeAxis(int32_t deviceId, int32_t axis) {
    getDevice(deviceId)->relativeAxes.add(axis, true);
}

void FakeEventHub::setKeyCodeState(int32_t deviceId, int32_t keyCode, int32_t state) {
    getDevice(deviceId)->keyCodeStates.replaceValueFor(keyCode, state);
}

void FakeEventHub::setRawLayoutInfo(int32_t deviceId, RawLayoutInfo info) {
    getDevice(deviceId)->layoutInfo = info;
}

void FakeEventHub::setScanCodeState(int32_t deviceId, int32_t scanCode, int32_t state) {
    getDevice(deviceId)->scanCodeStates.replaceValueFor(scanCode, state);
}

void FakeEventHub::setSwitchState(int32_t deviceId, int32_t switchCode, int32_t state) {
    getDevice(deviceId)->switchStates.replaceValueFor(switchCode, state);
}

void FakeEventHub::setAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t value) {
    getDevice(deviceId)->absoluteAxisValue.replaceValueFor(axis, value);
}

void FakeEventHub::addKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t keyCode,
                          uint32_t flags) {
    Device* device = getDevice(deviceId);
    KeyInfo info;
    info.keyCode = keyCode;
    info.flags = flags;
    if (scanCode) {
        device->keysByScanCode.add(scanCode, info);
    }
    if (usageCode) {
        device->keysByUsageCode.add(usageCode, info);
    }
}

void FakeEventHub::addKeyCodeMapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode) {
    getDevice(deviceId)->keyCodeMapping.insert_or_assign(fromKeyCode, toKeyCode);
}

void FakeEventHub::addKeyRemapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode) const {
    Device* device = getDevice(deviceId);
    device->keyRemapping.insert_or_assign(fromKeyCode, toKeyCode);
}

void FakeEventHub::addLed(int32_t deviceId, int32_t led, bool initialState) {
    getDevice(deviceId)->leds.add(led, initialState);
}

void FakeEventHub::addSensorAxis(int32_t deviceId, int32_t absCode,
                                 InputDeviceSensorType sensorType, int32_t sensorDataIndex) {
    SensorInfo info;
    info.sensorType = sensorType;
    info.sensorDataIndex = sensorDataIndex;
    getDevice(deviceId)->sensorsByAbsCode.emplace(absCode, info);
}

void FakeEventHub::setMscEvent(int32_t deviceId, int32_t mscEvent) {
    typename BitArray<MSC_MAX>::Buffer buffer;
    buffer[mscEvent / 32] = 1 << mscEvent % 32;
    getDevice(deviceId)->mscBitmask.loadFromBuffer(buffer);
}

void FakeEventHub::addRawLightInfo(int32_t rawId, RawLightInfo&& info) {
    mRawLightInfos.emplace(rawId, std::move(info));
}

void FakeEventHub::fakeLightBrightness(int32_t rawId, int32_t brightness) {
    mLightBrightness.emplace(rawId, brightness);
}

void FakeEventHub::fakeLightIntensities(int32_t rawId,
                                        const std::unordered_map<LightColor, int32_t> intensities) {
    mLightIntensities.emplace(rawId, std::move(intensities));
}

bool FakeEventHub::getLedState(int32_t deviceId, int32_t led) {
    return getDevice(deviceId)->leds.valueFor(led);
}

std::vector<std::string>& FakeEventHub::getExcludedDevices() {
    return mExcludedDevices;
}

void FakeEventHub::addVirtualKeyDefinition(int32_t deviceId,
                                           const VirtualKeyDefinition& definition) {
    getDevice(deviceId)->virtualKeys.push_back(definition);
}

void FakeEventHub::enqueueEvent(nsecs_t when, nsecs_t readTime, int32_t deviceId, int32_t type,
                                int32_t code, int32_t value) {
    std::scoped_lock<std::mutex> lock(mLock);
    RawEvent event;
    event.when = when;
    event.readTime = readTime;
    event.deviceId = deviceId;
    event.type = type;
    event.code = code;
    event.value = value;
    mEvents.push_back(event);

    if (type == EV_ABS) {
        setAbsoluteAxisValue(deviceId, code, value);
    }
}

void FakeEventHub::setVideoFrames(
        std::unordered_map<int32_t /*deviceId*/, std::vector<TouchVideoFrame>> videoFrames) {
    mVideoFrames = std::move(videoFrames);
}

void FakeEventHub::assertQueueIsEmpty() {
    std::unique_lock<std::mutex> lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    const bool queueIsEmpty =
            mEventsCondition.wait_for(lock, WAIT_TIMEOUT,
                                      [this]() REQUIRES(mLock) { return mEvents.size() == 0; });
    if (!queueIsEmpty) {
        FAIL() << "Timed out waiting for EventHub queue to be emptied.";
    }
}

FakeEventHub::Device* FakeEventHub::getDevice(int32_t deviceId) const {
    ssize_t index = mDevices.indexOfKey(deviceId);
    return index >= 0 ? mDevices.valueAt(index) : nullptr;
}

ftl::Flags<InputDeviceClass> FakeEventHub::getDeviceClasses(int32_t deviceId) const {
    Device* device = getDevice(deviceId);
    return device ? device->classes : ftl::Flags<InputDeviceClass>(0);
}

InputDeviceIdentifier FakeEventHub::getDeviceIdentifier(int32_t deviceId) const {
    Device* device = getDevice(deviceId);
    return device ? device->identifier : InputDeviceIdentifier();
}

int32_t FakeEventHub::getDeviceControllerNumber(int32_t) const {
    return 0;
}

std::optional<PropertyMap> FakeEventHub::getConfiguration(int32_t deviceId) const {
    Device* device = getDevice(deviceId);
    if (device == nullptr) {
        return {};
    }
    return device->configuration;
}

status_t FakeEventHub::getAbsoluteAxisInfo(int32_t deviceId, int axis,
                                           RawAbsoluteAxisInfo* outAxisInfo) const {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->absoluteAxes.indexOfKey(axis);
        if (index >= 0) {
            *outAxisInfo = device->absoluteAxes.valueAt(index);
            return OK;
        }
    }
    outAxisInfo->clear();
    return -1;
}

bool FakeEventHub::hasRelativeAxis(int32_t deviceId, int axis) const {
    Device* device = getDevice(deviceId);
    if (device) {
        return device->relativeAxes.indexOfKey(axis) >= 0;
    }
    return false;
}

bool FakeEventHub::hasInputProperty(int32_t, int) const {
    return false;
}

bool FakeEventHub::hasMscEvent(int32_t deviceId, int mscEvent) const {
    Device* device = getDevice(deviceId);
    if (device) {
        return mscEvent >= 0 && mscEvent <= MSC_MAX ? device->mscBitmask.test(mscEvent) : false;
    }
    return false;
}

status_t FakeEventHub::mapKey(int32_t deviceId, int32_t scanCode, int32_t usageCode,
                              int32_t metaState, int32_t* outKeycode, int32_t* outMetaState,
                              uint32_t* outFlags) const {
    Device* device = getDevice(deviceId);
    if (device) {
        const KeyInfo* key = getKey(device, scanCode, usageCode);
        if (key) {
            if (outKeycode) {
                auto it = device->keyRemapping.find(key->keyCode);
                *outKeycode = it != device->keyRemapping.end() ? it->second : key->keyCode;
            }
            if (outFlags) {
                *outFlags = key->flags;
            }
            if (outMetaState) {
                *outMetaState = metaState;
            }
            return OK;
        }
    }
    return NAME_NOT_FOUND;
}

const FakeEventHub::KeyInfo* FakeEventHub::getKey(Device* device, int32_t scanCode,
                                                  int32_t usageCode) const {
    if (usageCode) {
        ssize_t index = device->keysByUsageCode.indexOfKey(usageCode);
        if (index >= 0) {
            return &device->keysByUsageCode.valueAt(index);
        }
    }
    if (scanCode) {
        ssize_t index = device->keysByScanCode.indexOfKey(scanCode);
        if (index >= 0) {
            return &device->keysByScanCode.valueAt(index);
        }
    }
    return nullptr;
}

status_t FakeEventHub::mapAxis(int32_t, int32_t, AxisInfo*) const {
    return NAME_NOT_FOUND;
}

base::Result<std::pair<InputDeviceSensorType, int32_t>> FakeEventHub::mapSensor(
        int32_t deviceId, int32_t absCode) const {
    Device* device = getDevice(deviceId);
    if (!device) {
        return Errorf("Sensor device not found.");
    }
    auto it = device->sensorsByAbsCode.find(absCode);
    if (it == device->sensorsByAbsCode.end()) {
        return Errorf("Sensor map not found.");
    }
    const SensorInfo& info = it->second;
    return std::make_pair(info.sensorType, info.sensorDataIndex);
}

void FakeEventHub::setExcludedDevices(const std::vector<std::string>& devices) {
    mExcludedDevices = devices;
}

std::vector<RawEvent> FakeEventHub::getEvents(int) {
    std::scoped_lock lock(mLock);

    std::vector<RawEvent> buffer;
    std::swap(buffer, mEvents);

    mEventsCondition.notify_all();
    return buffer;
}

std::vector<TouchVideoFrame> FakeEventHub::getVideoFrames(int32_t deviceId) {
    auto it = mVideoFrames.find(deviceId);
    if (it != mVideoFrames.end()) {
        std::vector<TouchVideoFrame> frames = std::move(it->second);
        mVideoFrames.erase(deviceId);
        return frames;
    }
    return {};
}

int32_t FakeEventHub::getScanCodeState(int32_t deviceId, int32_t scanCode) const {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->scanCodeStates.indexOfKey(scanCode);
        if (index >= 0) {
            return device->scanCodeStates.valueAt(index);
        }
    }
    return AKEY_STATE_UNKNOWN;
}

std::optional<RawLayoutInfo> FakeEventHub::getRawLayoutInfo(int32_t deviceId) const {
    Device* device = getDevice(deviceId);
    return device ? device->layoutInfo : std::nullopt;
}

int32_t FakeEventHub::getKeyCodeState(int32_t deviceId, int32_t keyCode) const {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->keyCodeStates.indexOfKey(keyCode);
        if (index >= 0) {
            return device->keyCodeStates.valueAt(index);
        }
    }
    return AKEY_STATE_UNKNOWN;
}

int32_t FakeEventHub::getSwitchState(int32_t deviceId, int32_t sw) const {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->switchStates.indexOfKey(sw);
        if (index >= 0) {
            return device->switchStates.valueAt(index);
        }
    }
    return AKEY_STATE_UNKNOWN;
}

status_t FakeEventHub::getAbsoluteAxisValue(int32_t deviceId, int32_t axis,
                                            int32_t* outValue) const {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->absoluteAxisValue.indexOfKey(axis);
        if (index >= 0) {
            *outValue = device->absoluteAxisValue.valueAt(index);
            return OK;
        }
    }
    *outValue = 0;
    return -1;
}

void FakeEventHub::setMtSlotValues(int32_t deviceId, int32_t axis,
                                   const std::vector<int32_t>& values) {
    Device* device = getDevice(deviceId);
    if (!device) {
        FAIL() << "Missing device";
    }
    device->mtSlotValues[axis] = values;
}

base::Result<std::vector<int32_t>> FakeEventHub::getMtSlotValues(int32_t deviceId, int32_t axis,
                                                                 size_t slotCount) const {
    Device* device = getDevice(deviceId);
    if (!device) {
        ADD_FAILURE() << "Missing device";
        return base::ResultError("Missing device", UNKNOWN_ERROR);
    }
    const auto& mtSlotValuesIterator = device->mtSlotValues.find(axis);
    if (mtSlotValuesIterator == device->mtSlotValues.end()) {
        return base::ResultError("axis not supported", NAME_NOT_FOUND);
    }
    const auto& mtSlotValues = mtSlotValuesIterator->second;
    if (mtSlotValues.size() != slotCount) {
        ADD_FAILURE() << "MtSlot values specified for " << mtSlotValues.size()
                      << " slots but expected for " << slotCount << " Slots";
        return base::ResultError("Slot count mismatch", NAME_NOT_FOUND);
    }
    std::vector<int32_t> outValues(slotCount + 1);
    outValues[0] = axis;
    std::copy(mtSlotValues.begin(), mtSlotValues.end(), outValues.begin() + 1);
    return std::move(outValues);
}

int32_t FakeEventHub::getKeyCodeForKeyLocation(int32_t deviceId, int32_t locationKeyCode) const {
    Device* device = getDevice(deviceId);
    if (!device) {
        return AKEYCODE_UNKNOWN;
    }
    auto it = device->keyCodeMapping.find(locationKeyCode);
    return it != device->keyCodeMapping.end() ? it->second : locationKeyCode;
}

// Return true if the device has non-empty key layout.
bool FakeEventHub::markSupportedKeyCodes(int32_t deviceId, const std::vector<int32_t>& keyCodes,
                                         uint8_t* outFlags) const {
    Device* device = getDevice(deviceId);
    if (!device) return false;

    bool result = device->keysByScanCode.size() > 0 || device->keysByUsageCode.size() > 0;
    for (size_t i = 0; i < keyCodes.size(); i++) {
        for (size_t j = 0; j < device->keysByScanCode.size(); j++) {
            if (keyCodes[i] == device->keysByScanCode.valueAt(j).keyCode) {
                outFlags[i] = 1;
            }
        }
        for (size_t j = 0; j < device->keysByUsageCode.size(); j++) {
            if (keyCodes[i] == device->keysByUsageCode.valueAt(j).keyCode) {
                outFlags[i] = 1;
            }
        }
    }
    return result;
}

bool FakeEventHub::hasScanCode(int32_t deviceId, int32_t scanCode) const {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->keysByScanCode.indexOfKey(scanCode);
        return index >= 0;
    }
    return false;
}

bool FakeEventHub::hasKeyCode(int32_t deviceId, int32_t keyCode) const {
    Device* device = getDevice(deviceId);
    if (!device) {
        return false;
    }
    for (size_t i = 0; i < device->keysByScanCode.size(); i++) {
        if (keyCode == device->keysByScanCode.valueAt(i).keyCode) {
            return true;
        }
    }
    for (size_t j = 0; j < device->keysByUsageCode.size(); j++) {
        if (keyCode == device->keysByUsageCode.valueAt(j).keyCode) {
            return true;
        }
    }
    return false;
}

bool FakeEventHub::hasLed(int32_t deviceId, int32_t led) const {
    Device* device = getDevice(deviceId);
    return device && device->leds.indexOfKey(led) >= 0;
}

void FakeEventHub::setLedState(int32_t deviceId, int32_t led, bool on) {
    Device* device = getDevice(deviceId);
    if (device) {
        ssize_t index = device->leds.indexOfKey(led);
        if (index >= 0) {
            device->leds.replaceValueAt(led, on);
        } else {
            ADD_FAILURE() << "Attempted to set the state of an LED that the EventHub declared "
                             "was not present.  led="
                          << led;
        }
    }
}

void FakeEventHub::getVirtualKeyDefinitions(
        int32_t deviceId, std::vector<VirtualKeyDefinition>& outVirtualKeys) const {
    outVirtualKeys.clear();

    Device* device = getDevice(deviceId);
    if (device) {
        outVirtualKeys = device->virtualKeys;
    }
}

const std::shared_ptr<KeyCharacterMap> FakeEventHub::getKeyCharacterMap(int32_t) const {
    return nullptr;
}

bool FakeEventHub::setKeyboardLayoutOverlay(int32_t, std::shared_ptr<KeyCharacterMap>) {
    return false;
}

std::vector<int32_t> FakeEventHub::getVibratorIds(int32_t deviceId) const {
    return mVibrators;
}

std::optional<int32_t> FakeEventHub::getBatteryCapacity(int32_t, int32_t) const {
    return BATTERY_CAPACITY;
}

std::optional<int32_t> FakeEventHub::getBatteryStatus(int32_t, int32_t) const {
    return BATTERY_STATUS;
}

std::vector<int32_t> FakeEventHub::getRawBatteryIds(int32_t deviceId) const {
    return {DEFAULT_BATTERY};
}

std::optional<RawBatteryInfo> FakeEventHub::getRawBatteryInfo(int32_t deviceId,
                                                              int32_t batteryId) const {
    if (batteryId != DEFAULT_BATTERY) return {};
    static const auto BATTERY_INFO = RawBatteryInfo{.id = DEFAULT_BATTERY,
                                                    .name = "default battery",
                                                    .flags = InputBatteryClass::CAPACITY,
                                                    .path = BATTERY_DEVPATH};
    return BATTERY_INFO;
}

std::vector<int32_t> FakeEventHub::getRawLightIds(int32_t deviceId) const {
    std::vector<int32_t> ids;
    for (const auto& [rawId, info] : mRawLightInfos) {
        ids.push_back(rawId);
    }
    return ids;
}

std::optional<RawLightInfo> FakeEventHub::getRawLightInfo(int32_t deviceId, int32_t lightId) const {
    auto it = mRawLightInfos.find(lightId);
    if (it == mRawLightInfos.end()) {
        return std::nullopt;
    }
    return it->second;
}

void FakeEventHub::setLightBrightness(int32_t deviceId, int32_t lightId, int32_t brightness) {
    mLightBrightness.emplace(lightId, brightness);
}

void FakeEventHub::setLightIntensities(int32_t deviceId, int32_t lightId,
                                       std::unordered_map<LightColor, int32_t> intensities) {
    mLightIntensities.emplace(lightId, intensities);
};

std::optional<int32_t> FakeEventHub::getLightBrightness(int32_t deviceId, int32_t lightId) const {
    auto lightIt = mLightBrightness.find(lightId);
    if (lightIt == mLightBrightness.end()) {
        return std::nullopt;
    }
    return lightIt->second;
}

std::optional<std::unordered_map<LightColor, int32_t>> FakeEventHub::getLightIntensities(
        int32_t deviceId, int32_t lightId) const {
    auto lightIt = mLightIntensities.find(lightId);
    if (lightIt == mLightIntensities.end()) {
        return std::nullopt;
    }
    return lightIt->second;
};

void FakeEventHub::setSysfsRootPath(int32_t deviceId, std::string sysfsRootPath) const {
    Device* device = getDevice(deviceId);
    if (device == nullptr) {
        return;
    }
    device->sysfsRootPath = sysfsRootPath;
}

void FakeEventHub::sysfsNodeChanged(const std::string& sysfsNodePath) {
    int32_t foundDeviceId = -1;
    Device* foundDevice = nullptr;
    for (size_t i = 0; i < mDevices.size(); i++) {
        Device* d = mDevices.valueAt(i);
        if (sysfsNodePath.find(d->sysfsRootPath) != std::string::npos) {
            foundDeviceId = mDevices.keyAt(i);
            foundDevice = d;
        }
    }
    if (foundDevice == nullptr) {
        return;
    }
    // If device sysfs changed -> reopen the device
    if (!mRawLightInfos.empty() && !foundDevice->classes.test(InputDeviceClass::LIGHT)) {
        InputDeviceIdentifier identifier = foundDevice->identifier;
        ftl::Flags<InputDeviceClass> classes = foundDevice->classes;
        removeDevice(foundDeviceId);
        addDevice(foundDeviceId, identifier.name, classes | InputDeviceClass::LIGHT,
                  identifier.bus);
    }
}

} // namespace android
