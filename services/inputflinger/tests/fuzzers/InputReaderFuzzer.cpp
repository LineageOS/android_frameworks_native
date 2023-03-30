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

#include <InputReader.h>
#include <MapperHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <input/InputDevice.h>
#include <chrono>
#include <thread>

namespace android {

constexpr InputDeviceSensorType kInputDeviceSensorType[] = {
        InputDeviceSensorType::ACCELEROMETER,
        InputDeviceSensorType::MAGNETIC_FIELD,
        InputDeviceSensorType::ORIENTATION,
        InputDeviceSensorType::GYROSCOPE,
        InputDeviceSensorType::LIGHT,
        InputDeviceSensorType::PRESSURE,
        InputDeviceSensorType::TEMPERATURE,
        InputDeviceSensorType::PROXIMITY,
        InputDeviceSensorType::GRAVITY,
        InputDeviceSensorType::LINEAR_ACCELERATION,
        InputDeviceSensorType::ROTATION_VECTOR,
        InputDeviceSensorType::RELATIVE_HUMIDITY,
        InputDeviceSensorType::AMBIENT_TEMPERATURE,
        InputDeviceSensorType::MAGNETIC_FIELD_UNCALIBRATED,
        InputDeviceSensorType::GAME_ROTATION_VECTOR,
        InputDeviceSensorType::GYROSCOPE_UNCALIBRATED,
        InputDeviceSensorType::SIGNIFICANT_MOTION,
};

class FuzzInputReader : public InputReaderInterface {
public:
    FuzzInputReader(std::shared_ptr<EventHubInterface> fuzzEventHub,
                    const sp<InputReaderPolicyInterface>& fuzzPolicy,
                    InputListenerInterface& fuzzListener) {
        reader = std::make_unique<InputReader>(fuzzEventHub, fuzzPolicy, fuzzListener);
    }

    void dump(std::string& dump) { reader->dump(dump); }

    void monitor() { reader->monitor(); }

    bool isInputDeviceEnabled(int32_t deviceId) { return reader->isInputDeviceEnabled(deviceId); }

    status_t start() { return reader->start(); }

    status_t stop() { return reader->stop(); }

    std::vector<InputDeviceInfo> getInputDevices() const { return reader->getInputDevices(); }

    int32_t getScanCodeState(int32_t deviceId, uint32_t sourceMask, int32_t scanCode) {
        return reader->getScanCodeState(deviceId, sourceMask, scanCode);
    }

    int32_t getKeyCodeState(int32_t deviceId, uint32_t sourceMask, int32_t keyCode) {
        return reader->getKeyCodeState(deviceId, sourceMask, keyCode);
    }

    int32_t getSwitchState(int32_t deviceId, uint32_t sourceMask, int32_t sw) {
        return reader->getSwitchState(deviceId, sourceMask, sw);
    }

    void toggleCapsLockState(int32_t deviceId) { reader->toggleCapsLockState(deviceId); }

    bool hasKeys(int32_t deviceId, uint32_t sourceMask, const std::vector<int32_t>& keyCodes,
                 uint8_t* outFlags) {
        return reader->hasKeys(deviceId, sourceMask, keyCodes, outFlags);
    }

    void requestRefreshConfiguration(uint32_t changes) {
        reader->requestRefreshConfiguration(changes);
    }

    void vibrate(int32_t deviceId, const VibrationSequence& sequence, ssize_t repeat,
                 int32_t token) {
        reader->vibrate(deviceId, sequence, repeat, token);
    }

    void cancelVibrate(int32_t deviceId, int32_t token) { reader->cancelVibrate(deviceId, token); }

    bool isVibrating(int32_t deviceId) { return reader->isVibrating(deviceId); }

    std::vector<int32_t> getVibratorIds(int32_t deviceId) {
        return reader->getVibratorIds(deviceId);
    }

    std::optional<int32_t> getBatteryCapacity(int32_t deviceId) {
        return reader->getBatteryCapacity(deviceId);
    }

    std::optional<int32_t> getBatteryStatus(int32_t deviceId) {
        return reader->getBatteryStatus(deviceId);
    }

    std::optional<std::string> getBatteryDevicePath(int32_t deviceId) {
        return reader->getBatteryDevicePath(deviceId);
    }

    std::vector<InputDeviceLightInfo> getLights(int32_t deviceId) {
        return reader->getLights(deviceId);
    }

    std::vector<InputDeviceSensorInfo> getSensors(int32_t deviceId) {
        return reader->getSensors(deviceId);
    }

    bool canDispatchToDisplay(int32_t deviceId, int32_t displayId) {
        return reader->canDispatchToDisplay(deviceId, displayId);
    }

    bool enableSensor(int32_t deviceId, InputDeviceSensorType sensorType,
                      std::chrono::microseconds samplingPeriod,
                      std::chrono::microseconds maxBatchReportLatency) {
        return reader->enableSensor(deviceId, sensorType, samplingPeriod, maxBatchReportLatency);
    }

    void disableSensor(int32_t deviceId, InputDeviceSensorType sensorType) {
        return reader->disableSensor(deviceId, sensorType);
    }

    void flushSensor(int32_t deviceId, InputDeviceSensorType sensorType) {
        return reader->flushSensor(deviceId, sensorType);
    }

    bool setLightColor(int32_t deviceId, int32_t lightId, int32_t color) {
        return reader->setLightColor(deviceId, lightId, color);
    }

    bool setLightPlayerId(int32_t deviceId, int32_t lightId, int32_t playerId) {
        return reader->setLightPlayerId(deviceId, lightId, playerId);
    }

    std::optional<int32_t> getLightColor(int32_t deviceId, int32_t lightId) {
        return reader->getLightColor(deviceId, lightId);
    }

    std::optional<int32_t> getLightPlayerId(int32_t deviceId, int32_t lightId) {
        return reader->getLightPlayerId(deviceId, lightId);
    }

    void addKeyRemapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode) const {
        reader->addKeyRemapping(deviceId, fromKeyCode, toKeyCode);
    }

    int32_t getKeyCodeForKeyLocation(int32_t deviceId, int32_t locationKeyCode) const {
        return reader->getKeyCodeForKeyLocation(deviceId, locationKeyCode);
    }

    std::optional<std::string> getBluetoothAddress(int32_t deviceId) const {
        return reader->getBluetoothAddress(deviceId);
    }

    void sysfsNodeChanged(const std::string& sysfsNodePath) {
        reader->sysfsNodeChanged(sysfsNodePath);
    }

private:
    std::unique_ptr<InputReaderInterface> reader;
};

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp =
            std::make_shared<ThreadSafeFuzzedDataProvider>(data, size);

    FuzzInputListener fuzzListener;
    sp<FuzzInputReaderPolicy> fuzzPolicy = sp<FuzzInputReaderPolicy>::make(fdp);
    std::shared_ptr<FuzzEventHub> fuzzEventHub = std::make_shared<FuzzEventHub>(fdp);
    std::unique_ptr<FuzzInputReader> reader =
            std::make_unique<FuzzInputReader>(fuzzEventHub, fuzzPolicy, fuzzListener);
    size_t patternCount = fdp->ConsumeIntegralInRange<size_t>(1, 260);
    VibrationSequence pattern(patternCount);
    for (size_t i = 0; i < patternCount; ++i) {
        VibrationElement element(i);
        element.addChannel(/*vibratorId=*/fdp->ConsumeIntegral<int32_t>(),
                           /*amplitude=*/fdp->ConsumeIntegral<uint8_t>());
        pattern.addElement(element);
    }
    reader->vibrate(fdp->ConsumeIntegral<int32_t>(), pattern,
                    /*repeat=*/fdp->ConsumeIntegral<ssize_t>(),
                    /*token=*/fdp->ConsumeIntegral<int32_t>());
    reader->start();

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    std::string dump;
                    reader->dump(dump);
                },
                [&]() -> void { reader->monitor(); },
                [&]() -> void { reader->getInputDevices(); },
                [&]() -> void { reader->isInputDeviceEnabled(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void {
                    reader->getScanCodeState(fdp->ConsumeIntegral<int32_t>(),
                                             fdp->ConsumeIntegral<uint32_t>(),
                                             fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->getKeyCodeState(fdp->ConsumeIntegral<int32_t>(),
                                            fdp->ConsumeIntegral<uint32_t>(),
                                            fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->getSwitchState(fdp->ConsumeIntegral<int32_t>(),
                                           fdp->ConsumeIntegral<uint32_t>(),
                                           fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void { reader->toggleCapsLockState(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void {
                    size_t count = fdp->ConsumeIntegralInRange<size_t>(1, 1024);
                    std::vector<uint8_t> outFlags(count);
                    std::vector<int32_t> keyCodes;
                    for (size_t i = 0; i < count; ++i) {
                        keyCodes.push_back(fdp->ConsumeIntegral<int32_t>());
                    }
                    reader->hasKeys(fdp->ConsumeIntegral<int32_t>(),
                                    fdp->ConsumeIntegral<uint32_t>(), keyCodes, outFlags.data());
                },
                [&]() -> void {
                    reader->requestRefreshConfiguration(fdp->ConsumeIntegral<uint32_t>());
                },
                [&]() -> void {
                    reader->cancelVibrate(fdp->ConsumeIntegral<int32_t>(),
                                          fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->canDispatchToDisplay(fdp->ConsumeIntegral<int32_t>(),
                                                 fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->getKeyCodeForKeyLocation(fdp->ConsumeIntegral<int32_t>(),
                                                     fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void { reader->getBatteryCapacity(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void { reader->getBatteryStatus(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void { reader->getBatteryDevicePath(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void { reader->getLights(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void { reader->getSensors(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void {
                    reader->getLightPlayerId(fdp->ConsumeIntegral<int32_t>(),
                                             fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->getLightColor(fdp->ConsumeIntegral<int32_t>(),
                                          fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->setLightPlayerId(fdp->ConsumeIntegral<int32_t>(),
                                             fdp->ConsumeIntegral<int32_t>(),
                                             fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->setLightColor(fdp->ConsumeIntegral<int32_t>(),
                                          fdp->ConsumeIntegral<int32_t>(),
                                          fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->flushSensor(fdp->ConsumeIntegral<int32_t>(),
                                        fdp->PickValueInArray<InputDeviceSensorType>(
                                                kInputDeviceSensorType));
                },
                [&]() -> void {
                    reader->disableSensor(fdp->ConsumeIntegral<int32_t>(),
                                          fdp->PickValueInArray<InputDeviceSensorType>(
                                                  kInputDeviceSensorType));
                },
                [&]() -> void {
                    reader->enableSensor(fdp->ConsumeIntegral<int32_t>(),
                                         fdp->PickValueInArray<InputDeviceSensorType>(
                                                 kInputDeviceSensorType),
                                         std::chrono::microseconds(fdp->ConsumeIntegral<size_t>()),
                                         std::chrono::microseconds(fdp->ConsumeIntegral<size_t>()));
                },
                [&]() -> void { reader->getBluetoothAddress(fdp->ConsumeIntegral<int32_t>()); },
        })();
    }

    reader->stop();
    return 0;
}

} // namespace android
