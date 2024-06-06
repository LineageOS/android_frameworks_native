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

#include "Macros.h"

#include "InputDevice.h"

#include <algorithm>

#include <android/sysprop/InputProperties.sysprop.h>
#include <ftl/flags.h>

#include "CursorInputMapper.h"
#include "ExternalStylusInputMapper.h"
#include "InputReaderContext.h"
#include "JoystickInputMapper.h"
#include "KeyboardInputMapper.h"
#include "MultiTouchInputMapper.h"
#include "PeripheralController.h"
#include "RotaryEncoderInputMapper.h"
#include "SensorInputMapper.h"
#include "SingleTouchInputMapper.h"
#include "SwitchInputMapper.h"
#include "TouchpadInputMapper.h"
#include "VibratorInputMapper.h"

namespace android {

InputDevice::InputDevice(InputReaderContext* context, int32_t id, int32_t generation,
                         const InputDeviceIdentifier& identifier)
      : mContext(context),
        mId(id),
        mGeneration(generation),
        mControllerNumber(0),
        mIdentifier(identifier),
        mClasses(0),
        mSources(0),
        mIsWaking(false),
        mIsExternal(false),
        mHasMic(false),
        mDropUntilNextSync(false) {}

InputDevice::~InputDevice() {}

bool InputDevice::isEnabled() {
    if (!hasEventHubDevices()) {
        return false;
    }
    // An input device composed of sub devices can be individually enabled or disabled.
    // If any of the sub device is enabled then the input device is considered as enabled.
    bool enabled = false;
    for_each_subdevice([&enabled](auto& context) { enabled |= context.isDeviceEnabled(); });
    return enabled;
}

std::list<NotifyArgs> InputDevice::updateEnableState(nsecs_t when,
                                                     const InputReaderConfiguration& readerConfig,
                                                     bool forceEnable) {
    bool enable = forceEnable;
    if (!forceEnable) {
        // If the device was explicitly disabled by the user, it would be present in the
        // "disabledDevices" list. This device should be disabled.
        enable = readerConfig.disabledDevices.find(mId) == readerConfig.disabledDevices.end();

        // If a device is associated with a specific display but there is no
        // associated DisplayViewport, don't enable the device.
        if (enable && (mAssociatedDisplayPort || mAssociatedDisplayUniqueId) &&
            !mAssociatedViewport) {
            const std::string desc = mAssociatedDisplayPort
                    ? "port " + std::to_string(*mAssociatedDisplayPort)
                    : "uniqueId " + *mAssociatedDisplayUniqueId;
            ALOGW("Cannot enable input device %s because it is associated "
                  "with %s, but the corresponding viewport is not found",
                  getName().c_str(), desc.c_str());
            enable = false;
        }
    }

    std::list<NotifyArgs> out;
    if (isEnabled() == enable) {
        return out;
    }

    // When resetting some devices, the driver needs to be queried to ensure that a proper reset is
    // performed. The querying must happen when the device is enabled, so we reset after enabling
    // but before disabling the device. See MultiTouchMotionAccumulator::reset for more information.
    if (enable) {
        for_each_subdevice([](auto& context) { context.enableDevice(); });
        out += reset(when);
    } else {
        out += reset(when);
        for_each_subdevice([](auto& context) { context.disableDevice(); });
    }
    // Must change generation to flag this device as changed
    bumpGeneration();
    return out;
}

void InputDevice::dump(std::string& dump, const std::string& eventHubDevStr) {
    InputDeviceInfo deviceInfo = getDeviceInfo();

    dump += StringPrintf(INDENT "Device %d: %s\n", deviceInfo.getId(),
                         deviceInfo.getDisplayName().c_str());
    dump += StringPrintf(INDENT "%s", eventHubDevStr.c_str());
    dump += StringPrintf(INDENT2 "Generation: %d\n", mGeneration);
    dump += StringPrintf(INDENT2 "IsExternal: %s\n", toString(mIsExternal));
    dump += StringPrintf(INDENT2 "IsWaking: %s\n", toString(mIsWaking));
    dump += StringPrintf(INDENT2 "AssociatedDisplayPort: ");
    if (mAssociatedDisplayPort) {
        dump += StringPrintf("%" PRIu8 "\n", *mAssociatedDisplayPort);
    } else {
        dump += "<none>\n";
    }
    dump += StringPrintf(INDENT2 "AssociatedDisplayUniqueId: ");
    if (mAssociatedDisplayUniqueId) {
        dump += StringPrintf("%s\n", mAssociatedDisplayUniqueId->c_str());
    } else {
        dump += "<none>\n";
    }
    dump += StringPrintf(INDENT2 "HasMic:     %s\n", toString(mHasMic));
    dump += StringPrintf(INDENT2 "Sources: %s\n",
                         inputEventSourceToString(deviceInfo.getSources()).c_str());
    dump += StringPrintf(INDENT2 "KeyboardType: %d\n", deviceInfo.getKeyboardType());
    dump += StringPrintf(INDENT2 "ControllerNum: %d\n", deviceInfo.getControllerNumber());

    const std::vector<InputDeviceInfo::MotionRange>& ranges = deviceInfo.getMotionRanges();
    if (!ranges.empty()) {
        dump += INDENT2 "Motion Ranges:\n";
        for (size_t i = 0; i < ranges.size(); i++) {
            const InputDeviceInfo::MotionRange& range = ranges[i];
            const char* label = InputEventLookup::getAxisLabel(range.axis);
            char name[32];
            if (label) {
                strncpy(name, label, sizeof(name));
                name[sizeof(name) - 1] = '\0';
            } else {
                snprintf(name, sizeof(name), "%d", range.axis);
            }
            dump += StringPrintf(INDENT3
                                 "%s: source=%s, "
                                 "min=%0.3f, max=%0.3f, flat=%0.3f, fuzz=%0.3f, resolution=%0.3f\n",
                                 name, inputEventSourceToString(range.source).c_str(), range.min,
                                 range.max, range.flat, range.fuzz, range.resolution);
        }
    }

    for_each_mapper([&dump](InputMapper& mapper) { mapper.dump(dump); });
    if (mController) {
        mController->dump(dump);
    }
}

void InputDevice::addEmptyEventHubDevice(int32_t eventHubId) {
    if (mDevices.find(eventHubId) != mDevices.end()) {
        return;
    }
    std::unique_ptr<InputDeviceContext> contextPtr(new InputDeviceContext(*this, eventHubId));
    std::vector<std::unique_ptr<InputMapper>> mappers;

    mDevices.insert({eventHubId, std::make_pair(std::move(contextPtr), std::move(mappers))});
}

[[nodiscard]] std::list<NotifyArgs> InputDevice::addEventHubDevice(
        nsecs_t when, int32_t eventHubId, const InputReaderConfiguration& readerConfig) {
    if (mDevices.find(eventHubId) != mDevices.end()) {
        return {};
    }

    // Add an empty device configure and keep it enabled to allow mapper population with correct
    // configuration/context,
    // Note: we need to ensure device is kept enabled till mappers are configured
    // TODO: b/281852638 refactor tests to remove this flag and reliance on the empty device
    addEmptyEventHubDevice(eventHubId);
    std::list<NotifyArgs> out = configureInternal(when, readerConfig, {}, /*forceEnable=*/true);

    DevicePair& devicePair = mDevices[eventHubId];
    devicePair.second = createMappers(*devicePair.first, readerConfig);

    // Must change generation to flag this device as changed
    bumpGeneration();
    return out;
}

void InputDevice::removeEventHubDevice(int32_t eventHubId) {
    if (mController != nullptr && mController->getEventHubId() == eventHubId) {
        // Delete mController, since the corresponding eventhub device is going away
        mController = nullptr;
    }
    mDevices.erase(eventHubId);
}

std::list<NotifyArgs> InputDevice::configure(nsecs_t when,
                                             const InputReaderConfiguration& readerConfig,
                                             ConfigurationChanges changes) {
    return configureInternal(when, readerConfig, changes);
}
std::list<NotifyArgs> InputDevice::configureInternal(nsecs_t when,
                                                     const InputReaderConfiguration& readerConfig,
                                                     ConfigurationChanges changes,
                                                     bool forceEnable) {
    std::list<NotifyArgs> out;
    mSources = 0;
    mClasses = ftl::Flags<InputDeviceClass>(0);
    mControllerNumber = 0;

    for_each_subdevice([this](InputDeviceContext& context) {
        mClasses |= context.getDeviceClasses();
        int32_t controllerNumber = context.getDeviceControllerNumber();
        if (controllerNumber > 0) {
            if (mControllerNumber && mControllerNumber != controllerNumber) {
                ALOGW("InputDevice::configure(): composite device contains multiple unique "
                      "controller numbers");
            }
            mControllerNumber = controllerNumber;
        }
    });

    mIsExternal = mClasses.test(InputDeviceClass::EXTERNAL);
    mHasMic = mClasses.test(InputDeviceClass::MIC);

    using Change = InputReaderConfiguration::Change;

    if (!changes.any() || !isIgnored()) {
        // Full configuration should happen the first time configure is called
        // and when the device type is changed. Changing a device type can
        // affect various other parameters so should result in a
        // reconfiguration.
        if (!changes.any() || changes.test(Change::DEVICE_TYPE)) {
            mConfiguration.clear();
            for_each_subdevice([this](InputDeviceContext& context) {
                std::optional<PropertyMap> configuration =
                        getEventHub()->getConfiguration(context.getEventHubId());
                if (configuration) {
                    mConfiguration.addAll(&(*configuration));
                }
            });

            mAssociatedDeviceType =
                    getValueByKey(readerConfig.deviceTypeAssociations, mIdentifier.location);
            mIsWaking = mConfiguration.getBool("device.wake").value_or(false);
            mShouldSmoothScroll = mConfiguration.getBool("device.viewBehavior_smoothScroll");
        }

        if (!changes.any() || changes.test(Change::DEVICE_ALIAS)) {
            if (!(mClasses.test(InputDeviceClass::VIRTUAL))) {
                std::string alias = mContext->getPolicy()->getDeviceAlias(mIdentifier);
                if (mAlias != alias) {
                    mAlias = alias;
                    bumpGeneration();
                }
            }
        }

        if (!changes.any() || changes.test(Change::DISPLAY_INFO)) {
            const auto oldAssociatedDisplayId = getAssociatedDisplayId();

            // In most situations, no port or name will be specified.
            mAssociatedDisplayPort = std::nullopt;
            mAssociatedDisplayUniqueId = std::nullopt;
            mAssociatedViewport = std::nullopt;
            // Find the display port that corresponds to the current input port.
            const std::string& inputPort = mIdentifier.location;
            if (!inputPort.empty()) {
                const std::unordered_map<std::string, uint8_t>& ports =
                        readerConfig.portAssociations;
                const auto& displayPort = ports.find(inputPort);
                if (displayPort != ports.end()) {
                    mAssociatedDisplayPort = std::make_optional(displayPort->second);
                } else {
                    const std::unordered_map<std::string, std::string>& displayUniqueIds =
                            readerConfig.uniqueIdAssociations;
                    const auto& displayUniqueId = displayUniqueIds.find(inputPort);
                    if (displayUniqueId != displayUniqueIds.end()) {
                        mAssociatedDisplayUniqueId = displayUniqueId->second;
                    }
                }
            }

            // If it is associated with a specific display, then find the corresponding viewport
            // which will be used to enable/disable the device.
            if (mAssociatedDisplayPort) {
                mAssociatedViewport =
                        readerConfig.getDisplayViewportByPort(*mAssociatedDisplayPort);
                if (!mAssociatedViewport) {
                    ALOGW("Input device %s should be associated with display on port %" PRIu8 ", "
                          "but the corresponding viewport is not found.",
                          getName().c_str(), *mAssociatedDisplayPort);
                }
            } else if (mAssociatedDisplayUniqueId != std::nullopt) {
                mAssociatedViewport =
                        readerConfig.getDisplayViewportByUniqueId(*mAssociatedDisplayUniqueId);
                if (!mAssociatedViewport) {
                    ALOGW("Input device %s should be associated with display %s but the "
                          "corresponding viewport cannot be found",
                          getName().c_str(), mAssociatedDisplayUniqueId->c_str());
                }
            }

            if (getAssociatedDisplayId() != oldAssociatedDisplayId) {
                bumpGeneration();
            }
        }

        for_each_mapper([this, when, &readerConfig, changes, &out](InputMapper& mapper) {
            out += mapper.reconfigure(when, readerConfig, changes);
            mSources |= mapper.getSources();
        });

        if (!changes.any() || changes.test(Change::ENABLED_STATE) ||
            changes.test(Change::DISPLAY_INFO)) {
            // Whether a device is enabled can depend on the display association,
            // so update the enabled state when there is a change in display info.
            out += updateEnableState(when, readerConfig, forceEnable);
        }
    }
    return out;
}

std::list<NotifyArgs> InputDevice::reset(nsecs_t when) {
    std::list<NotifyArgs> out;
    for_each_mapper([&](InputMapper& mapper) { out += mapper.reset(when); });

    mContext->updateGlobalMetaState();

    out.push_back(notifyReset(when));
    return out;
}

std::list<NotifyArgs> InputDevice::process(const RawEvent* rawEvents, size_t count) {
    // Process all of the events in order for each mapper.
    // We cannot simply ask each mapper to process them in bulk because mappers may
    // have side-effects that must be interleaved.  For example, joystick movement events and
    // gamepad button presses are handled by different mappers but they should be dispatched
    // in the order received.
    std::list<NotifyArgs> out;
    for (const RawEvent* rawEvent = rawEvents; count != 0; rawEvent++) {
        if (debugRawEvents()) {
            const auto [type, code, value] =
                    InputEventLookup::getLinuxEvdevLabel(rawEvent->type, rawEvent->code,
                                                         rawEvent->value);
            ALOGD("Input event: eventHubDevice=%d type=%s code=%s value=%s when=%" PRId64,
                  rawEvent->deviceId, type.c_str(), code.c_str(), value.c_str(), rawEvent->when);
        }

        if (mDropUntilNextSync) {
            if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
                out += reset(rawEvent->when);
                mDropUntilNextSync = false;
                ALOGD_IF(debugRawEvents(), "Recovered from input event buffer overrun.");
            } else {
                ALOGD_IF(debugRawEvents(),
                         "Dropped input event while waiting for next input sync.");
            }
        } else if (rawEvent->type == EV_SYN && rawEvent->code == SYN_DROPPED) {
            ALOGI("Detected input event buffer overrun for device %s.", getName().c_str());
            mDropUntilNextSync = true;
        } else {
            for_each_mapper_in_subdevice(rawEvent->deviceId, [&](InputMapper& mapper) {
                out += mapper.process(rawEvent);
            });
        }
        --count;
    }
    postProcess(out);
    return out;
}

void InputDevice::postProcess(std::list<NotifyArgs>& args) const {
    if (mIsWaking) {
        // Update policy flags to request wake for the `NotifyArgs` that come from waking devices.
        for (auto& arg : args) {
            if (const auto notifyMotionArgs = std::get_if<NotifyMotionArgs>(&arg)) {
                notifyMotionArgs->policyFlags |= POLICY_FLAG_WAKE;
            } else if (const auto notifySwitchArgs = std::get_if<NotifySwitchArgs>(&arg)) {
                notifySwitchArgs->policyFlags |= POLICY_FLAG_WAKE;
            } else if (const auto notifyKeyArgs = std::get_if<NotifyKeyArgs>(&arg)) {
                notifyKeyArgs->policyFlags |= POLICY_FLAG_WAKE;
            }
        }
    }
}

std::list<NotifyArgs> InputDevice::timeoutExpired(nsecs_t when) {
    std::list<NotifyArgs> out;
    for_each_mapper([&](InputMapper& mapper) { out += mapper.timeoutExpired(when); });
    return out;
}

std::list<NotifyArgs> InputDevice::updateExternalStylusState(const StylusState& state) {
    std::list<NotifyArgs> out;
    for_each_mapper([&](InputMapper& mapper) { out += mapper.updateExternalStylusState(state); });
    return out;
}

InputDeviceInfo InputDevice::getDeviceInfo() {
    InputDeviceInfo outDeviceInfo;
    outDeviceInfo.initialize(mId, mGeneration, mControllerNumber, mIdentifier, mAlias, mIsExternal,
                             mHasMic, getAssociatedDisplayId().value_or(ADISPLAY_ID_NONE),
                             {mShouldSmoothScroll});

    for_each_mapper(
            [&outDeviceInfo](InputMapper& mapper) { mapper.populateDeviceInfo(outDeviceInfo); });

    if (mController) {
        mController->populateDeviceInfo(&outDeviceInfo);
    }
    return outDeviceInfo;
}

int32_t InputDevice::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    return getState(sourceMask, keyCode, &InputMapper::getKeyCodeState);
}

int32_t InputDevice::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    return getState(sourceMask, scanCode, &InputMapper::getScanCodeState);
}

int32_t InputDevice::getSwitchState(uint32_t sourceMask, int32_t switchCode) {
    return getState(sourceMask, switchCode, &InputMapper::getSwitchState);
}

int32_t InputDevice::getState(uint32_t sourceMask, int32_t code, GetStateFunc getStateFunc) {
    int32_t result = AKEY_STATE_UNKNOWN;
    for (auto& deviceEntry : mDevices) {
        auto& devicePair = deviceEntry.second;
        auto& mappers = devicePair.second;
        for (auto& mapperPtr : mappers) {
            InputMapper& mapper = *mapperPtr;
            if (sourcesMatchMask(mapper.getSources(), sourceMask)) {
                // If any mapper reports AKEY_STATE_DOWN or AKEY_STATE_VIRTUAL, return that
                // value.  Otherwise, return AKEY_STATE_UP as long as one mapper reports it.
                int32_t currentResult = (mapper.*getStateFunc)(sourceMask, code);
                if (currentResult >= AKEY_STATE_DOWN) {
                    return currentResult;
                } else if (currentResult == AKEY_STATE_UP) {
                    result = currentResult;
                }
            }
        }
    }
    return result;
}

std::vector<std::unique_ptr<InputMapper>> InputDevice::createMappers(
        InputDeviceContext& contextPtr, const InputReaderConfiguration& readerConfig) {
    ftl::Flags<InputDeviceClass> classes = contextPtr.getDeviceClasses();
    std::vector<std::unique_ptr<InputMapper>> mappers;

    // Switch-like devices.
    if (classes.test(InputDeviceClass::SWITCH)) {
        mappers.push_back(createInputMapper<SwitchInputMapper>(contextPtr, readerConfig));
    }

    // Scroll wheel-like devices.
    if (classes.test(InputDeviceClass::ROTARY_ENCODER)) {
        mappers.push_back(createInputMapper<RotaryEncoderInputMapper>(contextPtr, readerConfig));
    }

    // Vibrator-like devices.
    if (classes.test(InputDeviceClass::VIBRATOR)) {
        mappers.push_back(createInputMapper<VibratorInputMapper>(contextPtr, readerConfig));
    }

    // Battery-like devices or light-containing devices.
    // PeripheralController will be created with associated EventHub device.
    if (classes.test(InputDeviceClass::BATTERY) || classes.test(InputDeviceClass::LIGHT)) {
        mController = std::make_unique<PeripheralController>(contextPtr);
    }

    // Keyboard-like devices.
    uint32_t keyboardSource = 0;
    int32_t keyboardType = AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC;
    if (classes.test(InputDeviceClass::KEYBOARD)) {
        keyboardSource |= AINPUT_SOURCE_KEYBOARD;
    }
    if (classes.test(InputDeviceClass::ALPHAKEY)) {
        keyboardType = AINPUT_KEYBOARD_TYPE_ALPHABETIC;
    }
    if (classes.test(InputDeviceClass::DPAD)) {
        keyboardSource |= AINPUT_SOURCE_DPAD;
    }
    if (classes.test(InputDeviceClass::GAMEPAD)) {
        keyboardSource |= AINPUT_SOURCE_GAMEPAD;
    }

    if (keyboardSource != 0) {
        mappers.push_back(createInputMapper<KeyboardInputMapper>(contextPtr, readerConfig,
                                                                 keyboardSource, keyboardType));
    }

    // Cursor-like devices.
    if (classes.test(InputDeviceClass::CURSOR)) {
        mappers.push_back(createInputMapper<CursorInputMapper>(contextPtr, readerConfig));
    }

    // Touchscreens and touchpad devices.
    static const bool ENABLE_TOUCHPAD_GESTURES_LIBRARY =
            sysprop::InputProperties::enable_touchpad_gestures_library().value_or(true);
    if (ENABLE_TOUCHPAD_GESTURES_LIBRARY && classes.test(InputDeviceClass::TOUCHPAD) &&
        classes.test(InputDeviceClass::TOUCH_MT)) {
        mappers.push_back(createInputMapper<TouchpadInputMapper>(contextPtr, readerConfig));
    } else if (classes.test(InputDeviceClass::TOUCH_MT)) {
        mappers.push_back(createInputMapper<MultiTouchInputMapper>(contextPtr, readerConfig));
    } else if (classes.test(InputDeviceClass::TOUCH)) {
        mappers.push_back(createInputMapper<SingleTouchInputMapper>(contextPtr, readerConfig));
    }

    // Joystick-like devices.
    if (classes.test(InputDeviceClass::JOYSTICK)) {
        mappers.push_back(createInputMapper<JoystickInputMapper>(contextPtr, readerConfig));
    }

    // Motion sensor enabled devices.
    if (classes.test(InputDeviceClass::SENSOR)) {
        mappers.push_back(createInputMapper<SensorInputMapper>(contextPtr, readerConfig));
    }

    // External stylus-like devices.
    if (classes.test(InputDeviceClass::EXTERNAL_STYLUS)) {
        mappers.push_back(createInputMapper<ExternalStylusInputMapper>(contextPtr, readerConfig));
    }
    return mappers;
}

bool InputDevice::markSupportedKeyCodes(uint32_t sourceMask, const std::vector<int32_t>& keyCodes,
                                        uint8_t* outFlags) {
    bool result = false;
    for_each_mapper([&result, sourceMask, keyCodes, outFlags](InputMapper& mapper) {
        if (sourcesMatchMask(mapper.getSources(), sourceMask)) {
            result |= mapper.markSupportedKeyCodes(sourceMask, keyCodes, outFlags);
        }
    });
    return result;
}

int32_t InputDevice::getKeyCodeForKeyLocation(int32_t locationKeyCode) const {
    std::optional<int32_t> result = first_in_mappers<int32_t>(
            [locationKeyCode](const InputMapper& mapper) -> std::optional<int32_t> const {
                if (sourcesMatchMask(mapper.getSources(), AINPUT_SOURCE_KEYBOARD)) {
                    return std::make_optional(mapper.getKeyCodeForKeyLocation(locationKeyCode));
                }
                return std::nullopt;
            });
    if (!result) {
        ALOGE("Failed to get key code for key location: No matching InputMapper with source mask "
              "KEYBOARD found. The provided input device with id %d has sources %s.",
              getId(), inputEventSourceToString(getSources()).c_str());
        return AKEYCODE_UNKNOWN;
    }
    return *result;
}

std::list<NotifyArgs> InputDevice::vibrate(const VibrationSequence& sequence, ssize_t repeat,
                                           int32_t token) {
    std::list<NotifyArgs> out;
    for_each_mapper([&](InputMapper& mapper) { out += mapper.vibrate(sequence, repeat, token); });
    return out;
}

std::list<NotifyArgs> InputDevice::cancelVibrate(int32_t token) {
    std::list<NotifyArgs> out;
    for_each_mapper([&](InputMapper& mapper) { out += mapper.cancelVibrate(token); });
    return out;
}

bool InputDevice::isVibrating() {
    bool vibrating = false;
    for_each_mapper([&vibrating](InputMapper& mapper) { vibrating |= mapper.isVibrating(); });
    return vibrating;
}

/* There's no guarantee the IDs provided by the different mappers are unique, so if we have two
 * different vibration mappers then we could have duplicate IDs.
 * Alternatively, if we have a merged device that has multiple evdev nodes with FF_* capabilities,
 * we would definitely have duplicate IDs.
 */
std::vector<int32_t> InputDevice::getVibratorIds() {
    std::vector<int32_t> vibrators;
    for_each_mapper([&vibrators](InputMapper& mapper) {
        std::vector<int32_t> devVibs = mapper.getVibratorIds();
        vibrators.reserve(vibrators.size() + devVibs.size());
        vibrators.insert(vibrators.end(), devVibs.begin(), devVibs.end());
    });
    return vibrators;
}

bool InputDevice::enableSensor(InputDeviceSensorType sensorType,
                               std::chrono::microseconds samplingPeriod,
                               std::chrono::microseconds maxBatchReportLatency) {
    bool success = true;
    for_each_mapper(
            [&success, sensorType, samplingPeriod, maxBatchReportLatency](InputMapper& mapper) {
                success &= mapper.enableSensor(sensorType, samplingPeriod, maxBatchReportLatency);
            });
    return success;
}

void InputDevice::disableSensor(InputDeviceSensorType sensorType) {
    for_each_mapper([sensorType](InputMapper& mapper) { mapper.disableSensor(sensorType); });
}

void InputDevice::flushSensor(InputDeviceSensorType sensorType) {
    for_each_mapper([sensorType](InputMapper& mapper) { mapper.flushSensor(sensorType); });
}

std::list<NotifyArgs> InputDevice::cancelTouch(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    for_each_mapper([&](InputMapper& mapper) { out += mapper.cancelTouch(when, readTime); });
    return out;
}

bool InputDevice::setLightColor(int32_t lightId, int32_t color) {
    return mController ? mController->setLightColor(lightId, color) : false;
}

bool InputDevice::setLightPlayerId(int32_t lightId, int32_t playerId) {
    return mController ? mController->setLightPlayerId(lightId, playerId) : false;
}

std::optional<int32_t> InputDevice::getLightColor(int32_t lightId) {
    return mController ? mController->getLightColor(lightId) : std::nullopt;
}

std::optional<int32_t> InputDevice::getLightPlayerId(int32_t lightId) {
    return mController ? mController->getLightPlayerId(lightId) : std::nullopt;
}

int32_t InputDevice::getMetaState() {
    int32_t result = 0;
    for_each_mapper([&result](InputMapper& mapper) { result |= mapper.getMetaState(); });
    return result;
}

void InputDevice::updateMetaState(int32_t keyCode) {
    first_in_mappers<bool>([keyCode](InputMapper& mapper) {
        if (sourcesMatchMask(mapper.getSources(), AINPUT_SOURCE_KEYBOARD) &&
            mapper.updateMetaState(keyCode)) {
            return std::make_optional(true);
        }
        return std::optional<bool>();
    });
}

void InputDevice::addKeyRemapping(int32_t fromKeyCode, int32_t toKeyCode) {
    for_each_subdevice([fromKeyCode, toKeyCode](auto& context) {
        context.addKeyRemapping(fromKeyCode, toKeyCode);
    });
}

void InputDevice::bumpGeneration() {
    mGeneration = mContext->bumpGeneration();
}

NotifyDeviceResetArgs InputDevice::notifyReset(nsecs_t when) {
    return NotifyDeviceResetArgs(mContext->getNextId(), when, mId);
}

std::optional<int32_t> InputDevice::getAssociatedDisplayId() {
    // Check if we had associated to the specific display.
    if (mAssociatedViewport) {
        return mAssociatedViewport->displayId;
    }

    // No associated display port, check if some InputMapper is associated.
    return first_in_mappers<int32_t>(
            [](InputMapper& mapper) { return mapper.getAssociatedDisplayId(); });
}

// returns the number of mappers associated with the device
size_t InputDevice::getMapperCount() {
    size_t count = 0;
    for (auto& deviceEntry : mDevices) {
        auto& devicePair = deviceEntry.second;
        auto& mappers = devicePair.second;
        count += mappers.size();
    }
    return count;
}

void InputDevice::updateLedState(bool reset) {
    for_each_mapper([reset](InputMapper& mapper) { mapper.updateLedState(reset); });
}

std::optional<int32_t> InputDevice::getBatteryEventHubId() const {
    return mController ? std::make_optional(mController->getEventHubId()) : std::nullopt;
}

InputDeviceContext::InputDeviceContext(InputDevice& device, int32_t eventHubId)
      : mDevice(device),
        mContext(device.getContext()),
        mEventHub(device.getContext()->getEventHub()),
        mId(eventHubId),
        mDeviceId(device.getId()) {}

InputDeviceContext::~InputDeviceContext() {}

} // namespace android
