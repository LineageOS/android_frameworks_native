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

#include "InputMapper.h"

namespace android {

InputDevice::InputDevice(InputReaderContext* context, int32_t id, int32_t generation,
                         int32_t controllerNumber, const InputDeviceIdentifier& identifier,
                         uint32_t classes)
      : mContext(context),
        mId(id),
        mGeneration(generation),
        mControllerNumber(controllerNumber),
        mIdentifier(identifier),
        mClasses(classes),
        mSources(0),
        mIsExternal(false),
        mHasMic(false),
        mDropUntilNextSync(false) {}

InputDevice::~InputDevice() {
    size_t numMappers = mMappers.size();
    for (size_t i = 0; i < numMappers; i++) {
        delete mMappers[i];
    }
    mMappers.clear();
}

bool InputDevice::isEnabled() {
    return getEventHub()->isDeviceEnabled(mId);
}

void InputDevice::setEnabled(bool enabled, nsecs_t when) {
    if (isEnabled() == enabled) {
        return;
    }

    if (enabled) {
        getEventHub()->enableDevice(mId);
        reset(when);
    } else {
        reset(when);
        getEventHub()->disableDevice(mId);
    }
    // Must change generation to flag this device as changed
    bumpGeneration();
}

void InputDevice::dump(std::string& dump) {
    InputDeviceInfo deviceInfo;
    getDeviceInfo(&deviceInfo);

    dump += StringPrintf(INDENT "Device %d: %s\n", deviceInfo.getId(),
                         deviceInfo.getDisplayName().c_str());
    dump += StringPrintf(INDENT2 "Generation: %d\n", mGeneration);
    dump += StringPrintf(INDENT2 "IsExternal: %s\n", toString(mIsExternal));
    dump += StringPrintf(INDENT2 "AssociatedDisplayPort: ");
    if (mAssociatedDisplayPort) {
        dump += StringPrintf("%" PRIu8 "\n", *mAssociatedDisplayPort);
    } else {
        dump += "<none>\n";
    }
    dump += StringPrintf(INDENT2 "HasMic:     %s\n", toString(mHasMic));
    dump += StringPrintf(INDENT2 "Sources: 0x%08x\n", deviceInfo.getSources());
    dump += StringPrintf(INDENT2 "KeyboardType: %d\n", deviceInfo.getKeyboardType());

    const std::vector<InputDeviceInfo::MotionRange>& ranges = deviceInfo.getMotionRanges();
    if (!ranges.empty()) {
        dump += INDENT2 "Motion Ranges:\n";
        for (size_t i = 0; i < ranges.size(); i++) {
            const InputDeviceInfo::MotionRange& range = ranges[i];
            const char* label = getAxisLabel(range.axis);
            char name[32];
            if (label) {
                strncpy(name, label, sizeof(name));
                name[sizeof(name) - 1] = '\0';
            } else {
                snprintf(name, sizeof(name), "%d", range.axis);
            }
            dump += StringPrintf(INDENT3
                                 "%s: source=0x%08x, "
                                 "min=%0.3f, max=%0.3f, flat=%0.3f, fuzz=%0.3f, resolution=%0.3f\n",
                                 name, range.source, range.min, range.max, range.flat, range.fuzz,
                                 range.resolution);
        }
    }

    size_t numMappers = mMappers.size();
    for (size_t i = 0; i < numMappers; i++) {
        InputMapper* mapper = mMappers[i];
        mapper->dump(dump);
    }
}

void InputDevice::addMapper(InputMapper* mapper) {
    mMappers.push_back(mapper);
}

void InputDevice::configure(nsecs_t when, const InputReaderConfiguration* config,
                            uint32_t changes) {
    mSources = 0;

    if (!isIgnored()) {
        if (!changes) { // first time only
            mContext->getEventHub()->getConfiguration(mId, &mConfiguration);
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_KEYBOARD_LAYOUTS)) {
            if (!(mClasses & INPUT_DEVICE_CLASS_VIRTUAL)) {
                sp<KeyCharacterMap> keyboardLayout =
                        mContext->getPolicy()->getKeyboardLayoutOverlay(mIdentifier);
                if (mContext->getEventHub()->setKeyboardLayoutOverlay(mId, keyboardLayout)) {
                    bumpGeneration();
                }
            }
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_DEVICE_ALIAS)) {
            if (!(mClasses & INPUT_DEVICE_CLASS_VIRTUAL)) {
                std::string alias = mContext->getPolicy()->getDeviceAlias(mIdentifier);
                if (mAlias != alias) {
                    mAlias = alias;
                    bumpGeneration();
                }
            }
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_ENABLED_STATE)) {
            ssize_t index = config->disabledDevices.indexOf(mId);
            bool enabled = index < 0;
            setEnabled(enabled, when);
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
            // In most situations, no port will be specified.
            mAssociatedDisplayPort = std::nullopt;
            // Find the display port that corresponds to the current input port.
            const std::string& inputPort = mIdentifier.location;
            if (!inputPort.empty()) {
                const std::unordered_map<std::string, uint8_t>& ports = config->portAssociations;
                const auto& displayPort = ports.find(inputPort);
                if (displayPort != ports.end()) {
                    mAssociatedDisplayPort = std::make_optional(displayPort->second);
                }
            }
        }

        for (InputMapper* mapper : mMappers) {
            mapper->configure(when, config, changes);
            mSources |= mapper->getSources();
        }
    }
}

void InputDevice::reset(nsecs_t when) {
    for (InputMapper* mapper : mMappers) {
        mapper->reset(when);
    }

    mContext->updateGlobalMetaState();

    notifyReset(when);
}

void InputDevice::process(const RawEvent* rawEvents, size_t count) {
    // Process all of the events in order for each mapper.
    // We cannot simply ask each mapper to process them in bulk because mappers may
    // have side-effects that must be interleaved.  For example, joystick movement events and
    // gamepad button presses are handled by different mappers but they should be dispatched
    // in the order received.
    for (const RawEvent* rawEvent = rawEvents; count != 0; rawEvent++) {
#if DEBUG_RAW_EVENTS
        ALOGD("Input event: device=%d type=0x%04x code=0x%04x value=0x%08x when=%" PRId64,
              rawEvent->deviceId, rawEvent->type, rawEvent->code, rawEvent->value, rawEvent->when);
#endif

        if (mDropUntilNextSync) {
            if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
                mDropUntilNextSync = false;
#if DEBUG_RAW_EVENTS
                ALOGD("Recovered from input event buffer overrun.");
#endif
            } else {
#if DEBUG_RAW_EVENTS
                ALOGD("Dropped input event while waiting for next input sync.");
#endif
            }
        } else if (rawEvent->type == EV_SYN && rawEvent->code == SYN_DROPPED) {
            ALOGI("Detected input event buffer overrun for device %s.", getName().c_str());
            mDropUntilNextSync = true;
            reset(rawEvent->when);
        } else {
            for (InputMapper* mapper : mMappers) {
                mapper->process(rawEvent);
            }
        }
        --count;
    }
}

void InputDevice::timeoutExpired(nsecs_t when) {
    for (InputMapper* mapper : mMappers) {
        mapper->timeoutExpired(when);
    }
}

void InputDevice::updateExternalStylusState(const StylusState& state) {
    for (InputMapper* mapper : mMappers) {
        mapper->updateExternalStylusState(state);
    }
}

void InputDevice::getDeviceInfo(InputDeviceInfo* outDeviceInfo) {
    outDeviceInfo->initialize(mId, mGeneration, mControllerNumber, mIdentifier, mAlias, mIsExternal,
                              mHasMic);
    for (InputMapper* mapper : mMappers) {
        mapper->populateDeviceInfo(outDeviceInfo);
    }
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
    for (InputMapper* mapper : mMappers) {
        if (sourcesMatchMask(mapper->getSources(), sourceMask)) {
            // If any mapper reports AKEY_STATE_DOWN or AKEY_STATE_VIRTUAL, return that
            // value.  Otherwise, return AKEY_STATE_UP as long as one mapper reports it.
            int32_t currentResult = (mapper->*getStateFunc)(sourceMask, code);
            if (currentResult >= AKEY_STATE_DOWN) {
                return currentResult;
            } else if (currentResult == AKEY_STATE_UP) {
                result = currentResult;
            }
        }
    }
    return result;
}

bool InputDevice::markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                        const int32_t* keyCodes, uint8_t* outFlags) {
    bool result = false;
    for (InputMapper* mapper : mMappers) {
        if (sourcesMatchMask(mapper->getSources(), sourceMask)) {
            result |= mapper->markSupportedKeyCodes(sourceMask, numCodes, keyCodes, outFlags);
        }
    }
    return result;
}

void InputDevice::vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat,
                          int32_t token) {
    for (InputMapper* mapper : mMappers) {
        mapper->vibrate(pattern, patternSize, repeat, token);
    }
}

void InputDevice::cancelVibrate(int32_t token) {
    for (InputMapper* mapper : mMappers) {
        mapper->cancelVibrate(token);
    }
}

void InputDevice::cancelTouch(nsecs_t when) {
    for (InputMapper* mapper : mMappers) {
        mapper->cancelTouch(when);
    }
}

int32_t InputDevice::getMetaState() {
    int32_t result = 0;
    for (InputMapper* mapper : mMappers) {
        result |= mapper->getMetaState();
    }
    return result;
}

void InputDevice::updateMetaState(int32_t keyCode) {
    for (InputMapper* mapper : mMappers) {
        mapper->updateMetaState(keyCode);
    }
}

void InputDevice::fadePointer() {
    for (InputMapper* mapper : mMappers) {
        mapper->fadePointer();
    }
}

void InputDevice::bumpGeneration() {
    mGeneration = mContext->bumpGeneration();
}

void InputDevice::notifyReset(nsecs_t when) {
    NotifyDeviceResetArgs args(mContext->getNextSequenceNum(), when, mId);
    mContext->getListener()->notifyDeviceReset(&args);
}

std::optional<int32_t> InputDevice::getAssociatedDisplay() {
    for (InputMapper* mapper : mMappers) {
        std::optional<int32_t> associatedDisplayId = mapper->getAssociatedDisplay();
        if (associatedDisplayId) {
            return associatedDisplayId;
        }
    }

    return std::nullopt;
}

} // namespace android
