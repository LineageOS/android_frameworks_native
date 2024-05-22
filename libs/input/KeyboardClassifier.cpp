/*
 * Copyright 2024 The Android Open Source Project
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

#define LOG_TAG "KeyboardClassifier"

#include <android-base/logging.h>
#include <com_android_input_flags.h>
#include <ftl/flags.h>
#include <input/KeyboardClassifier.h>

#include "input_cxx_bridge.rs.h"

namespace input_flags = com::android::input::flags;

using android::input::RustInputDeviceIdentifier;

namespace android {

KeyboardClassifier::KeyboardClassifier() {
    if (input_flags::enable_keyboard_classifier()) {
        mRustClassifier = android::input::keyboardClassifier::create();
    }
}

KeyboardType KeyboardClassifier::getKeyboardType(DeviceId deviceId) {
    if (mRustClassifier) {
        return static_cast<KeyboardType>(
                android::input::keyboardClassifier::getKeyboardType(**mRustClassifier, deviceId));
    } else {
        auto it = mKeyboardTypeMap.find(deviceId);
        if (it == mKeyboardTypeMap.end()) {
            return KeyboardType::NONE;
        }
        return it->second;
    }
}

// Copied from EventHub.h
const uint32_t DEVICE_CLASS_KEYBOARD = android::os::IInputConstants::DEVICE_CLASS_KEYBOARD;
const uint32_t DEVICE_CLASS_ALPHAKEY = android::os::IInputConstants::DEVICE_CLASS_ALPHAKEY;

void KeyboardClassifier::notifyKeyboardChanged(DeviceId deviceId,
                                               const InputDeviceIdentifier& identifier,
                                               uint32_t deviceClasses) {
    if (mRustClassifier) {
        RustInputDeviceIdentifier rustIdentifier;
        rustIdentifier.name = identifier.name;
        rustIdentifier.location = identifier.location;
        rustIdentifier.unique_id = identifier.uniqueId;
        rustIdentifier.bus = identifier.bus;
        rustIdentifier.vendor = identifier.vendor;
        rustIdentifier.product = identifier.product;
        rustIdentifier.version = identifier.version;
        rustIdentifier.descriptor = identifier.descriptor;
        android::input::keyboardClassifier::notifyKeyboardChanged(**mRustClassifier, deviceId,
                                                                  rustIdentifier, deviceClasses);
    } else {
        bool isKeyboard = (deviceClasses & DEVICE_CLASS_KEYBOARD) != 0;
        bool hasAlphabeticKey = (deviceClasses & DEVICE_CLASS_ALPHAKEY) != 0;
        mKeyboardTypeMap.insert_or_assign(deviceId,
                                          isKeyboard ? (hasAlphabeticKey
                                                                ? KeyboardType::ALPHABETIC
                                                                : KeyboardType::NON_ALPHABETIC)
                                                     : KeyboardType::NONE);
    }
}

void KeyboardClassifier::processKey(DeviceId deviceId, int32_t evdevCode, uint32_t metaState) {
    if (mRustClassifier &&
        !android::input::keyboardClassifier::isFinalized(**mRustClassifier, deviceId)) {
        android::input::keyboardClassifier::processKey(**mRustClassifier, deviceId, evdevCode,
                                                       metaState);
    }
}

} // namespace android
