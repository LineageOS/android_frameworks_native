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

#pragma once

#include <android-base/result.h>
#include <input/Input.h>
#include <input/InputDevice.h>

#include "rust/cxx.h"

namespace android {

namespace input {
namespace keyboardClassifier {
struct KeyboardClassifier;
}
} // namespace input

/*
 * Keyboard classifier to classify keyboard into alphabetic and non-alphabetic keyboards
 */
class KeyboardClassifier {
public:
    KeyboardClassifier();
    /**
     * Get the type of keyboard that the classifier currently believes the device to be.
     */
    KeyboardType getKeyboardType(DeviceId deviceId);
    void notifyKeyboardChanged(DeviceId deviceId, const InputDeviceIdentifier& identifier,
                               uint32_t deviceClasses);
    void processKey(DeviceId deviceId, int32_t evdevCode, uint32_t metaState);

private:
    std::optional<rust::Box<android::input::keyboardClassifier::KeyboardClassifier>>
            mRustClassifier;
    std::unordered_map<DeviceId, KeyboardType> mKeyboardTypeMap;
};

} // namespace android
