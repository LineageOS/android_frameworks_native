/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _LIBINPUT_KEYBOARD_H
#define _LIBINPUT_KEYBOARD_H

#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/InputEventLabels.h>
#include <input/PropertyMap.h>
#include <utils/Errors.h>

namespace android {

class KeyLayoutMap;
class KeyCharacterMap;

/**
 * Loads the key layout map and key character map for a keyboard device.
 */
class KeyMap {
public:
    std::string keyLayoutFile;
    std::shared_ptr<KeyLayoutMap> keyLayoutMap;

    std::string keyCharacterMapFile;
    std::shared_ptr<KeyCharacterMap> keyCharacterMap;

    KeyMap();
    ~KeyMap();

    status_t load(const InputDeviceIdentifier& deviceIdenfier,
            const PropertyMap* deviceConfiguration);

    inline bool haveKeyLayout() const {
        return !keyLayoutFile.empty();
    }

    inline bool haveKeyCharacterMap() const {
        return !keyCharacterMapFile.empty();
    }

    inline bool isComplete() const {
        return haveKeyLayout() && haveKeyCharacterMap();
    }

private:
    bool probeKeyMap(const InputDeviceIdentifier& deviceIdentifier, const std::string& name);
    status_t loadKeyLayout(const InputDeviceIdentifier& deviceIdentifier, const std::string& name);
    status_t loadKeyCharacterMap(const InputDeviceIdentifier& deviceIdentifier,
                                 const std::string& name);
};

/**
 * Returns true if the keyboard is eligible for use as a built-in keyboard.
 */
extern bool isEligibleBuiltInKeyboard(const InputDeviceIdentifier& deviceIdentifier,
        const PropertyMap* deviceConfiguration, const KeyMap* keyMap);

/**
 * Updates a meta state field when a key is pressed or released.
 */
extern int32_t updateMetaState(int32_t keyCode, bool down, int32_t oldMetaState);

/**
 * Normalizes the meta state such that if either the left or right modifier
 * meta state bits are set then the result will also include the universal
 * bit for that modifier.
 */
extern int32_t normalizeMetaState(int32_t oldMetaState);

/**
 * Returns true if a key is a meta key like ALT or CAPS_LOCK.
 */
extern bool isMetaKey(int32_t keyCode);

} // namespace android

#endif // _LIBINPUT_KEYBOARD_H
