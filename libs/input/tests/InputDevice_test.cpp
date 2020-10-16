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

#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <gtest/gtest.h>
#include <input/InputDevice.h>
#include <input/KeyLayoutMap.h>
#include <input/Keyboard.h>

namespace android {

// --- InputDeviceIdentifierTest ---

TEST(InputDeviceIdentifierTest, getCanonicalName) {
    InputDeviceIdentifier identifier;
    identifier.name = "test device";
    ASSERT_EQ(std::string("test_device"), identifier.getCanonicalName());

    identifier.name = "deviceName-123 version_C!";
    ASSERT_EQ(std::string("deviceName-123_version_C_"), identifier.getCanonicalName());
}

class InputDeviceKeyMapTest : public testing::Test {
protected:
    void loadKeyLayout(const char* name) {
        std::string path =
                getInputDeviceConfigurationFilePathByName(name,
                                                          InputDeviceConfigurationFileType::
                                                                  KEY_LAYOUT);
        ASSERT_FALSE(path.empty());
        base::Result<std::shared_ptr<KeyLayoutMap>> ret = KeyLayoutMap::load(path);
        ASSERT_TRUE(ret) << "Cannot load KeyLayout at " << path;
        mKeyMap.keyLayoutMap = std::move(*ret);
        mKeyMap.keyLayoutFile = path;
    }

    void loadKeyCharacterMap(const char* name) {
        InputDeviceIdentifier identifier;
        identifier.name = name;
        std::string path =
                getInputDeviceConfigurationFilePathByName(identifier.getCanonicalName(),
                                                          InputDeviceConfigurationFileType::
                                                                  KEY_CHARACTER_MAP);
        ASSERT_FALSE(path.empty()) << "KeyCharacterMap for " << name << " not found";
        base::Result<std::shared_ptr<KeyCharacterMap>> ret =
                KeyCharacterMap::load(path, KeyCharacterMap::Format::BASE);
        ASSERT_TRUE(ret) << "Cannot load KeyCharacterMap at " << path;
        mKeyMap.keyCharacterMap = *ret;
        mKeyMap.keyCharacterMapFile = path;
    }

    virtual void SetUp() override {
        loadKeyLayout("Generic");
        loadKeyCharacterMap("Generic");
    }

    virtual void TearDown() override {}

    KeyMap mKeyMap;
};

TEST_F(InputDeviceKeyMapTest, keyCharacterMapParcelingTest) {
    Parcel parcel;
    mKeyMap.keyCharacterMap->writeToParcel(&parcel);
    parcel.setDataPosition(0);
    std::shared_ptr<KeyCharacterMap> map = KeyCharacterMap::readFromParcel(&parcel);
    // Verify the key character map is the same as original
    ASSERT_EQ(*map, *mKeyMap.keyCharacterMap);
}

} // namespace android