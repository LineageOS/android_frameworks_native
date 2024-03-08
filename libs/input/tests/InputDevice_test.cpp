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
#include <linux/uinput.h>
#include "android-base/file.h"

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
        ASSERT_TRUE(ret.ok()) << "Cannot load KeyLayout at " << path;
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
        ASSERT_TRUE(ret.ok()) << "Cannot load KeyCharacterMap at " << path;
        mKeyMap.keyCharacterMap = *ret;
        mKeyMap.keyCharacterMapFile = path;
    }

    void SetUp() override {
#if !defined(__ANDROID__)
        GTEST_SKIP() << "b/253299089 Generic files are currently read directly from device.";
#endif
        loadKeyLayout("Generic");
        loadKeyCharacterMap("Generic");
    }

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

TEST_F(InputDeviceKeyMapTest, keyCharacterMapWithOverlayParcelingTest) {
    Parcel parcel;
    std::string overlayPath = base::GetExecutableDirectory() + "/data/german.kcm";
    base::Result<std::shared_ptr<KeyCharacterMap>> overlay =
            KeyCharacterMap::load(overlayPath, KeyCharacterMap::Format::OVERLAY);
    ASSERT_TRUE(overlay.ok()) << "Cannot load KeyCharacterMap at " << overlayPath;
    mKeyMap.keyCharacterMap->combine(*overlay->get());
    mKeyMap.keyCharacterMap->writeToParcel(&parcel);
    parcel.setDataPosition(0);
    std::shared_ptr<KeyCharacterMap> map = KeyCharacterMap::readFromParcel(&parcel);
    ASSERT_EQ(*map, *mKeyMap.keyCharacterMap);
}

TEST_F(InputDeviceKeyMapTest, keyCharacterMapApplyMultipleOverlaysTest) {
    std::string frenchOverlayPath = base::GetExecutableDirectory() + "/data/french.kcm";
    std::string englishOverlayPath = base::GetExecutableDirectory() + "/data/english_us.kcm";
    std::string germanOverlayPath = base::GetExecutableDirectory() + "/data/german.kcm";
    base::Result<std::shared_ptr<KeyCharacterMap>> frenchOverlay =
            KeyCharacterMap::load(frenchOverlayPath, KeyCharacterMap::Format::OVERLAY);
    ASSERT_TRUE(frenchOverlay.ok()) << "Cannot load KeyCharacterMap at " << frenchOverlayPath;
    base::Result<std::shared_ptr<KeyCharacterMap>> englishOverlay =
            KeyCharacterMap::load(englishOverlayPath, KeyCharacterMap::Format::OVERLAY);
    ASSERT_TRUE(englishOverlay.ok()) << "Cannot load KeyCharacterMap at " << englishOverlayPath;
    base::Result<std::shared_ptr<KeyCharacterMap>> germanOverlay =
            KeyCharacterMap::load(germanOverlayPath, KeyCharacterMap::Format::OVERLAY);
    ASSERT_TRUE(germanOverlay.ok()) << "Cannot load KeyCharacterMap at " << germanOverlayPath;

    // Apply the French overlay
    mKeyMap.keyCharacterMap->combine(*frenchOverlay->get());
    // Copy the result for later
    std::shared_ptr<KeyCharacterMap> frenchOverlaidKeyCharacterMap =
            std::make_shared<KeyCharacterMap>(*mKeyMap.keyCharacterMap);

    // Apply the English overlay
    mKeyMap.keyCharacterMap->combine(*englishOverlay->get());
    // Verify that the result is different from the French overlay result
    ASSERT_NE(*mKeyMap.keyCharacterMap, *frenchOverlaidKeyCharacterMap);

    // Apply the German overlay
    mKeyMap.keyCharacterMap->combine(*germanOverlay->get());
    // Verify that the result is different from the French overlay result
    ASSERT_NE(*mKeyMap.keyCharacterMap, *frenchOverlaidKeyCharacterMap);

    // Apply the French overlay
    mKeyMap.keyCharacterMap->combine(*frenchOverlay->get());
    // Verify that the result is the same like after applying it initially
    ASSERT_EQ(*mKeyMap.keyCharacterMap, *frenchOverlaidKeyCharacterMap);
}

TEST_F(InputDeviceKeyMapTest, keyCharacterMapApplyOverlayTest) {
    std::string frenchOverlayPath = base::GetExecutableDirectory() + "/data/french.kcm";
    base::Result<std::shared_ptr<KeyCharacterMap>> frenchOverlay =
            KeyCharacterMap::load(frenchOverlayPath, KeyCharacterMap::Format::OVERLAY);
    ASSERT_TRUE(frenchOverlay.ok()) << "Cannot load KeyCharacterMap at " << frenchOverlayPath;

    // Apply the French overlay
    mKeyMap.keyCharacterMap->combine(*frenchOverlay->get());

    // Check if mapping for key_Q is correct
    int32_t outKeyCode;
    status_t mapKeyResult = mKeyMap.keyCharacterMap->mapKey(KEY_Q, /*usageCode=*/0, &outKeyCode);
    ASSERT_EQ(mapKeyResult, OK) << "No mapping for KEY_Q for " << frenchOverlayPath;
    ASSERT_EQ(outKeyCode, AKEYCODE_A);

    mapKeyResult = mKeyMap.keyCharacterMap->mapKey(KEY_E, /*usageCode=*/0, &outKeyCode);
    ASSERT_NE(mapKeyResult, OK) << "Mapping exists for KEY_E for " << frenchOverlayPath;
}

TEST_F(InputDeviceKeyMapTest, keyCharacterMapBadAxisLabel) {
    std::string klPath = base::GetExecutableDirectory() + "/data/bad_axis_label.kl";

    base::Result<std::shared_ptr<KeyLayoutMap>> ret = KeyLayoutMap::load(klPath);
    ASSERT_FALSE(ret.ok()) << "Should not be able to load KeyLayout at " << klPath;
}

TEST_F(InputDeviceKeyMapTest, keyCharacterMapBadLedLabel) {
    std::string klPath = base::GetExecutableDirectory() + "/data/bad_led_label.kl";

    base::Result<std::shared_ptr<KeyLayoutMap>> ret = KeyLayoutMap::load(klPath);
    ASSERT_FALSE(ret.ok()) << "Should not be able to load KeyLayout at " << klPath;
}

TEST(InputDeviceKeyLayoutTest, HidUsageCodesFallbackMapping) {
    std::string klPath = base::GetExecutableDirectory() + "/data/hid_fallback_mapping.kl";
    base::Result<std::shared_ptr<KeyLayoutMap>> ret = KeyLayoutMap::load(klPath);
    ASSERT_TRUE(ret.ok()) << "Unable to load KeyLayout at " << klPath;
    const std::shared_ptr<KeyLayoutMap>& keyLayoutMap = *ret;

    static constexpr std::array<int32_t, 5> hidUsageCodesWithoutFallback = {0x0c0067, 0x0c0070,
                                                                            0x0c006F, 0x0c0079,
                                                                            0x0c007A};
    for (int32_t hidUsageCode : hidUsageCodesWithoutFallback) {
        int32_t outKeyCode;
        uint32_t outFlags;
        keyLayoutMap->mapKey(0, hidUsageCode, &outKeyCode, &outFlags);
        ASSERT_FALSE(outFlags & POLICY_FLAG_FALLBACK_USAGE_MAPPING)
                << "HID usage code should not be marked as fallback";
        std::vector<int32_t> usageCodes = keyLayoutMap->findUsageCodesForKey(outKeyCode);
        ASSERT_NE(std::find(usageCodes.begin(), usageCodes.end(), hidUsageCode), usageCodes.end())
                << "Fallback usage code should be mapped to key";
    }

    static constexpr std::array<int32_t, 6> hidUsageCodesWithFallback = {0x0c007C, 0x0c0173,
                                                                         0x0c019C, 0x0c01A2,
                                                                         0x0d0044, 0x0d005a};
    for (int32_t hidUsageCode : hidUsageCodesWithFallback) {
        int32_t outKeyCode;
        uint32_t outFlags;
        keyLayoutMap->mapKey(0, hidUsageCode, &outKeyCode, &outFlags);
        ASSERT_TRUE(outFlags & POLICY_FLAG_FALLBACK_USAGE_MAPPING)
                << "HID usage code should be marked as fallback";
        std::vector<int32_t> usageCodes = keyLayoutMap->findUsageCodesForKey(outKeyCode);
        ASSERT_EQ(std::find(usageCodes.begin(), usageCodes.end(), hidUsageCode), usageCodes.end())
                << "Fallback usage code should not be mapped to key";
    }
}

TEST(InputDeviceKeyLayoutTest, DoesNotLoadWhenRequiredKernelConfigIsMissing) {
#if !defined(__ANDROID__)
    GTEST_SKIP() << "Can't check kernel configs on host";
#endif
    std::string klPath = base::GetExecutableDirectory() + "/data/kl_with_required_fake_config.kl";
    base::Result<std::shared_ptr<KeyLayoutMap>> ret = KeyLayoutMap::load(klPath);
    ASSERT_FALSE(ret.ok()) << "Should not be able to load KeyLayout at " << klPath;
    // We assert error message here because it's used by 'validatekeymaps' tool
    ASSERT_EQ("Missing kernel config", ret.error().message());
}

TEST(InputDeviceKeyLayoutTest, LoadsWhenRequiredKernelConfigIsPresent) {
#if !defined(__ANDROID__)
    GTEST_SKIP() << "Can't check kernel configs on host";
#endif
    std::string klPath = base::GetExecutableDirectory() + "/data/kl_with_required_real_config.kl";
    base::Result<std::shared_ptr<KeyLayoutMap>> ret = KeyLayoutMap::load(klPath);
    ASSERT_TRUE(ret.ok()) << "Cannot load KeyLayout at " << klPath;
    const std::shared_ptr<KeyLayoutMap>& map = *ret;
    ASSERT_NE(nullptr, map) << "Map should be valid because CONFIG_UHID should always be present";
}

} // namespace android
