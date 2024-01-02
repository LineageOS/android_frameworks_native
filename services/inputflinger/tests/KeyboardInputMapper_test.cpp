/*
 * Copyright 2023 The Android Open Source Project
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

#include "KeyboardInputMapper.h"

#include <gtest/gtest.h>

#include "InputMapperTest.h"
#include "InterfaceMocks.h"

#define TAG "KeyboardInputMapper_test"

namespace android {

using testing::_;
using testing::Args;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

/**
 * Unit tests for KeyboardInputMapper.
 */
class KeyboardInputMapperUnitTest : public InputMapperUnitTest {
protected:
    sp<FakeInputReaderPolicy> mFakePolicy;
    const std::unordered_map<int32_t, int32_t> mKeyCodeMap{{KEY_0, AKEYCODE_0},
                                                           {KEY_A, AKEYCODE_A},
                                                           {KEY_LEFTCTRL, AKEYCODE_CTRL_LEFT},
                                                           {KEY_LEFTALT, AKEYCODE_ALT_LEFT},
                                                           {KEY_RIGHTALT, AKEYCODE_ALT_RIGHT},
                                                           {KEY_LEFTSHIFT, AKEYCODE_SHIFT_LEFT},
                                                           {KEY_RIGHTSHIFT, AKEYCODE_SHIFT_RIGHT},
                                                           {KEY_FN, AKEYCODE_FUNCTION},
                                                           {KEY_LEFTCTRL, AKEYCODE_CTRL_LEFT},
                                                           {KEY_RIGHTCTRL, AKEYCODE_CTRL_RIGHT},
                                                           {KEY_LEFTMETA, AKEYCODE_META_LEFT},
                                                           {KEY_RIGHTMETA, AKEYCODE_META_RIGHT},
                                                           {KEY_CAPSLOCK, AKEYCODE_CAPS_LOCK},
                                                           {KEY_NUMLOCK, AKEYCODE_NUM_LOCK},
                                                           {KEY_SCROLLLOCK, AKEYCODE_SCROLL_LOCK}};

    void SetUp() override {
        InputMapperUnitTest::SetUp();
        createDevice();

        // set key-codes expected in tests
        for (const auto& [scanCode, outKeycode] : mKeyCodeMap) {
            EXPECT_CALL(mMockEventHub, mapKey(EVENTHUB_ID, scanCode, _, _, _, _, _))
                    .WillRepeatedly(DoAll(SetArgPointee<4>(outKeycode), Return(NO_ERROR)));
        }

        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        EXPECT_CALL(mMockInputReaderContext, getPolicy).WillRepeatedly(Return(mFakePolicy.get()));

        mMapper = createInputMapper<KeyboardInputMapper>(*mDeviceContext, mReaderConfiguration,
                                                         AINPUT_SOURCE_KEYBOARD,
                                                         AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    }

    void testPointerVisibilityForKeys(const std::vector<int32_t>& keyCodes, bool expectVisible) {
        EXPECT_CALL(mMockInputReaderContext, fadePointer)
                .Times(expectVisible ? 0 : keyCodes.size());
        for (int32_t keyCode : keyCodes) {
            process(EV_KEY, keyCode, 1);
            process(EV_SYN, SYN_REPORT, 0);
            process(EV_KEY, keyCode, 0);
            process(EV_SYN, SYN_REPORT, 0);
        }
    }

    void testTouchpadTapStateForKeys(const std::vector<int32_t>& keyCodes,
                                     const bool expectPrevent) {
        EXPECT_CALL(mMockInputReaderContext, isPreventingTouchpadTaps).Times(keyCodes.size());
        if (expectPrevent) {
            EXPECT_CALL(mMockInputReaderContext, setPreventingTouchpadTaps(true))
                    .Times(keyCodes.size());
        }
        for (int32_t keyCode : keyCodes) {
            process(EV_KEY, keyCode, 1);
            process(EV_SYN, SYN_REPORT, 0);
            process(EV_KEY, keyCode, 0);
            process(EV_SYN, SYN_REPORT, 0);
        }
    }
};

/**
 * Pointer visibility should remain unaffected if there is no active Input Method Connection
 */
TEST_F(KeyboardInputMapperUnitTest, KeystrokesWithoutIMeConnectionDoesNotHidePointer) {
    testPointerVisibilityForKeys({KEY_0, KEY_A, KEY_LEFTCTRL}, /* expectVisible= */ true);
}

/**
 * Pointer should hide if there is a active Input Method Connection
 */
TEST_F(KeyboardInputMapperUnitTest, AlphanumericKeystrokesWithIMeConnectionHidePointer) {
    mFakePolicy->setIsInputMethodConnectionActive(true);
    testPointerVisibilityForKeys({KEY_0, KEY_A}, /* expectVisible= */ false);
}

/**
 * Pointer should still hide if touchpad taps are already disabled
 */
TEST_F(KeyboardInputMapperUnitTest, AlphanumericKeystrokesWithTouchpadTapDisabledHidePointer) {
    mFakePolicy->setIsInputMethodConnectionActive(true);
    EXPECT_CALL(mMockInputReaderContext, isPreventingTouchpadTaps).WillRepeatedly(Return(true));
    testPointerVisibilityForKeys({KEY_0, KEY_A}, /* expectVisible= */ false);
}

/**
 * Pointer visibility should remain unaffected by meta keys even if Input Method Connection is
 * active
 */
TEST_F(KeyboardInputMapperUnitTest, MetaKeystrokesWithIMeConnectionDoesNotHidePointer) {
    mFakePolicy->setIsInputMethodConnectionActive(true);
    std::vector<int32_t> metaKeys{KEY_LEFTALT,   KEY_RIGHTALT, KEY_LEFTSHIFT, KEY_RIGHTSHIFT,
                                  KEY_FN,        KEY_LEFTCTRL, KEY_RIGHTCTRL, KEY_LEFTMETA,
                                  KEY_RIGHTMETA, KEY_CAPSLOCK, KEY_NUMLOCK,   KEY_SCROLLLOCK};
    testPointerVisibilityForKeys(metaKeys, /* expectVisible= */ true);
}

/**
 * Touchpad tap should not be disabled if there is no active Input Method Connection
 */
TEST_F(KeyboardInputMapperUnitTest, KeystrokesWithoutIMeConnectionDontDisableTouchpadTap) {
    testTouchpadTapStateForKeys({KEY_0, KEY_A, KEY_LEFTCTRL}, /* expectPrevent= */ false);
}

/**
 * Touchpad tap should be disabled if there is a active Input Method Connection
 */
TEST_F(KeyboardInputMapperUnitTest, AlphanumericKeystrokesWithIMeConnectionDisableTouchpadTap) {
    mFakePolicy->setIsInputMethodConnectionActive(true);
    testTouchpadTapStateForKeys({KEY_0, KEY_A}, /* expectPrevent= */ true);
}

/**
 * Touchpad tap should not be disabled by meta keys even if Input Method Connection is active
 */
TEST_F(KeyboardInputMapperUnitTest, MetaKeystrokesWithIMeConnectionDontDisableTouchpadTap) {
    mFakePolicy->setIsInputMethodConnectionActive(true);
    std::vector<int32_t> metaKeys{KEY_LEFTALT,   KEY_RIGHTALT, KEY_LEFTSHIFT, KEY_RIGHTSHIFT,
                                  KEY_FN,        KEY_LEFTCTRL, KEY_RIGHTCTRL, KEY_LEFTMETA,
                                  KEY_RIGHTMETA, KEY_CAPSLOCK, KEY_NUMLOCK,   KEY_SCROLLLOCK};
    testTouchpadTapStateForKeys(metaKeys, /* expectPrevent= */ false);
}

TEST_F(KeyboardInputMapperUnitTest, KeyPressTimestampRecorded) {
    nsecs_t when = ARBITRARY_TIME;
    std::vector<int32_t> keyCodes{KEY_0, KEY_A, KEY_LEFTCTRL, KEY_RIGHTALT, KEY_LEFTSHIFT};
    EXPECT_CALL(mMockInputReaderContext, setLastKeyDownTimestamp)
            .With(Args<0>(when))
            .Times(keyCodes.size());
    for (int32_t keyCode : keyCodes) {
        process(when, EV_KEY, keyCode, 1);
        process(when, EV_SYN, SYN_REPORT, 0);
        process(when, EV_KEY, keyCode, 0);
        process(when, EV_SYN, SYN_REPORT, 0);
    }
}

} // namespace android
