/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <attestation/HmacKeyManager.h>
#include <gtest/gtest.h>

namespace android {

class HmacKeyManagerTest : public testing::Test {
protected:
    HmacKeyManager mHmacKeyManager;
};

/**
 * Ensure that separate calls to sign the same data are generating the same key.
 * We avoid asserting against INVALID_HMAC. Since the key is random, there is a non-zero chance
 * that a specific key and data combination would produce INVALID_HMAC, which would cause flaky
 * tests.
 */
TEST_F(HmacKeyManagerTest, GeneratedHmac_IsConsistent) {
    std::array<uint8_t, 10> data = {4, 3, 5, 1, 8, 5, 2, 7, 1, 8};

    std::array<uint8_t, 32> hmac1 = mHmacKeyManager.sign(data.data(), sizeof(data));
    std::array<uint8_t, 32> hmac2 = mHmacKeyManager.sign(data.data(), sizeof(data));
    ASSERT_EQ(hmac1, hmac2);
}

/**
 * Ensure that changes in the hmac verification data produce a different hmac.
 */
TEST_F(HmacKeyManagerTest, GeneratedHmac_ChangesWhenFieldsChange) {
    std::array<uint8_t, 10> data = {4, 3, 5, 1, 8, 5, 2, 7, 1, 8};
    std::array<uint8_t, 32> initialHmac = mHmacKeyManager.sign(data.data(), sizeof(data));

    data[2] = 2;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(data.data(), sizeof(data)));
}

} // namespace android