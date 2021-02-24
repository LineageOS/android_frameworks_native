/*
 * Copyright 2021 The Android Open Source Project
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

#define LOG_TAG "HashCombineTest"

#include <math.h>
#include <stdlib.h>

#include <math/half.h>
#include <math/vec4.h>

#include <gtest/gtest.h>

namespace android {

class HashCombineTest : public testing::Test {
protected:
};

TEST_F(HashCombineTest, Basics) {
    char a = 40;
    int b = 32;
    int c = 55;
    float d = 42.f;
    float d_ = 42.1f;

    EXPECT_NE(hashCombine(a, b, c, d), hashCombine(a, b, c, d_));
}

}; // namespace android
