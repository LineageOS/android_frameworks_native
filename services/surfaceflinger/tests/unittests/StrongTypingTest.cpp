/*
 * Copyright 2019 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "Scheduler/StrongTyping.h"

using namespace testing;

namespace android {

TEST(StrongTypeTest, comparison) {
    using SpunkyType = StrongTyping<int, struct SpunkyTypeTag, Compare>;
    SpunkyType f1(10);

    EXPECT_TRUE(f1 == f1);
    EXPECT_TRUE(SpunkyType(10) != SpunkyType(11));
    EXPECT_FALSE(SpunkyType(31) != SpunkyType(31));

    EXPECT_TRUE(SpunkyType(10) < SpunkyType(11));
    EXPECT_TRUE(SpunkyType(-1) < SpunkyType(0));
    EXPECT_FALSE(SpunkyType(-10) < SpunkyType(-20));

    EXPECT_TRUE(SpunkyType(10) <= SpunkyType(11));
    EXPECT_TRUE(SpunkyType(10) <= SpunkyType(10));
    EXPECT_TRUE(SpunkyType(-10) <= SpunkyType(1));
    EXPECT_FALSE(SpunkyType(10) <= SpunkyType(9));

    EXPECT_TRUE(SpunkyType(11) >= SpunkyType(11));
    EXPECT_TRUE(SpunkyType(12) >= SpunkyType(11));
    EXPECT_FALSE(SpunkyType(11) >= SpunkyType(12));

    EXPECT_FALSE(SpunkyType(11) > SpunkyType(12));
    EXPECT_TRUE(SpunkyType(-11) < SpunkyType(7));
}

TEST(StrongTypeTest, addition) {
    using FunkyType = StrongTyping<int, struct FunkyTypeTag, Compare, Add>;
    FunkyType f2(22);
    FunkyType f1(10);

    EXPECT_THAT(f1 + f2, Eq(FunkyType(32)));
    EXPECT_THAT(f2 + f1, Eq(FunkyType(32)));

    EXPECT_THAT(++f1.value(), Eq(11));
    EXPECT_THAT(f1.value(), Eq(11));
    EXPECT_THAT(f1++.value(), Eq(11));
    EXPECT_THAT(f1++.value(), Eq(12));
    EXPECT_THAT(f1.value(), Eq(13));

    auto f3 = f1;
    EXPECT_THAT(f1, Eq(f3));
    EXPECT_THAT(f1, Lt(f2));

    f3 += f1;
    EXPECT_THAT(f1.value(), Eq(13));
    EXPECT_THAT(f3.value(), Eq(26));
}
} // namespace android
