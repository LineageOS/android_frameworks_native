/*
 * Copyright 2020 The Android Open Source Project
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

#include "Fps.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {

TEST(FpsTest, construct) {
    Fps fpsDefault;
    EXPECT_FALSE(fpsDefault.isValid());

    Fps fps1(60.0f);
    EXPECT_TRUE(fps1.isValid());
    Fps fps2 = Fps::fromPeriodNsecs(static_cast<nsecs_t>(1e9f / 60.0f));
    EXPECT_TRUE(fps2.isValid());
    EXPECT_TRUE(fps1.equalsWithMargin(fps2));
}

TEST(FpsTest, compare) {
    constexpr float kEpsilon = 1e-4f;
    const Fps::EqualsInBuckets equalsInBuckets;
    const Fps::EqualsWithMargin equalsWithMargin;

    EXPECT_TRUE(Fps(60.0f).equalsWithMargin(Fps(60.f)));
    EXPECT_TRUE(Fps(60.0f).equalsWithMargin(Fps(60.f - kEpsilon)));
    EXPECT_TRUE(Fps(60.0f).equalsWithMargin(Fps(60.f + kEpsilon)));

    EXPECT_TRUE(equalsInBuckets(Fps(60.0f), Fps(60.0f)));
    EXPECT_TRUE(equalsInBuckets(Fps(60.0f), Fps(60.0f - kEpsilon)));
    EXPECT_TRUE(equalsInBuckets(Fps(60.0f), Fps(60.0f + kEpsilon)));

    EXPECT_TRUE(equalsWithMargin(Fps(60.0f), Fps(60.0f)));
    EXPECT_TRUE(equalsWithMargin(Fps(60.0f), Fps(60.0f - kEpsilon)));
    EXPECT_TRUE(equalsWithMargin(Fps(60.0f), Fps(60.0f + kEpsilon)));

    EXPECT_TRUE(Fps(60.0f).lessThanOrEqualWithMargin(Fps(60.f + kEpsilon)));
    EXPECT_TRUE(Fps(60.0f).lessThanOrEqualWithMargin(Fps(60.f)));
    EXPECT_TRUE(Fps(60.0f).lessThanOrEqualWithMargin(Fps(60.f - kEpsilon)));

    EXPECT_TRUE(Fps(60.0f).greaterThanOrEqualWithMargin(Fps(60.f + kEpsilon)));
    EXPECT_TRUE(Fps(60.0f).greaterThanOrEqualWithMargin(Fps(60.f)));
    EXPECT_TRUE(Fps(60.0f).greaterThanOrEqualWithMargin(Fps(60.f - kEpsilon)));

    // Fps with difference of 1 should be different
    EXPECT_FALSE(Fps(60.0f).equalsWithMargin(Fps(61.f)));
    EXPECT_TRUE(Fps(60.0f).lessThanWithMargin(Fps(61.f)));
    EXPECT_TRUE(Fps(60.0f).greaterThanWithMargin(Fps(59.f)));

    // These are common refresh rates which should be different.
    EXPECT_FALSE(Fps(60.0f).equalsWithMargin(Fps(59.94f)));
    EXPECT_TRUE(Fps(60.0f).greaterThanWithMargin(Fps(59.94f)));
    EXPECT_FALSE(equalsInBuckets(Fps(60.0f), Fps(59.94f)));
    EXPECT_FALSE(equalsWithMargin(Fps(60.0f), Fps(59.94f)));
    EXPECT_NE(std::hash<Fps>()(Fps(60.0f)), std::hash<Fps>()(Fps(59.94f)));

    EXPECT_FALSE(Fps(30.0f).equalsWithMargin(Fps(29.97f)));
    EXPECT_TRUE(Fps(30.0f).greaterThanWithMargin(Fps(29.97f)));
    EXPECT_FALSE(equalsInBuckets(Fps(30.0f), Fps(29.97f)));
    EXPECT_FALSE(equalsWithMargin(Fps(30.0f), Fps(29.97f)));
    EXPECT_NE(std::hash<Fps>()(Fps(30.0f)), std::hash<Fps>()(Fps(29.97f)));
}

TEST(FpsTest, getIntValue) {
    EXPECT_EQ(30, Fps(30.1f).getIntValue());
    EXPECT_EQ(31, Fps(30.9f).getIntValue());
    EXPECT_EQ(31, Fps(30.5f).getIntValue());
}

TEST(FpsTest, equalsInBucketsImpliesEqualHashes) {
    constexpr float kStep = 1e-4f;
    const Fps::EqualsInBuckets equals;
    for (float fps = 30.0f; fps < 31.0f; fps += kStep) {
        const Fps left(fps);
        const Fps right(fps + kStep);
        if (equals(left, right)) {
            ASSERT_EQ(std::hash<Fps>()(left), std::hash<Fps>()(right))
                    << "left= " << left << " right=" << right;
        }
    }
}

} // namespace android
