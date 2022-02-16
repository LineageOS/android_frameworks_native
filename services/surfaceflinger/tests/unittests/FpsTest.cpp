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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <scheduler/Fps.h>

#include "FpsOps.h"

namespace android {

TEST(FpsTest, construct) {
    EXPECT_FALSE(Fps().isValid());

    EXPECT_FALSE((0_Hz).isValid());
    EXPECT_TRUE((120_Hz).isValid());
    EXPECT_TRUE((0.5_Hz).isValid());

    EXPECT_FALSE(Fps::fromPeriodNsecs(0).isValid());

    const Fps fps = Fps::fromPeriodNsecs(16'666'667);
    EXPECT_TRUE(fps.isValid());
    EXPECT_EQ(fps, 60_Hz);
}

TEST(FpsTest, compare) {
    EXPECT_EQ(60_Hz, 60_Hz);
    EXPECT_EQ(60_Hz, 59.9999_Hz);
    EXPECT_EQ(60_Hz, 60.0001_Hz);

    EXPECT_LE(60_Hz, 60_Hz);
    EXPECT_LE(60_Hz, 59.9999_Hz);
    EXPECT_LE(60_Hz, 60.0001_Hz);

    EXPECT_GE(60_Hz, 60_Hz);
    EXPECT_GE(60_Hz, 59.9999_Hz);
    EXPECT_GE(60_Hz, 60.0001_Hz);

    // Fps with difference of 1 should be different.
    EXPECT_NE(60_Hz, 61_Hz);
    EXPECT_LT(60_Hz, 61_Hz);
    EXPECT_GT(60_Hz, 59_Hz);

    // These are common refresh rates which should be different.
    EXPECT_NE(60_Hz, 59.94_Hz);
    EXPECT_GT(60_Hz, 59.94_Hz);
    EXPECT_NE(30_Hz, 29.97_Hz);
    EXPECT_GT(30_Hz, 29.97_Hz);
}

TEST(FpsTest, getIntValue) {
    EXPECT_EQ(30, (30.1_Hz).getIntValue());
    EXPECT_EQ(31, (30.9_Hz).getIntValue());
    EXPECT_EQ(31, (30.5_Hz).getIntValue());
}

TEST(FpsTest, range) {
    const auto fps = Fps::fromPeriodNsecs(16'666'665);

    EXPECT_TRUE((FpsRange{60.000004_Hz, 60.000004_Hz}.includes(fps)));
    EXPECT_TRUE((FpsRange{59_Hz, 60.1_Hz}.includes(fps)));
    EXPECT_FALSE((FpsRange{75_Hz, 90_Hz}.includes(fps)));
    EXPECT_FALSE((FpsRange{60.0011_Hz, 90_Hz}.includes(fps)));
    EXPECT_FALSE((FpsRange{50_Hz, 59.998_Hz}.includes(fps)));
}

} // namespace android
