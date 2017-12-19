/*
 * Copyright (C) 2018 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <log/log.h>

#include "TestableSurfaceFlinger.h"

namespace android {
namespace {

class DisplayTransactionTest : public testing::Test {
protected:
    DisplayTransactionTest();
    ~DisplayTransactionTest() override;

    void setupComposer(int virtualDisplayCount);
    void setupPrimaryDisplay(int width, int height);

    TestableSurfaceFlinger mFlinger;
};

DisplayTransactionTest::DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

DisplayTransactionTest::~DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

TEST_F(DisplayTransactionTest, PlaceholderTrivialTest) {
    auto result = mFlinger.getDefaultDisplayDeviceLocked();
    EXPECT_EQ(nullptr, result.get());

    EXPECT_EQ(nullptr, mFlinger.mutableBuiltinDisplays()[0].get());
    mFlinger.mutableBuiltinDisplays()[0] = new BBinder();
    EXPECT_NE(nullptr, mFlinger.mutableBuiltinDisplays()[0].get());
}

} // namespace
} // namespace android
