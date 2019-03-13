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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"
#define LOG_NDEBUG 0

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <log/log.h>

#include "AllowedDisplayConfigs.h"

namespace android {
namespace {

class AllowedDisplayConfigsTest : public testing::Test {
protected:
    AllowedDisplayConfigsTest();
    ~AllowedDisplayConfigsTest() override;

    void buildAllowedConfigs();

    const std::vector<int32_t> expectedConfigs = {0, 2, 7, 129};
    constexpr static int32_t notAllowedConfig = 5;
    std::unique_ptr<const AllowedDisplayConfigs> mAllowedConfigs;
};

AllowedDisplayConfigsTest::AllowedDisplayConfigsTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

AllowedDisplayConfigsTest::~AllowedDisplayConfigsTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

void AllowedDisplayConfigsTest::buildAllowedConfigs() {
    AllowedDisplayConfigs::Builder builder;
    for (int config : expectedConfigs) {
        builder.addConfig(config);
    }
    mAllowedConfigs = builder.build();
}

/* ------------------------------------------------------------------------
 * Test cases
 */

TEST_F(AllowedDisplayConfigsTest, checkConfigs) {
    buildAllowedConfigs();

    // Check that all expected configs are allowed
    for (int config : expectedConfigs) {
        EXPECT_TRUE(mAllowedConfigs->isConfigAllowed(config));
    }

    // Check that all the allowed configs are expected
    std::vector<int32_t> allowedConfigVector;
    mAllowedConfigs->getAllowedConfigs(&allowedConfigVector);
    EXPECT_EQ(allowedConfigVector, expectedConfigs);

    // Check that notAllowedConfig is indeed not allowed
    EXPECT_TRUE(std::find(expectedConfigs.begin(), expectedConfigs.end(), notAllowedConfig) ==
                expectedConfigs.end());
    EXPECT_FALSE(mAllowedConfigs->isConfigAllowed(notAllowedConfig));
}

TEST_F(AllowedDisplayConfigsTest, getAllowedConfigsNullptr) {
    buildAllowedConfigs();

    // No other expectations rather than no crash
    mAllowedConfigs->getAllowedConfigs(nullptr);
}

} // namespace
} // namespace android
