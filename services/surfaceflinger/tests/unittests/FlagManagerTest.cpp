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

#include <cstdint>
#undef LOG_TAG
#define LOG_TAG "FlagManagerTest"

#include "FlagManager.h"

#include <android-base/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <server_configurable_flags/get_flags.h>
#include <optional>

namespace android {

using testing::Return;

class MockFlagManager : public FlagManager {
public:
    MockFlagManager() = default;
    ~MockFlagManager() = default;

    MOCK_METHOD(std::string, getServerConfigurableFlag, (const std::string& experimentFlagName),
                (const, override));
};

class FlagManagerTest : public testing::Test {
public:
    FlagManagerTest();
    ~FlagManagerTest() override;
    std::unique_ptr<MockFlagManager> mFlagManager;

    template <typename T>
    T getValue(const std::string& experimentFlagName, std::optional<T> systemPropertyOpt,
               T defaultValue);
};

FlagManagerTest::FlagManagerTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    mFlagManager = std::make_unique<MockFlagManager>();
}

FlagManagerTest::~FlagManagerTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

template <typename T>
T FlagManagerTest::getValue(const std::string& experimentFlagName,
                            std::optional<T> systemPropertyOpt, T defaultValue) {
    return mFlagManager->getValue(experimentFlagName, systemPropertyOpt, defaultValue);
}

namespace {
TEST_F(FlagManagerTest, getValue_bool_default) {
    EXPECT_CALL(*mFlagManager, getServerConfigurableFlag).Times(1).WillOnce(Return(""));
    const bool defaultValue = false;
    std::optional<bool> systemPropertyValue = std::nullopt;
    const bool result = FlagManagerTest::getValue("test_flag", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, defaultValue);
}

TEST_F(FlagManagerTest, getValue_bool_sysprop) {
    const bool defaultValue = false;
    std::optional<bool> systemPropertyValue = std::make_optional(true);
    const bool result = FlagManagerTest::getValue("test_flag", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, true);
}

TEST_F(FlagManagerTest, getValue_bool_experiment) {
    EXPECT_CALL(*mFlagManager, getServerConfigurableFlag).Times(1).WillOnce(Return("1"));
    const bool defaultValue = false;
    std::optional<bool> systemPropertyValue = std::nullopt;
    const bool result = FlagManagerTest::getValue("test_flag", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, true);
}

TEST_F(FlagManagerTest, getValue_int32_default) {
    EXPECT_CALL(*mFlagManager, getServerConfigurableFlag).Times(1).WillOnce(Return(""));
    int32_t defaultValue = 30;
    std::optional<int32_t> systemPropertyValue = std::nullopt;
    int32_t result = FlagManagerTest::getValue("test_flag", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, defaultValue);
}

TEST_F(FlagManagerTest, getValue_int32_sysprop) {
    int32_t defaultValue = 30;
    std::optional<int32_t> systemPropertyValue = std::make_optional(10);
    int32_t result = FlagManagerTest::getValue("test_flag", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, 10);
}

TEST_F(FlagManagerTest, getValue_int32_experiment) {
    EXPECT_CALL(*mFlagManager, getServerConfigurableFlag).Times(1).WillOnce(Return("50"));
    std::int32_t defaultValue = 30;
    std::optional<std::int32_t> systemPropertyValue = std::nullopt;
    std::int32_t result = FlagManagerTest::getValue("test_flag", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, 50);
}

TEST_F(FlagManagerTest, getValue_int64_default) {
    EXPECT_CALL(*mFlagManager, getServerConfigurableFlag).Times(1).WillOnce(Return(""));
    int64_t defaultValue = 30;
    std::optional<int64_t> systemPropertyValue = std::nullopt;
    int64_t result = getValue("flag_name", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, defaultValue);
}

TEST_F(FlagManagerTest, getValue_int64_sysprop) {
    int64_t defaultValue = 30;
    std::optional<int64_t> systemPropertyValue = std::make_optional(10);
    int64_t result = getValue("flag_name", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, 10);
}

TEST_F(FlagManagerTest, getValue_int64_experiment) {
    EXPECT_CALL(*mFlagManager, getServerConfigurableFlag).Times(1).WillOnce(Return("50"));
    int64_t defaultValue = 30;
    std::optional<int64_t> systemPropertyValue = std::nullopt;
    int64_t result = getValue("flag_name", systemPropertyValue, defaultValue);
    ASSERT_EQ(result, 50);
}
} // namespace
} // namespace android
