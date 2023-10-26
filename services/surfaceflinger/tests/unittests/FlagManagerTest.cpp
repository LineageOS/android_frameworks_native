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

#undef LOG_TAG
#define LOG_TAG "FlagManagerTest"

#include "FlagManager.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

namespace android {

using testing::Return;

class TestableFlagManager : public FlagManager {
public:
    TestableFlagManager() : FlagManager(ConstructorTag{}) { markBootCompleted(); }
    ~TestableFlagManager() = default;

    MOCK_METHOD(std::optional<bool>, getBoolProperty, (const char*), (const, override));
    MOCK_METHOD(bool, getServerConfigurableFlag, (const char*), (const, override));

    void markBootIncomplete() { mBootCompleted = false; }
};

class FlagManagerTest : public testing::Test {
public:
    FlagManagerTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }
    ~FlagManagerTest() override {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    TestableFlagManager mFlagManager;
};

TEST_F(FlagManagerTest, isSingleton) {
    EXPECT_EQ(&FlagManager::getInstance(), &FlagManager::getInstance());
}

TEST_F(FlagManagerTest, creashesIfQueriedBeforeBoot) {
    mFlagManager.markBootIncomplete();
    EXPECT_DEATH(FlagManager::getInstance().use_adpf_cpu_hint(), "");
}

TEST_F(FlagManagerTest, returnsOverride) {
    EXPECT_CALL(mFlagManager, getBoolProperty).WillOnce(Return(true));
    EXPECT_EQ(true, mFlagManager.test_flag());

    EXPECT_CALL(mFlagManager, getBoolProperty).WillOnce(Return(false));
    EXPECT_EQ(false, mFlagManager.test_flag());
}

TEST_F(FlagManagerTest, returnsValue) {
    EXPECT_CALL(mFlagManager, getBoolProperty).WillRepeatedly(Return(std::nullopt));

    EXPECT_CALL(mFlagManager, getServerConfigurableFlag).WillOnce(Return(true));
    EXPECT_EQ(true, mFlagManager.test_flag());

    EXPECT_CALL(mFlagManager, getServerConfigurableFlag).WillOnce(Return(false));
    EXPECT_EQ(false, mFlagManager.test_flag());
}

} // namespace android
