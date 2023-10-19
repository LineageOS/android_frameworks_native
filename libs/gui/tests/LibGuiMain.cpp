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

#include "gtest/gtest.h"
#include "log/log.h"

namespace {

class TestCaseLogger : public ::testing::EmptyTestEventListener {
    void OnTestStart(const ::testing::TestInfo& testInfo) override {
        ALOGD("Begin test: %s#%s", testInfo.test_suite_name(), testInfo.name());
    }

    void OnTestEnd(const testing::TestInfo& testInfo) override {
        ALOGD("End test:   %s#%s", testInfo.test_suite_name(), testInfo.name());
    }
};

} // namespace

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    testing::UnitTest::GetInstance()->listeners().Append(new TestCaseLogger());
    return RUN_ALL_TESTS();
}