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

#undef LOG_TAG
#define LOG_TAG "gpuservice_unittest"

#include <cutils/properties.h>
#include <gmock/gmock.h>
#include <gpustats/GpuStats.h>
#include <gtest/gtest.h>
#include <stats_pull_atom_callback.h>
#include <statslog.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include "TestableGpuStats.h"

namespace android {
namespace {

using testing::HasSubstr;

// clang-format off
#define BUILTIN_DRIVER_PKG_NAME   "system"
#define BUILTIN_DRIVER_VER_NAME   "0"
#define BUILTIN_DRIVER_VER_CODE   0
#define BUILTIN_DRIVER_BUILD_TIME 123
#define UPDATED_DRIVER_PKG_NAME   "updated"
#define UPDATED_DRIVER_VER_NAME   "1"
#define UPDATED_DRIVER_VER_CODE   1
#define UPDATED_DRIVER_BUILD_TIME 234
#define VULKAN_VERSION            345
#define APP_PKG_NAME_1            "testapp1"
#define APP_PKG_NAME_2            "testapp2"
#define DRIVER_LOADING_TIME_1     678
#define DRIVER_LOADING_TIME_2     789
#define DRIVER_LOADING_TIME_3     891

enum InputCommand : int32_t {
    DUMP_ALL               = 0,
    DUMP_GLOBAL            = 1,
    DUMP_APP               = 2,
    DUMP_ALL_THEN_CLEAR    = 3,
    DUMP_GLOBAL_THEN_CLEAR = 4,
    DUMP_APP_THEN_CLEAR    = 5,
};
// clang-format on

class GpuStatsTest : public testing::Test {
public:
    GpuStatsTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~GpuStatsTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    std::string inputCommand(InputCommand cmd);

    void SetUp() override {
        mCpuVulkanVersion = property_get_int32("ro.cpuvulkan.version", 0);
        mGlesVersion = property_get_int32("ro.opengles.version", 0);
    }

    std::unique_ptr<GpuStats> mGpuStats = std::make_unique<GpuStats>();
    int32_t mCpuVulkanVersion = 0;
    int32_t mGlesVersion = 0;
};

std::string GpuStatsTest::inputCommand(InputCommand cmd) {
    std::string result;
    Vector<String16> args;

    switch (cmd) {
        case InputCommand::DUMP_ALL:
            break;
        case InputCommand::DUMP_GLOBAL:
            args.push_back(String16("--global"));
            break;
        case InputCommand::DUMP_APP:
            args.push_back(String16("--app"));
            break;
        case InputCommand::DUMP_ALL_THEN_CLEAR:
            args.push_back(String16("--clear"));
            break;
        case InputCommand::DUMP_GLOBAL_THEN_CLEAR:
            args.push_back(String16("--global"));
            args.push_back(String16("--clear"));
            break;
        case InputCommand::DUMP_APP_THEN_CLEAR:
            args.push_back(String16("--app"));
            args.push_back(String16("--clear"));
            break;
    }

    mGpuStats->dump(args, &result);
    return result;
}

TEST_F(GpuStatsTest, statsEmptyByDefault) {
    ASSERT_TRUE(inputCommand(InputCommand::DUMP_ALL).empty());
}

TEST_F(GpuStatsTest, canInsertBuiltinDriverStats) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    std::string expectedResult = "driverPackageName = " + std::string(BUILTIN_DRIVER_PKG_NAME);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "driverVersionName = " + std::string(BUILTIN_DRIVER_VER_NAME);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "driverVersionCode = " + std::to_string(BUILTIN_DRIVER_VER_CODE);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "driverBuildTime = " + std::to_string(BUILTIN_DRIVER_BUILD_TIME);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr("glLoadingCount = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr("glLoadingFailureCount = 0"));
    expectedResult = "appPackageName = " + std::string(APP_PKG_NAME_1);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
    expectedResult = "driverVersionCode = " + std::to_string(BUILTIN_DRIVER_VER_CODE);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
    expectedResult = "glDriverLoadingTime: " + std::to_string(DRIVER_LOADING_TIME_1);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
}

TEST_F(GpuStatsTest, canInsertUpdatedDriverStats) {
    mGpuStats->insertDriverStats(UPDATED_DRIVER_PKG_NAME, UPDATED_DRIVER_VER_NAME,
                                 UPDATED_DRIVER_VER_CODE, UPDATED_DRIVER_BUILD_TIME, APP_PKG_NAME_2,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::VULKAN_UPDATED, false,
                                 DRIVER_LOADING_TIME_2);

    std::string expectedResult = "driverPackageName = " + std::string(UPDATED_DRIVER_PKG_NAME);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "driverVersionName = " + std::string(UPDATED_DRIVER_VER_NAME);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "driverVersionCode = " + std::to_string(UPDATED_DRIVER_VER_CODE);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "driverBuildTime = " + std::to_string(UPDATED_DRIVER_BUILD_TIME);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr("vkLoadingCount = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr("vkLoadingFailureCount = 1"));
    expectedResult = "appPackageName = " + std::string(APP_PKG_NAME_2);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
    expectedResult = "driverVersionCode = " + std::to_string(UPDATED_DRIVER_VER_CODE);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
    expectedResult = "vkDriverLoadingTime: " + std::to_string(DRIVER_LOADING_TIME_2);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
}

TEST_F(GpuStatsTest, canInsertAngleDriverStats) {
    mGpuStats->insertDriverStats(UPDATED_DRIVER_PKG_NAME, UPDATED_DRIVER_VER_NAME,
                                 UPDATED_DRIVER_VER_CODE, UPDATED_DRIVER_BUILD_TIME, APP_PKG_NAME_2,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::ANGLE, true,
                                 DRIVER_LOADING_TIME_3);

    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr("angleLoadingCount = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr("angleLoadingFailureCount = 0"));
    std::string expectedResult = "angleDriverLoadingTime: " + std::to_string(DRIVER_LOADING_TIME_3);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult));
}

TEST_F(GpuStatsTest, canDump3dApiVersion) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    std::string expectedResult = "vulkanVersion = " + std::to_string(VULKAN_VERSION);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "cpuVulkanVersion = " + std::to_string(mCpuVulkanVersion);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
    expectedResult = "glesVersion = " + std::to_string(mGlesVersion);
    EXPECT_THAT(inputCommand(InputCommand::DUMP_GLOBAL), HasSubstr(expectedResult));
}

TEST_F(GpuStatsTest, canNotInsertTargetStatsBeforeProperSetup) {
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CPU_VULKAN_IN_USE, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::FALSE_PREROTATION, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::GLES_1_IN_USE, 0);

    EXPECT_TRUE(inputCommand(InputCommand::DUMP_APP).empty());
}

TEST_F(GpuStatsTest, canInsertTargetStatsAfterProperSetup) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CPU_VULKAN_IN_USE, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::FALSE_PREROTATION, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::GLES_1_IN_USE, 0);

    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("cpuVulkanInUse = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("falsePrerotation = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("gles1InUse = 1"));
}

TEST_F(GpuStatsTest, canDumpAllBeforeClearAll) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_ALL_THEN_CLEAR).empty());
    EXPECT_TRUE(inputCommand(InputCommand::DUMP_ALL).empty());
}

TEST_F(GpuStatsTest, canDumpGlobalBeforeClearGlobal) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL_THEN_CLEAR).empty());
    EXPECT_TRUE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP).empty());
}

TEST_F(GpuStatsTest, canDumpAppBeforeClearApp) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP_THEN_CLEAR).empty());
    EXPECT_TRUE(inputCommand(InputCommand::DUMP_APP).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
}

TEST_F(GpuStatsTest, skipPullInvalidAtom) {
    TestableGpuStats testableGpuStats(mGpuStats.get());
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP).empty());

    EXPECT_TRUE(testableGpuStats.makePullAtomCallback(-1) == AStatsManager_PULL_SKIP);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP).empty());
}

TEST_F(GpuStatsTest, canPullGlobalAtom) {
    TestableGpuStats testableGpuStats(mGpuStats.get());
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP).empty());

    EXPECT_TRUE(testableGpuStats.makePullAtomCallback(android::util::GPU_STATS_GLOBAL_INFO) ==
                AStatsManager_PULL_SUCCESS);

    EXPECT_TRUE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP).empty());
}

TEST_F(GpuStatsTest, canPullAppAtom) {
    TestableGpuStats testableGpuStats(mGpuStats.get());
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_FALSE(inputCommand(InputCommand::DUMP_APP).empty());

    EXPECT_TRUE(testableGpuStats.makePullAtomCallback(android::util::GPU_STATS_APP_INFO) ==
                AStatsManager_PULL_SUCCESS);

    EXPECT_FALSE(inputCommand(InputCommand::DUMP_GLOBAL).empty());
    EXPECT_TRUE(inputCommand(InputCommand::DUMP_APP).empty());
}

} // namespace
} // namespace android
