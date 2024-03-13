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

#include <unistd.h>
#include <binder/ProcessState.h>
#include <cutils/properties.h>
#include <gmock/gmock.h>
#include <gpustats/GpuStats.h>
#include <gtest/gtest.h>
#include <stats_pull_atom_callback.h>
#include <statslog.h>
#include <utils/Looper.h>
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
#define VULKAN_ENGINE_NAME_1      "testVulkanEngine1"
#define VULKAN_ENGINE_NAME_2      "testVulkanEngine2"
#define APP_PKG_NAME_1            "testapp1"
#define APP_PKG_NAME_2            "testapp2"
#define DRIVER_LOADING_TIME_1     678
#define DRIVER_LOADING_TIME_2     789
#define DRIVER_LOADING_TIME_3     891

constexpr uint64_t VULKAN_FEATURES_MASK = 0x600D;
constexpr uint32_t VULKAN_API_VERSION = 0x400000;
constexpr int32_t VULKAN_INSTANCE_EXTENSION_1 = 0x1234;
constexpr int32_t VULKAN_INSTANCE_EXTENSION_2 = 0x8765;
constexpr int32_t VULKAN_DEVICE_EXTENSION_1 = 0x9012;
constexpr int32_t VULKAN_DEVICE_EXTENSION_2 = 0x3456;

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
    sp<android::Looper> looper;
public:
    GpuStatsTest() : looper(Looper::prepare(0 /* opts */)) {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~GpuStatsTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());

        // This is required for test due to GpuStats instance spawns binder transactions
        // in its destructor. After the gtest destructor test exits immidiatelly.
        // It results in binder thread not able to process above binder transactions and memory leak
        // occures. Binder thread needs time to process callbacks transactions.
        // It leads to GpuStats instance destructor needs to be called in advance.
        mGpuStats.reset(nullptr);
        // performs all pending callbacks until all data has been consumed
        // gives time to process binder transactions by thread pool
        looper->pollAll(1000);
    }

    std::string inputCommand(InputCommand cmd);

    void SetUp() override {
        mCpuVulkanVersion = property_get_int32("ro.cpuvulkan.version", 0);
        mGlesVersion = property_get_int32("ro.opengles.version", 0);

        // start the thread pool
        sp<ProcessState> ps(ProcessState::self());
        ps->startThreadPool();
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
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_GLES_CONTEXT, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_VULKAN_API_VERSION,
                                 VULKAN_API_VERSION);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_VULKAN_DEVICE, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_VULKAN_SWAPCHAIN, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_DEVICE_FEATURES_ENABLED,
                                 VULKAN_FEATURES_MASK);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_INSTANCE_EXTENSION,
                                 VULKAN_INSTANCE_EXTENSION_1);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_DEVICE_EXTENSION,
                                 VULKAN_DEVICE_EXTENSION_1);
    mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                             VULKAN_ENGINE_NAME_1);

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
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_GLES_CONTEXT, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_VULKAN_API_VERSION,
                                 VULKAN_API_VERSION);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_VULKAN_DEVICE, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::CREATED_VULKAN_SWAPCHAIN, 0);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_DEVICE_FEATURES_ENABLED,
                                 VULKAN_FEATURES_MASK);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_INSTANCE_EXTENSION,
                                 VULKAN_INSTANCE_EXTENSION_1);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_INSTANCE_EXTENSION,
                                 VULKAN_INSTANCE_EXTENSION_2);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_DEVICE_EXTENSION,
                                 VULKAN_DEVICE_EXTENSION_1);
    mGpuStats->insertTargetStats(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                 GpuStatsInfo::Stats::VULKAN_DEVICE_EXTENSION,
                                 VULKAN_DEVICE_EXTENSION_2);
    mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                             VULKAN_ENGINE_NAME_1);

    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("cpuVulkanInUse = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("falsePrerotation = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("gles1InUse = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("createdGlesContext = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("createdVulkanDevice = 1"));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("createdVulkanSwapchain = 1"));
    std::stringstream expectedResult;
    expectedResult << "vulkanApiVersion = 0x" << std::hex << VULKAN_API_VERSION;
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
    expectedResult.str("");
    expectedResult << "vulkanDeviceFeaturesEnabled = 0x" << std::hex << VULKAN_FEATURES_MASK;
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
    expectedResult.str("");
    expectedResult << "vulkanInstanceExtensions: 0x" << std::hex << VULKAN_INSTANCE_EXTENSION_1
                    << " 0x" << std::hex << VULKAN_INSTANCE_EXTENSION_2;
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
    expectedResult.str("");
    expectedResult << "vulkanDeviceExtensions: 0x" << std::hex << VULKAN_DEVICE_EXTENSION_1
                    << " 0x" << std::hex << VULKAN_DEVICE_EXTENSION_2;
    expectedResult.str("");
    expectedResult << "vulkanEngineNames: " << VULKAN_ENGINE_NAME_1 << ",";

    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
}

// Verify the vulkanEngineNames list behaves like a set and dedupes additions
TEST_F(GpuStatsTest, vulkanEngineNamesBehavesLikeSet) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);
    for (int i = 0; i < 4; i++) {
        mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                       VULKAN_ENGINE_NAME_1);
    }

    std::stringstream wrongResult, expectedResult;
    wrongResult << "vulkanEngineNames: " << VULKAN_ENGINE_NAME_1 << ", " <<
                   VULKAN_ENGINE_NAME_1;
    expectedResult << "vulkanEngineNames: " << VULKAN_ENGINE_NAME_1;

    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), Not(HasSubstr(wrongResult.str())));
    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
}

TEST_F(GpuStatsTest, vulkanEngineNamesCheckEmptyEngineNameAlone) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                   "");

    std::stringstream expectedResult;
    expectedResult << "vulkanEngineNames: ,";

    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
}

TEST_F(GpuStatsTest, vulkanEngineNamesCheckEmptyEngineNameWithOthers) {
    mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                 BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME, APP_PKG_NAME_1,
                                 VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                 DRIVER_LOADING_TIME_1);

    mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                   VULKAN_ENGINE_NAME_1);
    mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                   "");
    mGpuStats->addVulkanEngineName(APP_PKG_NAME_1, BUILTIN_DRIVER_VER_CODE,
                                   VULKAN_ENGINE_NAME_2);

    std::stringstream expectedResult;
    expectedResult << "vulkanEngineNames: " << VULKAN_ENGINE_NAME_1 << ", "
                   << ", " <<  VULKAN_ENGINE_NAME_2;

    EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
}

// Verify we always have the most recently used apps in mAppStats, even when we fill it.
TEST_F(GpuStatsTest, canInsertMoreThanMaxNumAppRecords) {
    constexpr int kNumExtraApps = 15;
    static_assert(kNumExtraApps > GpuStats::APP_RECORD_HEADROOM);

    // Insert stats for GpuStats::MAX_NUM_APP_RECORDS so we fill it up.
    for (int i = 0; i < GpuStats::MAX_NUM_APP_RECORDS + kNumExtraApps; ++i) {
        std::stringstream nameStream;
        nameStream << "testapp" << "_" << i;
        std::string fullPkgName = nameStream.str();

        mGpuStats->insertDriverStats(BUILTIN_DRIVER_PKG_NAME, BUILTIN_DRIVER_VER_NAME,
                                     BUILTIN_DRIVER_VER_CODE, BUILTIN_DRIVER_BUILD_TIME,
                                     fullPkgName, VULKAN_VERSION, GpuStatsInfo::Driver::GL, true,
                                     DRIVER_LOADING_TIME_1);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                     GpuStatsInfo::Stats::CPU_VULKAN_IN_USE, 0);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                     GpuStatsInfo::Stats::FALSE_PREROTATION, 0);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                     GpuStatsInfo::Stats::GLES_1_IN_USE, 0);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                     GpuStatsInfo::Stats::CREATED_GLES_CONTEXT, 0);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::CREATED_VULKAN_API_VERSION,
                                    VULKAN_API_VERSION);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::CREATED_VULKAN_DEVICE, 0);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::CREATED_VULKAN_SWAPCHAIN, 0);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::VULKAN_DEVICE_FEATURES_ENABLED,
                                    VULKAN_FEATURES_MASK);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::VULKAN_INSTANCE_EXTENSION,
                                    VULKAN_INSTANCE_EXTENSION_1);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::VULKAN_INSTANCE_EXTENSION,
                                    VULKAN_INSTANCE_EXTENSION_2);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::VULKAN_DEVICE_EXTENSION,
                                    VULKAN_DEVICE_EXTENSION_1);
        mGpuStats->insertTargetStats(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                    GpuStatsInfo::Stats::VULKAN_DEVICE_EXTENSION,
                                    VULKAN_DEVICE_EXTENSION_2);
        mGpuStats->addVulkanEngineName(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                 VULKAN_ENGINE_NAME_1);
        mGpuStats->addVulkanEngineName(fullPkgName, BUILTIN_DRIVER_VER_CODE,
                                 VULKAN_ENGINE_NAME_2);

        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(fullPkgName.c_str()));
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("cpuVulkanInUse = 1"));
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("falsePrerotation = 1"));
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("gles1InUse = 1"));
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("createdGlesContext = 1"));
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("createdVulkanDevice = 1"));
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr("createdVulkanSwapchain = 1"));
        std::stringstream expectedResult;
        expectedResult << "vulkanApiVersion = 0x" << std::hex << VULKAN_API_VERSION;
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
        expectedResult.str("");
        expectedResult << "vulkanDeviceFeaturesEnabled = 0x" << std::hex << VULKAN_FEATURES_MASK;
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
        expectedResult.str("");
        expectedResult << "vulkanInstanceExtensions: 0x" << std::hex << VULKAN_INSTANCE_EXTENSION_1
                        << " 0x" << std::hex << VULKAN_INSTANCE_EXTENSION_2;
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
        expectedResult.str("");
        expectedResult << "vulkanDeviceExtensions: 0x" << std::hex << VULKAN_DEVICE_EXTENSION_1
                        << " 0x" << std::hex << VULKAN_DEVICE_EXTENSION_2;
        expectedResult.str("");
        expectedResult << "vulkanEngineNames: " << VULKAN_ENGINE_NAME_1 << ", "
                       << VULKAN_ENGINE_NAME_2 << ",";
        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(expectedResult.str()));
    }

    // mAppStats purges GpuStats::APP_RECORD_HEADROOM apps removed everytime it's filled up.
    int numPurges = kNumExtraApps / GpuStats::APP_RECORD_HEADROOM;
    numPurges += (kNumExtraApps % GpuStats::APP_RECORD_HEADROOM) == 0 ? 0 : 1;

    // Verify the remaining apps are present.
    for (int i = numPurges * GpuStats::APP_RECORD_HEADROOM;
         i < GpuStats::MAX_NUM_APP_RECORDS + kNumExtraApps;
         ++i) {
        std::stringstream nameStream;
        // Add a newline to search for the exact package name.
        nameStream << "testapp" << "_" << i << "\n";
        std::string fullPkgName = nameStream.str();

        EXPECT_THAT(inputCommand(InputCommand::DUMP_APP), HasSubstr(fullPkgName.c_str()));
    }
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
