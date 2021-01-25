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

#include <android-base/stringprintf.h>
#include <bpf/BpfMap.h>
#include <gmock/gmock.h>
#include <gpumem/GpuMem.h>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include "TestableGpuMem.h"

namespace android {
namespace {

using base::StringPrintf;
using testing::HasSubstr;

constexpr uint32_t TEST_MAP_SIZE = 10;
constexpr uint64_t TEST_GLOBAL_KEY = 0;
constexpr uint64_t TEST_GLOBAL_VAL = 123;
constexpr uint64_t TEST_PROC_KEY_1 = 1;
constexpr uint64_t TEST_PROC_VAL_1 = 234;
constexpr uint64_t TEST_PROC_KEY_2 = 4294967298; // (1 << 32) + 2
constexpr uint64_t TEST_PROC_VAL_2 = 345;
constexpr uint32_t TEST_KEY_MASK = 0x1 | 0x2 | 0x4;
constexpr uint32_t TEST_KEY_COUNT = 3;

class GpuMemTest : public testing::Test {
public:
    GpuMemTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~GpuMemTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void SetUp() override {
        bpf::setrlimitForTest();

        mGpuMem = std::make_unique<GpuMem>();
        mTestableGpuMem = TestableGpuMem(mGpuMem.get());
        mTestableGpuMem.setInitialized();
        errno = 0;
        mTestMap = bpf::BpfMap<uint64_t, uint64_t>(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE,
                                                   BPF_F_NO_PREALLOC);

        EXPECT_EQ(0, errno);
        EXPECT_LE(0, mTestMap.getMap().get());
        EXPECT_TRUE(mTestMap.isValid());
    }

    std::string dumpsys() {
        std::string result;
        Vector<String16> args;
        mGpuMem->dump(args, &result);
        return result;
    }

    std::unique_ptr<GpuMem> mGpuMem;
    TestableGpuMem mTestableGpuMem;
    bpf::BpfMap<uint64_t, uint64_t> mTestMap;
};

TEST_F(GpuMemTest, validGpuMemTotalBpfPaths) {
    EXPECT_EQ(mTestableGpuMem.getGpuMemTraceGroup(), "gpu_mem");
    EXPECT_EQ(mTestableGpuMem.getGpuMemTotalTracepoint(), "gpu_mem_total");
    EXPECT_EQ(mTestableGpuMem.getGpuMemTotalProgPath(),
              "/sys/fs/bpf/prog_gpu_mem_tracepoint_gpu_mem_gpu_mem_total");
    EXPECT_EQ(mTestableGpuMem.getGpuMemTotalMapPath(), "/sys/fs/bpf/map_gpu_mem_gpu_mem_total_map");
}

TEST_F(GpuMemTest, bpfInitializationFailed) {
    EXPECT_EQ(dumpsys(), "Failed to initialize GPU memory eBPF\n");
}

TEST_F(GpuMemTest, gpuMemTotalMapEmpty) {
    mTestableGpuMem.setGpuMemTotalMap(mTestMap);

    EXPECT_EQ(dumpsys(), "GPU memory total usage map is empty\n");
}

TEST_F(GpuMemTest, globalMemTotal) {
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_GLOBAL_KEY, TEST_GLOBAL_VAL, BPF_ANY));
    mTestableGpuMem.setGpuMemTotalMap(mTestMap);

    EXPECT_THAT(dumpsys(), HasSubstr(StringPrintf("Global total: %" PRIu64 "\n", TEST_GLOBAL_VAL)));
}

TEST_F(GpuMemTest, missingGlobalMemTotal) {
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_1, TEST_PROC_VAL_1, BPF_ANY));
    mTestableGpuMem.setGpuMemTotalMap(mTestMap);

    EXPECT_THAT(dumpsys(), HasSubstr("Global total: N/A"));
}

TEST_F(GpuMemTest, procMemTotal) {
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_1, TEST_PROC_VAL_1, BPF_ANY));
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_2, TEST_PROC_VAL_2, BPF_ANY));
    mTestableGpuMem.setGpuMemTotalMap(mTestMap);

    EXPECT_THAT(dumpsys(),
                HasSubstr(StringPrintf("Memory snapshot for GPU %u:\n",
                                       (uint32_t)(TEST_PROC_KEY_1 >> 32))));
    EXPECT_THAT(dumpsys(),
                HasSubstr(StringPrintf("Proc %u total: %" PRIu64 "\n", (uint32_t)TEST_PROC_KEY_1,
                                       TEST_PROC_VAL_1)));
    EXPECT_THAT(dumpsys(),
                HasSubstr(StringPrintf("Memory snapshot for GPU %u:\n",
                                       (uint32_t)(TEST_PROC_KEY_2 >> 32))));
    EXPECT_THAT(dumpsys(),
                HasSubstr(StringPrintf("Proc %u total: %" PRIu64 "\n", (uint32_t)TEST_PROC_KEY_2,
                                       TEST_PROC_VAL_2)));
}

TEST_F(GpuMemTest, traverseGpuMemTotals) {
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_GLOBAL_KEY, TEST_GLOBAL_VAL, BPF_ANY));
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_1, TEST_PROC_VAL_1, BPF_ANY));
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_2, TEST_PROC_VAL_2, BPF_ANY));
    mTestableGpuMem.setGpuMemTotalMap(mTestMap);

    static uint32_t sMask = 0;
    static uint32_t sCount = 0;
    mGpuMem->traverseGpuMemTotals([](int64_t, uint32_t gpuId, uint32_t pid, uint64_t size) {
        const uint64_t key = ((uint64_t)gpuId << 32) | pid;
        switch (key) {
            case TEST_GLOBAL_KEY:
                EXPECT_EQ(size, TEST_GLOBAL_VAL);
                sMask |= 0x1;
                break;
            case TEST_PROC_KEY_1:
                EXPECT_EQ(size, TEST_PROC_VAL_1);
                sMask |= 0x2;
                break;
            case TEST_PROC_KEY_2:
                EXPECT_EQ(size, TEST_PROC_VAL_2);
                sMask |= 0x4;
                break;
        }
        sCount++;
    });

    EXPECT_EQ(sMask, TEST_KEY_MASK);
    EXPECT_EQ(sCount, TEST_KEY_COUNT);
}

} // namespace
} // namespace android
