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

#define BPF_MAP_MAKE_VISIBLE_FOR_TESTING
#include <bpf/BpfMap.h>
#include <gpumem/GpuMem.h>
#include <gtest/gtest.h>
#include <perfetto/trace/trace.pb.h>
#include <tracing/GpuMemTracer.h>

#include "TestableGpuMem.h"

namespace android {

constexpr uint32_t TEST_MAP_SIZE = 10;
constexpr uint64_t TEST_GLOBAL_KEY = 0;
constexpr uint32_t TEST_GLOBAL_PID = 0;
constexpr uint64_t TEST_GLOBAL_VAL = 123;
constexpr uint32_t TEST_GLOBAL_GPU_ID = 0;
constexpr uint64_t TEST_PROC_KEY_1 = 1;
constexpr uint32_t TEST_PROC_PID_1 = 1;
constexpr uint64_t TEST_PROC_VAL_1 = 234;
constexpr uint32_t TEST_PROC_1_GPU_ID = 0;
constexpr uint64_t TEST_PROC_KEY_2 = 4294967298; // (1 << 32) + 2
constexpr uint32_t TEST_PROC_PID_2 = 2;
constexpr uint64_t TEST_PROC_VAL_2 = 345;
constexpr uint32_t TEST_PROC_2_GPU_ID = 1;

class GpuMemTracerTest : public testing::Test {
public:
    GpuMemTracerTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~GpuMemTracerTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void SetUp() override {
        bpf::setrlimitForTest();

        mGpuMem = std::make_shared<GpuMem>();
        mGpuMemTracer = std::make_unique<GpuMemTracer>();
        mGpuMemTracer->initializeForTest(mGpuMem);
        mTestableGpuMem = TestableGpuMem(mGpuMem.get());

        errno = 0;
        mTestMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC);

        EXPECT_EQ(0, errno);
        EXPECT_TRUE(mTestMap.isValid());
    }

    int getTracerThreadCount() { return mGpuMemTracer->tracerThreadCount; }

    std::vector<perfetto::protos::TracePacket> readGpuMemTotalPacketsBlocking(
            perfetto::TracingSession* tracingSession) {
        std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
        perfetto::protos::Trace trace;
        trace.ParseFromArray(raw_trace.data(), int(raw_trace.size()));

        std::vector<perfetto::protos::TracePacket> packets;
        for (const auto& packet : trace.packet()) {
            if (!packet.has_gpu_mem_total_event()) {
                continue;
            }
            packets.emplace_back(packet);
        }
        return packets;
    }

    std::shared_ptr<GpuMem> mGpuMem;
    TestableGpuMem mTestableGpuMem;
    std::unique_ptr<GpuMemTracer> mGpuMemTracer;
    bpf::BpfMap<uint64_t, uint64_t> mTestMap;
};

static constexpr uint64_t getSizeForPid(uint32_t pid) {
    switch (pid) {
        case TEST_GLOBAL_PID:
            return TEST_GLOBAL_VAL;
        case TEST_PROC_PID_1:
            return TEST_PROC_VAL_1;
        case TEST_PROC_PID_2:
            return TEST_PROC_VAL_2;
    }
    return 0;
}

static constexpr uint32_t getGpuIdForPid(uint32_t pid) {
    switch (pid) {
        case TEST_GLOBAL_PID:
            return TEST_GLOBAL_GPU_ID;
        case TEST_PROC_PID_1:
            return TEST_PROC_1_GPU_ID;
        case TEST_PROC_PID_2:
            return TEST_PROC_2_GPU_ID;
    }
    return 0;
}

TEST_F(GpuMemTracerTest, traceInitialCountersAfterGpuMemInitialize) {
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_GLOBAL_KEY, TEST_GLOBAL_VAL, BPF_ANY));
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_1, TEST_PROC_VAL_1, BPF_ANY));
    ASSERT_RESULT_OK(mTestMap.writeValue(TEST_PROC_KEY_2, TEST_PROC_VAL_2, BPF_ANY));
    mTestableGpuMem.setGpuMemTotalMap(mTestMap);
    mTestableGpuMem.setInitialized();

    // Only 1 tracer thread should be existing for test.
    EXPECT_EQ(getTracerThreadCount(), 1);
    auto tracingSession = mGpuMemTracer->getTracingSessionForTest();

    tracingSession->StartBlocking();
    // Sleep for a short time to let the tracer thread finish its work
    sleep(1);
    tracingSession->StopBlocking();

    // The test tracer thread should have finished its execution by now.
    EXPECT_EQ(getTracerThreadCount(), 0);

    auto packets = readGpuMemTotalPacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 3);

    const auto& packet0 = packets[0];
    ASSERT_TRUE(packet0.has_timestamp());
    ASSERT_TRUE(packet0.has_gpu_mem_total_event());
    const auto& gpuMemEvent0 = packet0.gpu_mem_total_event();
    ASSERT_TRUE(gpuMemEvent0.has_pid());
    const auto& pid0 = gpuMemEvent0.pid();
    ASSERT_TRUE(gpuMemEvent0.has_size());
    EXPECT_EQ(gpuMemEvent0.size(), getSizeForPid(pid0));
    ASSERT_TRUE(gpuMemEvent0.has_gpu_id());
    EXPECT_EQ(gpuMemEvent0.gpu_id(), getGpuIdForPid(pid0));

    const auto& packet1 = packets[1];
    ASSERT_TRUE(packet1.has_timestamp());
    ASSERT_TRUE(packet1.has_gpu_mem_total_event());
    const auto& gpuMemEvent1 = packet1.gpu_mem_total_event();
    ASSERT_TRUE(gpuMemEvent1.has_pid());
    const auto& pid1 = gpuMemEvent1.pid();
    ASSERT_TRUE(gpuMemEvent1.has_size());
    EXPECT_EQ(gpuMemEvent1.size(), getSizeForPid(pid1));
    ASSERT_TRUE(gpuMemEvent1.has_gpu_id());
    EXPECT_EQ(gpuMemEvent1.gpu_id(), getGpuIdForPid(pid1));

    const auto& packet2 = packets[2];
    ASSERT_TRUE(packet2.has_timestamp());
    ASSERT_TRUE(packet2.has_gpu_mem_total_event());
    const auto& gpuMemEvent2 = packet2.gpu_mem_total_event();
    ASSERT_TRUE(gpuMemEvent2.has_pid());
    const auto& pid2 = gpuMemEvent2.pid();
    ASSERT_TRUE(gpuMemEvent2.has_size());
    EXPECT_EQ(gpuMemEvent2.size(), getSizeForPid(pid2));
    ASSERT_TRUE(gpuMemEvent2.has_gpu_id());
    EXPECT_EQ(gpuMemEvent2.gpu_id(), getGpuIdForPid(pid2));
}

TEST_F(GpuMemTracerTest, noTracingWithoutGpuMemInitialize) {
    // Only 1 tracer thread should be existing for test.
    EXPECT_EQ(getTracerThreadCount(), 1);

    auto tracingSession = mGpuMemTracer->getTracingSessionForTest();

    tracingSession->StartBlocking();
    // Sleep for a short time to let the tracer thread finish its work
    sleep(1);
    tracingSession->StopBlocking();

    // The test tracer thread should have finished its execution by now.
    EXPECT_EQ(getTracerThreadCount(), 0);

    auto packets = readGpuMemTotalPacketsBlocking(tracingSession.get());
    EXPECT_EQ(packets.size(), 0);
}
} // namespace android
