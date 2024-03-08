// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <android-base/macros.h>
#include <android/hardware_buffer.h>
#include <benchmark/benchmark.h>

constexpr AHardwareBuffer_Desc k720pDesc = {.width = 1280,
                                            .height = 720,
                                            .layers = 1,
                                            .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
                                            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
                                            .stride = 0};

static void BM_BufferAllocationDeallocation(benchmark::State& state) {
    AHardwareBuffer* buffer = nullptr;
    for (auto _ : state) {
        int status = AHardwareBuffer_allocate(&k720pDesc, &buffer);
        if (UNLIKELY(status != 0)) {
            state.SkipWithError("Unable to allocate buffer.");
        }
        AHardwareBuffer_release(buffer);
        buffer = nullptr;
    }
}
BENCHMARK(BM_BufferAllocationDeallocation);

static void BM_AHardwareBuffer_Id(benchmark::State& state) {
    AHardwareBuffer* buffer = nullptr;
    int status = AHardwareBuffer_allocate(&k720pDesc, &buffer);
    if (UNLIKELY(status != 0)) {
        state.SkipWithError("Unable to allocate buffer.");
    }

    for (auto _ : state) {
        uint64_t id = 0;
        int status = AHardwareBuffer_getId(buffer, &id);
        if (UNLIKELY(status != 0)) {
            state.SkipWithError("Unable to get ID.");
        }
    }

    AHardwareBuffer_release(buffer);
}
BENCHMARK(BM_AHardwareBuffer_Id);

static void BM_AHardwareBuffer_Desc(benchmark::State& state) {
    AHardwareBuffer* buffer = nullptr;
    int status = AHardwareBuffer_allocate(&k720pDesc, &buffer);
    if (UNLIKELY(status != 0)) {
        state.SkipWithError("Unable to allocate buffer.");
    }

    for (auto _ : state) {
        AHardwareBuffer_Desc desc = {};
        AHardwareBuffer_describe(buffer, &desc);
    }

    AHardwareBuffer_release(buffer);
}
BENCHMARK(BM_AHardwareBuffer_Desc);

BENCHMARK_MAIN();
