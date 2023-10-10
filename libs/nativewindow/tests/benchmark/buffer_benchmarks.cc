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

static void BM_BufferAllocationDeallocation(benchmark::State& state) {
    AHardwareBuffer_Desc buffer_desc = {.width = 1280,
                                        .height = 720,
                                        .layers = 1,
                                        .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
                                        .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
                                        .stride = 0};
    AHardwareBuffer* buffer = nullptr;
    for (auto _ : state) {
        int status = AHardwareBuffer_allocate(&buffer_desc, &buffer);
        if (UNLIKELY(status != 0)) {
            state.SkipWithError("Unable to allocate buffer.");
        }
        AHardwareBuffer_release(buffer);
        buffer = nullptr;
    }
}
BENCHMARK(BM_BufferAllocationDeallocation);

BENCHMARK_MAIN();