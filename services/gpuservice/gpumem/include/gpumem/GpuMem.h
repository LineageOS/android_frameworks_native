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

#pragma once

#include <bpf/BpfMap.h>
#include <utils/String16.h>
#include <utils/Vector.h>

namespace android {

class GpuMem {
public:
    GpuMem() = default;
    ~GpuMem();

    // initialize eBPF program and map
    void initialize();
    // dumpsys interface
    void dump(const Vector<String16>& args, std::string* result);
    bool isInitialized() { return mInitialized.load(); }

    // Traverse the map and send each value read back to the callback function.
    // Used for tracing.
    template <typename lambda>
    void traceGpuMemTotals(lambda tracerCallback) {
        auto res = mGpuMemTotalMap.getFirstKey();
        if (!res.ok()) return;
        uint64_t key = res.value();
        while (true) {
            uint32_t gpu_id = key >> 32;
            uint32_t pid = key;

            res = mGpuMemTotalMap.readValue(key);
            if (!res.ok()) break;
            uint64_t size = res.value();

            tracerCallback(gpu_id, pid, size);
            res = mGpuMemTotalMap.getNextKey(key);
            if (!res.ok()) break;
            key = res.value();
        }
    }

private:
    // Friend class for testing.
    friend class TestableGpuMem;

    // set gpu memory total map
    void setGpuMemTotalMap(bpf::BpfMap<uint64_t, uint64_t>& map);

    // indicate whether ebpf has been initialized
    std::atomic<bool> mInitialized = false;
    // bpf map for GPU memory total data
    android::bpf::BpfMap<uint64_t, uint64_t> mGpuMemTotalMap;

    // gpu memory tracepoint event category
    static constexpr char kGpuMemTraceGroup[] = "gpu_mem";
    // gpu memory total tracepoint
    static constexpr char kGpuMemTotalTracepoint[] = "gpu_mem_total";
    // pinned gpu memory total bpf c program path in bpf sysfs
    static constexpr char kGpuMemTotalProgPath[] =
            "/sys/fs/bpf/prog_gpu_mem_tracepoint_gpu_mem_gpu_mem_total";
    // pinned gpu memory total bpf map path in bpf sysfs
    static constexpr char kGpuMemTotalMapPath[] = "/sys/fs/bpf/map_gpu_mem_gpu_mem_total_map";
    // 30 seconds timeout for trying to attach bpf program to tracepoint
    static constexpr int kGpuWaitTimeout = 30;
};

} // namespace android
