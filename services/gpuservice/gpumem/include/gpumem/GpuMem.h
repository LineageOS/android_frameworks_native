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

private:
    // Friend class for testing.
    friend class TestableGpuMem;

    // set gpu memory total map
    void setGpuMemTotalMap(bpf::BpfMap<uint64_t, uint64_t>& map);

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
};

} // namespace android
