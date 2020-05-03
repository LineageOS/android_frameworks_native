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
#define LOG_TAG "GpuMem"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "gpumem/GpuMem.h"

#include <android-base/stringprintf.h>
#include <libbpf.h>
#include <libbpf_android.h>
#include <log/log.h>
#include <utils/Trace.h>

#include <unordered_map>
#include <vector>

namespace android {

using base::StringAppendF;

GpuMem::~GpuMem() {
    bpf_detach_tracepoint(kGpuMemTraceGroup, kGpuMemTotalTracepoint);
}

void GpuMem::initialize() {
    // Make sure bpf programs are loaded
    bpf::waitForProgsLoaded();

    int fd = bpf::bpfFdGet(kGpuMemTotalProgPath, BPF_F_RDONLY);
    if (fd < 0) {
        ALOGE("Failed to retrieve pinned program from %s", kGpuMemTotalProgPath);
        return;
    }

    // Attach the program to the tracepoint, and the tracepoint is automatically enabled here.
    if (bpf_attach_tracepoint(fd, kGpuMemTraceGroup, kGpuMemTotalTracepoint) < 0) {
        ALOGE("Failed to attach bpf program to %s/%s tracepoint", kGpuMemTraceGroup,
              kGpuMemTotalTracepoint);
        return;
    }

    // Use the read-only wrapper BpfMapRO to properly retrieve the read-only map.
    auto map = bpf::BpfMapRO<uint64_t, uint64_t>(kGpuMemTotalMapPath);
    if (!map.isValid()) {
        ALOGE("Failed to create bpf map from %s", kGpuMemTotalMapPath);
        return;
    }
    setGpuMemTotalMap(map);
}

void GpuMem::setGpuMemTotalMap(bpf::BpfMap<uint64_t, uint64_t>& map) {
    mGpuMemTotalMap = std::move(map);
}

// Dump the snapshots of global and per process memory usage on all gpus
void GpuMem::dump(const Vector<String16>& /* args */, std::string* result) {
    ATRACE_CALL();

    if (!mGpuMemTotalMap.isValid()) {
        result->append("Failed to initialize GPU memory eBPF\n");
        return;
    }

    auto res = mGpuMemTotalMap.getFirstKey();
    if (!res.ok()) {
        result->append("GPU memory total usage map is empty\n");
        return;
    }
    uint64_t key = res.value();
    // unordered_map<gpu_id, vector<pair<pid, size>>>
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, uint64_t>>> dumpMap;
    while (true) {
        uint32_t gpu_id = key >> 32;
        uint32_t pid = key;

        res = mGpuMemTotalMap.readValue(key);
        if (!res.ok()) break;
        uint64_t size = res.value();

        dumpMap[gpu_id].emplace_back(pid, size);

        res = mGpuMemTotalMap.getNextKey(key);
        if (!res.ok()) break;
        key = res.value();
    }

    for (auto& gpu : dumpMap) {
        if (gpu.second.empty()) continue;
        StringAppendF(result, "Memory snapshot for GPU %u:\n", gpu.first);

        std::sort(gpu.second.begin(), gpu.second.end(),
                  [](auto& l, auto& r) { return l.first < r.first; });

        int i = 0;
        if (gpu.second[0].first != 0) {
            StringAppendF(result, "Global total: N/A\n");
        } else {
            StringAppendF(result, "Global total: %" PRIu64 "\n", gpu.second[0].second);
            i++;
        }
        for (; i < gpu.second.size(); i++) {
            StringAppendF(result, "Proc %u total: %" PRIu64 "\n", gpu.second[i].first,
                          gpu.second[i].second);
        }
    }
}

} // namespace android
