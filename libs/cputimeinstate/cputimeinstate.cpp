/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "libtimeinstate"

#include "cputimeinstate.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>

#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <libbpf.h>
#include <log/log.h>

#define BPF_FS_PATH "/sys/fs/bpf/"

using android::base::StringPrintf;
using android::base::unique_fd;

namespace android {
namespace bpf {

struct time_key_t {
    uint32_t uid;
    uint32_t freq;
};

struct val_t {
    uint64_t ar[100];
};

static std::mutex gInitializedMutex;
static bool gInitialized = false;
static uint32_t gNPolicies = 0;
static std::vector<std::vector<uint32_t>> gPolicyFreqs;
static std::vector<std::vector<uint32_t>> gPolicyCpus;
static std::set<uint32_t> gAllFreqs;
static unique_fd gMapFd;

static std::optional<std::vector<uint32_t>> readNumbersFromFile(const std::string &path) {
    std::string data;

    if (!android::base::ReadFileToString(path, &data)) return {};

    auto strings = android::base::Split(data, " \n");
    std::vector<uint32_t> ret;
    for (const auto &s : strings) {
        if (s.empty()) continue;
        uint32_t n;
        if (!android::base::ParseUint(s, &n)) return {};
        ret.emplace_back(n);
    }
    return ret;
}

static int isPolicyFile(const struct dirent *d) {
    return android::base::StartsWith(d->d_name, "policy");
}

static int comparePolicyFiles(const struct dirent **d1, const struct dirent **d2) {
    uint32_t policyN1, policyN2;
    if (sscanf((*d1)->d_name, "policy%" SCNu32 "", &policyN1) != 1 ||
        sscanf((*d2)->d_name, "policy%" SCNu32 "", &policyN2) != 1)
        return 0;
    return policyN1 - policyN2;
}

static bool initGlobals() {
    std::lock_guard<std::mutex> guard(gInitializedMutex);
    if (gInitialized) return true;

    struct dirent **dirlist;
    const char basepath[] = "/sys/devices/system/cpu/cpufreq";
    int ret = scandir(basepath, &dirlist, isPolicyFile, comparePolicyFiles);
    if (ret == -1) return false;
    gNPolicies = ret;

    std::vector<std::string> policyFileNames;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        policyFileNames.emplace_back(dirlist[i]->d_name);
        free(dirlist[i]);
    }
    free(dirlist);

    for (const auto &policy : policyFileNames) {
        std::vector<uint32_t> freqs;
        for (const auto &name : {"available", "boost"}) {
            std::string path =
                    StringPrintf("%s/%s/scaling_%s_frequencies", basepath, policy.c_str(), name);
            auto nums = readNumbersFromFile(path);
            if (!nums) return false;
            freqs.insert(freqs.end(), nums->begin(), nums->end());
        }
        std::sort(freqs.begin(), freqs.end());
        gPolicyFreqs.emplace_back(freqs);

        for (auto freq : freqs) gAllFreqs.insert(freq);

        std::string path = StringPrintf("%s/%s/%s", basepath, policy.c_str(), "related_cpus");
        auto cpus = readNumbersFromFile(path);
        if (!cpus) return false;
        gPolicyCpus.emplace_back(*cpus);
    }

    gMapFd = unique_fd{bpf_obj_get(BPF_FS_PATH "map_time_in_state_uid_times_map")};
    if (gMapFd < 0) return false;

    gInitialized = true;
    return true;
}

static bool attachTracepointProgram(const std::string &eventType, const std::string &eventName) {
    std::string path = StringPrintf(BPF_FS_PATH "prog_time_in_state_tracepoint_%s_%s",
                                    eventType.c_str(), eventName.c_str());
    int prog_fd = bpf_obj_get(path.c_str());
    if (prog_fd < 0) return false;
    return bpf_attach_tracepoint(prog_fd, eventType.c_str(), eventName.c_str()) >= 0;
}

// Start tracking and aggregating data to be reported by getUidCpuFreqTimes and getUidsCpuFreqTimes.
// Returns true on success, false otherwise.
// Tracking is active only once a live process has successfully called this function; if the calling
// process dies then it must be called again to resume tracking.
// This function should *not* be called while tracking is already active; doing so is unnecessary
// and can lead to accounting errors.
bool startTrackingUidCpuFreqTimes() {
    return attachTracepointProgram("sched", "sched_switch") &&
            attachTracepointProgram("power", "cpu_frequency");
}

// Retrieve the times in ns that uid spent running at each CPU frequency and store in freqTimes.
// Return contains no value on error, otherwise it contains a vector of vectors using the format:
// [[t0_0, t0_1, ...],
//  [t1_0, t1_1, ...], ...]
// where ti_j is the ns that uid spent running on the ith cluster at that cluster's jth lowest freq.
std::optional<std::vector<std::vector<uint64_t>>> getUidCpuFreqTimes(uint32_t uid) {
    if (!gInitialized && !initGlobals()) return {};
    time_key_t key = {.uid = uid, .freq = 0};

    std::vector<std::vector<uint64_t>> out(gNPolicies);
    std::vector<uint32_t> idxs(gNPolicies, 0);

    val_t value;
    for (uint32_t freq : gAllFreqs) {
        key.freq = freq;
        int ret = findMapEntry(gMapFd, &key, &value);
        if (ret) {
            if (errno == ENOENT)
                memset(&value.ar, 0, sizeof(value.ar));
            else
                return {};
        }
        for (uint32_t i = 0; i < gNPolicies; ++i) {
            if (idxs[i] == gPolicyFreqs[i].size() || freq != gPolicyFreqs[i][idxs[i]]) continue;
            uint64_t time = 0;
            for (uint32_t cpu : gPolicyCpus[i]) time += value.ar[cpu];
            idxs[i] += 1;
            out[i].emplace_back(time);
        }
    }

    return out;
}

// Retrieve the times in ns that each uid spent running at each CPU freq and store in freqTimeMap.
// Return contains no value on error, otherwise it contains a map from uids to vectors of vectors
// using the format:
// { uid0 -> [[t0_0_0, t0_0_1, ...], [t0_1_0, t0_1_1, ...], ...],
//   uid1 -> [[t1_0_0, t1_0_1, ...], [t1_1_0, t1_1_1, ...], ...], ... }
// where ti_j_k is the ns uid i spent running on the jth cluster at the cluster's kth lowest freq.
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
getUidsCpuFreqTimes() {
    if (!gInitialized && !initGlobals()) return {};

    int fd = bpf_obj_get(BPF_FS_PATH "map_time_in_state_uid_times_map");
    if (fd < 0) return {};
    BpfMap<time_key_t, val_t> m(fd);

    std::vector<std::unordered_map<uint32_t, uint32_t>> policyFreqIdxs;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        std::unordered_map<uint32_t, uint32_t> freqIdxs;
        for (size_t j = 0; j < gPolicyFreqs[i].size(); ++j) freqIdxs[gPolicyFreqs[i][j]] = j;
        policyFreqIdxs.emplace_back(freqIdxs);
    }
    std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>> map;
    auto fn = [&map, &policyFreqIdxs](const time_key_t &key, const val_t &val,
                                             const BpfMap<time_key_t, val_t> &) {
        if (map.find(key.uid) == map.end()) {
            map[key.uid].resize(gNPolicies);
            for (uint32_t i = 0; i < gNPolicies; ++i) {
                map[key.uid][i].resize(gPolicyFreqs[i].size(), 0);
            }
        }

        for (size_t policy = 0; policy < gNPolicies; ++policy) {
            for (const auto &cpu : gPolicyCpus[policy]) {
                auto freqIdx = policyFreqIdxs[policy][key.freq];
                map[key.uid][policy][freqIdx] += val.ar[cpu];
            }
        }
        return android::netdutils::status::ok;
    };
    if (isOk(m.iterateWithValue(fn))) return map;
    return {};
}

// Clear all time in state data for a given uid. Returns false on error, true otherwise.
bool clearUidCpuFreqTimes(uint32_t uid) {
    if (!gInitialized && !initGlobals()) return false;
    time_key_t key = {.uid = uid, .freq = 0};

    std::vector<uint32_t> idxs(gNPolicies, 0);
    for (auto freq : gAllFreqs) {
        key.freq = freq;
        if (deleteMapEntry(gMapFd, &key) && errno != ENOENT) return false;
    }
    return true;
}

} // namespace bpf
} // namespace android
