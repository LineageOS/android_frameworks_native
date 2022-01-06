/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "GpuWork"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "gpuwork/GpuWork.h"

#include <android-base/stringprintf.h>
#include <binder/PermissionCache.h>
#include <bpf/WaitForProgsLoaded.h>
#include <libbpf.h>
#include <libbpf_android.h>
#include <log/log.h>
#include <random>
#include <stats_event.h>
#include <statslog.h>
#include <unistd.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <bit>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "gpuwork/gpu_work.h"

#define MS_IN_NS (1000000)

namespace android {
namespace gpuwork {

namespace {

// Gets a BPF map from |mapPath|.
template <class Key, class Value>
bool getBpfMap(const char* mapPath, bpf::BpfMap<Key, Value>* out) {
    errno = 0;
    auto map = bpf::BpfMap<Key, Value>(mapPath);
    if (!map.isValid()) {
        ALOGW("Failed to create bpf map from %s [%d(%s)]", mapPath, errno, strerror(errno));
        return false;
    }
    *out = std::move(map);
    return true;
}

template <typename SourceType>
inline int32_t cast_int32(SourceType) = delete;

template <typename SourceType>
inline int32_t bitcast_int32(SourceType) = delete;

template <>
inline int32_t bitcast_int32<uint32_t>(uint32_t source) {
    int32_t result;
    memcpy(&result, &source, sizeof(result));
    return result;
}

template <>
inline int32_t cast_int32<uint64_t>(uint64_t source) {
    if (source > std::numeric_limits<int32_t>::max()) {
        return std::numeric_limits<int32_t>::max();
    }
    return static_cast<int32_t>(source);
}

template <>
inline int32_t cast_int32<long long>(long long source) {
    if (source > std::numeric_limits<int32_t>::max()) {
        return std::numeric_limits<int32_t>::max();
    } else if (source < std::numeric_limits<int32_t>::min()) {
        return std::numeric_limits<int32_t>::min();
    }
    return static_cast<int32_t>(source);
}

} // namespace

using base::StringAppendF;

GpuWork::~GpuWork() {
    // If we created our clearer thread, then we must stop it and join it.
    if (mMapClearerThread.joinable()) {
        // Tell the thread to terminate.
        {
            std::scoped_lock<std::mutex> lock(mMutex);
            mIsTerminating = true;
            mIsTerminatingConditionVariable.notify_all();
        }

        // Now, we can join it.
        mMapClearerThread.join();
    }

    {
        std::scoped_lock<std::mutex> lock(mMutex);
        if (mStatsdRegistered) {
            AStatsManager_clearPullAtomCallback(android::util::GPU_FREQ_TIME_IN_STATE_PER_UID);
        }
    }

    bpf_detach_tracepoint("power", "gpu_work_period");
}

void GpuWork::initialize() {
    // Make sure BPF programs are loaded.
    bpf::waitForProgsLoaded();

    waitForPermissions();

    // Get the BPF maps before trying to attach the BPF program; if we can't get
    // the maps then there is no point in attaching the BPF program.
    {
        std::lock_guard<std::mutex> lock(mMutex);

        if (!getBpfMap("/sys/fs/bpf/map_gpu_work_gpu_work_map", &mGpuWorkMap)) {
            return;
        }

        if (!getBpfMap("/sys/fs/bpf/map_gpu_work_gpu_work_global_data", &mGpuWorkGlobalDataMap)) {
            return;
        }

        mPreviousMapClearTimePoint = std::chrono::steady_clock::now();
    }

    // Attach the tracepoint ONLY if we got the map above.
    if (!attachTracepoint("/sys/fs/bpf/prog_gpu_work_tracepoint_power_gpu_work_period", "power",
                          "gpu_work_period")) {
        return;
    }

    // Create the map clearer thread, and store it to |mMapClearerThread|.
    std::thread thread([this]() { periodicallyClearMap(); });

    mMapClearerThread.swap(thread);

    {
        std::lock_guard<std::mutex> lock(mMutex);
        AStatsManager_setPullAtomCallback(int32_t{android::util::GPU_FREQ_TIME_IN_STATE_PER_UID},
                                          nullptr, GpuWork::pullAtomCallback, this);
        mStatsdRegistered = true;
    }

    ALOGI("Initialized!");

    mInitialized.store(true);
}

void GpuWork::dump(const Vector<String16>& /* args */, std::string* result) {
    if (!mInitialized.load()) {
        result->append("GPU time in state information is not available.\n");
        return;
    }

    // Ordered map ensures output data is sorted by UID.
    std::map<Uid, UidTrackingInfo> dumpMap;

    {
        std::lock_guard<std::mutex> lock(mMutex);

        if (!mGpuWorkMap.isValid()) {
            result->append("GPU time in state map is not available.\n");
            return;
        }

        // Iteration of BPF hash maps can be unreliable (no data races, but elements
        // may be repeated), as the map is typically being modified by other
        // threads. The buckets are all preallocated. Our eBPF program only updates
        // entries (in-place) or adds entries. |GpuWork| only iterates or clears the
        // map while holding |mMutex|. Given this, we should be able to iterate over
        // all elements reliably. In the worst case, we might see elements more than
        // once.

        // Note that userspace reads of BPF maps make a copy of the value, and
        // thus the returned value is not being concurrently accessed by the BPF
        // program (no atomic reads needed below).

        mGpuWorkMap.iterateWithValue([&dumpMap](const Uid& key, const UidTrackingInfo& value,
                                                const android::bpf::BpfMap<Uid, UidTrackingInfo>&)
                                             -> base::Result<void> {
            dumpMap[key] = value;
            return {};
        });
    }

    // Find the largest frequency where some UID has spent time in that frequency.
    size_t largestFrequencyWithTime = 0;
    for (const auto& uidToUidInfo : dumpMap) {
        for (size_t i = largestFrequencyWithTime + 1; i < kNumTrackedFrequencies; ++i) {
            if (uidToUidInfo.second.frequency_times_ns[i] > 0) {
                largestFrequencyWithTime = i;
            }
        }
    }

    // Dump time in state information.
    // E.g.
    // uid/freq: 0MHz 50MHz 100MHz ...
    // 1000: 0 0 0 0 ...
    // 1003: 0 0 3456 0 ...
    // [errors:3]1006: 0 0 3456 0 ...

    // Header.
    result->append("GPU time in frequency state in ms.\n");
    result->append("uid/freq: 0MHz");
    for (size_t i = 1; i <= largestFrequencyWithTime; ++i) {
        StringAppendF(result, " %zuMHz", i * 50);
    }
    result->append("\n");

    for (const auto& uidToUidInfo : dumpMap) {
        if (uidToUidInfo.second.error_count) {
            StringAppendF(result, "[errors:%" PRIu32 "]", uidToUidInfo.second.error_count);
        }
        StringAppendF(result, "%" PRIu32 ":", uidToUidInfo.first);
        for (size_t i = 0; i <= largestFrequencyWithTime; ++i) {
            StringAppendF(result, " %" PRIu64,
                          uidToUidInfo.second.frequency_times_ns[i] / MS_IN_NS);
        }
        result->append("\n");
    }
}

bool GpuWork::attachTracepoint(const char* programPath, const char* tracepointGroup,
                               const char* tracepointName) {
    errno = 0;
    base::unique_fd fd(bpf::retrieveProgram(programPath));
    if (fd < 0) {
        ALOGW("Failed to retrieve pinned program from %s [%d(%s)]", programPath, errno,
              strerror(errno));
        return false;
    }

    // Attach the program to the tracepoint. The tracepoint is automatically enabled.
    errno = 0;
    int count = 0;
    while (bpf_attach_tracepoint(fd.get(), tracepointGroup, tracepointName) < 0) {
        if (++count > kGpuWaitTimeoutSeconds) {
            ALOGW("Failed to attach bpf program to %s/%s tracepoint [%d(%s)]", tracepointGroup,
                  tracepointName, errno, strerror(errno));
            return false;
        }
        // Retry until GPU driver loaded or timeout.
        sleep(1);
        errno = 0;
    }

    return true;
}

AStatsManager_PullAtomCallbackReturn GpuWork::pullAtomCallback(int32_t atomTag,
                                                               AStatsEventList* data,
                                                               void* cookie) {
    ATRACE_CALL();

    GpuWork* gpuWork = reinterpret_cast<GpuWork*>(cookie);
    if (atomTag == android::util::GPU_FREQ_TIME_IN_STATE_PER_UID) {
        return gpuWork->pullFrequencyAtoms(data);
    }

    return AStatsManager_PULL_SKIP;
}

AStatsManager_PullAtomCallbackReturn GpuWork::pullFrequencyAtoms(AStatsEventList* data) {
    ATRACE_CALL();

    if (!data || !mInitialized.load()) {
        return AStatsManager_PULL_SKIP;
    }

    std::lock_guard<std::mutex> lock(mMutex);

    if (!mGpuWorkMap.isValid()) {
        return AStatsManager_PULL_SKIP;
    }

    std::unordered_map<Uid, UidTrackingInfo> uidInfos;

    // Iteration of BPF hash maps can be unreliable (no data races, but elements
    // may be repeated), as the map is typically being modified by other
    // threads. The buckets are all preallocated. Our eBPF program only updates
    // entries (in-place) or adds entries. |GpuWork| only iterates or clears the
    // map while holding |mMutex|. Given this, we should be able to iterate over
    // all elements reliably. In the worst case, we might see elements more than
    // once.

    // Note that userspace reads of BPF maps make a copy of the value, and thus
    // the returned value is not being concurrently accessed by the BPF program
    // (no atomic reads needed below).

    mGpuWorkMap.iterateWithValue(
            [&uidInfos](const Uid& key, const UidTrackingInfo& value,
                        const android::bpf::BpfMap<Uid, UidTrackingInfo>&) -> base::Result<void> {
                uidInfos[key] = value;
                return {};
            });

    ALOGI("pullFrequencyAtoms: uidInfos.size() == %zu", uidInfos.size());

    // Get a list of just the UIDs; the order does not matter.
    std::vector<Uid> uids;
    for (const auto& pair : uidInfos) {
        uids.push_back(pair.first);
    }

    std::random_device device;
    std::default_random_engine random_engine(device());

    // If we have more than |kNumSampledUids| UIDs, choose |kNumSampledUids|
    // random UIDs. We swap them to the front of the list. Given the list
    // indices 0..i..n-1, we have the following inclusive-inclusive ranges:
    // - [0, i-1] == the randomly chosen elements.
    // - [i, n-1] == the remaining unchosen elements.
    if (uids.size() > kNumSampledUids) {
        for (size_t i = 0; i < kNumSampledUids; ++i) {
            std::uniform_int_distribution<size_t> uniform_dist(i, uids.size() - 1);
            size_t random_index = uniform_dist(random_engine);
            std::swap(uids[i], uids[random_index]);
        }
        // Only keep the front |kNumSampledUids| elements.
        uids.resize(kNumSampledUids);
    }

    ALOGI("pullFrequencyAtoms: uids.size() == %zu", uids.size());

    auto now = std::chrono::steady_clock::now();

    int32_t duration = cast_int32(
            std::chrono::duration_cast<std::chrono::seconds>(now - mPreviousMapClearTimePoint)
                    .count());

    for (const Uid uid : uids) {
        const UidTrackingInfo& info = uidInfos[uid];
        ALOGI("pullFrequencyAtoms: adding stats for UID %" PRIu32, uid);
        android::util::addAStatsEvent(data, int32_t{android::util::GPU_FREQ_TIME_IN_STATE_PER_UID},
                                      // uid
                                      bitcast_int32(uid),
                                      // time_duration_seconds
                                      int32_t{duration},
                                      // max_freq_mhz
                                      int32_t{1000},
                                      // freq_0_mhz_time_millis
                                      cast_int32(info.frequency_times_ns[0] / 1000000),
                                      // freq_50_mhz_time_millis
                                      cast_int32(info.frequency_times_ns[1] / 1000000),
                                      // ... etc. ...
                                      cast_int32(info.frequency_times_ns[2] / 1000000),
                                      cast_int32(info.frequency_times_ns[3] / 1000000),
                                      cast_int32(info.frequency_times_ns[4] / 1000000),
                                      cast_int32(info.frequency_times_ns[5] / 1000000),
                                      cast_int32(info.frequency_times_ns[6] / 1000000),
                                      cast_int32(info.frequency_times_ns[7] / 1000000),
                                      cast_int32(info.frequency_times_ns[8] / 1000000),
                                      cast_int32(info.frequency_times_ns[9] / 1000000),
                                      cast_int32(info.frequency_times_ns[10] / 1000000),
                                      cast_int32(info.frequency_times_ns[11] / 1000000),
                                      cast_int32(info.frequency_times_ns[12] / 1000000),
                                      cast_int32(info.frequency_times_ns[13] / 1000000),
                                      cast_int32(info.frequency_times_ns[14] / 1000000),
                                      cast_int32(info.frequency_times_ns[15] / 1000000),
                                      cast_int32(info.frequency_times_ns[16] / 1000000),
                                      cast_int32(info.frequency_times_ns[17] / 1000000),
                                      cast_int32(info.frequency_times_ns[18] / 1000000),
                                      cast_int32(info.frequency_times_ns[19] / 1000000),
                                      // freq_1000_mhz_time_millis
                                      cast_int32(info.frequency_times_ns[20] / 1000000));
    }
    clearMap();
    return AStatsManager_PULL_SUCCESS;
}

void GpuWork::periodicallyClearMap() {
    std::unique_lock<std::mutex> lock(mMutex);

    auto previousTime = std::chrono::steady_clock::now();

    while (true) {
        if (mIsTerminating) {
            break;
        }
        auto nextTime = std::chrono::steady_clock::now();
        auto differenceSeconds =
                std::chrono::duration_cast<std::chrono::seconds>(nextTime - previousTime);
        if (differenceSeconds.count() > kMapClearerWaitDurationSeconds) {
            // It has been >1 hour, so clear the map, if needed.
            clearMapIfNeeded();
            // We only update |previousTime| if we actually checked the map.
            previousTime = nextTime;
        }
        // Sleep for ~1 hour. It does not matter if we don't check the map for 2
        // hours.
        mIsTerminatingConditionVariable.wait_for(lock,
                                                 std::chrono::seconds{
                                                         kMapClearerWaitDurationSeconds});
    }
}

void GpuWork::clearMapIfNeeded() {
    if (!mInitialized.load() || !mGpuWorkMap.isValid() || !mGpuWorkGlobalDataMap.isValid()) {
        ALOGW("Map clearing could not occur because we are not initialized properly");
        return;
    }

    base::Result<GlobalData> globalData = mGpuWorkGlobalDataMap.readValue(0);
    if (!globalData.ok()) {
        ALOGW("Could not read BPF global data map entry");
        return;
    }

    // Note that userspace reads of BPF maps make a copy of the value, and thus
    // the return value is not being concurrently accessed by the BPF program
    // (no atomic reads needed below).

    uint64_t numEntries = globalData.value().num_map_entries;

    // If the map is <=75% full, we do nothing.
    if (numEntries <= (kMaxTrackedUids / 4) * 3) {
        return;
    }

    clearMap();
}

void GpuWork::clearMap() {
    if (!mInitialized.load() || !mGpuWorkMap.isValid() || !mGpuWorkGlobalDataMap.isValid()) {
        ALOGW("Map clearing could not occur because we are not initialized properly");
        return;
    }

    base::Result<GlobalData> globalData = mGpuWorkGlobalDataMap.readValue(0);
    if (!globalData.ok()) {
        ALOGW("Could not read BPF global data map entry");
        return;
    }

    // Iterating BPF maps to delete keys is tricky. If we just repeatedly call
    // |getFirstKey()| and delete that, we may loop forever (or for a long time)
    // because our BPF program might be repeatedly re-adding UID keys. Also,
    // even if we limit the number of elements we try to delete, we might only
    // delete new entries, leaving old entries in the map. If we delete a key A
    // and then call |getNextKey(A)|, the first key in the map is returned, so
    // we have the same issue.
    //
    // Thus, we instead get the next key and then delete the previous key. We
    // also limit the number of deletions we try, just in case.

    base::Result<Uid> key = mGpuWorkMap.getFirstKey();

    for (size_t i = 0; i < kMaxTrackedUids; ++i) {
        if (!key.ok()) {
            break;
        }
        base::Result<Uid> previousKey = key;
        key = mGpuWorkMap.getNextKey(previousKey.value());
        mGpuWorkMap.deleteValue(previousKey.value());
    }

    // Reset our counter; |globalData| is a copy of the data, so we have to use
    // |writeValue|.
    globalData.value().num_map_entries = 0;
    mGpuWorkGlobalDataMap.writeValue(0, globalData.value(), BPF_ANY);

    // Update |mPreviousMapClearTimePoint| so we know when we started collecting
    // the stats.
    mPreviousMapClearTimePoint = std::chrono::steady_clock::now();
}

void GpuWork::waitForPermissions() {
    const String16 permissionRegisterStatsPullAtom(kPermissionRegisterStatsPullAtom);
    int count = 0;
    while (!PermissionCache::checkPermission(permissionRegisterStatsPullAtom, getpid(), getuid())) {
        if (++count > kPermissionsWaitTimeoutSeconds) {
            ALOGW("Timed out waiting for android.permission.REGISTER_STATS_PULL_ATOM");
            return;
        }
        // Retry.
        sleep(1);
    }
}

} // namespace gpuwork
} // namespace android
