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
#include <bpf/WaitForProgsLoaded.h>
#include <libbpf.h>
#include <libbpf_android.h>
#include <log/log.h>
#include <unistd.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <chrono>
#include <cstdint>
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

    bpf_detach_tracepoint("power", "gpu_work_period");
}

void GpuWork::initialize() {
    // Make sure BPF programs are loaded.
    bpf::waitForProgsLoaded();

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
    }

    // Attach the tracepoint ONLY if we got the map above.
    if (!attachTracepoint("/sys/fs/bpf/prog_gpu_work_tracepoint_power_gpu_work_period", "power",
                          "gpu_work_period")) {
        return;
    }

    // Create the map clearer thread, and store it to |mMapClearerThread|.
    std::thread thread([this]() { periodicallyClearMap(); });

    mMapClearerThread.swap(thread);

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
}

} // namespace gpuwork
} // namespace android
