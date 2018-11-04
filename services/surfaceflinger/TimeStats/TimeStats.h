/*
 * Copyright 2018 The Android Open Source Project
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

#include <timestatsproto/TimeStatsHelper.h>
#include <timestatsproto/TimeStatsProtoHeader.h>

#include <hardware/hwcomposer_defs.h>

#include <ui/FenceTime.h>

#include <utils/String16.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>

using namespace android::surfaceflinger;

namespace android {
class String8;

class TimeStats {
    // TODO(zzyiwei): Bound the timeStatsTracker with weighted LRU
    // static const size_t MAX_NUM_LAYER_RECORDS = 200;
    static const size_t MAX_NUM_TIME_RECORDS = 64;

    struct FrameTime {
        uint64_t frameNumber = 0;
        nsecs_t postTime = 0;
        nsecs_t latchTime = 0;
        nsecs_t acquireTime = 0;
        nsecs_t desiredTime = 0;
        nsecs_t presentTime = 0;
    };

    struct TimeRecord {
        bool ready = false;
        FrameTime frameTime;
        std::shared_ptr<FenceTime> acquireFence;
        std::shared_ptr<FenceTime> presentFence;
    };

    struct LayerRecord {
        std::string layerName;
        // This is the index in timeRecords, at which the timestamps for that
        // specific frame are still not fully received. This is not waiting for
        // fences to signal, but rather waiting to receive those fences/timestamps.
        int32_t waitData = -1;
        uint32_t droppedFrames = 0;
        TimeRecord prevTimeRecord;
        std::deque<TimeRecord> timeRecords;
    };

    struct PowerTime {
        int32_t powerMode = HWC_POWER_MODE_OFF;
        nsecs_t prevTime = 0;
    };

    struct GlobalRecord {
        nsecs_t prevPresentTime = 0;
        std::deque<std::shared_ptr<FenceTime>> presentFences;
    };

public:
    static TimeStats& getInstance();
    void parseArgs(bool asProto, const Vector<String16>& args, size_t& index, String8& result);
    void incrementTotalFrames();
    void incrementMissedFrames();
    void incrementClientCompositionFrames();

    void setPostTime(int32_t layerID, uint64_t frameNumber, const std::string& layerName,
                     nsecs_t postTime);
    void setLatchTime(int32_t layerID, uint64_t frameNumber, nsecs_t latchTime);
    void setDesiredTime(int32_t layerID, uint64_t frameNumber, nsecs_t desiredTime);
    void setAcquireTime(int32_t layerID, uint64_t frameNumber, nsecs_t acquireTime);
    void setAcquireFence(int32_t layerID, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& acquireFence);
    void setPresentTime(int32_t layerID, uint64_t frameNumber, nsecs_t presentTime);
    void setPresentFence(int32_t layerID, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& presentFence);
    // On producer disconnect with BufferQueue.
    void onDisconnect(int32_t layerID);
    // On layer tear down.
    void onDestroy(int32_t layerID);
    // When SF is cleaning up the queue, clear the LayerRecord as well.
    void clearLayerRecord(int32_t layerID);
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    void removeTimeRecord(int32_t layerID, uint64_t frameNumber);

    void setPowerMode(int32_t powerMode);
    void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence);

private:
    TimeStats() = default;

    bool recordReadyLocked(int32_t layerID, TimeRecord* timeRecord);
    void flushAvailableRecordsToStatsLocked(int32_t layerID);
    void flushPowerTimeLocked();
    void flushAvailableGlobalRecordsToStatsLocked();

    void enable();
    void disable();
    void clear();
    bool isEnabled();
    void dump(bool asProto, std::optional<uint32_t> maxLayers, String8& result);

    std::atomic<bool> mEnabled = false;
    std::mutex mMutex;
    TimeStatsHelper::TimeStatsGlobal mTimeStats;
    // Hashmap for LayerRecord with layerID as the hash key
    std::unordered_map<int32_t, LayerRecord> mTimeStatsTracker;
    PowerTime mPowerTime;
    GlobalRecord mGlobalRecord;
};

} // namespace android
