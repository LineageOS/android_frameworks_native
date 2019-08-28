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

#include <hardware/hwcomposer_defs.h>
#include <perfetto/trace/android/graphics_frame_event.pbzero.h>
#include <perfetto/tracing.h>
#include <timestatsproto/TimeStatsHelper.h>
#include <timestatsproto/TimeStatsProtoHeader.h>
#include <ui/FenceTime.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>

using namespace android::surfaceflinger;

namespace android {

class TimeStats {
public:
    using FrameEvent = perfetto::protos::pbzero::GraphicsFrameEvent;

    virtual ~TimeStats() = default;

    // Sets up the perfetto tracing backend and data source.
    virtual void initializeTracing() = 0;
    // Registers the data source with the perfetto backend. Called as part of initializeTracing()
    // and should not be called manually outside of tests. Public to allow for substituting a
    // perfetto::kInProcessBackend in tests.
    virtual void registerTracingDataSource() = 0;
    // Starts tracking a new layer for tracing. Needs to be called once before traceTimestamp() or
    // traceFence() for each layer.
    virtual void traceNewLayer(int32_t layerID, const std::string& layerName) = 0;
    // Creates a trace point at the timestamp provided.
    virtual void traceTimestamp(int32_t layerID, uint64_t bufferID, uint64_t frameNumber,
                                nsecs_t timestamp, FrameEvent::BufferEventType type,
                                nsecs_t duration = 0) = 0;
    // Creates a trace point after the provided fence has been signalled. If a startTime is provided
    // the trace will have be timestamped from startTime until fence signalling time. If no
    // startTime is provided, a durationless trace point will be created timestamped at fence
    // signalling time. If the fence hasn't signalled yet, the trace point will be created the next
    // time after signalling a trace call for this buffer occurs.
    virtual void traceFence(int32_t layerID, uint64_t bufferID, uint64_t frameNumber,
                            const std::shared_ptr<FenceTime>& fence,
                            FrameEvent::BufferEventType type, nsecs_t startTime = 0) = 0;

    virtual void parseArgs(bool asProto, const Vector<String16>& args, std::string& result) = 0;
    virtual bool isEnabled() = 0;
    virtual std::string miniDump() = 0;

    virtual void incrementTotalFrames() = 0;
    virtual void incrementMissedFrames() = 0;
    virtual void incrementClientCompositionFrames() = 0;

    virtual void setPostTime(int32_t layerID, uint64_t frameNumber, const std::string& layerName,
                             nsecs_t postTime) = 0;
    virtual void setLatchTime(int32_t layerID, uint64_t frameNumber, nsecs_t latchTime) = 0;
    virtual void setDesiredTime(int32_t layerID, uint64_t frameNumber, nsecs_t desiredTime) = 0;
    virtual void setAcquireTime(int32_t layerID, uint64_t frameNumber, nsecs_t acquireTime) = 0;
    virtual void setAcquireFence(int32_t layerID, uint64_t frameNumber,
                                 const std::shared_ptr<FenceTime>& acquireFence) = 0;
    virtual void setPresentTime(int32_t layerID, uint64_t frameNumber, nsecs_t presentTime) = 0;
    virtual void setPresentFence(int32_t layerID, uint64_t frameNumber,
                                 const std::shared_ptr<FenceTime>& presentFence) = 0;
    // Clean up the layer record
    virtual void onDestroy(int32_t layerID) = 0;
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    virtual void removeTimeRecord(int32_t layerID, uint64_t frameNumber) = 0;

    virtual void setPowerMode(int32_t powerMode) = 0;
    // Source of truth is RefrehRateStats.
    virtual void recordRefreshRate(uint32_t fps, nsecs_t duration) = 0;
    virtual void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) = 0;

    static constexpr char kTimeStatsDataSource[] = "android.surfaceflinger.timestats";

    // The maximum amount of time a fence has to signal before it is discarded.
    // Used to avoid fence's from previous traces generating new trace points in later ones.
    // Public for testing.
    static constexpr nsecs_t kFenceSignallingDeadline = 60'000'000'000; // 60 seconds
};

namespace impl {

class TimeStats : public android::TimeStats {
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

    struct PendingFence {
        uint64_t frameNumber;
        FrameEvent::BufferEventType type;
        std::shared_ptr<FenceTime> fence;
        nsecs_t startTime;
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

    struct TraceRecord {
        std::string layerName;
        using BufferID = uint64_t;
        std::unordered_map<BufferID, std::vector<PendingFence>> pendingFences;
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
    class TimeStatsDataSource : public perfetto::DataSource<TimeStatsDataSource> {
        virtual void OnSetup(const SetupArgs&) override{};
        virtual void OnStart(const StartArgs&) override { ALOGV("TimeStats trace started"); };
        virtual void OnStop(const StopArgs&) override { ALOGV("TimeStats trace stopped"); };
    };

    TimeStats() = default;

    void initializeTracing() override;
    void registerTracingDataSource() override;
    void traceNewLayer(int32_t layerID, const std::string& layerName) override;
    void traceTimestamp(int32_t layerID, uint64_t bufferID, uint64_t frameNumber, nsecs_t timestamp,
                        FrameEvent::BufferEventType type, nsecs_t duration = 0) override;
    void traceFence(int32_t layerID, uint64_t bufferID, uint64_t frameNumber,
                    const std::shared_ptr<FenceTime>& fence, FrameEvent::BufferEventType type,
                    nsecs_t startTime = 0) override;

    void parseArgs(bool asProto, const Vector<String16>& args, std::string& result) override;
    bool isEnabled() override;
    std::string miniDump() override;

    void incrementTotalFrames() override;
    void incrementMissedFrames() override;
    void incrementClientCompositionFrames() override;

    void setPostTime(int32_t layerID, uint64_t frameNumber, const std::string& layerName,
                     nsecs_t postTime) override;
    void setLatchTime(int32_t layerID, uint64_t frameNumber, nsecs_t latchTime) override;
    void setDesiredTime(int32_t layerID, uint64_t frameNumber, nsecs_t desiredTime) override;
    void setAcquireTime(int32_t layerID, uint64_t frameNumber, nsecs_t acquireTime) override;
    void setAcquireFence(int32_t layerID, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& acquireFence) override;
    void setPresentTime(int32_t layerID, uint64_t frameNumber, nsecs_t presentTime) override;
    void setPresentFence(int32_t layerID, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& presentFence) override;
    // Clean up the layer record
    void onDestroy(int32_t layerID) override;
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    void removeTimeRecord(int32_t layerID, uint64_t frameNumber) override;

    void setPowerMode(int32_t powerMode) override;
    // Source of truth is RefrehRateStats.
    void recordRefreshRate(uint32_t fps, nsecs_t duration) override;
    void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) override;

    static const size_t MAX_NUM_TIME_RECORDS = 64;

private:
    // Checks if any pending fences for a layer and buffer have signalled and, if they have, creates
    // trace points for them.
    void tracePendingFencesLocked(TimeStatsDataSource::TraceContext& ctx, int32_t layerID,
                                  uint64_t bufferID);
    // Creates a trace point by translating a start time and an end time to a timestamp and
    // duration. If startTime is later than end time it sets end time as the timestamp and the
    // duration to 0. Used by traceFence().
    void traceSpanLocked(TimeStatsDataSource::TraceContext& ctx, int32_t layerID, uint64_t bufferID,
                         uint64_t frameNumber, FrameEvent::BufferEventType type, nsecs_t startTime,
                         nsecs_t endTime);
    void traceLocked(TimeStatsDataSource::TraceContext& ctx, int32_t layerID, uint64_t bufferID,
                     uint64_t frameNumber, nsecs_t timestamp, FrameEvent::BufferEventType type,
                     nsecs_t duration = 0);

    bool recordReadyLocked(int32_t layerID, TimeRecord* timeRecord);
    void flushAvailableRecordsToStatsLocked(int32_t layerID);
    void flushPowerTimeLocked();
    void flushAvailableGlobalRecordsToStatsLocked();

    void enable();
    void disable();
    void clear();
    void dump(bool asProto, std::optional<uint32_t> maxLayers, std::string& result);

    std::atomic<bool> mEnabled = false;
    std::mutex mMutex;
    TimeStatsHelper::TimeStatsGlobal mTimeStats;
    // Hashmap for LayerRecord with layerID as the hash key
    std::unordered_map<int32_t, LayerRecord> mTimeStatsTracker;
    PowerTime mPowerTime;
    GlobalRecord mGlobalRecord;

    std::mutex mTraceMutex;
    std::unordered_map<int32_t, TraceRecord> mTraceTracker;

    static const size_t MAX_NUM_LAYER_RECORDS = 200;
    static const size_t MAX_NUM_LAYER_STATS = 200;
};

} // namespace impl

} // namespace android
