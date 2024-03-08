/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/thread_annotations.h>
#include <kll.h>
#include <statslog.h>
#include <utils/Timers.h>

#include "InputEventTimeline.h"

namespace android::inputdispatcher {

enum SketchIndex : size_t {
    EVENT_TO_READ = 0,
    READ_TO_DELIVER = 1,
    DELIVER_TO_CONSUME = 2,
    CONSUME_TO_FINISH = 3,
    CONSUME_TO_GPU_COMPLETE = 4,
    GPU_COMPLETE_TO_PRESENT = 5,
    END_TO_END = 6, // EVENT_TO_PRESENT
    SIZE = 7,       // Must be last
};

// Let's create a full timeline here:
// eventTime
// readTime
// <---- after this point, the data becomes per-connection
// deliveryTime // time at which the event was sent to the receiver
// consumeTime  // time at which the receiver read the event
// finishTime   // time at which the finish event was received
// GraphicsTimeline::GPU_COMPLETED_TIME
// GraphicsTimeline::PRESENT_TIME

/**
 * Keep sketches of the provided events and report slow events
 */
class LatencyAggregator final : public InputEventTimelineProcessor {
public:
    LatencyAggregator();
    /**
     * Record a complete event timeline
     */
    void processTimeline(const InputEventTimeline& timeline) override;

    std::string dump(const char* prefix) const;

    ~LatencyAggregator();

private:
    // Binder call -- called on a binder thread. This is different from the thread where the rest of
    // the public API is called.
    static AStatsManager_PullAtomCallbackReturn pullAtomCallback(int32_t atom_tag,
                                                                 AStatsEventList* data,
                                                                 void* cookie);
    AStatsManager_PullAtomCallbackReturn pullData(AStatsEventList* data);

    // ---------- Slow event handling ----------
    void processSlowEvent(const InputEventTimeline& timeline);
    nsecs_t mLastSlowEventTime = 0;
    // How many slow events have been skipped due to rate limiting
    size_t mNumSkippedSlowEvents = 0;
    // How many events have been received since the last time we reported a slow event
    size_t mNumEventsSinceLastSlowEventReport = 0;

    // ---------- Statistics handling ----------
    // Statistics is pulled rather than pushed. It's pulled on a binder thread, and therefore will
    // be accessed by two different threads. The lock is needed to protect the pulled data.
    mutable std::mutex mLock;
    void processStatistics(const InputEventTimeline& timeline);
    // Sketches
    std::array<std::unique_ptr<dist_proc::aggregation::KllQuantile>, SketchIndex::SIZE>
            mDownSketches GUARDED_BY(mLock);
    std::array<std::unique_ptr<dist_proc::aggregation::KllQuantile>, SketchIndex::SIZE>
            mMoveSketches GUARDED_BY(mLock);
    // How many events have been processed so far
    size_t mNumSketchEventsProcessed GUARDED_BY(mLock) = 0;
};

} // namespace android::inputdispatcher
