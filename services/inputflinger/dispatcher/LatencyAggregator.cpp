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

#define LOG_TAG "LatencyAggregator"
#include "LatencyAggregator.h"

#include <inttypes.h>

#include <android-base/stringprintf.h>
#include <input/Input.h>
#include <log/log.h>
#include <server_configurable_flags/get_flags.h>

using android::base::StringPrintf;
using std::chrono_literals::operator""ms;

// Category (=namespace) name for the input settings that are applied at boot time
static const char* INPUT_NATIVE_BOOT = "input_native_boot";
// Feature flag name for the threshold of end-to-end touch latency that would trigger
// SlowEventReported atom to be pushed
static const char* SLOW_EVENT_MIN_REPORTING_LATENCY_MILLIS =
        "slow_event_min_reporting_latency_millis";
// Feature flag name for the minimum delay before reporting a slow event after having just reported
// a slow event. This helps limit the amount of data sent to the server
static const char* SLOW_EVENT_MIN_REPORTING_INTERVAL_MILLIS =
        "slow_event_min_reporting_interval_millis";

// If an event has end-to-end latency > 200 ms, it will get reported as a slow event.
std::chrono::milliseconds DEFAULT_SLOW_EVENT_MIN_REPORTING_LATENCY = 200ms;
// If we receive two slow events less than 1 min apart, we will only report 1 of them.
std::chrono::milliseconds DEFAULT_SLOW_EVENT_MIN_REPORTING_INTERVAL = 60000ms;

static std::chrono::milliseconds getSlowEventMinReportingLatency() {
    std::string millis = server_configurable_flags::
            GetServerConfigurableFlag(INPUT_NATIVE_BOOT, SLOW_EVENT_MIN_REPORTING_LATENCY_MILLIS,
                                      std::to_string(
                                              DEFAULT_SLOW_EVENT_MIN_REPORTING_LATENCY.count()));
    return std::chrono::milliseconds(std::stoi(millis));
}

static std::chrono::milliseconds getSlowEventMinReportingInterval() {
    std::string millis = server_configurable_flags::
            GetServerConfigurableFlag(INPUT_NATIVE_BOOT, SLOW_EVENT_MIN_REPORTING_INTERVAL_MILLIS,
                                      std::to_string(
                                              DEFAULT_SLOW_EVENT_MIN_REPORTING_INTERVAL.count()));
    return std::chrono::milliseconds(std::stoi(millis));
}

namespace android::inputdispatcher {

void Sketch::addValue(nsecs_t value) {
    // TODO(b/167947340): replace with real sketch
}

android::util::BytesField Sketch::serialize() {
    return android::util::BytesField("TODO(b/167947340): use real sketch data", 4 /*length*/);
}

void Sketch::reset() {
    // TODO(b/167947340): reset the sketch
}

LatencyAggregator::LatencyAggregator() {
    AStatsManager_setPullAtomCallback(android::util::INPUT_EVENT_LATENCY_SKETCH, nullptr,
                                      LatencyAggregator::pullAtomCallback, this);
}

LatencyAggregator::~LatencyAggregator() {
    AStatsManager_clearPullAtomCallback(android::util::INPUT_EVENT_LATENCY_SKETCH);
}

AStatsManager_PullAtomCallbackReturn LatencyAggregator::pullAtomCallback(int32_t atomTag,
                                                                         AStatsEventList* data,
                                                                         void* cookie) {
    LatencyAggregator* pAggregator = reinterpret_cast<LatencyAggregator*>(cookie);
    if (pAggregator == nullptr) {
        LOG_ALWAYS_FATAL("pAggregator is null!");
    }
    return pAggregator->pullData(data);
}

void LatencyAggregator::processTimeline(const InputEventTimeline& timeline) {
    processStatistics(timeline);
    processSlowEvent(timeline);
}

void LatencyAggregator::processStatistics(const InputEventTimeline& timeline) {
    std::array<Sketch, SketchIndex::SIZE>& sketches =
            timeline.isDown ? mDownSketches : mMoveSketches;

    // Process common ones first
    const nsecs_t eventToRead = timeline.readTime - timeline.eventTime;

    sketches[SketchIndex::EVENT_TO_READ].addValue(eventToRead);

    // Now process per-connection ones
    for (const auto& [connectionToken, connectionTimeline] : timeline.connectionTimelines) {
        if (!connectionTimeline.isComplete()) {
            continue;
        }
        const nsecs_t readToDeliver = connectionTimeline.deliveryTime - timeline.readTime;
        const nsecs_t deliverToConsume =
                connectionTimeline.consumeTime - connectionTimeline.deliveryTime;
        const nsecs_t consumeToFinish =
                connectionTimeline.finishTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompletedTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME];
        const nsecs_t presentTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME];
        const nsecs_t consumeToGpuComplete = gpuCompletedTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompleteToPresent = presentTime - gpuCompletedTime;
        const nsecs_t endToEnd = presentTime - timeline.eventTime;

        sketches[SketchIndex::READ_TO_DELIVER].addValue(readToDeliver);
        sketches[SketchIndex::DELIVER_TO_CONSUME].addValue(deliverToConsume);
        sketches[SketchIndex::CONSUME_TO_FINISH].addValue(consumeToFinish);
        sketches[SketchIndex::CONSUME_TO_GPU_COMPLETE].addValue(consumeToGpuComplete);
        sketches[SketchIndex::GPU_COMPLETE_TO_PRESENT].addValue(gpuCompleteToPresent);
        sketches[SketchIndex::END_TO_END].addValue(endToEnd);
    }
}

AStatsManager_PullAtomCallbackReturn LatencyAggregator::pullData(AStatsEventList* data) {
    android::util::addAStatsEvent(data, android::util::INPUT_EVENT_LATENCY_SKETCH,
                                  // DOWN sketches
                                  mDownSketches[SketchIndex::EVENT_TO_READ].serialize(),
                                  mDownSketches[SketchIndex::READ_TO_DELIVER].serialize(),
                                  mDownSketches[SketchIndex::DELIVER_TO_CONSUME].serialize(),
                                  mDownSketches[SketchIndex::CONSUME_TO_FINISH].serialize(),
                                  mDownSketches[SketchIndex::CONSUME_TO_GPU_COMPLETE].serialize(),
                                  mDownSketches[SketchIndex::GPU_COMPLETE_TO_PRESENT].serialize(),
                                  mDownSketches[SketchIndex::END_TO_END].serialize(),
                                  // MOVE sketches
                                  mMoveSketches[SketchIndex::EVENT_TO_READ].serialize(),
                                  mMoveSketches[SketchIndex::READ_TO_DELIVER].serialize(),
                                  mMoveSketches[SketchIndex::DELIVER_TO_CONSUME].serialize(),
                                  mMoveSketches[SketchIndex::CONSUME_TO_FINISH].serialize(),
                                  mMoveSketches[SketchIndex::CONSUME_TO_GPU_COMPLETE].serialize(),
                                  mMoveSketches[SketchIndex::GPU_COMPLETE_TO_PRESENT].serialize(),
                                  mMoveSketches[SketchIndex::END_TO_END].serialize());

    for (size_t i = 0; i < SketchIndex::SIZE; i++) {
        mDownSketches[i].reset();
        mMoveSketches[i].reset();
    }
    return AStatsManager_PULL_SUCCESS;
}

void LatencyAggregator::processSlowEvent(const InputEventTimeline& timeline) {
    static const std::chrono::duration sSlowEventThreshold = getSlowEventMinReportingLatency();
    static const std::chrono::duration sSlowEventReportingInterval =
            getSlowEventMinReportingInterval();
    for (const auto& [token, connectionTimeline] : timeline.connectionTimelines) {
        if (!connectionTimeline.isComplete()) {
            continue;
        }
        mNumEventsSinceLastSlowEventReport++;
        const nsecs_t presentTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME];
        const std::chrono::nanoseconds endToEndLatency =
                std::chrono::nanoseconds(presentTime - timeline.eventTime);
        if (endToEndLatency < sSlowEventThreshold) {
            continue;
        }
        // This is a slow event. Before we report it, check if we are reporting too often
        const std::chrono::duration elapsedSinceLastReport =
                std::chrono::nanoseconds(timeline.eventTime - mLastSlowEventTime);
        if (elapsedSinceLastReport < sSlowEventReportingInterval) {
            mNumSkippedSlowEvents++;
            continue;
        }

        const nsecs_t eventToRead = timeline.readTime - timeline.eventTime;
        const nsecs_t readToDeliver = connectionTimeline.deliveryTime - timeline.readTime;
        const nsecs_t deliverToConsume =
                connectionTimeline.consumeTime - connectionTimeline.deliveryTime;
        const nsecs_t consumeToFinish =
                connectionTimeline.finishTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompletedTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME];
        const nsecs_t consumeToGpuComplete = gpuCompletedTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompleteToPresent = presentTime - gpuCompletedTime;

        android::util::stats_write(android::util::SLOW_INPUT_EVENT_REPORTED, timeline.isDown,
                                   static_cast<int32_t>(ns2us(eventToRead)),
                                   static_cast<int32_t>(ns2us(readToDeliver)),
                                   static_cast<int32_t>(ns2us(deliverToConsume)),
                                   static_cast<int32_t>(ns2us(consumeToFinish)),
                                   static_cast<int32_t>(ns2us(consumeToGpuComplete)),
                                   static_cast<int32_t>(ns2us(gpuCompleteToPresent)),
                                   static_cast<int32_t>(ns2us(endToEndLatency.count())),
                                   static_cast<int32_t>(mNumEventsSinceLastSlowEventReport),
                                   static_cast<int32_t>(mNumSkippedSlowEvents));
        mNumEventsSinceLastSlowEventReport = 0;
        mNumSkippedSlowEvents = 0;
        mLastSlowEventTime = timeline.readTime;
    }
}

std::string LatencyAggregator::dump(const char* prefix) {
    return StringPrintf("%sLatencyAggregator:", prefix) +
            StringPrintf("\n%s  mLastSlowEventTime=%" PRId64, prefix, mLastSlowEventTime) +
            StringPrintf("\n%s  mNumEventsSinceLastSlowEventReport = %zu", prefix,
                         mNumEventsSinceLastSlowEventReport) +
            StringPrintf("\n%s  mNumSkippedSlowEvents = %zu", prefix, mNumSkippedSlowEvents);
}

} // namespace android::inputdispatcher
