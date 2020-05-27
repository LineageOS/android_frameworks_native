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

// #define LOG_NDEBUG 0

#include "LayerInfoV2.h"

#include <algorithm>
#include <utility>

#undef LOG_TAG
#define LOG_TAG "LayerInfoV2"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

namespace android::scheduler {

LayerInfoV2::LayerInfoV2(nsecs_t highRefreshRatePeriod, LayerHistory::LayerVoteType defaultVote)
      : mHighRefreshRatePeriod(highRefreshRatePeriod),
        mDefaultVote(defaultVote),
        mLayerVote({defaultVote, 0.0f}) {}

void LayerInfoV2::setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now,
                                     bool pendingConfigChange) {
    lastPresentTime = std::max(lastPresentTime, static_cast<nsecs_t>(0));

    mLastUpdatedTime = std::max(lastPresentTime, now);

    FrameTimeData frameTime = {.presetTime = lastPresentTime,
                               .queueTime = mLastUpdatedTime,
                               .pendingConfigChange = pendingConfigChange};

    mFrameTimes.push_back(frameTime);
    if (mFrameTimes.size() > HISTORY_SIZE) {
        mFrameTimes.pop_front();
    }
}

bool LayerInfoV2::isFrameTimeValid(const FrameTimeData& frameTime) const {
    return frameTime.queueTime >= std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          mFrameTimeValidSince.time_since_epoch())
                                          .count();
}

bool LayerInfoV2::isFrequent(nsecs_t now) const {
    // Find the first valid frame time
    auto it = mFrameTimes.begin();
    for (; it != mFrameTimes.end(); ++it) {
        if (isFrameTimeValid(*it)) {
            break;
        }
    }

    // If we know nothing about this layer we consider it as frequent as it might be the start
    // of an animation.
    if (std::distance(it, mFrameTimes.end()) < FREQUENT_LAYER_WINDOW_SIZE) {
        return true;
    }

    // Find the first active frame
    for (; it != mFrameTimes.end(); ++it) {
        if (it->queueTime >= getActiveLayerThreshold(now)) {
            break;
        }
    }

    const auto numFrames = std::distance(it, mFrameTimes.end());
    if (numFrames < FREQUENT_LAYER_WINDOW_SIZE) {
        return false;
    }

    // Layer is considered frequent if the average frame rate is higher than the threshold
    const auto totalTime = mFrameTimes.back().queueTime - it->queueTime;
    return (1e9f * (numFrames - 1)) / totalTime >= MIN_FPS_FOR_FREQUENT_LAYER;
}

bool LayerInfoV2::hasEnoughDataForHeuristic() const {
    // The layer had to publish at least HISTORY_SIZE or HISTORY_TIME of updates
    if (mFrameTimes.size() < 2) {
        return false;
    }

    if (!isFrameTimeValid(mFrameTimes.front())) {
        return false;
    }

    if (mFrameTimes.size() < HISTORY_SIZE &&
        mFrameTimes.back().queueTime - mFrameTimes.front().queueTime < HISTORY_TIME.count()) {
        return false;
    }

    return true;
}

std::pair<nsecs_t, bool> LayerInfoV2::calculateAverageFrameTime() const {
    nsecs_t totalPresentTimeDeltas = 0;
    nsecs_t totalQueueTimeDeltas = 0;
    bool missingPresentTime = false;
    int numFrames = 0;
    for (auto it = mFrameTimes.begin(); it != mFrameTimes.end() - 1; ++it) {
        // Ignore frames captured during a config change
        if (it->pendingConfigChange || (it + 1)->pendingConfigChange) {
            continue;
        }

        totalQueueTimeDeltas +=
                std::max(((it + 1)->queueTime - it->queueTime), mHighRefreshRatePeriod);
        numFrames++;

        if (it->presetTime == 0 || (it + 1)->presetTime == 0) {
            missingPresentTime = true;
            continue;
        }

        totalPresentTimeDeltas +=
                std::max(((it + 1)->presetTime - it->presetTime), mHighRefreshRatePeriod);
    }

    // Calculate the average frame time based on presentation timestamps. If those
    // doesn't exist, we look at the time the buffer was queued only. We can do that only if
    // we calculated a refresh rate based on presentation timestamps in the past. The reason
    // we look at the queue time is to handle cases where hwui attaches presentation timestamps
    // when implementing render ahead for specific refresh rates. When hwui no longer provides
    // presentation timestamps we look at the queue time to see if the current refresh rate still
    // matches the content.
    const auto averageFrameTime =
            static_cast<float>(missingPresentTime ? totalQueueTimeDeltas : totalPresentTimeDeltas) /
            numFrames;
    return {static_cast<nsecs_t>(averageFrameTime), missingPresentTime};
}

bool LayerInfoV2::isRefreshRateStable(nsecs_t averageFrameTime, bool missingPresentTime) const {
    for (auto it = mFrameTimes.begin(); it != mFrameTimes.end() - 1; ++it) {
        // Ignore frames captured during a config change
        if (it->pendingConfigChange || (it + 1)->pendingConfigChange) {
            continue;
        }
        const auto presentTimeDeltas = [&] {
            const auto delta = missingPresentTime ? (it + 1)->queueTime - it->queueTime
                                                  : (it + 1)->presetTime - it->presetTime;
            return std::max(delta, mHighRefreshRatePeriod);
        }();

        if (std::abs(presentTimeDeltas - averageFrameTime) > 2 * averageFrameTime) {
            return false;
        }
    }

    return true;
}

std::optional<float> LayerInfoV2::calculateRefreshRateIfPossible() {
    static constexpr float MARGIN = 1.0f; // 1Hz

    if (!hasEnoughDataForHeuristic()) {
        ALOGV("Not enough data");
        return std::nullopt;
    }

    const auto [averageFrameTime, missingPresentTime] = calculateAverageFrameTime();

    // If there are no presentation timestamps provided we can't calculate the refresh rate
    if (missingPresentTime && mLastReportedRefreshRate == 0) {
        return std::nullopt;
    }

    if (!isRefreshRateStable(averageFrameTime, missingPresentTime)) {
        return std::nullopt;
    }

    const auto refreshRate = 1e9f / averageFrameTime;
    if (std::abs(refreshRate - mLastReportedRefreshRate) > MARGIN) {
        mLastReportedRefreshRate = refreshRate;
    }

    ALOGV("Refresh rate: %.2f", mLastReportedRefreshRate);
    return mLastReportedRefreshRate;
}

std::pair<LayerHistory::LayerVoteType, float> LayerInfoV2::getRefreshRate(nsecs_t now) {
    if (mLayerVote.type != LayerHistory::LayerVoteType::Heuristic) {
        return {mLayerVote.type, mLayerVote.fps};
    }

    if (!isFrequent(now)) {
        return {LayerHistory::LayerVoteType::Min, 0};
    }

    auto refreshRate = calculateRefreshRateIfPossible();
    if (refreshRate.has_value()) {
        return {LayerHistory::LayerVoteType::Heuristic, refreshRate.value()};
    }

    return {LayerHistory::LayerVoteType::Max, 0};
}

} // namespace android::scheduler
