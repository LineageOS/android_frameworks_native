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

void LayerInfoV2::setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now) {
    lastPresentTime = std::max(lastPresentTime, static_cast<nsecs_t>(0));

    mLastUpdatedTime = std::max(lastPresentTime, now);

    FrameTimeData frameTime = {.presetTime = lastPresentTime, .queueTime = mLastUpdatedTime};

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

std::optional<float> LayerInfoV2::calculateRefreshRateIfPossible() {
    static constexpr float MARGIN = 1.0f; // 1Hz

    if (!hasEnoughDataForHeuristic()) {
        ALOGV("Not enough data");
        return std::nullopt;
    }

    // Calculate the refresh rate by finding the average delta between frames
    nsecs_t totalPresentTimeDeltas = 0;
    int numFrames = 0;
    for (auto it = mFrameTimes.begin(); it != mFrameTimes.end() - 1; ++it) {
        // If there are no presentation timestamp provided we can't calculate the refresh rate
        if (it->presetTime == 0 || (it + 1)->presetTime == 0) {
            continue;
        }

        totalPresentTimeDeltas +=
                std::max(((it + 1)->presetTime - it->presetTime), mHighRefreshRatePeriod);
        numFrames++;
    }
    if (numFrames == 0) {
        return std::nullopt;
    }
    const float averageFrameTime = static_cast<float>(totalPresentTimeDeltas) / numFrames;

    // Now once we calculated the refresh rate we need to make sure that all the frames we captured
    // are evenly distributed and we don't calculate the average across some burst of frames.
    for (auto it = mFrameTimes.begin(); it != mFrameTimes.end() - 1; ++it) {
        const nsecs_t frameTimeDeltas = [&] {
            nsecs_t delta;
            if (it->presetTime == 0 || (it + 1)->presetTime == 0) {
                delta = (it + 1)->queueTime - it->queueTime;
            } else {
                delta = (it + 1)->presetTime - it->presetTime;
            }
            return std::max(delta, mHighRefreshRatePeriod);
        }();
        if (std::abs(frameTimeDeltas - averageFrameTime) > 2 * averageFrameTime) {
            return std::nullopt;
        }
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
