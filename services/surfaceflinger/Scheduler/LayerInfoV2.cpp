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

LayerInfoV2::LayerInfoV2(const std::string& name, nsecs_t highRefreshRatePeriod,
                         LayerHistory::LayerVoteType defaultVote)
      : mName(name),
        mHighRefreshRatePeriod(highRefreshRatePeriod),
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

bool LayerInfoV2::isFrequent(nsecs_t now) const {
    for (auto it = mFrameTimes.crbegin(); it != mFrameTimes.crend(); ++it) {
        if (now - it->queueTime >= MAX_FREQUENT_LAYER_PERIOD_NS.count()) {
            ALOGV("%s infrequent (last frame is %.2fms ago", mName.c_str(),
                  (now - mFrameTimes.back().queueTime) / 1e6f);
            return false;
        }

        const auto numFrames = std::distance(mFrameTimes.crbegin(), it + 1);
        if (numFrames >= FREQUENT_LAYER_WINDOW_SIZE) {
            ALOGV("%s frequent (burst of %zu frames", mName.c_str(), numFrames);
            return true;
        }
    }

    ALOGV("%s infrequent (not enough frames %zu)", mName.c_str(), mFrameTimes.size());
    return false;
}

bool LayerInfoV2::hasEnoughDataForHeuristic() const {
    // The layer had to publish at least HISTORY_SIZE or HISTORY_TIME of updates
    if (mFrameTimes.size() < 2) {
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
    nsecs_t totalQueueTimeDeltas = 0;
    auto missingPresentTime = false;
    for (auto it = mFrameTimes.begin(); it != mFrameTimes.end() - 1; ++it) {
        totalQueueTimeDeltas +=
                std::max(((it + 1)->queueTime - it->queueTime), mHighRefreshRatePeriod);

        if (it->presetTime == 0 || (it + 1)->presetTime == 0) {
            missingPresentTime = true;
            continue;
        }

        totalPresentTimeDeltas +=
                std::max(((it + 1)->presetTime - it->presetTime), mHighRefreshRatePeriod);
    }

    // If there are no presentation timestamps provided we can't calculate the refresh rate
    if (missingPresentTime && mLastReportedRefreshRate == 0) {
        return std::nullopt;
    }

    // Calculate the average frame time based on presentation timestamps. If those
    // doesn't exist, we look at the time the buffer was queued only. We can do that only if
    // we calculated a refresh rate based on presentation timestamps in the past. The reason
    // we look at the queue time is to handle cases where hwui attaches presentation timestamps
    // when implementing render ahead for specific refresh rates. When hwui no longer provides
    // presentation timestamps we look at the queue time to see if the current refresh rate still
    // matches the content.
    const float averageFrameTime =
            static_cast<float>(missingPresentTime ? totalQueueTimeDeltas : totalPresentTimeDeltas) /
            (mFrameTimes.size() - 1);

    // Now once we calculated the refresh rate we need to make sure that all the frames we captured
    // are evenly distributed and we don't calculate the average across some burst of frames.
    for (auto it = mFrameTimes.begin(); it != mFrameTimes.end() - 1; ++it) {
        const auto presentTimeDeltas = [&] {
            const auto delta = missingPresentTime ? (it + 1)->queueTime - it->queueTime
                                                  : (it + 1)->presetTime - it->presetTime;
            return std::max(delta, mHighRefreshRatePeriod);
        }();

        if (std::abs(presentTimeDeltas - averageFrameTime) > 2 * averageFrameTime) {
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
        ALOGV("%s voted %d ", mName.c_str(), static_cast<int>(mLayerVote.type));
        return {mLayerVote.type, mLayerVote.fps};
    }

    if (!isFrequent(now)) {
        ALOGV("%s is infrequent", mName.c_str());
        return {LayerHistory::LayerVoteType::Min, 0};
    }

    auto refreshRate = calculateRefreshRateIfPossible();
    if (refreshRate.has_value()) {
        ALOGV("%s calculated refresh rate: %.2f", mName.c_str(), refreshRate.value());
        return {LayerHistory::LayerVoteType::Heuristic, refreshRate.value()};
    }

    ALOGV("%s Max (can't resolve refresh rate", mName.c_str());
    return {LayerHistory::LayerVoteType::Max, 0};
}

} // namespace android::scheduler
