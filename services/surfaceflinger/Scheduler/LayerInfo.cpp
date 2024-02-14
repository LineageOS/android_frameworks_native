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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

// #define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerInfo.h"

#include <algorithm>
#include <utility>

#include <android/native_window.h>
#include <cutils/compiler.h>
#include <cutils/trace.h>
#include <ftl/enum.h>
#include <gui/TraceUtils.h>
#include <system/window.h>

#undef LOG_TAG
#define LOG_TAG "LayerInfo"

namespace android::scheduler {

bool LayerInfo::sTraceEnabled = false;

LayerInfo::LayerInfo(const std::string& name, uid_t ownerUid,
                     LayerHistory::LayerVoteType defaultVote)
      : mName(name),
        mOwnerUid(ownerUid),
        mDefaultVote(defaultVote),
        mLayerVote({defaultVote, Fps()}),
        mLayerProps(std::make_unique<LayerProps>()),
        mRefreshRateHistory(name) {
    ;
}

void LayerInfo::setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now, LayerUpdateType updateType,
                                   bool pendingModeChange, const LayerProps& props) {
    lastPresentTime = std::max(lastPresentTime, static_cast<nsecs_t>(0));

    mLastUpdatedTime = std::max(lastPresentTime, now);
    *mLayerProps = props;
    switch (updateType) {
        case LayerUpdateType::AnimationTX:
            mLastAnimationTime = std::max(lastPresentTime, now);
            break;
        case LayerUpdateType::SetFrameRate:
            if (FlagManager::getInstance().vrr_config()) {
                break;
            }
            FALLTHROUGH_INTENDED;
        case LayerUpdateType::Buffer:
            FrameTimeData frameTime = {.presentTime = lastPresentTime,
                                       .queueTime = mLastUpdatedTime,
                                       .pendingModeChange = pendingModeChange,
                                       .isSmallDirty = props.isSmallDirty};
            mFrameTimes.push_back(frameTime);
            if (mFrameTimes.size() > HISTORY_SIZE) {
                mFrameTimes.pop_front();
            }
            break;
    }
}

void LayerInfo::setProperties(const android::scheduler::LayerProps& properties) {
    *mLayerProps = properties;
}

bool LayerInfo::isFrameTimeValid(const FrameTimeData& frameTime) const {
    return frameTime.queueTime >= std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          mFrameTimeValidSince.time_since_epoch())
                                          .count();
}

LayerInfo::Frequent LayerInfo::isFrequent(nsecs_t now) const {
    // If we know nothing about this layer (e.g. after touch event),
    // we consider it as frequent as it might be the start of an animation.
    if (mFrameTimes.size() < kFrequentLayerWindowSize) {
        return {/* isFrequent */ true, /* clearHistory */ false, /* isConclusive */ true};
    }

    // Non-active layers are also infrequent
    if (mLastUpdatedTime < getActiveLayerThreshold(now)) {
        return {/* isFrequent */ false, /* clearHistory */ false, /* isConclusive */ true};
    }

    // We check whether we can classify this layer as frequent or infrequent:
    //  - frequent: a layer posted kFrequentLayerWindowSize within
    //              kMaxPeriodForFrequentLayerNs of each other.
    // -  infrequent: a layer posted kFrequentLayerWindowSize with longer
    //                gaps than kFrequentLayerWindowSize.
    // If we can't determine the layer classification yet, we return the last
    // classification.
    bool isFrequent = true;
    bool isInfrequent = true;
    int32_t smallDirtyCount = 0;
    const auto n = mFrameTimes.size() - 1;
    for (size_t i = 0; i < kFrequentLayerWindowSize - 1; i++) {
        if (mFrameTimes[n - i].queueTime - mFrameTimes[n - i - 1].queueTime <
            kMaxPeriodForFrequentLayerNs.count()) {
            isInfrequent = false;
            if (mFrameTimes[n - i].presentTime == 0 && mFrameTimes[n - i].isSmallDirty) {
                smallDirtyCount++;
            }
        } else {
            isFrequent = false;
        }
    }

    // Vote the small dirty when a layer contains at least HISTORY_SIZE of small dirty updates.
    bool isSmallDirty = false;
    if (smallDirtyCount >= kNumSmallDirtyThreshold) {
        if (mLastSmallDirtyCount >= HISTORY_SIZE) {
            isSmallDirty = true;
        } else {
            mLastSmallDirtyCount++;
        }
    } else {
        mLastSmallDirtyCount = 0;
    }

    if (isFrequent || isInfrequent) {
        // If the layer was previously inconclusive, we clear
        // the history as indeterminate layers changed to frequent,
        // and we should not look at the stale data.
        return {isFrequent, isFrequent && !mIsFrequencyConclusive, /* isConclusive */ true,
                isSmallDirty};
    }

    // If we can't determine whether the layer is frequent or not, we return
    // the last known classification and mark the layer frequency as inconclusive.
    isFrequent = !mLastRefreshRate.infrequent;

    // If the layer was previously tagged as animating, we clear
    // the history as it is likely the layer just changed its behavior,
    // and we should not look at stale data.
    return {isFrequent, isFrequent && mLastRefreshRate.animating, /* isConclusive */ false};
}

Fps LayerInfo::getFps(nsecs_t now) const {
    // Find the first active frame
    auto it = mFrameTimes.begin();
    for (; it != mFrameTimes.end(); ++it) {
        if (it->queueTime >= getActiveLayerThreshold(now)) {
            break;
        }
    }

    const auto numFrames = std::distance(it, mFrameTimes.end());
    if (numFrames < kFrequentLayerWindowSize) {
        return Fps();
    }

    // Layer is considered frequent if the average frame rate is higher than the threshold
    const auto totalTime = mFrameTimes.back().queueTime - it->queueTime;
    return Fps::fromPeriodNsecs(totalTime / (numFrames - 1));
}

bool LayerInfo::isAnimating(nsecs_t now) const {
    return mLastAnimationTime >= getActiveLayerThreshold(now);
}

bool LayerInfo::hasEnoughDataForHeuristic() const {
    // The layer had to publish at least HISTORY_SIZE or HISTORY_DURATION of updates
    if (mFrameTimes.size() < 2) {
        ALOGV("fewer than 2 frames recorded: %zu", mFrameTimes.size());
        return false;
    }

    if (!isFrameTimeValid(mFrameTimes.front())) {
        ALOGV("stale frames still captured");
        return false;
    }

    const auto totalDuration = mFrameTimes.back().queueTime - mFrameTimes.front().queueTime;
    if (mFrameTimes.size() < HISTORY_SIZE && totalDuration < HISTORY_DURATION.count()) {
        ALOGV("not enough frames captured: %zu | %.2f seconds", mFrameTimes.size(),
              totalDuration / 1e9f);
        return false;
    }

    return true;
}

std::optional<nsecs_t> LayerInfo::calculateAverageFrameTime() const {
    // Ignore frames captured during a mode change
    const bool isDuringModeChange =
            std::any_of(mFrameTimes.begin(), mFrameTimes.end(),
                        [](const auto& frame) { return frame.pendingModeChange; });
    if (isDuringModeChange) {
        return std::nullopt;
    }

    const bool isMissingPresentTime =
            std::any_of(mFrameTimes.begin(), mFrameTimes.end(),
                        [](auto frame) { return frame.presentTime == 0; });
    if (isMissingPresentTime && !mLastRefreshRate.reported.isValid()) {
        // If there are no presentation timestamps and we haven't calculated
        // one in the past then we can't calculate the refresh rate
        return std::nullopt;
    }

    // Calculate the average frame time based on presentation timestamps. If those
    // doesn't exist, we look at the time the buffer was queued only. We can do that only if
    // we calculated a refresh rate based on presentation timestamps in the past. The reason
    // we look at the queue time is to handle cases where hwui attaches presentation timestamps
    // when implementing render ahead for specific refresh rates. When hwui no longer provides
    // presentation timestamps we look at the queue time to see if the current refresh rate still
    // matches the content.

    auto getFrameTime = isMissingPresentTime ? [](FrameTimeData data) { return data.queueTime; }
                                             : [](FrameTimeData data) { return data.presentTime; };

    nsecs_t totalDeltas = 0;
    int numDeltas = 0;
    int32_t smallDirtyCount = 0;
    auto prevFrame = mFrameTimes.begin();
    for (auto it = mFrameTimes.begin() + 1; it != mFrameTimes.end(); ++it) {
        const auto currDelta = getFrameTime(*it) - getFrameTime(*prevFrame);
        if (currDelta < kMinPeriodBetweenFrames) {
            // Skip this frame, but count the delta into the next frame
            continue;
        }

        // If this is a small area update, we don't want to consider it for calculating the average
        // frame time. Instead, we let the bigger frame updates to drive the calculation.
        if (it->isSmallDirty && currDelta < kMinPeriodBetweenSmallDirtyFrames) {
            smallDirtyCount++;
            continue;
        }

        prevFrame = it;

        if (currDelta > kMaxPeriodBetweenFrames) {
            // Skip this frame and the current delta.
            continue;
        }

        totalDeltas += currDelta;
        numDeltas++;
    }

    if (smallDirtyCount > 0) {
        ATRACE_FORMAT_INSTANT("small dirty = %" PRIu32, smallDirtyCount);
    }

    if (numDeltas == 0) {
        return std::nullopt;
    }

    const auto averageFrameTime = static_cast<double>(totalDeltas) / static_cast<double>(numDeltas);
    return static_cast<nsecs_t>(averageFrameTime);
}

std::optional<Fps> LayerInfo::calculateRefreshRateIfPossible(const RefreshRateSelector& selector,
                                                             nsecs_t now) {
    ATRACE_CALL();
    static constexpr float MARGIN = 1.0f; // 1Hz
    if (!hasEnoughDataForHeuristic()) {
        ALOGV("Not enough data");
        return std::nullopt;
    }

    if (const auto averageFrameTime = calculateAverageFrameTime()) {
        const auto refreshRate = Fps::fromPeriodNsecs(*averageFrameTime);
        const auto closestKnownRefreshRate = mRefreshRateHistory.add(refreshRate, now, selector);
        if (closestKnownRefreshRate.isValid()) {
            using fps_approx_ops::operator!=;

            // To avoid oscillation, use the last calculated refresh rate if it is close enough.
            if (std::abs(mLastRefreshRate.calculated.getValue() - refreshRate.getValue()) >
                        MARGIN &&
                mLastRefreshRate.reported != closestKnownRefreshRate) {
                mLastRefreshRate.calculated = refreshRate;
                mLastRefreshRate.reported = closestKnownRefreshRate;
            }

            ALOGV("%s %s rounded to nearest known frame rate %s", mName.c_str(),
                  to_string(refreshRate).c_str(), to_string(mLastRefreshRate.reported).c_str());
        } else {
            ALOGV("%s Not stable (%s) returning last known frame rate %s", mName.c_str(),
                  to_string(refreshRate).c_str(), to_string(mLastRefreshRate.reported).c_str());
        }
    }

    return mLastRefreshRate.reported.isValid() ? std::make_optional(mLastRefreshRate.reported)
                                               : std::nullopt;
}

LayerInfo::RefreshRateVotes LayerInfo::getRefreshRateVote(const RefreshRateSelector& selector,
                                                          nsecs_t now) {
    ATRACE_CALL();
    LayerInfo::RefreshRateVotes votes;

    if (mLayerVote.type != LayerHistory::LayerVoteType::Heuristic) {
        if (mLayerVote.category != FrameRateCategory::Default) {
            const auto voteType = mLayerVote.type == LayerHistory::LayerVoteType::NoVote
                    ? LayerHistory::LayerVoteType::NoVote
                    : LayerHistory::LayerVoteType::ExplicitCategory;
            ATRACE_FORMAT_INSTANT("Vote %s (category=%s)", ftl::enum_string(voteType).c_str(),
                                  ftl::enum_string(mLayerVote.category).c_str());
            ALOGV("%s voted %s with category: %s", mName.c_str(),
                  ftl::enum_string(voteType).c_str(),
                  ftl::enum_string(mLayerVote.category).c_str());
            votes.push_back({voteType, Fps(), Seamlessness::Default, mLayerVote.category,
                             mLayerVote.categorySmoothSwitchOnly});
        }

        if (mLayerVote.fps.isValid() ||
            mLayerVote.type != LayerHistory::LayerVoteType::ExplicitDefault) {
            ATRACE_FORMAT_INSTANT("Vote %s", ftl::enum_string(mLayerVote.type).c_str());
            ALOGV("%s voted %d", mName.c_str(), static_cast<int>(mLayerVote.type));
            votes.push_back({mLayerVote.type, mLayerVote.fps, mLayerVote.seamlessness,
                             FrameRateCategory::Default, mLayerVote.categorySmoothSwitchOnly});
        }

        return votes;
    }

    if (isAnimating(now)) {
        ATRACE_FORMAT_INSTANT("animating");
        ALOGV("%s is animating", mName.c_str());
        mLastRefreshRate.animating = true;
        votes.push_back({LayerHistory::LayerVoteType::Max, Fps()});
        return votes;
    }

    // Vote for max refresh rate whenever we're front-buffered.
    if (FlagManager::getInstance().vrr_config() && isFrontBuffered()) {
        ATRACE_FORMAT_INSTANT("front buffered");
        ALOGV("%s is front-buffered", mName.c_str());
        votes.push_back({LayerHistory::LayerVoteType::Max, Fps()});
        return votes;
    }

    const LayerInfo::Frequent frequent = isFrequent(now);
    mIsFrequencyConclusive = frequent.isConclusive;
    if (!frequent.isFrequent) {
        ATRACE_FORMAT_INSTANT("infrequent");
        ALOGV("%s is infrequent", mName.c_str());
        mLastRefreshRate.infrequent = true;
        mLastSmallDirtyCount = 0;
        // Infrequent layers vote for minimal refresh rate for
        // battery saving purposes and also to prevent b/135718869.
        votes.push_back({LayerHistory::LayerVoteType::Min, Fps()});
        return votes;
    }

    if (frequent.clearHistory) {
        clearHistory(now);
    }

    // Return no vote if the recent frames are small dirty.
    if (frequent.isSmallDirty && !mLastRefreshRate.reported.isValid()) {
        ATRACE_FORMAT_INSTANT("NoVote (small dirty)");
        ALOGV("%s is small dirty", mName.c_str());
        votes.push_back({LayerHistory::LayerVoteType::NoVote, Fps()});
        return votes;
    }

    auto refreshRate = calculateRefreshRateIfPossible(selector, now);
    if (refreshRate.has_value()) {
        ATRACE_FORMAT_INSTANT("calculated (%s)", to_string(*refreshRate).c_str());
        ALOGV("%s calculated refresh rate: %s", mName.c_str(), to_string(*refreshRate).c_str());
        votes.push_back({LayerHistory::LayerVoteType::Heuristic, refreshRate.value()});
        return votes;
    }

    ATRACE_FORMAT_INSTANT("Max (can't resolve refresh rate)");
    ALOGV("%s Max (can't resolve refresh rate)", mName.c_str());
    votes.push_back({LayerHistory::LayerVoteType::Max, Fps()});
    return votes;
}

const char* LayerInfo::getTraceTag(LayerHistory::LayerVoteType type) const {
    if (mTraceTags.count(type) == 0) {
        auto tag = "LFPS " + mName + " " + ftl::enum_string(type);
        mTraceTags.emplace(type, std::move(tag));
    }

    return mTraceTags.at(type).c_str();
}

LayerInfo::FrameRate LayerInfo::getSetFrameRateVote() const {
    return mLayerProps->setFrameRateVote;
}

bool LayerInfo::isVisible() const {
    return mLayerProps->visible;
}

int32_t LayerInfo::getFrameRateSelectionPriority() const {
    return mLayerProps->frameRateSelectionPriority;
}

bool LayerInfo::isFrontBuffered() const {
    return mLayerProps->isFrontBuffered;
}

FloatRect LayerInfo::getBounds() const {
    return mLayerProps->bounds;
}

ui::Transform LayerInfo::getTransform() const {
    return mLayerProps->transform;
}

LayerInfo::RefreshRateHistory::HeuristicTraceTagData
LayerInfo::RefreshRateHistory::makeHeuristicTraceTagData() const {
    const std::string prefix = "LFPS ";
    const std::string suffix = "Heuristic ";
    return {.min = prefix + mName + suffix + "min",
            .max = prefix + mName + suffix + "max",
            .consistent = prefix + mName + suffix + "consistent",
            .average = prefix + mName + suffix + "average"};
}

void LayerInfo::RefreshRateHistory::clear() {
    mRefreshRates.clear();
}

Fps LayerInfo::RefreshRateHistory::add(Fps refreshRate, nsecs_t now,
                                       const RefreshRateSelector& selector) {
    mRefreshRates.push_back({refreshRate, now});
    while (mRefreshRates.size() >= HISTORY_SIZE ||
           now - mRefreshRates.front().timestamp > HISTORY_DURATION.count()) {
        mRefreshRates.pop_front();
    }

    if (CC_UNLIKELY(sTraceEnabled)) {
        if (!mHeuristicTraceTagData.has_value()) {
            mHeuristicTraceTagData = makeHeuristicTraceTagData();
        }

        ATRACE_INT(mHeuristicTraceTagData->average.c_str(), refreshRate.getIntValue());
    }

    return selectRefreshRate(selector);
}

Fps LayerInfo::RefreshRateHistory::selectRefreshRate(const RefreshRateSelector& selector) const {
    if (mRefreshRates.empty()) return Fps();

    const auto [min, max] =
            std::minmax_element(mRefreshRates.begin(), mRefreshRates.end(),
                                [](const auto& lhs, const auto& rhs) {
                                    return isStrictlyLess(lhs.refreshRate, rhs.refreshRate);
                                });

    const auto maxClosestRate = selector.findClosestKnownFrameRate(max->refreshRate);
    const bool consistent = [&](Fps maxFps, Fps minFps) {
        if (FlagManager::getInstance().use_known_refresh_rate_for_fps_consistency()) {
            if (maxFps.getValue() - minFps.getValue() <
                MARGIN_CONSISTENT_FPS_FOR_CLOSEST_REFRESH_RATE) {
                const auto minClosestRate = selector.findClosestKnownFrameRate(minFps);
                using fps_approx_ops::operator==;
                return maxClosestRate == minClosestRate;
            }
            return false;
        }
        return maxFps.getValue() - minFps.getValue() < MARGIN_CONSISTENT_FPS;
    }(max->refreshRate, min->refreshRate);

    if (CC_UNLIKELY(sTraceEnabled)) {
        if (!mHeuristicTraceTagData.has_value()) {
            mHeuristicTraceTagData = makeHeuristicTraceTagData();
        }

        ATRACE_INT(mHeuristicTraceTagData->max.c_str(), max->refreshRate.getIntValue());
        ATRACE_INT(mHeuristicTraceTagData->min.c_str(), min->refreshRate.getIntValue());
        ATRACE_INT(mHeuristicTraceTagData->consistent.c_str(), consistent);
    }

    return consistent ? maxClosestRate : Fps();
}

FrameRateCompatibility LayerInfo::FrameRate::convertCompatibility(int8_t compatibility) {
    switch (compatibility) {
        case ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT:
            return FrameRateCompatibility::Default;
        case ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE:
            return FrameRateCompatibility::ExactOrMultiple;
        case ANATIVEWINDOW_FRAME_RATE_EXACT:
            return FrameRateCompatibility::Exact;
        case ANATIVEWINDOW_FRAME_RATE_MIN:
            return FrameRateCompatibility::Min;
        case ANATIVEWINDOW_FRAME_RATE_GTE:
            return FrameRateCompatibility::Gte;
        case ANATIVEWINDOW_FRAME_RATE_NO_VOTE:
            return FrameRateCompatibility::NoVote;
        default:
            LOG_ALWAYS_FATAL("Invalid frame rate compatibility value %d", compatibility);
            return FrameRateCompatibility::Default;
    }
}

Seamlessness LayerInfo::FrameRate::convertChangeFrameRateStrategy(int8_t strategy) {
    switch (strategy) {
        case ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS:
            return Seamlessness::OnlySeamless;
        case ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS:
            return Seamlessness::SeamedAndSeamless;
        default:
            LOG_ALWAYS_FATAL("Invalid change frame sate strategy value %d", strategy);
            return Seamlessness::Default;
    }
}

FrameRateCategory LayerInfo::FrameRate::convertCategory(int8_t category) {
    switch (category) {
        case ANATIVEWINDOW_FRAME_RATE_CATEGORY_DEFAULT:
            return FrameRateCategory::Default;
        case ANATIVEWINDOW_FRAME_RATE_CATEGORY_NO_PREFERENCE:
            return FrameRateCategory::NoPreference;
        case ANATIVEWINDOW_FRAME_RATE_CATEGORY_LOW:
            return FrameRateCategory::Low;
        case ANATIVEWINDOW_FRAME_RATE_CATEGORY_NORMAL:
            return FrameRateCategory::Normal;
        case ANATIVEWINDOW_FRAME_RATE_CATEGORY_HIGH_HINT:
            return FrameRateCategory::HighHint;
        case ANATIVEWINDOW_FRAME_RATE_CATEGORY_HIGH:
            return FrameRateCategory::High;
        default:
            LOG_ALWAYS_FATAL("Invalid frame rate category value %d", category);
            return FrameRateCategory::Default;
    }
}

LayerInfo::FrameRateSelectionStrategy LayerInfo::convertFrameRateSelectionStrategy(
        int8_t strategy) {
    switch (strategy) {
        case ANATIVEWINDOW_FRAME_RATE_SELECTION_STRATEGY_PROPAGATE:
            return FrameRateSelectionStrategy::Propagate;
        case ANATIVEWINDOW_FRAME_RATE_SELECTION_STRATEGY_OVERRIDE_CHILDREN:
            return FrameRateSelectionStrategy::OverrideChildren;
        case ANATIVEWINDOW_FRAME_RATE_SELECTION_STRATEGY_SELF:
            return FrameRateSelectionStrategy::Self;
        default:
            LOG_ALWAYS_FATAL("Invalid frame rate selection strategy value %d", strategy);
            return FrameRateSelectionStrategy::Self;
    }
}

bool LayerInfo::FrameRate::isNoVote() const {
    return vote.type == FrameRateCompatibility::NoVote;
}

bool LayerInfo::FrameRate::isValid() const {
    return isNoVote() || vote.rate.isValid() || category != FrameRateCategory::Default;
}

std::ostream& operator<<(std::ostream& stream, const LayerInfo::FrameRate& rate) {
    return stream << "{rate=" << rate.vote.rate << " type=" << ftl::enum_string(rate.vote.type)
                  << " seamlessness=" << ftl::enum_string(rate.vote.seamlessness) << '}';
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
