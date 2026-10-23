/*
 * Copyright 2019 The Android Open Source Project
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
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <deque>
#include <map>
#include <ranges>
#include <set>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <common/trace.h>
#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <ftl/match.h>
#include <ftl/unit.h>
#include <scheduler/FrameRateMode.h>

#include "RefreshRateSelector.h"

#include <com_android_graphics_surfaceflinger_flags.h>

namespace android::scheduler {
namespace {

using namespace com::android::graphics::surfaceflinger;

struct RefreshRateScore {
    FrameRateMode frameRateMode;
    float overallScore;
    struct {
        float modeBelowThreshold;
        float modeAboveThreshold;
    } fixedRateBelowThresholdLayersScore;
};

constexpr RefreshRateSelector::GlobalSignals kNoSignals;

std::string formatLayerInfo(const RefreshRateSelector::LayerRequirement& layer, float weight) {
    return base::StringPrintf("%s (type=%s, weight=%.2f, seamlessness=%s) %s", layer.name.c_str(),
                              ftl::enum_string(layer.vote).c_str(), weight,
                              ftl::enum_string(layer.seamlessness).c_str(),
                              to_string(layer.desiredRefreshRate).c_str());
}

std::vector<Fps> constructKnownFrameRates(const DisplayModes& modes) {
    std::vector<Fps> knownFrameRates = {24_Hz, 30_Hz, 45_Hz, 60_Hz, 72_Hz};
    knownFrameRates.reserve(knownFrameRates.size() + modes.size());

    // Add all supported refresh rates.
    for (const auto& [id, mode] : modes) {
        knownFrameRates.push_back(mode->getPeakFps());
    }

    // Sort and remove duplicates.
    std::sort(knownFrameRates.begin(), knownFrameRates.end(), isStrictlyLess);
    knownFrameRates.erase(std::unique(knownFrameRates.begin(), knownFrameRates.end(),
                                      isApproxEqual),
                          knownFrameRates.end());
    return knownFrameRates;
}

std::vector<DisplayModeIterator> sortByRefreshRate(const DisplayModes& modes) {
    std::vector<DisplayModeIterator> sortedModes;
    sortedModes.reserve(modes.size());
    for (auto it = modes.begin(); it != modes.end(); ++it) {
        sortedModes.push_back(it);
    }

    std::sort(sortedModes.begin(), sortedModes.end(), [](auto it1, auto it2) {
        const auto& mode1 = it1->second;
        const auto& mode2 = it2->second;

        if (mode1->getVsyncRate().getPeriodNsecs() == mode2->getVsyncRate().getPeriodNsecs()) {
            return mode1->getGroup() > mode2->getGroup();
        }

        return mode1->getVsyncRate().getPeriodNsecs() > mode2->getVsyncRate().getPeriodNsecs();
    });

    return sortedModes;
}

struct FrameRateGap {
    Fps lowerFps;
    Fps higherFps;
    int diff;

    bool operator<(const FrameRateGap& other) const { return diff < other.diff; }
};

std::optional<unsigned> findBestDividerForFrameRateGap(const FrameRateGap& gap,
                                                       const DisplayMode& mode, unsigned start,
                                                       FpsRange range,
                                                       const std::set<unsigned>& usedDividers) {
    float targetFps = gap.lowerFps.getValue() + static_cast<float>(gap.diff) / 2.f;
    unsigned idealDivider = static_cast<unsigned>(
            std::round(static_cast<float>(mode.getVsyncRate().getValue()) / targetFps));
    if (idealDivider < start || usedDividers.find(idealDivider) != usedDividers.end()) {
        return std::nullopt;
    }

    return idealDivider;
}

std::vector<unsigned> getModeDivisorsFromAnchorList(const DisplayMode& mode, FpsRange range,
                                                    std::vector<Fps> anchorList,
                                                    size_t numFrameRates) {
    std::vector<Fps> frameRates;
    std::set<unsigned> dividers;

    using fps_approx_ops::operator<;

    // Add min and max fps to the anchor list to always select the highest and lowest possible frame
    // rate.
    anchorList.push_back(std::min(range.max, mode.getPeakFps(), fps_approx_ops::operator<));
    anchorList.push_back(std::max(range.min, 1_Hz, fps_approx_ops::operator<));

    for (const Fps fps : anchorList) {
        if (fps < range.min || range.max < fps || mode.getPeakFps() < fps) {
            continue;
        }

        unsigned divider =
                static_cast<unsigned>(std::round(mode.getVsyncRate().getValue() / fps.getValue()));
        if (dividers.find(divider) == dividers.end()) {
            frameRates.push_back(fps);
            dividers.insert(divider);
        }
    }
    if (frameRates.empty()) {
        return {};
    }

    // if we have enough divisors from the anchor list, just return it.
    if (dividers.size() >= numFrameRates) {
        std::vector<unsigned> result(dividers.begin(), dividers.end());
        std::sort(result.begin(), result.end());
        return result;
    }

    // Use a priority_queue to get the highest gap to fill in each iteration
    std::priority_queue<FrameRateGap> gapQueue;
    std::sort(frameRates.begin(), frameRates.end(), fps_approx_ops::operator<);
    for (size_t i = 0; i < frameRates.size() - 1; ++i) {
        Fps lower = frameRates[i];
        Fps higher = frameRates[i + 1];
        gapQueue.push({lower, higher, higher.getIntValue() - lower.getIntValue()});
    }

    using fps_approx_ops::operator/;
    const unsigned start =
            static_cast<unsigned>(std::max(1,
                                           static_cast<int>(mode.getVsyncRate() /
                                                            std::min(range.max, mode.getPeakFps(),
                                                                     fps_approx_ops::operator<)) -
                                                   1));

    while (!gapQueue.empty() && dividers.size() < numFrameRates) {
        FrameRateGap largestGap = gapQueue.top();
        gapQueue.pop();

        // There is no point to add frame rates < 30, for that we rely on the anchor list
        if (largestGap.higherFps < 30_Hz) continue;
        const auto bestDividerOpt =
                findBestDividerForFrameRateGap(largestGap, mode, start, range, dividers);
        if (bestDividerOpt.has_value()) {
            dividers.insert(*bestDividerOpt);
            Fps newValue = Fps::fromValue((mode.getVsyncRate().getValue()) /
                                          static_cast<float>(*bestDividerOpt));

            gapQueue.push({largestGap.lowerFps, newValue,
                           newValue.getIntValue() - largestGap.lowerFps.getIntValue()});
            gapQueue.push({newValue, largestGap.higherFps,
                           largestGap.higherFps.getIntValue() - newValue.getIntValue()});
        }
    }

    std::vector<unsigned> result(dividers.begin(), dividers.end());
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<unsigned> getModeDivisors(const DisplayMode& mode, FpsRange range,
                                      const std::vector<Fps>& anchorList, size_t numFrameRates,
                                      bool enableFrameRateOverride) {
    if (!enableFrameRateOverride) {
        return {1};
    }

    if (mode.getVrrConfig().has_value()) {
        return getModeDivisorsFromAnchorList(mode, range, anchorList, numFrameRates);
    }

    const auto vsyncRate = mode.getVsyncRate();
    const auto peakFps = mode.getPeakFps();

    using fps_approx_ops::operator/;
    // use signed type as `fps / range.max` might be 0
    const unsigned start = static_cast<unsigned>(
            std::max(1,
                     static_cast<int>(vsyncRate /
                                      std::min(range.max, peakFps, fps_approx_ops::operator<)) -
                             1));
    const unsigned end = vsyncRate /
            std::max(range.min, RefreshRateSelector::kMinSupportedFrameRate,
                     fps_approx_ops::operator<);
    std::vector<unsigned> divisors;
    if (end < start) {
        return {};
    }

    divisors.reserve(end - start + 1);
    for (unsigned i = start; i <= end; i++) {
        divisors.push_back(i);
    }

    return divisors;
}

std::string toString(const RefreshRateSelector::PolicyVariant& policy) {
    using namespace std::string_literals;

    return ftl::match(
            policy,
            [](const RefreshRateSelector::DisplayManagerPolicy& policy) {
                return "DisplayManagerPolicy"s + policy.toString();
            },
            [](const RefreshRateSelector::OverridePolicy& policy) {
                return "OverridePolicy"s + policy.toString();
            },
            [](RefreshRateSelector::NoOverridePolicy) { return "NoOverridePolicy"s; });
}

} // namespace

auto RefreshRateSelector::createFrameRateModes(
        const Policy& policy, std::function<bool(const DisplayMode&)>&& filterModes,
        const FpsRange& renderRange, bool onlyDivisorsForSameGroup) const
        -> std::vector<FrameRateMode> {
    struct Key {
        Fps fps;
        int32_t group;
    };

    struct KeyLess {
        bool operator()(const Key& a, const Key& b) const {
            using namespace fps_approx_ops;
            if (a.fps != b.fps) {
                return a.fps < b.fps;
            }

            // For the same fps the order doesn't really matter, but we still
            // want the behaviour of a strictly less operator.
            // We use the group id as the secondary ordering for that.
            return a.group < b.group;
        }
    };

    const auto& defaultMode = mDisplayModes.get(policy.defaultMode)->get();
    std::map<Key, DisplayModeIterator, KeyLess> ratesMap;
    for (auto it = mDisplayModes.begin(); it != mDisplayModes.end(); ++it) {
        const auto& [id, mode] = *it;

        if (!filterModes(*mode)) {
            continue;
        }
        const auto vsyncRate = mode->getVsyncRate();
        const auto peakFps = mode->getPeakFps();

        bool enableFrameRateOverride = mConfig.enableFrameRateOverride;
        if (onlyDivisorsForSameGroup) {
            if (mode->getGroup() != defaultMode->getGroup()) {
                enableFrameRateOverride = false;
            }
        }

        const auto divisors = getModeDivisors(*mode, renderRange, kFpsAnchorList, kNumFrameRates,
                                              enableFrameRateOverride);
        for (auto divisor : divisors) {
            const auto fps = vsyncRate / divisor;
            using fps_approx_ops::operator<;
            if (divisor > 1 &&
                (!mode->getVrrConfig().has_value() && fps < kMinSupportedFrameRate)) {
                break;
            }

            if (mConfig.enableFrameRateOverride && !renderRange.includes(fps)) {
                continue;
            }

            using fps_approx_ops::operator>;
            // Exclude frame rates that are higher than the display peakFps. This may happen during
            // early boot when the policy ranges are not yet in effect.
            if (fps > peakFps) {
                continue;
            }

            const auto [existingIter, emplaceHappened] =
                    ratesMap.try_emplace(Key{fps, mode->getGroup()}, it);
            if (emplaceHappened) {
                ALOGV("%s: including %s (%s(%s))", __func__, to_string(fps).c_str(),
                      to_string(peakFps).c_str(), to_string(vsyncRate).c_str());
            } else {
                // If the primary physical range is a single rate, prefer to stay in that rate
                // even if there is a lower physical refresh rate available. This would cause more
                // cases to stay within the primary physical range
                const Fps existingModeFps = existingIter->second->second->getPeakFps();
                const bool existingModeIsPrimaryRange = policy.primaryRangeIsSingleRate() &&
                        policy.primaryRanges.physical.includes(existingModeFps);
                const bool newModeIsPrimaryRange = policy.primaryRangeIsSingleRate() &&
                        policy.primaryRanges.physical.includes(mode->getPeakFps());
                if (newModeIsPrimaryRange == existingModeIsPrimaryRange) {
                    // We might need to update the map as we found a lower refresh rate
                    if (isStrictlyLess(mode->getPeakFps(), existingModeFps)) {
                        existingIter->second = it;
                        ALOGV("%s: changing %s (%s(%s)) as we found a lower physical rate",
                              __func__, to_string(fps).c_str(), to_string(peakFps).c_str(),
                              to_string(vsyncRate).c_str());
                    }
                } else if (newModeIsPrimaryRange) {
                    existingIter->second = it;
                    ALOGV("%s: changing %s (%s(%s)) to stay in the primary range", __func__,
                          to_string(fps).c_str(), to_string(peakFps).c_str(),
                          to_string(vsyncRate).c_str());
                }
            }
        }
    }

    std::vector<FrameRateMode> frameRateModes;
    frameRateModes.reserve(ratesMap.size());
    for (const auto& [key, mode] : ratesMap) {
        frameRateModes.emplace_back(FrameRateMode{key.fps, ftl::as_non_null(mode->second)});
    }

    // We always want that the lowest frame rate will be corresponding to the
    // lowest mode for power saving.
    const auto lowestRefreshRateIt =
            std::min_element(frameRateModes.begin(), frameRateModes.end(),
                             [](const FrameRateMode& lhs, const FrameRateMode& rhs) {
                                 return isStrictlyLess(lhs.modePtr->getVsyncRate(),
                                                       rhs.modePtr->getVsyncRate());
                             });
    frameRateModes.erase(frameRateModes.begin(), lowestRefreshRateIt);

    return frameRateModes;
}

struct RefreshRateSelector::RefreshRateScoreComparator {
    bool operator()(const RefreshRateScore& lhs, const RefreshRateScore& rhs) const {
        const auto& [frameRateMode, overallScore, _] = lhs;

        ALOGV("%s sorting scores %.2f", to_string(frameRateMode).c_str(), overallScore);

        if (!ScoredFrameRate::scoresEqual(overallScore, rhs.overallScore)) {
            return overallScore > rhs.overallScore;
        }

        if (refreshRateOrder == RefreshRateOrder::Descending) {
            using fps_approx_ops::operator>;
            return frameRateMode.fps > rhs.frameRateMode.fps;
        } else {
            using fps_approx_ops::operator<;
            return frameRateMode.fps < rhs.frameRateMode.fps;
        }
    }

    const RefreshRateOrder refreshRateOrder;
};

std::string RefreshRateSelector::Policy::toString() const {
    return base::StringPrintf("{defaultModeId=%d, allowGroupSwitching=%s"
                              ", primaryRanges=%s, appRequestRanges=%s idleScreenConfig=%s}",
                              ftl::to_underlying(defaultMode),
                              allowGroupSwitching ? "true" : "false",
                              to_string(primaryRanges).c_str(), to_string(appRequestRanges).c_str(),
                              idleScreenConfigOpt ? idleScreenConfigOpt->toString().c_str()
                                                  : "nullptr");
}

std::pair<nsecs_t, nsecs_t> RefreshRateSelector::getDisplayFrames(nsecs_t layerPeriod,
                                                                  nsecs_t displayPeriod) const {
    auto [quotient, remainder] = std::div(layerPeriod, displayPeriod);
    if (remainder <= MARGIN_FOR_PERIOD_CALCULATION ||
        std::abs(remainder - displayPeriod) <= MARGIN_FOR_PERIOD_CALCULATION) {
        quotient++;
        remainder = 0;
    }

    return {quotient, remainder};
}

float RefreshRateSelector::calculateNonExactMatchingDefaultLayerScoreLocked(
        nsecs_t displayPeriod, nsecs_t layerPeriod) const {
    // Find the actual rate the layer will render, assuming
    // that layerPeriod is the minimal period to render a frame.
    // For example if layerPeriod is 20ms and displayPeriod is 16ms,
    // then the actualLayerPeriod will be 32ms, because it is the
    // smallest multiple of the display period which is >= layerPeriod.
    auto actualLayerPeriod = displayPeriod;
    int multiplier = 1;
    while (layerPeriod > actualLayerPeriod + MARGIN_FOR_PERIOD_CALCULATION) {
        multiplier++;
        actualLayerPeriod = displayPeriod * multiplier;
    }

    // Because of the threshold we used above it's possible that score is slightly
    // above 1.
    return std::min(1.0f, static_cast<float>(layerPeriod) / static_cast<float>(actualLayerPeriod));
}

float RefreshRateSelector::calculateNonExactMatchingLayerScoreLocked(const LayerRequirement& layer,
                                                                     Fps refreshRate) const {
    constexpr float kScoreForFractionalPairs = .8f;

    const auto displayPeriod = refreshRate.getPeriodNsecs();
    const auto layerPeriod = layer.desiredRefreshRate.getPeriodNsecs();
    if (layer.vote == LayerVoteType::ExplicitDefault) {
        return calculateNonExactMatchingDefaultLayerScoreLocked(displayPeriod, layerPeriod);
    }

    if (layer.vote == LayerVoteType::ExplicitGte) {
        using fps_approx_ops::operator>=;
        if (refreshRate >= layer.desiredRefreshRate) {
            return 1.0f;
        } else {
            return calculateDistanceScoreLocked(layer.desiredRefreshRate, refreshRate);
        }
    }

    if (layer.vote == LayerVoteType::ExplicitExactOrMultiple ||
        layer.vote == LayerVoteType::Heuristic) {
        using fps_approx_ops::operator<;
        if (refreshRate < 60_Hz) {
            const bool favorsAtLeast60 =
                    std::find_if(mFrameRatesThatFavorsAtLeast60.begin(),
                                 mFrameRatesThatFavorsAtLeast60.end(), [&](Fps fps) {
                                     using fps_approx_ops::operator==;
                                     return fps == layer.desiredRefreshRate;
                                 }) != mFrameRatesThatFavorsAtLeast60.end();
            if (favorsAtLeast60) {
                return 0;
            }
        }

        const float multiplier = refreshRate.getValue() / layer.desiredRefreshRate.getValue();

        // We only want to score this layer as a fractional pair if the content is not
        // significantly faster than the display rate, at it would cause a significant frame drop.
        // It is more appropriate to choose a higher display rate even if
        // a pull-down will be required.
        constexpr float kMinMultiplier = 0.75f;
        if (multiplier >= kMinMultiplier &&
            isFractionalPairOrMultiple(refreshRate, layer.desiredRefreshRate)) {
            return kScoreForFractionalPairs;
        }

        // Calculate how many display vsyncs we need to present a single frame for this
        // layer
        const auto [displayFramesQuotient, displayFramesRemainder] =
                getDisplayFrames(layerPeriod, displayPeriod);
        static constexpr size_t MAX_FRAMES_TO_FIT = 10; // Stop calculating when score < 0.1
        if (displayFramesRemainder == 0) {
            // Layer desired refresh rate matches the display rate.
            return 1.0f;
        }

        if (displayFramesQuotient == 0) {
            // Layer desired refresh rate is higher than the display rate.
            return (static_cast<float>(layerPeriod) / static_cast<float>(displayPeriod)) *
                    (1.0f / (MAX_FRAMES_TO_FIT + 1));
        }

        // Layer desired refresh rate is lower than the display rate. Check how well it fits
        // the cadence.
        auto diff = std::abs(displayFramesRemainder - (displayPeriod - displayFramesRemainder));
        int iter = 2;
        while (diff > MARGIN_FOR_PERIOD_CALCULATION && iter < MAX_FRAMES_TO_FIT) {
            diff = diff - (displayPeriod - diff);
            iter++;
        }

        return (1.0f / iter);
    }

    return 0;
}

float RefreshRateSelector::calculateDistanceScoreLocked(Fps referenceRate, Fps refreshRate) const {
    using fps_approx_ops::operator>=;
    const float ratio = referenceRate >= refreshRate
            ? refreshRate.getValue() / referenceRate.getValue()
            : referenceRate.getValue() / refreshRate.getValue();
    // Use ratio^2 to get a lower score the more we get further from the reference rate.
    return ratio * ratio;
}

float RefreshRateSelector::calculateDistanceScoreFromMaxLocked(Fps refreshRate) const {
    const auto& maxFps = mAppRequestFrameRates.back().fps;
    return calculateDistanceScoreLocked(maxFps, refreshRate);
}

float RefreshRateSelector::calculateLayerScoreLocked(const LayerRequirement& layer, Fps refreshRate,
                                                     bool isSeamlessSwitch) const {
    // Slightly prefer seamless switches.
    constexpr float kSeamedSwitchPenalty = 0.95f;
    const float seamlessness = isSeamlessSwitch ? 1.0f : kSeamedSwitchPenalty;

    if (layer.vote == LayerVoteType::ExplicitCategory) {
        // HighHint is considered later for touch boost.
        if (layer.frameRateCategory == FrameRateCategory::HighHint) {
            return 0.f;
        }

        if (getFrameRateCategoryRange(layer.frameRateCategory).includes(refreshRate)) {
            return 1.f;
        }

        FpsRange categoryRange = getFrameRateCategoryRange(layer.frameRateCategory);
        using fps_approx_ops::operator<;
        if (refreshRate < categoryRange.min) {
            return calculateNonExactMatchingDefaultLayerScoreLocked(refreshRate.getPeriodNsecs(),
                                                                    categoryRange.min
                                                                            .getPeriodNsecs());
        }
        return calculateNonExactMatchingDefaultLayerScoreLocked(refreshRate.getPeriodNsecs(),
                                                                categoryRange.max.getPeriodNsecs());
    }

    // If the layer wants Max, give higher score to the higher refresh rate
    if (layer.vote == LayerVoteType::Max) {
        return calculateDistanceScoreFromMaxLocked(refreshRate);
    }

    if (layer.vote == LayerVoteType::ExplicitExact) {
        const int divisor = getFrameRateDivisor(refreshRate, layer.desiredRefreshRate);
        if (supportsAppFrameRateOverrideByContent()) {
            // Since we support frame rate override, allow refresh rates which are
            // multiples of the layer's request, as those apps would be throttled
            // down to run at the desired refresh rate.
            return divisor > 0;
        }

        return divisor == 1;
    }

    // If the layer frame rate is a divisor of the refresh rate it should score
    // the highest score.
    if (layer.desiredRefreshRate.isValid() &&
        getFrameRateDivisor(refreshRate, layer.desiredRefreshRate) > 0) {
        return 1.0f * seamlessness;
    }

    // The layer frame rate is not a divisor of the refresh rate,
    // there is a small penalty attached to the score to favor the frame rates
    // the exactly matches the display refresh rate or a multiple.
    constexpr float kNonExactMatchingPenalty = 0.95f;
    return calculateNonExactMatchingLayerScoreLocked(layer, refreshRate) * seamlessness *
            kNonExactMatchingPenalty;
}

auto RefreshRateSelector::getRankedFrameRates(const std::vector<LayerRequirement>& allLayers,
                                              GlobalSignals signals, Fps pacesetterFps) const
        -> RankedFrameRates {
    GetRankedFrameRatesCache cache{allLayers, signals, pacesetterFps};

    std::lock_guard lock(mLock);

    if (mGetRankedFrameRatesCache && mGetRankedFrameRatesCache->matches(cache)) {
        return mGetRankedFrameRatesCache->result;
    }

    cache.result = getRankedFrameRatesLocked(allLayers, signals, pacesetterFps);
    mGetRankedFrameRatesCache = std::move(cache);
    return mGetRankedFrameRatesCache->result;
}

using LayerRequirementPtrs = std::vector<const RefreshRateSelector::LayerRequirement*>;
using PerUidLayerRequirements = std::unordered_map<uid_t, LayerRequirementPtrs>;

PerUidLayerRequirements groupLayersByUid(const LayerRequirementPtrs& layers) {
    PerUidLayerRequirements layersByUid;
    for (const auto& layer : layers) {
        const auto it = layersByUid.emplace(layer->ownerUid, LayerRequirementPtrs()).first;
        auto& layersWithSameUid = it->second;
        layersWithSameUid.push_back(layer);
    }
    return layersByUid;
}

LayerRequirementPtrs filterLayersForOutput(
        const std::vector<RefreshRateSelector::LayerRequirement>& layers,
        LayerFilter outputFilter) {
    const bool allowArbitraryFollowerRates =
            FlagManager::getInstance().follower_arbitrary_refresh_rate_selection_combined();
    LayerRequirementPtrs filteredLayers;
    for (const auto& layer : layers) {
        if (!allowArbitraryFollowerRates ||
            outputFilter.layerStack == layer.layerFilter.layerStack) {
            filteredLayers.push_back(&layer);
        }
    }

    return filteredLayers;
}

auto RefreshRateSelector::getRankedFrameRatesLocked(const std::vector<LayerRequirement>& allLayers,
                                                    GlobalSignals signals, Fps pacesetterFps) const
        -> RankedFrameRates {
    using namespace fps_approx_ops;
    SFTRACE_CALL();

    const LayerRequirementPtrs layers = filterLayersForOutput(allLayers, mLayerFilter);
    ALOGV("%s: %zu allLayers, %zu layers", __func__, allLayers.size(), layers.size());

    const auto& activeMode = *getActiveModeLocked().modePtr;

    if (pacesetterFps.isValid() &&
        !FlagManager::getInstance().follower_arbitrary_refresh_rate_selection_combined()) {
        ALOGV("Follower display");

        const auto ranking = rankFrameRates(activeMode.getGroup(), RefreshRateOrder::Descending,
                                            std::nullopt, [&](FrameRateMode mode) {
                                                return mode.modePtr->getPeakFps() == pacesetterFps;
                                            });

        if (!ranking.empty()) {
            SFTRACE_FORMAT_INSTANT("%s (Follower display)",
                                   to_string(ranking.front().frameRateMode.fps).c_str());

            return {ranking, kNoSignals, pacesetterFps};
        }

        ALOGW("Follower display cannot follow the pacesetter");
    }

    // Keep the display at max frame rate for the duration of powering on the display.
    if (signals.powerOnImminent) {
        ALOGV("Power On Imminent");
        const auto ranking = rankFrameRates(activeMode.getGroup(), RefreshRateOrder::Descending);
        SFTRACE_FORMAT_INSTANT("%s (Power On Imminent)",
                               to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, GlobalSignals{.powerOnImminent = true}};
    }

    // A method for UI Toolkit to send the touch signal via "HighHint" category vote,
    // which will touch boost when there are no ExplicitDefault layer votes on the app.
    // At most one app can have the "HighHint" touch boost vote at a time.
    // This accounts for cases such as games that use `setFrameRate`
    // with Default compatibility to limit the frame rate and disabling touch boost.
    bool isAppTouchBoost = false;
    const auto layersByUid = groupLayersByUid(layers);
    for (const auto& [uid, layersWithSameUid] : layersByUid) {
        bool hasHighHint = false;
        bool hasExplicitDefault = false;
        for (const auto& layer : layersWithSameUid) {
            switch (layer->vote) {
                case LayerVoteType::ExplicitDefault:
                    hasExplicitDefault = true;
                    break;
                case LayerVoteType::ExplicitCategory:
                    if (layer->frameRateCategory == FrameRateCategory::HighHint) {
                        hasHighHint = true;
                    }
                    break;
                default:
                    // No action
                    break;
            }
            if (hasHighHint && hasExplicitDefault) {
                break;
            }
        }

        if (hasHighHint && !hasExplicitDefault) {
            // Focused app has touch signal (HighHint) and no frame rate ExplicitDefault votes
            // (which prevents touch boost due to games use case).
            isAppTouchBoost = true;
            break;
        }
    }

    int noVoteLayers = 0;
    // Layers that prefer the same mode ("no-op").
    int noPreferenceLayers = 0;
    int minVoteLayers = 0;
    int maxVoteLayers = 0;
    int explicitDefaultVoteLayers = 0;
    int explicitExactOrMultipleVoteLayers = 0;
    int explicitExact = 0;
    int explicitGteLayers = 0;
    int explicitCategoryVoteLayers = 0;
    int seamedFocusedLayers = 0;
    int categorySmoothSwitchOnlyLayers = 0;

    for (const auto* layerPtr : layers) {
        const auto& layer = *layerPtr;
        switch (layer.vote) {
            case LayerVoteType::NoVote:
                noVoteLayers++;
                break;
            case LayerVoteType::Min:
                minVoteLayers++;
                break;
            case LayerVoteType::Max:
                maxVoteLayers++;
                break;
            case LayerVoteType::ExplicitDefault:
                explicitDefaultVoteLayers++;
                break;
            case LayerVoteType::ExplicitExactOrMultiple:
                explicitExactOrMultipleVoteLayers++;
                break;
            case LayerVoteType::ExplicitExact:
                explicitExact++;
                break;
            case LayerVoteType::ExplicitGte:
                explicitGteLayers++;
                break;
            case LayerVoteType::ExplicitCategory:
                // HighHint does not count as an explicit signal from an app. It is a touch signal
                // sent from UI Toolkit.
                if (layer.frameRateCategory != FrameRateCategory::HighHint) {
                    explicitCategoryVoteLayers++;
                }
                if (layer.frameRateCategory == FrameRateCategory::NoPreference) {
                    noPreferenceLayers++;
                }
                break;
            case LayerVoteType::Heuristic:
                break;
        }

        if (layer.seamlessness == Seamlessness::SeamedAndSeamless && layer.focused) {
            seamedFocusedLayers++;
        }
        if (layer.frameRateCategorySmoothSwitchOnly) {
            categorySmoothSwitchOnlyLayers++;
        }
    }

    const bool hasExplicitVoteLayers = explicitDefaultVoteLayers > 0 ||
            explicitExactOrMultipleVoteLayers > 0 || explicitExact > 0 || explicitGteLayers > 0 ||
            explicitCategoryVoteLayers > 0;

    const Policy* policy = getCurrentPolicyLocked();
    const auto& defaultMode = mDisplayModes.get(policy->defaultMode)->get();

    // If the default mode group is different from the group of current mode,
    // this means a layer requesting a seamed mode switch just disappeared and
    // we should switch back to the default group.
    // However if a seamed layer is still present we anchor around the group
    // of the current mode, in order to prevent unnecessary seamed mode switches
    // (e.g. when pausing a video playback).
    const auto anchorGroup =
            seamedFocusedLayers > 0 ? activeMode.getGroup() : defaultMode->getGroup();

    // Consider the touch event if there are no Explicit* layers. Otherwise wait until after we've
    // selected a refresh rate to see if we should apply touch boost.
    if (signals.touch && !hasExplicitVoteLayers) {
        ALOGV("Touch Boost");
        const auto ranking = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
        SFTRACE_FORMAT_INSTANT("%s (Touch Boost)",
                               to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, GlobalSignals{.touch = true}};
    }

    // If the primary range consists of a single refresh rate then we can only
    // move out the of range if layers explicitly request a different refresh
    // rate.
    if (!signals.touch && signals.idle &&
        !(policy->primaryRangeIsSingleRate() && hasExplicitVoteLayers)) {
        ALOGV("Idle");
        const auto ranking = rankFrameRates(activeMode.getGroup(), RefreshRateOrder::Ascending);
        SFTRACE_FORMAT_INSTANT("%s (Idle)", to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, GlobalSignals{.idle = true}};
    }

    if (layers.empty() || noVoteLayers == layers.size()) {
        ALOGV("No layers with votes");
        const auto ranking = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
        SFTRACE_FORMAT_INSTANT("%s (No layers with votes)",
                               to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, kNoSignals};
    }

    // If all layers are category NoPreference, use the current config.
    if (noPreferenceLayers + noVoteLayers == layers.size()) {
        ALOGV("All layers NoPreference");
        constexpr float kScore = std::numeric_limits<float>::max();
        FrameRateRanking currentMode;
        currentMode.emplace_back(ScoredFrameRate{getActiveModeLocked(), kScore});
        SFTRACE_FORMAT_INSTANT("%s (All layers NoPreference)",
                              to_string(currentMode.front().frameRateMode.fps).c_str());
        return {currentMode, kNoSignals};
    }

    const bool smoothSwitchOnly = categorySmoothSwitchOnlyLayers > 0;
    const DisplayModeId activeModeId = activeMode.getId();

    // Only if all layers want Min we should return Min
    if (noVoteLayers + minVoteLayers == layers.size()) {
        ALOGV("All layers Min");
        const auto ranking = rankFrameRates(activeMode.getGroup(), RefreshRateOrder::Ascending,
                                            std::nullopt, [&](FrameRateMode mode) {
                                                return !smoothSwitchOnly ||
                                                        mode.modePtr->getId() == activeModeId;
                                            });
        SFTRACE_FORMAT_INSTANT("%s (All layers Min)",
                               to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, kNoSignals};
    }

    // Find the best refresh rate based on score
    std::vector<RefreshRateScore> scores;
    scores.reserve(mAppRequestFrameRates.size());

    for (const FrameRateMode& it : mAppRequestFrameRates) {
        scores.emplace_back(RefreshRateScore{it, 0.0f});
    }

    for (const auto* layerPtr : layers) {
        const auto& layer = *layerPtr;
        ALOGV("Calculating score for %s (%s, weight %.2f, desired %.2f, category %s) ",
              layer.name.c_str(), ftl::enum_string(layer.vote).c_str(), layer.weight,
              layer.desiredRefreshRate.getValue(),
              ftl::enum_string(layer.frameRateCategory).c_str());
        if (layer.isNoVote() || layer.frameRateCategory == FrameRateCategory::NoPreference ||
            layer.vote == LayerVoteType::Min) {
            ALOGV("%s scoring skipped due to vote", formatLayerInfo(layer, layer.weight).c_str());
            continue;
        }

        const auto weight = layer.weight;

        for (auto& [mode, overallScore, fixedRateBelowThresholdLayersScore] : scores) {
            const auto& [fps, modePtr] = mode;
            const bool isSeamlessSwitch = modePtr->getGroup() == activeMode.getGroup();

            if (layer.seamlessness == Seamlessness::OnlySeamless && !isSeamlessSwitch) {
                ALOGV("%s ignores %s to avoid non-seamless switch. Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(), to_string(*modePtr).c_str(),
                      to_string(activeMode).c_str());
                continue;
            }

            if (layer.seamlessness == Seamlessness::SeamedAndSeamless && !isSeamlessSwitch &&
                !layer.focused) {
                ALOGV("%s ignores %s because it's not focused and the switch is going to be seamed."
                      " Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(), to_string(*modePtr).c_str(),
                      to_string(activeMode).c_str());
                continue;
            }

            if (smoothSwitchOnly && modePtr->getId() != activeModeId) {
                ALOGV("%s ignores %s because it's non-VRR and smooth switch only."
                      " Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(), to_string(*modePtr).c_str(),
                      to_string(activeMode).c_str());
                continue;
            }

            // Layers with default seamlessness vote for the current mode group if
            // there are layers with seamlessness=SeamedAndSeamless and for the default
            // mode group otherwise. In second case, if the current mode group is different
            // from the default, this means a layer with seamlessness=SeamedAndSeamless has just
            // disappeared.
            const bool isInPolicyForDefault = modePtr->getGroup() == anchorGroup;
            if (layer.seamlessness == Seamlessness::Default && !isInPolicyForDefault) {
                ALOGV("%s ignores %s. Current mode = %s", formatLayerInfo(layer, weight).c_str(),
                      to_string(*modePtr).c_str(), to_string(activeMode).c_str());
                continue;
            }

            const bool inPrimaryPhysicalRange =
                    policy->primaryRanges.physical.includes(modePtr->getPeakFps());
            const bool inPrimaryRenderRange = policy->primaryRanges.render.includes(fps);
            if (((policy->primaryRangeIsSingleRate() && !inPrimaryPhysicalRange) ||
                 !inPrimaryRenderRange) &&
                !(layer.focused &&
                  (layer.vote == LayerVoteType::ExplicitDefault ||
                   layer.vote == LayerVoteType::ExplicitExact))) {
                // Only focused layers with ExplicitDefault frame rate settings are allowed to score
                // refresh rates outside the primary range.
                continue;
            }

            const float layerScore = calculateLayerScoreLocked(layer, fps, isSeamlessSwitch);
            const float weightedLayerScore = weight * layerScore;

            // Layer with fixed source has a special consideration which depends on the
            // mConfig.frameRateMultipleThreshold. We don't want these layers to score
            // refresh rates above the threshold, but we also don't want to favor the lower
            // ones by having a greater number of layers scoring them. Instead, we calculate
            // the score independently for these layers and later decide which
            // refresh rates to add it. For example, desired 24 fps with 120 Hz threshold should not
            // score 120 Hz, but desired 60 fps should contribute to the score.
            const bool fixedSourceLayer = [](LayerVoteType vote) {
                switch (vote) {
                    case LayerVoteType::ExplicitExactOrMultiple:
                    case LayerVoteType::Heuristic:
                        return true;
                    case LayerVoteType::NoVote:
                    case LayerVoteType::Min:
                    case LayerVoteType::Max:
                    case LayerVoteType::ExplicitDefault:
                    case LayerVoteType::ExplicitExact:
                    case LayerVoteType::ExplicitGte:
                    case LayerVoteType::ExplicitCategory:
                        return false;
                }
            }(layer.vote);
            const bool layerBelowThreshold = mConfig.frameRateMultipleThreshold != 0 &&
                    layer.desiredRefreshRate <
                            Fps::fromValue(mConfig.frameRateMultipleThreshold / 2);
            if (fixedSourceLayer && layerBelowThreshold) {
                const bool modeAboveThreshold =
                        modePtr->getPeakFps() >= Fps::fromValue(mConfig.frameRateMultipleThreshold);
                if (modeAboveThreshold) {
                    ALOGV("%s gives %s (%s(%s)) fixed source (above threshold) score of %.4f",
                          formatLayerInfo(layer, weight).c_str(), to_string(fps).c_str(),
                          to_string(modePtr->getPeakFps()).c_str(),
                          to_string(modePtr->getVsyncRate()).c_str(), layerScore);
                    fixedRateBelowThresholdLayersScore.modeAboveThreshold += weightedLayerScore;
                } else {
                    ALOGV("%s gives %s (%s(%s)) fixed source (below threshold) score of %.4f",
                          formatLayerInfo(layer, weight).c_str(), to_string(fps).c_str(),
                          to_string(modePtr->getPeakFps()).c_str(),
                          to_string(modePtr->getVsyncRate()).c_str(), layerScore);
                    fixedRateBelowThresholdLayersScore.modeBelowThreshold += weightedLayerScore;
                }
            } else {
                ALOGV("%s gives %s (%s(%s)) score of %.4f", formatLayerInfo(layer, weight).c_str(),
                      to_string(fps).c_str(), to_string(modePtr->getPeakFps()).c_str(),
                      to_string(modePtr->getVsyncRate()).c_str(), layerScore);
                overallScore += weightedLayerScore;
            }
        }
    }

    // We want to find the best refresh rate without the fixed source layers,
    // so we could know whether we should add the modeAboveThreshold scores or not.
    // If the best refresh rate is already above the threshold, it means that
    // some non-fixed source layers already scored it, so we can just add the score
    // for all fixed source layers, even the ones that are above the threshold.
    const bool maxScoreAboveThreshold = [&] {
        if (mConfig.frameRateMultipleThreshold == 0 || scores.empty()) {
            return false;
        }

        const auto maxScoreIt =
                std::max_element(scores.begin(), scores.end(),
                                 [](RefreshRateScore max, RefreshRateScore current) {
                                     return current.overallScore > max.overallScore;
                                 });
        ALOGV("%s (%s(%s)) is the best refresh rate without fixed source layers. It is %s the "
              "threshold for "
              "refresh rate multiples",
              to_string(maxScoreIt->frameRateMode.fps).c_str(),
              to_string(maxScoreIt->frameRateMode.modePtr->getPeakFps()).c_str(),
              to_string(maxScoreIt->frameRateMode.modePtr->getVsyncRate()).c_str(),
              maxScoreAboveThreshold ? "above" : "below");
        return maxScoreIt->frameRateMode.modePtr->getPeakFps() >=
                Fps::fromValue(mConfig.frameRateMultipleThreshold);
    }();

    // Now we can add the fixed rate layers score
    for (auto& [frameRateMode, overallScore, fixedRateBelowThresholdLayersScore] : scores) {
        overallScore += fixedRateBelowThresholdLayersScore.modeBelowThreshold;
        if (maxScoreAboveThreshold) {
            overallScore += fixedRateBelowThresholdLayersScore.modeAboveThreshold;
        }
        ALOGV("%s (%s(%s)) adjusted overallScore is %.4f", to_string(frameRateMode.fps).c_str(),
              to_string(frameRateMode.modePtr->getPeakFps()).c_str(),
              to_string(frameRateMode.modePtr->getVsyncRate()).c_str(), overallScore);
    }

    // Now that we scored all the refresh rates we need to pick the one that got the highest
    // overallScore. Sort the scores based on their overallScore in descending order of priority.
    const RefreshRateOrder refreshRateOrder =
            maxVoteLayers > 0 ? RefreshRateOrder::Descending : RefreshRateOrder::Ascending;
    std::sort(scores.begin(), scores.end(),
              RefreshRateScoreComparator{.refreshRateOrder = refreshRateOrder});

    FrameRateRanking ranking;
    ranking.reserve(scores.size());

    std::transform(scores.begin(), scores.end(), back_inserter(ranking),
                   [](const RefreshRateScore& score) {
                       return ScoredFrameRate{score.frameRateMode, score.overallScore};
                   });

    const bool noLayerScore = std::all_of(scores.begin(), scores.end(), [](RefreshRateScore score) {
        return score.overallScore == 0;
    });

    // TODO(b/364651864): Evaluate correctness of primaryRangeIsSingleRate.
    if (!mIsVrrDisplay.load() && policy->primaryRangeIsSingleRate()) {
        // If we never scored any layers, then choose the rate from the primary
        // range instead of picking a random score from the app range.
        if (noLayerScore) {
            ALOGV("Layers not scored");
            const auto descending = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
            SFTRACE_FORMAT_INSTANT("%s (Layers not scored)",
                                   to_string(descending.front().frameRateMode.fps).c_str());
            return {descending, kNoSignals};
        } else {
            ALOGV("primaryRangeIsSingleRate");
            SFTRACE_FORMAT_INSTANT("%s (primaryRangeIsSingleRate)",
                                   to_string(ranking.front().frameRateMode.fps).c_str());
            return {ranking, kNoSignals};
        }
    }

    // Consider the touch event if there are no ExplicitDefault layers. ExplicitDefault are mostly
    // interactive (as opposed to ExplicitExactOrMultiple) and therefore if those posted an explicit
    // vote we should not change it if we get a touch event. Only apply touch boost if it will
    // actually increase the refresh rate over the normal selection.
    const auto isTouchBoostForExplicitExact = [&]() -> bool {
        if (supportsAppFrameRateOverrideByContent()) {
            // Enable touch boost if there are other layers besides exact
            return explicitExact + noVoteLayers + explicitGteLayers != layers.size();
        } else {
            // Enable touch boost if there are no exact layers
            return explicitExact == 0;
        }
    };

    const auto isTouchBoostForCategory = [&]() -> bool {
        return explicitCategoryVoteLayers + noVoteLayers + explicitGteLayers != layers.size();
    };

    // This accounts for cases such as games that use `setFrameRate` with Default
    // compatibility to limit the frame rate, which should not have touch boost.
    const bool isLateGlobalTouchBoost = signals.touch && explicitDefaultVoteLayers == 0;
    const bool isLateTouchBoost = isLateGlobalTouchBoost || isAppTouchBoost;
    if (isLateTouchBoost && isTouchBoostForExplicitExact() && isTouchBoostForCategory()) {
        const auto touchRefreshRates = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
        using fps_approx_ops::operator<;

        if (scores.front().frameRateMode.fps <= touchRefreshRates.front().frameRateMode.fps) {
            ALOGV("Touch Boost [late]");
            SFTRACE_FORMAT_INSTANT("%s (Touch Boost [late])",
                                   to_string(touchRefreshRates.front().frameRateMode.fps).c_str());
            return {touchRefreshRates, GlobalSignals{.touch = true}};
        }
    }

    // If we never scored any layers, and we don't favor high refresh rates, prefer to stay with the
    // current config
    if (noLayerScore && refreshRateOrder == RefreshRateOrder::Ascending) {
        ALOGV("preferredDisplayMode");
        const auto ascendingWithPreferred =
                rankFrameRates(anchorGroup, RefreshRateOrder::Ascending, activeMode.getId());
        SFTRACE_FORMAT_INSTANT("%s (preferredDisplayMode)",
                               to_string(ascendingWithPreferred.front().frameRateMode.fps).c_str());
        return {ascendingWithPreferred, kNoSignals};
    }

    ALOGV("%s (scored)", to_string(ranking.front().frameRateMode.fps).c_str());
    SFTRACE_FORMAT_INSTANT("%s (scored)", to_string(ranking.front().frameRateMode.fps).c_str());
    return {ranking, kNoSignals};
}

auto RefreshRateSelector::getFrameRateOverrides(const std::vector<LayerRequirement>& allLayers,
                                                Fps displayRefreshRate,
                                                GlobalSignals globalSignals) const
        -> UidToFrameRateOverride {
    SFTRACE_CALL();
    if (!mConfig.enableFrameRateOverride) {
        return {};
    }

    std::lock_guard lock(mLock);
    const LayerRequirementPtrs layers = filterLayersForOutput(allLayers, mLayerFilter);

    ALOGV("%s: %zu allLayers, %zu layers", __func__, allLayers.size(), layers.size());

    std::vector<std::pair<Fps, float>> scoredFrameRates;
    if (!mIsVrrDisplay) {
        // We don't want to run lower than 30fps
        const auto* policyPtr = getCurrentPolicyLocked();
        const Fps minFrameRate =
                std::max(policyPtr->appRequestRanges.render.min, 30_Hz, isApproxLess);

        using fps_approx_ops::operator/;
        const unsigned numMultiples = displayRefreshRate / minFrameRate;
        scoredFrameRates.reserve(numMultiples);

        for (unsigned n = numMultiples; n > 0; n--) {
            const Fps divisor = displayRefreshRate / n;
            if (policyPtr->appRequestRanges.render.includes(divisor)) {
                ALOGV("%s: adding %s as a potential frame rate", __func__,
                      to_string(divisor).c_str());
                scoredFrameRates.emplace_back(divisor, 0);
            }
        }
    } else {
        for (const auto& frameRate : mAppRequestFrameRates) {
            const int divisor = getFrameRateDivisor(displayRefreshRate, frameRate.fps);
            if (divisor > 0) {
                ALOGV("%s: adding %s as a potential frame rate", __func__,
                      to_string(frameRate.fps).c_str());
                scoredFrameRates.emplace_back(frameRate.fps, 0);
            }
        }
    }

    const auto layersByUid = groupLayersByUid(layers);
    UidToFrameRateOverride frameRateOverrides;
    for (const auto& [uid, layersWithSameUid] : layersByUid) {
        // Look for cases that should not have frame rate overrides.
        bool hasExplicitExactOrMultiple = false;
        bool hasExplicitDefault = false;
        bool hasHighHint = false;
        bool hasSkipOverrideLayer = false;
        for (const auto& layer : layersWithSameUid) {
            switch (layer->vote) {
                case LayerVoteType::ExplicitExactOrMultiple:
                    hasExplicitExactOrMultiple = true;
                    break;
                case LayerVoteType::ExplicitDefault:
                    hasExplicitDefault = true;
                    break;
                case LayerVoteType::ExplicitCategory:
                    if (layer->frameRateCategory == FrameRateCategory::HighHint) {
                        hasHighHint = true;
                    }
                    break;
                case LayerVoteType::Max:
                case LayerVoteType::Heuristic:
                    hasSkipOverrideLayer = true;
                    break;
                default:
                    // No action
                    break;
            }
            if (hasExplicitExactOrMultiple && hasExplicitDefault && hasHighHint &&
                hasSkipOverrideLayer) {
                break;
            }
        }

        if (hasSkipOverrideLayer) {
            ALOGV("%s: Skipping due to vote(s): uid=%d", __func__, uid);
            continue;
        }

        // Layers with ExplicitExactOrMultiple expect touch boost
        if (globalSignals.touch && hasExplicitExactOrMultiple) {
            continue;
        }

        // Mirrors getRankedFrameRates. If there is no ExplicitDefault, expect touch boost and
        // skip frame rate override.
        if (hasHighHint && !hasExplicitDefault) {
            continue;
        }

        for (auto& [_, score] : scoredFrameRates) {
            score = 0;
        }

        for (const auto& layer : layersWithSameUid) {
            if (layer->isNoVote() || layer->frameRateCategory == FrameRateCategory::NoPreference ||
                layer->vote == LayerVoteType::Min) {
                continue;
            }

            LOG_ALWAYS_FATAL_IF(layer->vote != LayerVoteType::ExplicitDefault &&
                                        layer->vote != LayerVoteType::ExplicitExactOrMultiple &&
                                        layer->vote != LayerVoteType::ExplicitExact &&
                                        layer->vote != LayerVoteType::ExplicitGte &&
                                        layer->vote != LayerVoteType::ExplicitCategory,
                                "Invalid layer vote type for frame rate overrides");
            for (auto& [fps, score] : scoredFrameRates) {
                constexpr bool isSeamlessSwitch = true;
                const auto layerScore = calculateLayerScoreLocked(*layer, fps, isSeamlessSwitch);
                score += layer->weight * layerScore;
            }
        }

        // If we never scored any layers, we don't have a preferred frame rate
        if (std::all_of(scoredFrameRates.begin(), scoredFrameRates.end(),
                        [](const auto& scoredFrameRate) {
                            const auto [_, score] = scoredFrameRate;
                            return score == 0;
                        })) {
            continue;
        }

        // Now that we scored all the refresh rates we need to pick the lowest refresh rate
        // that got the highest score.
        const auto [overrideFps, _] =
                *std::max_element(scoredFrameRates.begin(), scoredFrameRates.end(),
                                  [](const auto& lhsPair, const auto& rhsPair) {
                                      const float lhs = lhsPair.second;
                                      const float rhs = rhsPair.second;
                                      return lhs < rhs && !ScoredFrameRate::scoresEqual(lhs, rhs);
                                  });
        ALOGV("%s: overriding to %s for uid=%d", __func__, to_string(overrideFps).c_str(), uid);
        SFTRACE_FORMAT_INSTANT("%s: overriding to %s for uid=%d", __func__,
                               to_string(overrideFps).c_str(), uid);
        if (SFTRACE_ENABLED()) {
            std::stringstream ss;
            ss << "FrameRateOverride " << uid;
            SFTRACE_INT(ss.str().c_str(), overrideFps.getIntValue());
        }
        frameRateOverrides.emplace(uid, overrideFps);
    }

    return frameRateOverrides;
}

ftl::Optional<FrameRateMode> RefreshRateSelector::onKernelTimerChanged(
        ftl::Optional<DisplayModeId> desiredModeIdOpt, bool timerExpired) const {
    std::lock_guard lock(mLock);

    const auto current =
            desiredModeIdOpt
                    .and_then([this](DisplayModeId modeId)
                                      REQUIRES(mLock) { return mDisplayModes.get(modeId); })
                    .transform([](const DisplayModePtr& modePtr) {
                        return FrameRateMode{modePtr->getPeakFps(), ftl::as_non_null(modePtr)};
                    })
                    .or_else([this] {
                        ftl::FakeGuard guard(mLock);
                        return std::make_optional(getActiveModeLocked());
                    })
                    .value();

    const DisplayModePtr& min = mConfigGroupMinRefreshRateModeIt->second;
    if (current.modePtr->getId() == min->getId()) {
        return {};
    }

    return timerExpired ? FrameRateMode{min->getPeakFps(), ftl::as_non_null(min)} : current;
}

const DisplayModePtr& RefreshRateSelector::getMinRefreshRateByPolicyLocked() const {
    const auto& activeMode = *getActiveModeLocked().modePtr;

    for (const FrameRateMode& mode : mPrimaryFrameRates) {
        if (activeMode.getGroup() == mode.modePtr->getGroup()) {
            return mode.modePtr.get();
        }
    }

    ALOGE("Can't find min refresh rate by policy with the same mode group as the current mode %s",
          to_string(activeMode).c_str());

    // Default to the lowest refresh rate.
    return mPrimaryFrameRates.front().modePtr.get();
}

const DisplayModePtr& RefreshRateSelector::getMaxRefreshRateByPolicyLocked(int anchorGroup) const {
    const ftl::NonNull<DisplayModePtr>* maxByAnchor = &mPrimaryFrameRates.back().modePtr;
    const ftl::NonNull<DisplayModePtr>* max = &mPrimaryFrameRates.back().modePtr;

    bool maxByAnchorFound = false;
    for (auto it = mPrimaryFrameRates.rbegin(); it != mPrimaryFrameRates.rend(); ++it) {
        using namespace fps_approx_ops;
        if (it->modePtr->getPeakFps() > (*max)->getPeakFps()) {
            max = &it->modePtr;
        }

        if (anchorGroup == it->modePtr->getGroup() &&
            it->modePtr->getPeakFps() >= (*maxByAnchor)->getPeakFps()) {
            maxByAnchorFound = true;
            maxByAnchor = &it->modePtr;
        }
    }

    if (maxByAnchorFound) {
        return maxByAnchor->get();
    }

    ALOGE("Can't find max refresh rate by policy with the same group %d", anchorGroup);

    // Default to the highest refresh rate.
    return max->get();
}

auto RefreshRateSelector::getPreferredFpsForMode(std::optional<int> anchorGroupOpt,
                                                 RefreshRateOrder refreshRateOrder) const
        -> PreferredFpsForMode {
    using namespace fps_approx_ops;

    const bool ascending = (refreshRateOrder == RefreshRateOrder::Ascending);
    if (!ascending) return {};

    // find the lowest >=60  frame rate for each display mode
    PreferredFpsForMode preferredFpsForMode;
    for (const auto& frameRateMode : mPrimaryFrameRates | std::views::reverse) {
        if (anchorGroupOpt && frameRateMode.modePtr->getGroup() != anchorGroupOpt) {
            continue;
        }

        const auto [iter, _] =
                preferredFpsForMode.try_emplace(frameRateMode.modePtr->getId(), frameRateMode.fps);
        if (frameRateMode.fps >= 60_Hz && frameRateMode.fps < iter->second) {
            iter->second = frameRateMode.fps;
        }
    }

    return preferredFpsForMode;
}

auto RefreshRateSelector::rankFrameRates(std::optional<int> anchorGroupOpt,
                                         RefreshRateOrder refreshRateOrder,
                                         std::optional<DisplayModeId> preferredDisplayModeOpt,
                                         const RankFrameRatesPredicate& predicate) const
        -> FrameRateRanking {
    const char* const whence = __func__;

    using namespace fps_approx_ops;
    const bool ascending = (refreshRateOrder == RefreshRateOrder::Ascending);
    const auto preferredFpsForMode = getPreferredFpsForMode(anchorGroupOpt, refreshRateOrder);
    std::deque<ScoredFrameRate> ranking;
    const auto rankFrameRate = [&](const FrameRateMode& frameRateMode) REQUIRES(mLock) {
        const auto& modePtr = frameRateMode.modePtr;
        if ((anchorGroupOpt && modePtr->getGroup() != anchorGroupOpt) ||
            !predicate(frameRateMode)) {
            return;
        }

        const auto id = modePtr->getId();
        const auto fpsOpt = preferredFpsForMode.get(id);
        if (fpsOpt && frameRateMode.fps != *fpsOpt) {
           return;
        }

        float score = calculateDistanceScoreFromMaxLocked(frameRateMode.fps);
        if (ascending) {
            score = 1.0f / score;
        }

        constexpr float kScore = std::numeric_limits<float>::max();
        if (preferredDisplayModeOpt) {
            if (*preferredDisplayModeOpt == modePtr->getId()) {
                ranking.emplace_front(ScoredFrameRate{frameRateMode, kScore});
                return;
            }
            constexpr float kNonPreferredModePenalty = 0.95f;
            score *= kNonPreferredModePenalty;
        } else if (ascending && id == getMinRefreshRateByPolicyLocked()->getId()) {
            ranking.emplace_front(ScoredFrameRate{frameRateMode, kScore});
            return;
        }

        ALOGV("%s(%s) %s (%s(%s)) scored %.2f", whence, ftl::enum_string(refreshRateOrder).c_str(),
              to_string(frameRateMode.fps).c_str(), to_string(modePtr->getPeakFps()).c_str(),
              to_string(modePtr->getVsyncRate()).c_str(), score);
        ranking.emplace_back(ScoredFrameRate{frameRateMode, score});
    };

    if (refreshRateOrder == RefreshRateOrder::Ascending) {
        std::for_each(mPrimaryFrameRates.begin(), mPrimaryFrameRates.end(), rankFrameRate);
    } else {
        std::for_each(mPrimaryFrameRates.rbegin(), mPrimaryFrameRates.rend(), rankFrameRate);
    }

    if (!ranking.empty() || !anchorGroupOpt) {
        return {ranking.begin(), ranking.end()};
    }

    ALOGW("Can't find %s refresh rate by policy with the same mode group"
          " as the mode group %d",
          refreshRateOrder == RefreshRateOrder::Ascending ? "min" : "max", anchorGroupOpt.value());

    constexpr std::optional<int> kNoAnchorGroup = std::nullopt;
    return rankFrameRates(kNoAnchorGroup, refreshRateOrder, preferredDisplayModeOpt);
}

FrameRateMode RefreshRateSelector::getActiveMode() const {
    std::lock_guard lock(mLock);
    return getActiveModeLocked();
}

const FrameRateMode& RefreshRateSelector::getActiveModeLocked() const {
    return *mActiveModeOpt;
}

void RefreshRateSelector::setActiveMode(DisplayModeId modeId, Fps renderFrameRate) {
    std::lock_guard lock(mLock);

    // Invalidate the cached invocation to getRankedFrameRates. This forces
    // the refresh rate to be recomputed on the next call to getRankedFrameRates.
    mGetRankedFrameRatesCache.reset();

    const auto activeModeOpt = mDisplayModes.get(modeId);
    LOG_ALWAYS_FATAL_IF(!activeModeOpt);

    mActiveModeOpt.emplace(FrameRateMode{renderFrameRate, ftl::as_non_null(activeModeOpt->get())});
    mIsVrrDisplay = activeModeOpt->get()->getVrrConfig().has_value();
}

RefreshRateSelector::RefreshRateSelector(DisplayModes modes, DisplayModeId activeModeId,
                                         Config config)
      : mKnownFrameRates(constructKnownFrameRates(modes)), mConfig(config) {
    createIdleTimer(mConfig.legacyIdleTimerTimeout);
    FTL_FAKE_GUARD(kMainThreadContext, updateDisplayModes(std::move(modes), activeModeId));
}

void RefreshRateSelector::createIdleTimer(std::chrono::milliseconds timeout) {
    if (timeout > 0ms) {
        mIdleTimer.emplace(
                "IdleTimer", timeout,
                [this] {
                    std::scoped_lock lock(mIdleTimerCallbacksMutex);
                    if (const auto callbacks = getIdleTimerCallbacks()) {
                        callbacks->onReset();
                    }
                },
                [this] {
                    std::scoped_lock lock(mIdleTimerCallbacksMutex);
                    if (const auto callbacks = getIdleTimerCallbacks()) {
                        callbacks->onExpired();
                    }
                });
    }
}

void RefreshRateSelector::updateDisplayModes(DisplayModes modes, DisplayModeId activeModeId) {
    std::lock_guard lock(mLock);

    // Invalidate the cached invocation to getRankedFrameRates. This forces
    // the refresh rate to be recomputed on the next call to getRankedFrameRates.
    mGetRankedFrameRatesCache.reset();

    mDisplayModes = std::move(modes);
    const auto activeModeOpt = mDisplayModes.get(activeModeId);
    LOG_ALWAYS_FATAL_IF(!activeModeOpt);
    mActiveModeOpt = FrameRateMode{activeModeOpt->get()->getPeakFps(),
                                   ftl::as_non_null(activeModeOpt->get())};
    mIsVrrDisplay = activeModeOpt->get()->getVrrConfig().has_value();

    const auto sortedModes = sortByRefreshRate(mDisplayModes);

    // Reset the policy because the old one may no longer be valid.
    mDisplayManagerPolicy = {};
    mDisplayManagerPolicy.defaultMode = activeModeId;

    constructAvailableRefreshRates();
}

bool RefreshRateSelector::isPolicyValidLocked(const Policy& policy) const {
    // defaultMode must be a valid mode, and within the given refresh rate range.
    if (const auto mode = mDisplayModes.get(policy.defaultMode)) {
        if (!policy.primaryRanges.physical.includes(mode->get()->getPeakFps())) {
            ALOGE("Default mode is not in the primary range.");
            return false;
        }
    } else {
        ALOGE("Default mode is not found.");
        return false;
    }

    const auto& primaryRanges = policy.primaryRanges;
    const auto& appRequestRanges = policy.appRequestRanges;
    ALOGE_IF(!appRequestRanges.physical.includes(primaryRanges.physical),
             "Physical range is invalid: primary: %s appRequest: %s",
             to_string(primaryRanges.physical).c_str(),
             to_string(appRequestRanges.physical).c_str());
    ALOGE_IF(!appRequestRanges.render.includes(primaryRanges.render),
             "Render range is invalid: primary: %s appRequest: %s",
             to_string(primaryRanges.render).c_str(), to_string(appRequestRanges.render).c_str());

    return primaryRanges.valid() && appRequestRanges.valid();
}

auto RefreshRateSelector::setPolicy(const PolicyVariant& policy) -> SetPolicyResult {
    Policy oldPolicy;
    PhysicalDisplayId displayId;
    {
        std::lock_guard lock(mLock);
        oldPolicy = *getCurrentPolicyLocked();

        const bool valid = ftl::match(
                policy,
                [this](const auto& policy) {
                    ftl::FakeGuard guard(mLock);
                    if (!isPolicyValidLocked(policy)) {
                        ALOGE("Invalid policy: %s", policy.toString().c_str());
                        return false;
                    }

                    using T = std::decay_t<decltype(policy)>;

                    if constexpr (std::is_same_v<T, DisplayManagerPolicy>) {
                        mDisplayManagerPolicy = policy;
                    } else {
                        static_assert(std::is_same_v<T, OverridePolicy>);
                        mOverridePolicy = policy;
                    }
                    return true;
                },
                [this](NoOverridePolicy) {
                    ftl::FakeGuard guard(mLock);
                    mOverridePolicy.reset();
                    return true;
                });

        if (!valid) {
            return SetPolicyResult::Invalid;
        }

        mGetRankedFrameRatesCache.reset();

        const auto& idleScreenConfigOpt = getCurrentPolicyLocked()->idleScreenConfigOpt;
        if (idleScreenConfigOpt != oldPolicy.idleScreenConfigOpt) {
            if (!idleScreenConfigOpt.has_value()) {
                if (mIdleTimer) {
                    // fallback to legacy timer if existed, otherwise pause the old timer
                    if (mConfig.legacyIdleTimerTimeout > 0ms) {
                        mIdleTimer->setInterval(mConfig.legacyIdleTimerTimeout);
                        mIdleTimer->resume();
                    } else {
                        mIdleTimer->pause();
                    }
                }
            } else if (idleScreenConfigOpt->timeoutMillis > 0) {
                // create a new timer or reconfigure
                const auto timeout = std::chrono::milliseconds{idleScreenConfigOpt->timeoutMillis};
                if (!mIdleTimer) {
                    createIdleTimer(timeout);
                    if (mIdleTimerStarted) {
                        mIdleTimer->start();
                    }
                } else {
                    mIdleTimer->setInterval(timeout);
                    mIdleTimer->resume();
                }
            } else {
                if (mIdleTimer) {
                    mIdleTimer->pause();
                }
            }
        }

        if (getCurrentPolicyLocked()->similarExceptIdleConfig(oldPolicy)) {
            return SetPolicyResult::Unchanged;
        }

        constructAvailableRefreshRates();

        displayId = getActiveModeLocked().modePtr->getPhysicalDisplayId();
    }

    const unsigned numModeChanges = std::exchange(mNumModeSwitchesInPolicy, 0u);

    ALOGI("Display %s policy changed\n"
          "Previous: %s\n"
          "Current:  %s\n"
          "%u mode changes were performed under the previous policy",
          to_string(displayId).c_str(), oldPolicy.toString().c_str(), toString(policy).c_str(),
          numModeChanges);

    return SetPolicyResult::Changed;
}

auto RefreshRateSelector::getCurrentPolicyLocked() const -> const Policy* {
    return mOverridePolicy ? &mOverridePolicy.value() : &mDisplayManagerPolicy;
}

auto RefreshRateSelector::getCurrentPolicy() const -> Policy {
    std::lock_guard lock(mLock);
    return *getCurrentPolicyLocked();
}

auto RefreshRateSelector::getDisplayManagerPolicy() const -> Policy {
    std::lock_guard lock(mLock);
    return mDisplayManagerPolicy;
}

bool RefreshRateSelector::isModeAllowed(const FrameRateMode& mode) const {
    std::lock_guard lock(mLock);
    return std::find(mAppRequestFrameRates.begin(), mAppRequestFrameRates.end(), mode) !=
            mAppRequestFrameRates.end();
}

void RefreshRateSelector::constructAvailableRefreshRates() {
    // Filter modes based on current policy and sort on refresh rate.
    const Policy* policy = getCurrentPolicyLocked();
    ALOGV("%s: %s ", __func__, policy->toString().c_str());

    const auto& defaultMode = mDisplayModes.get(policy->defaultMode)->get();
    const auto sortedModes = sortByRefreshRate(mDisplayModes);
    mGlobalMinRefreshRateModeIt = sortedModes.front();
    mGlobalMaxRefreshRateModeIt = sortedModes.back();
    mConfigGroupMinRefreshRateModeIt = *std::find_if(sortedModes.cbegin(), sortedModes.cend(),
                                            [group = defaultMode->getGroup()](const auto& it) {
                                                return it->second->getGroup() == group;
                                            });
    mConfigGroupMaxRefreshRateModeIt = *std::find_if(sortedModes.crbegin(), sortedModes.crend(),
                                            [group = defaultMode->getGroup()](const auto& it) {
                                                return it->second->getGroup() == group;
                                            });

    const auto filterRefreshRates = [&](const FpsRanges& ranges, const char* rangeName,
                                        bool allowAllGroups = false) REQUIRES(mLock) {
        const auto filterModes = [&](const DisplayMode& mode) {
            bool hdrOutputTypeMatches = FlagManager::getInstance().enable_user_preferred_hdr_mode()
                    ? mode.getHdrOutputType() == defaultMode->getHdrOutputType()
                    : true;
            return mode.getResolution() == defaultMode->getResolution() &&
                    mode.getDpi() == defaultMode->getDpi() &&
                    (allowAllGroups || policy->allowGroupSwitching ||
                     mode.getGroup() == defaultMode->getGroup()) &&
                    ranges.physical.includes(mode.getPeakFps()) &&
                    (supportsFrameRateOverride() || ranges.render.includes(mode.getPeakFps())) &&
                    hdrOutputTypeMatches;
        };

        auto frameRateModes = createFrameRateModes(*policy, filterModes, ranges.render,
                                                   allowAllGroups && !mIsVrrDisplay);
        if (frameRateModes.empty()) {
            ALOGW("No matching frame rate modes for %s range. policy: %s", rangeName,
                  policy->toString().c_str());
            // TODO(b/292105422): Ideally DisplayManager should not send render ranges smaller than
            // the min supported. See b/292047939.
            //  For not we just ignore the render ranges.
            frameRateModes = createFrameRateModes(*policy, filterModes, {},
                                                  allowAllGroups && !mIsVrrDisplay);
        }
        LOG_ALWAYS_FATAL_IF(frameRateModes.empty(),
                            "No matching frame rate modes for %s range even after ignoring the "
                            "render range. policy: %s",
                            rangeName, policy->toString().c_str());

        const auto stringifyModes = [&] {
            std::string str;
            for (const auto& frameRateMode : frameRateModes) {
                str += to_string(frameRateMode) + " ";
            }
            return str;
        };
        ALOGV("%s render rates: %s, isVrrDisplay? %d", rangeName, stringifyModes().c_str(),
              mIsVrrDisplay.load());

        return frameRateModes;
    };

    mPrimaryFrameRates = filterRefreshRates(policy->primaryRanges, "primary");
    mAppRequestFrameRates = filterRefreshRates(policy->appRequestRanges, "app request");

    const bool useMrrFullList =
            FlagManager::getInstance().mrr_full_frame_rate_list() && !mIsVrrDisplay;
    const FpsRange fullRange = useMrrFullList
            ? FpsRange{0_Hz, mGlobalMaxRefreshRateModeIt->second->getPeakFps()}
            : getSupportedFrameRateRangeLocked();

    mAllFrameRates =
            filterRefreshRates(FpsRanges(fullRange, fullRange), "full frame rates", useMrrFullList);
}

bool RefreshRateSelector::isVrrDisplay() const {
    return mIsVrrDisplay;
}

Fps RefreshRateSelector::findClosestKnownFrameRate(Fps frameRate) const {
    using namespace fps_approx_ops;

    if (frameRate <= mKnownFrameRates.front()) {
        return mKnownFrameRates.front();
    }

    if (frameRate >= mKnownFrameRates.back()) {
        return mKnownFrameRates.back();
    }

    auto lowerBound = std::lower_bound(mKnownFrameRates.begin(), mKnownFrameRates.end(), frameRate,
                                       isStrictlyLess);

    const auto distance1 = std::abs(frameRate.getValue() - lowerBound->getValue());
    const auto distance2 = std::abs(frameRate.getValue() - std::prev(lowerBound)->getValue());
    return distance1 < distance2 ? *lowerBound : *std::prev(lowerBound);
}

std::vector<float> RefreshRateSelector::getSupportedFrameRates() const {
    std::scoped_lock lock(mLock);
    const size_t frameRatesSize = mIsVrrDisplay ? mAllFrameRates.size()
            : std::min<size_t>(11, mAllFrameRates.size());
    std::vector<float> supportedFrameRates;
    supportedFrameRates.reserve(frameRatesSize);
    std::transform(mAllFrameRates.rbegin(),
                   mAllFrameRates.rbegin() + static_cast<int>(frameRatesSize),
                   std::back_inserter(supportedFrameRates),
                   [](FrameRateMode mode) { return mode.fps.getValue(); });
    return supportedFrameRates;
}

void RefreshRateSelector::setLayerFilter(LayerFilter layerFilter) {
    std::scoped_lock lock(mLock);
    mLayerFilter = layerFilter;
}

FpsRange RefreshRateSelector::getSupportedFrameRateRangeLocked() const {
    return {0_Hz, mConfigGroupMaxRefreshRateModeIt->second->getPeakFps()};
}

auto RefreshRateSelector::getIdleTimerAction() const -> KernelIdleTimerAction {
    std::lock_guard lock(mLock);

    const Fps deviceMinFps = mConfigGroupMinRefreshRateModeIt->second->getPeakFps();
    const DisplayModePtr& minByPolicy = getMinRefreshRateByPolicyLocked();

    // Kernel idle timer will set the refresh rate to the device min. If DisplayManager says that
    // the min allowed refresh rate is higher than the device min, we do not want to enable the
    // timer.
    if (isStrictlyLess(deviceMinFps, minByPolicy->getPeakFps())) {
        return KernelIdleTimerAction::TurnOff;
    }

    const DisplayModePtr& maxByPolicy =
            getMaxRefreshRateByPolicyLocked(getActiveModeLocked().modePtr->getGroup());
    if (minByPolicy == maxByPolicy) {
        // Turn on the timer when the min of the primary range is below the device min.
        if (const Policy* currentPolicy = getCurrentPolicyLocked();
            isApproxLess(currentPolicy->primaryRanges.physical.min, deviceMinFps)) {
            return KernelIdleTimerAction::TurnOn;
        }
        return KernelIdleTimerAction::TurnOff;
    }

    // Turn on the timer in all other cases.
    return KernelIdleTimerAction::TurnOn;
}

int RefreshRateSelector::getFrameRateDivisor(Fps displayRefreshRate, Fps layerFrameRate) {
    // This calculation needs to be in sync with the java code
    // in DisplayManagerService.getDisplayInfoForFrameRateOverride

    // The threshold must be smaller than 0.001 in order to differentiate
    // between the fractional pairs (e.g. 59.94 and 60).
    constexpr float kThreshold = 0.0009f;
    const auto numPeriods = displayRefreshRate.getValue() / layerFrameRate.getValue();
    const auto numPeriodsRounded = std::round(numPeriods);
    if (std::abs(numPeriods - numPeriodsRounded) > kThreshold) {
        return 0;
    }

    return static_cast<int>(numPeriodsRounded);
}

bool RefreshRateSelector::isFractionalPairOrMultiple(Fps smaller, Fps bigger) {
    if (isStrictlyLess(bigger, smaller)) {
        return isFractionalPairOrMultiple(bigger, smaller);
    }

    const auto multiplier = std::round(bigger.getValue() / smaller.getValue());
    constexpr float kCoef = 1000.f / 1001.f;
    return isApproxEqual(bigger, Fps::fromValue(smaller.getValue() * multiplier / kCoef)) ||
            isApproxEqual(bigger, Fps::fromValue(smaller.getValue() * multiplier * kCoef));
}

void RefreshRateSelector::dump(utils::Dumper& dumper) const {
    using namespace std::string_view_literals;

    std::lock_guard lock(mLock);

    const auto activeMode = getActiveModeLocked();
    dumper.dump("renderRate"sv, to_string(activeMode.fps));
    dumper.dump("activeMode"sv, to_string(*activeMode.modePtr));

    dumper.dump("displayModes"sv);
    {
        utils::Dumper::Indent indent(dumper);
        for (const auto& [id, mode] : mDisplayModes) {
            dumper.dump({}, to_string(*mode));
        }
    }

    dumper.dump("displayManagerPolicy"sv, mDisplayManagerPolicy.toString());

    if (const Policy& currentPolicy = *getCurrentPolicyLocked();
        mOverridePolicy && currentPolicy != mDisplayManagerPolicy) {
        dumper.dump("overridePolicy"sv, currentPolicy.toString());
    }

    dumper.dump("enableFrameRateOverride"sv, mConfig.enableFrameRateOverride);

    dumper.dump("idleTimer"sv);
    {
        utils::Dumper::Indent indent(dumper);
        dumper.dump("interval"sv, mIdleTimer.transform(&OneShotTimer::interval));
        dumper.dump("controller"sv,
                    mConfig.kernelIdleTimerController
                            .and_then(&ftl::enum_name<KernelIdleTimerController>)
                            .value_or("Platform"sv));
    }
}

std::chrono::milliseconds RefreshRateSelector::getIdleTimerTimeout() {
    if (mIdleTimer) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(mIdleTimer->interval());
    }
    return mConfig.legacyIdleTimerTimeout;
}

// TODO(b/293651105): Extract category FpsRange mapping to OEM-configurable config.
FpsRange RefreshRateSelector::getFrameRateCategoryRange(FrameRateCategory category) const {
    using fps_approx_ops::operator<;
    const Fps peakFps = getActiveModeLocked().modePtr->getPeakFps();
    const Fps maxFps = peakFps < 120_Hz ? 120_Hz : peakFps;
    switch (category) {
        case FrameRateCategory::High:
            return FpsRange{kFrameRateCategoryRateHigh, maxFps};
        case FrameRateCategory::Normal:
            return FpsRange{kFrameRateCategoryRateNormal, maxFps};
        case FrameRateCategory::Low:
            return FpsRange{48_Hz, maxFps};
        case FrameRateCategory::HighHint:
        case FrameRateCategory::NoPreference:
        case FrameRateCategory::Default:
            LOG_ALWAYS_FATAL("Should not get fps range for frame rate category: %s",
                             ftl::enum_string(category).c_str());
        default:
            LOG_ALWAYS_FATAL("Invalid frame rate category for range: %s",
                             ftl::enum_string(category).c_str());
    }
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
