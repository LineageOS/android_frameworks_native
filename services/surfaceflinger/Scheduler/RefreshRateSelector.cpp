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

#include <chrono>
#include <cmath>
#include <deque>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <ftl/match.h>
#include <utils/Trace.h>

#include "../SurfaceFlingerProperties.h"
#include "RefreshRateSelector.h"

#undef LOG_TAG
#define LOG_TAG "RefreshRateSelector"

namespace android::scheduler {
namespace {

struct RefreshRateScore {
    DisplayModeIterator modeIt;
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
        knownFrameRates.push_back(mode->getFps());
    }

    // Sort and remove duplicates.
    std::sort(knownFrameRates.begin(), knownFrameRates.end(), isStrictlyLess);
    knownFrameRates.erase(std::unique(knownFrameRates.begin(), knownFrameRates.end(),
                                      isApproxEqual),
                          knownFrameRates.end());
    return knownFrameRates;
}

// The Filter is a `bool(const DisplayMode&)` predicate.
template <typename Filter>
std::vector<DisplayModeIterator> sortByRefreshRate(const DisplayModes& modes, Filter&& filter) {
    std::vector<DisplayModeIterator> sortedModes;
    sortedModes.reserve(modes.size());

    for (auto it = modes.begin(); it != modes.end(); ++it) {
        const auto& [id, mode] = *it;

        if (filter(*mode)) {
            ALOGV("%s: including mode %d", __func__, id.value());
            sortedModes.push_back(it);
        }
    }

    std::sort(sortedModes.begin(), sortedModes.end(), [](auto it1, auto it2) {
        const auto& mode1 = it1->second;
        const auto& mode2 = it2->second;

        if (mode1->getVsyncPeriod() == mode2->getVsyncPeriod()) {
            return mode1->getGroup() > mode2->getGroup();
        }

        return mode1->getVsyncPeriod() > mode2->getVsyncPeriod();
    });

    return sortedModes;
}

bool canModesSupportFrameRateOverride(const std::vector<DisplayModeIterator>& sortedModes) {
    for (const auto it1 : sortedModes) {
        const auto& mode1 = it1->second;
        for (const auto it2 : sortedModes) {
            const auto& mode2 = it2->second;

            if (RefreshRateSelector::getFrameRateDivisor(mode1->getFps(), mode2->getFps()) >= 2) {
                return true;
            }
        }
    }
    return false;
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

struct RefreshRateSelector::RefreshRateScoreComparator {
    bool operator()(const RefreshRateScore& lhs, const RefreshRateScore& rhs) const {
        const auto& [modeIt, overallScore, _] = lhs;

        std::string name = to_string(modeIt->second->getFps());
        ALOGV("%s sorting scores %.2f", name.c_str(), overallScore);

        ATRACE_INT(name.c_str(), static_cast<int>(std::round(overallScore * 100)));

        if (!ScoredRefreshRate::scoresEqual(overallScore, rhs.overallScore)) {
            return overallScore > rhs.overallScore;
        }

        // If overallScore tie we will pick the higher refresh rate if
        // high refresh rate is the priority else the lower refresh rate.
        if (refreshRateOrder == RefreshRateOrder::Descending) {
            using fps_approx_ops::operator>;
            return modeIt->second->getFps() > rhs.modeIt->second->getFps();
        } else {
            using fps_approx_ops::operator<;
            return modeIt->second->getFps() < rhs.modeIt->second->getFps();
        }
    }

    const RefreshRateOrder refreshRateOrder;
};

std::string RefreshRateSelector::Policy::toString() const {
    return base::StringPrintf("{defaultModeId=%d, allowGroupSwitching=%s"
                              ", primaryRange=%s, appRequestRange=%s}",
                              defaultMode.value(), allowGroupSwitching ? "true" : "false",
                              to_string(primaryRange).c_str(), to_string(appRequestRange).c_str());
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

float RefreshRateSelector::calculateNonExactMatchingLayerScoreLocked(const LayerRequirement& layer,
                                                                     Fps refreshRate) const {
    constexpr float kScoreForFractionalPairs = .8f;

    const auto displayPeriod = refreshRate.getPeriodNsecs();
    const auto layerPeriod = layer.desiredRefreshRate.getPeriodNsecs();
    if (layer.vote == LayerVoteType::ExplicitDefault) {
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
        return std::min(1.0f,
                        static_cast<float>(layerPeriod) / static_cast<float>(actualLayerPeriod));
    }

    if (layer.vote == LayerVoteType::ExplicitExactOrMultiple ||
        layer.vote == LayerVoteType::Heuristic) {
        if (isFractionalPairOrMultiple(refreshRate, layer.desiredRefreshRate)) {
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

float RefreshRateSelector::calculateRefreshRateScoreForFps(Fps refreshRate) const {
    const float ratio =
            refreshRate.getValue() / mAppRequestRefreshRates.back()->second->getFps().getValue();
    // Use ratio^2 to get a lower score the more we get further from peak
    return ratio * ratio;
}

float RefreshRateSelector::calculateLayerScoreLocked(const LayerRequirement& layer, Fps refreshRate,
                                                     bool isSeamlessSwitch) const {
    // Slightly prefer seamless switches.
    constexpr float kSeamedSwitchPenalty = 0.95f;
    const float seamlessness = isSeamlessSwitch ? 1.0f : kSeamedSwitchPenalty;

    // If the layer wants Max, give higher score to the higher refresh rate
    if (layer.vote == LayerVoteType::Max) {
        return calculateRefreshRateScoreForFps(refreshRate);
    }

    if (layer.vote == LayerVoteType::ExplicitExact) {
        const int divisor = getFrameRateDivisor(refreshRate, layer.desiredRefreshRate);
        if (mSupportsFrameRateOverrideByContent) {
            // Since we support frame rate override, allow refresh rates which are
            // multiples of the layer's request, as those apps would be throttled
            // down to run at the desired refresh rate.
            return divisor > 0;
        }

        return divisor == 1;
    }

    // If the layer frame rate is a divisor of the refresh rate it should score
    // the highest score.
    if (getFrameRateDivisor(refreshRate, layer.desiredRefreshRate) > 0) {
        return 1.0f * seamlessness;
    }

    // The layer frame rate is not a divisor of the refresh rate,
    // there is a small penalty attached to the score to favor the frame rates
    // the exactly matches the display refresh rate or a multiple.
    constexpr float kNonExactMatchingPenalty = 0.95f;
    return calculateNonExactMatchingLayerScoreLocked(layer, refreshRate) * seamlessness *
            kNonExactMatchingPenalty;
}

auto RefreshRateSelector::getRankedRefreshRates(const std::vector<LayerRequirement>& layers,
                                                GlobalSignals signals) const -> RankedRefreshRates {
    std::lock_guard lock(mLock);

    if (mGetRankedRefreshRatesCache &&
        mGetRankedRefreshRatesCache->arguments == std::make_pair(layers, signals)) {
        return mGetRankedRefreshRatesCache->result;
    }

    const auto result = getRankedRefreshRatesLocked(layers, signals);
    mGetRankedRefreshRatesCache = GetRankedRefreshRatesCache{{layers, signals}, result};
    return result;
}

auto RefreshRateSelector::getRankedRefreshRatesLocked(const std::vector<LayerRequirement>& layers,
                                                      GlobalSignals signals) const
        -> RankedRefreshRates {
    using namespace fps_approx_ops;
    ATRACE_CALL();
    ALOGV("%s: %zu layers", __func__, layers.size());

    const auto& activeMode = *getActiveModeItLocked()->second;

    // Keep the display at max refresh rate for the duration of powering on the display.
    if (signals.powerOnImminent) {
        ALOGV("Power On Imminent");
        return {rankRefreshRates(activeMode.getGroup(), RefreshRateOrder::Descending),
                GlobalSignals{.powerOnImminent = true}};
    }

    int noVoteLayers = 0;
    int minVoteLayers = 0;
    int maxVoteLayers = 0;
    int explicitDefaultVoteLayers = 0;
    int explicitExactOrMultipleVoteLayers = 0;
    int explicitExact = 0;
    int seamedFocusedLayers = 0;

    for (const auto& layer : layers) {
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
            case LayerVoteType::Heuristic:
                break;
        }

        if (layer.seamlessness == Seamlessness::SeamedAndSeamless && layer.focused) {
            seamedFocusedLayers++;
        }
    }

    const bool hasExplicitVoteLayers = explicitDefaultVoteLayers > 0 ||
            explicitExactOrMultipleVoteLayers > 0 || explicitExact > 0;

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
        return {rankRefreshRates(anchorGroup, RefreshRateOrder::Descending),
                GlobalSignals{.touch = true}};
    }

    // If the primary range consists of a single refresh rate then we can only
    // move out the of range if layers explicitly request a different refresh
    // rate.
    const bool primaryRangeIsSingleRate =
            isApproxEqual(policy->primaryRange.min, policy->primaryRange.max);

    if (!signals.touch && signals.idle && !(primaryRangeIsSingleRate && hasExplicitVoteLayers)) {
        ALOGV("Idle");
        return {rankRefreshRates(activeMode.getGroup(), RefreshRateOrder::Ascending),
                GlobalSignals{.idle = true}};
    }

    if (layers.empty() || noVoteLayers == layers.size()) {
        ALOGV("No layers with votes");
        return {rankRefreshRates(anchorGroup, RefreshRateOrder::Descending), kNoSignals};
    }

    // Only if all layers want Min we should return Min
    if (noVoteLayers + minVoteLayers == layers.size()) {
        ALOGV("All layers Min");
        return {rankRefreshRates(activeMode.getGroup(), RefreshRateOrder::Ascending), kNoSignals};
    }

    // Find the best refresh rate based on score
    std::vector<RefreshRateScore> scores;
    scores.reserve(mAppRequestRefreshRates.size());

    for (const DisplayModeIterator modeIt : mAppRequestRefreshRates) {
        scores.emplace_back(RefreshRateScore{modeIt, 0.0f});
    }

    for (const auto& layer : layers) {
        ALOGV("Calculating score for %s (%s, weight %.2f, desired %.2f) ", layer.name.c_str(),
              ftl::enum_string(layer.vote).c_str(), layer.weight,
              layer.desiredRefreshRate.getValue());
        if (layer.vote == LayerVoteType::NoVote || layer.vote == LayerVoteType::Min) {
            continue;
        }

        const auto weight = layer.weight;

        for (auto& [modeIt, overallScore, fixedRateBelowThresholdLayersScore] : scores) {
            const auto& [id, mode] = *modeIt;
            const bool isSeamlessSwitch = mode->getGroup() == activeMode.getGroup();

            if (layer.seamlessness == Seamlessness::OnlySeamless && !isSeamlessSwitch) {
                ALOGV("%s ignores %s to avoid non-seamless switch. Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(), to_string(*mode).c_str(),
                      to_string(activeMode).c_str());
                continue;
            }

            if (layer.seamlessness == Seamlessness::SeamedAndSeamless && !isSeamlessSwitch &&
                !layer.focused) {
                ALOGV("%s ignores %s because it's not focused and the switch is going to be seamed."
                      " Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(), to_string(*mode).c_str(),
                      to_string(activeMode).c_str());
                continue;
            }

            // Layers with default seamlessness vote for the current mode group if
            // there are layers with seamlessness=SeamedAndSeamless and for the default
            // mode group otherwise. In second case, if the current mode group is different
            // from the default, this means a layer with seamlessness=SeamedAndSeamless has just
            // disappeared.
            const bool isInPolicyForDefault = mode->getGroup() == anchorGroup;
            if (layer.seamlessness == Seamlessness::Default && !isInPolicyForDefault) {
                ALOGV("%s ignores %s. Current mode = %s", formatLayerInfo(layer, weight).c_str(),
                      to_string(*mode).c_str(), to_string(activeMode).c_str());
                continue;
            }

            const bool inPrimaryRange = policy->primaryRange.includes(mode->getFps());
            if ((primaryRangeIsSingleRate || !inPrimaryRange) &&
                !(layer.focused &&
                  (layer.vote == LayerVoteType::ExplicitDefault ||
                   layer.vote == LayerVoteType::ExplicitExact))) {
                // Only focused layers with ExplicitDefault frame rate settings are allowed to score
                // refresh rates outside the primary range.
                continue;
            }

            const float layerScore =
                    calculateLayerScoreLocked(layer, mode->getFps(), isSeamlessSwitch);
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
                        return false;
                }
            }(layer.vote);
            const bool layerBelowThreshold = mConfig.frameRateMultipleThreshold != 0 &&
                    layer.desiredRefreshRate <
                            Fps::fromValue(mConfig.frameRateMultipleThreshold / 2);
            if (fixedSourceLayer && layerBelowThreshold) {
                const bool modeAboveThreshold =
                        mode->getFps() >= Fps::fromValue(mConfig.frameRateMultipleThreshold);
                if (modeAboveThreshold) {
                    ALOGV("%s gives %s fixed source (above threshold) score of %.4f",
                          formatLayerInfo(layer, weight).c_str(), to_string(mode->getFps()).c_str(),
                          layerScore);
                    fixedRateBelowThresholdLayersScore.modeAboveThreshold += weightedLayerScore;
                } else {
                    ALOGV("%s gives %s fixed source (below threshold) score of %.4f",
                          formatLayerInfo(layer, weight).c_str(), to_string(mode->getFps()).c_str(),
                          layerScore);
                    fixedRateBelowThresholdLayersScore.modeBelowThreshold += weightedLayerScore;
                }
            } else {
                ALOGV("%s gives %s score of %.4f", formatLayerInfo(layer, weight).c_str(),
                      to_string(mode->getFps()).c_str(), layerScore);
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
                                     const auto& [modeIt, overallScore, _] = current;
                                     return overallScore > max.overallScore;
                                 });
        ALOGV("%s is the best refresh rate without fixed source layers. It is %s the threshold for "
              "refresh rate multiples",
              to_string(maxScoreIt->modeIt->second->getFps()).c_str(),
              maxScoreAboveThreshold ? "above" : "below");
        return maxScoreIt->modeIt->second->getFps() >=
                Fps::fromValue(mConfig.frameRateMultipleThreshold);
    }();

    // Now we can add the fixed rate layers score
    for (auto& [modeIt, overallScore, fixedRateBelowThresholdLayersScore] : scores) {
        overallScore += fixedRateBelowThresholdLayersScore.modeBelowThreshold;
        if (maxScoreAboveThreshold) {
            overallScore += fixedRateBelowThresholdLayersScore.modeAboveThreshold;
        }
        ALOGV("%s adjusted overallScore is %.4f", to_string(modeIt->second->getFps()).c_str(),
              overallScore);
    }

    // Now that we scored all the refresh rates we need to pick the one that got the highest
    // overallScore. Sort the scores based on their overallScore in descending order of priority.
    const RefreshRateOrder refreshRateOrder =
            maxVoteLayers > 0 ? RefreshRateOrder::Descending : RefreshRateOrder::Ascending;
    std::sort(scores.begin(), scores.end(),
              RefreshRateScoreComparator{.refreshRateOrder = refreshRateOrder});

    RefreshRateRanking ranking;
    ranking.reserve(scores.size());

    std::transform(scores.begin(), scores.end(), back_inserter(ranking),
                   [](const RefreshRateScore& score) {
                       return ScoredRefreshRate{score.modeIt->second, score.overallScore};
                   });

    const bool noLayerScore = std::all_of(scores.begin(), scores.end(), [](RefreshRateScore score) {
        return score.overallScore == 0;
    });

    if (primaryRangeIsSingleRate) {
        // If we never scored any layers, then choose the rate from the primary
        // range instead of picking a random score from the app range.
        if (noLayerScore) {
            ALOGV("Layers not scored");
            return {rankRefreshRates(anchorGroup, RefreshRateOrder::Descending), kNoSignals};
        } else {
            return {ranking, kNoSignals};
        }
    }

    // Consider the touch event if there are no ExplicitDefault layers. ExplicitDefault are mostly
    // interactive (as opposed to ExplicitExactOrMultiple) and therefore if those posted an explicit
    // vote we should not change it if we get a touch event. Only apply touch boost if it will
    // actually increase the refresh rate over the normal selection.
    const bool touchBoostForExplicitExact = [&] {
        if (mSupportsFrameRateOverrideByContent) {
            // Enable touch boost if there are other layers besides exact
            return explicitExact + noVoteLayers != layers.size();
        } else {
            // Enable touch boost if there are no exact layers
            return explicitExact == 0;
        }
    }();

    const auto touchRefreshRates = rankRefreshRates(anchorGroup, RefreshRateOrder::Descending);

    using fps_approx_ops::operator<;

    if (signals.touch && explicitDefaultVoteLayers == 0 && touchBoostForExplicitExact &&
        scores.front().modeIt->second->getFps() < touchRefreshRates.front().modePtr->getFps()) {
        ALOGV("Touch Boost");
        return {touchRefreshRates, GlobalSignals{.touch = true}};
    }

    // If we never scored any layers, and we don't favor high refresh rates, prefer to stay with the
    // current config
    if (noLayerScore && refreshRateOrder == RefreshRateOrder::Ascending) {
        const auto preferredDisplayMode = activeMode.getId();
        return {rankRefreshRates(anchorGroup, RefreshRateOrder::Ascending, preferredDisplayMode),
                kNoSignals};
    }

    return {ranking, kNoSignals};
}

using LayerRequirementPtrs = std::vector<const RefreshRateSelector::LayerRequirement*>;
using PerUidLayerRequirements = std::unordered_map<uid_t, LayerRequirementPtrs>;

PerUidLayerRequirements groupLayersByUid(
        const std::vector<RefreshRateSelector::LayerRequirement>& layers) {
    PerUidLayerRequirements layersByUid;
    for (const auto& layer : layers) {
        const auto it = layersByUid.emplace(layer.ownerUid, LayerRequirementPtrs()).first;
        auto& layersWithSameUid = it->second;
        layersWithSameUid.push_back(&layer);
    }

    // Remove uids that can't have a frame rate override
    for (auto it = layersByUid.begin(); it != layersByUid.end();) {
        const auto& layersWithSameUid = it->second;
        bool skipUid = false;
        for (const auto& layer : layersWithSameUid) {
            using LayerVoteType = RefreshRateSelector::LayerVoteType;

            if (layer->vote == LayerVoteType::Max || layer->vote == LayerVoteType::Heuristic) {
                skipUid = true;
                break;
            }
        }
        if (skipUid) {
            it = layersByUid.erase(it);
        } else {
            ++it;
        }
    }

    return layersByUid;
}

auto RefreshRateSelector::getFrameRateOverrides(const std::vector<LayerRequirement>& layers,
                                                Fps displayRefreshRate,
                                                GlobalSignals globalSignals) const
        -> UidToFrameRateOverride {
    ATRACE_CALL();

    ALOGV("%s: %zu layers", __func__, layers.size());

    std::lock_guard lock(mLock);

    std::vector<RefreshRateScore> scores;
    scores.reserve(mDisplayModes.size());

    for (auto it = mDisplayModes.begin(); it != mDisplayModes.end(); ++it) {
        scores.emplace_back(RefreshRateScore{it, 0.0f});
    }

    std::sort(scores.begin(), scores.end(), [](const auto& lhs, const auto& rhs) {
        const auto& mode1 = lhs.modeIt->second;
        const auto& mode2 = rhs.modeIt->second;
        return isStrictlyLess(mode1->getFps(), mode2->getFps());
    });

    const auto layersByUid = groupLayersByUid(layers);
    UidToFrameRateOverride frameRateOverrides;
    for (const auto& [uid, layersWithSameUid] : layersByUid) {
        // Layers with ExplicitExactOrMultiple expect touch boost
        const bool hasExplicitExactOrMultiple =
                std::any_of(layersWithSameUid.cbegin(), layersWithSameUid.cend(),
                            [](const auto& layer) {
                                return layer->vote == LayerVoteType::ExplicitExactOrMultiple;
                            });

        if (globalSignals.touch && hasExplicitExactOrMultiple) {
            continue;
        }

        for (auto& [_, score, _1] : scores) {
            score = 0;
        }

        for (const auto& layer : layersWithSameUid) {
            if (layer->vote == LayerVoteType::NoVote || layer->vote == LayerVoteType::Min) {
                continue;
            }

            LOG_ALWAYS_FATAL_IF(layer->vote != LayerVoteType::ExplicitDefault &&
                                layer->vote != LayerVoteType::ExplicitExactOrMultiple &&
                                layer->vote != LayerVoteType::ExplicitExact);
            for (auto& [modeIt, score, _] : scores) {
                constexpr bool isSeamlessSwitch = true;
                const auto layerScore = calculateLayerScoreLocked(*layer, modeIt->second->getFps(),
                                                                  isSeamlessSwitch);
                score += layer->weight * layerScore;
            }
        }

        // We just care about the refresh rates which are a divisor of the
        // display refresh rate
        const auto it = std::remove_if(scores.begin(), scores.end(), [&](RefreshRateScore score) {
            const auto& [id, mode] = *score.modeIt;
            return getFrameRateDivisor(displayRefreshRate, mode->getFps()) == 0;
        });
        scores.erase(it, scores.end());

        // If we never scored any layers, we don't have a preferred frame rate
        if (std::all_of(scores.begin(), scores.end(),
                        [](RefreshRateScore score) { return score.overallScore == 0; })) {
            continue;
        }

        // Now that we scored all the refresh rates we need to pick the lowest refresh rate
        // that got the highest score.
        const DisplayModePtr& bestRefreshRate =
                std::min_element(scores.begin(), scores.end(),
                                 RefreshRateScoreComparator{.refreshRateOrder =
                                                                    RefreshRateOrder::Ascending})
                        ->modeIt->second;
        frameRateOverrides.emplace(uid, bestRefreshRate->getFps());
    }

    return frameRateOverrides;
}

std::optional<Fps> RefreshRateSelector::onKernelTimerChanged(
        std::optional<DisplayModeId> desiredActiveModeId, bool timerExpired) const {
    std::lock_guard lock(mLock);

    const DisplayModePtr& current = desiredActiveModeId
            ? mDisplayModes.get(*desiredActiveModeId)->get()
            : getActiveModeItLocked()->second;

    const DisplayModePtr& min = mMinRefreshRateModeIt->second;
    if (current == min) {
        return {};
    }

    const auto& mode = timerExpired ? min : current;
    return mode->getFps();
}

const DisplayModePtr& RefreshRateSelector::getMinRefreshRateByPolicyLocked() const {
    const auto& activeMode = *getActiveModeItLocked()->second;

    for (const DisplayModeIterator modeIt : mPrimaryRefreshRates) {
        const auto& mode = modeIt->second;
        if (activeMode.getGroup() == mode->getGroup()) {
            return mode;
        }
    }

    ALOGE("Can't find min refresh rate by policy with the same mode group as the current mode %s",
          to_string(activeMode).c_str());

    // Default to the lowest refresh rate.
    return mPrimaryRefreshRates.front()->second;
}

const DisplayModePtr& RefreshRateSelector::getMaxRefreshRateByPolicyLocked(int anchorGroup) const {
    for (auto it = mPrimaryRefreshRates.rbegin(); it != mPrimaryRefreshRates.rend(); ++it) {
        const auto& mode = (*it)->second;
        if (anchorGroup == mode->getGroup()) {
            return mode;
        }
    }

    ALOGE("Can't find max refresh rate by policy with the same group %d", anchorGroup);

    // Default to the highest refresh rate.
    return mPrimaryRefreshRates.back()->second;
}

auto RefreshRateSelector::rankRefreshRates(
        std::optional<int> anchorGroupOpt, RefreshRateOrder refreshRateOrder,
        std::optional<DisplayModeId> preferredDisplayModeOpt) const -> RefreshRateRanking {
    std::deque<ScoredRefreshRate> ranking;

    const auto rankRefreshRate = [&](DisplayModeIterator it) REQUIRES(mLock) {
        const auto& mode = it->second;
        if (anchorGroupOpt && mode->getGroup() != anchorGroupOpt) {
            return;
        }

        float score = calculateRefreshRateScoreForFps(mode->getFps());
        const bool inverseScore = (refreshRateOrder == RefreshRateOrder::Ascending);
        if (inverseScore) {
            score = 1.0f / score;
        }
        if (preferredDisplayModeOpt) {
            if (*preferredDisplayModeOpt == mode->getId()) {
                constexpr float kScore = std::numeric_limits<float>::max();
                ranking.push_front(ScoredRefreshRate{mode, kScore});
                return;
            }
            constexpr float kNonPreferredModePenalty = 0.95f;
            score *= kNonPreferredModePenalty;
        }
        ranking.push_back(ScoredRefreshRate{mode, score});
    };

    if (refreshRateOrder == RefreshRateOrder::Ascending) {
        std::for_each(mPrimaryRefreshRates.begin(), mPrimaryRefreshRates.end(), rankRefreshRate);
    } else {
        std::for_each(mPrimaryRefreshRates.rbegin(), mPrimaryRefreshRates.rend(), rankRefreshRate);
    }

    if (!ranking.empty() || !anchorGroupOpt) {
        return {ranking.begin(), ranking.end()};
    }

    ALOGW("Can't find %s refresh rate by policy with the same mode group"
          " as the mode group %d",
          refreshRateOrder == RefreshRateOrder::Ascending ? "min" : "max", anchorGroupOpt.value());

    constexpr std::optional<int> kNoAnchorGroup = std::nullopt;
    return rankRefreshRates(kNoAnchorGroup, refreshRateOrder, preferredDisplayModeOpt);
}

DisplayModePtr RefreshRateSelector::getActiveModePtr() const {
    std::lock_guard lock(mLock);
    return getActiveModeItLocked()->second;
}

const DisplayMode& RefreshRateSelector::getActiveMode() const {
    // Reads from kMainThreadContext do not require mLock.
    ftl::FakeGuard guard(mLock);
    return *mActiveModeIt->second;
}

DisplayModeIterator RefreshRateSelector::getActiveModeItLocked() const {
    // Reads under mLock do not require kMainThreadContext.
    return FTL_FAKE_GUARD(kMainThreadContext, mActiveModeIt);
}

void RefreshRateSelector::setActiveModeId(DisplayModeId modeId) {
    std::lock_guard lock(mLock);

    // Invalidate the cached invocation to getRankedRefreshRates. This forces
    // the refresh rate to be recomputed on the next call to getRankedRefreshRates.
    mGetRankedRefreshRatesCache.reset();

    mActiveModeIt = mDisplayModes.find(modeId);
    LOG_ALWAYS_FATAL_IF(mActiveModeIt == mDisplayModes.end());
}

RefreshRateSelector::RefreshRateSelector(DisplayModes modes, DisplayModeId activeModeId,
                                         Config config)
      : mKnownFrameRates(constructKnownFrameRates(modes)), mConfig(config) {
    initializeIdleTimer();
    FTL_FAKE_GUARD(kMainThreadContext, updateDisplayModes(std::move(modes), activeModeId));
}

void RefreshRateSelector::initializeIdleTimer() {
    if (mConfig.idleTimerTimeout > 0ms) {
        mIdleTimer.emplace(
                "IdleTimer", mConfig.idleTimerTimeout,
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

    // Invalidate the cached invocation to getRankedRefreshRates. This forces
    // the refresh rate to be recomputed on the next call to getRankedRefreshRates.
    mGetRankedRefreshRatesCache.reset();

    mDisplayModes = std::move(modes);
    mActiveModeIt = mDisplayModes.find(activeModeId);
    LOG_ALWAYS_FATAL_IF(mActiveModeIt == mDisplayModes.end());

    const auto sortedModes =
            sortByRefreshRate(mDisplayModes, [](const DisplayMode&) { return true; });
    mMinRefreshRateModeIt = sortedModes.front();
    mMaxRefreshRateModeIt = sortedModes.back();

    // Reset the policy because the old one may no longer be valid.
    mDisplayManagerPolicy = {};
    mDisplayManagerPolicy.defaultMode = activeModeId;

    mSupportsFrameRateOverrideByContent =
            mConfig.enableFrameRateOverride && canModesSupportFrameRateOverride(sortedModes);

    constructAvailableRefreshRates();
}

bool RefreshRateSelector::isPolicyValidLocked(const Policy& policy) const {
    // defaultMode must be a valid mode, and within the given refresh rate range.
    if (const auto mode = mDisplayModes.get(policy.defaultMode)) {
        if (!policy.primaryRange.includes(mode->get()->getFps())) {
            ALOGE("Default mode is not in the primary range.");
            return false;
        }
    } else {
        ALOGE("Default mode is not found.");
        return false;
    }

    using namespace fps_approx_ops;
    return policy.appRequestRange.min <= policy.primaryRange.min &&
            policy.appRequestRange.max >= policy.primaryRange.max;
}

auto RefreshRateSelector::setPolicy(const PolicyVariant& policy) -> SetPolicyResult {
    Policy oldPolicy;
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

        mGetRankedRefreshRatesCache.reset();

        if (*getCurrentPolicyLocked() == oldPolicy) {
            return SetPolicyResult::Unchanged;
        }
        constructAvailableRefreshRates();
    }

    const auto displayId = getActiveMode().getPhysicalDisplayId();
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

bool RefreshRateSelector::isModeAllowed(DisplayModeId modeId) const {
    std::lock_guard lock(mLock);
    return std::any_of(mAppRequestRefreshRates.begin(), mAppRequestRefreshRates.end(),
                       [modeId](DisplayModeIterator modeIt) {
                           return modeIt->second->getId() == modeId;
                       });
}

void RefreshRateSelector::constructAvailableRefreshRates() {
    // Filter modes based on current policy and sort on refresh rate.
    const Policy* policy = getCurrentPolicyLocked();
    ALOGV("%s: %s ", __func__, policy->toString().c_str());

    const auto& defaultMode = mDisplayModes.get(policy->defaultMode)->get();

    const auto filterRefreshRates = [&](FpsRange range, const char* rangeName) REQUIRES(mLock) {
        const auto filter = [&](const DisplayMode& mode) {
            return mode.getResolution() == defaultMode->getResolution() &&
                    mode.getDpi() == defaultMode->getDpi() &&
                    (policy->allowGroupSwitching || mode.getGroup() == defaultMode->getGroup()) &&
                    range.includes(mode.getFps());
        };

        const auto modes = sortByRefreshRate(mDisplayModes, filter);
        LOG_ALWAYS_FATAL_IF(modes.empty(), "No matching modes for %s range %s", rangeName,
                            to_string(range).c_str());

        const auto stringifyModes = [&] {
            std::string str;
            for (const auto modeIt : modes) {
                str += to_string(modeIt->second->getFps());
                str.push_back(' ');
            }
            return str;
        };
        ALOGV("%s refresh rates: %s", rangeName, stringifyModes().c_str());

        return modes;
    };

    mPrimaryRefreshRates = filterRefreshRates(policy->primaryRange, "primary");
    mAppRequestRefreshRates = filterRefreshRates(policy->appRequestRange, "app request");
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

auto RefreshRateSelector::getIdleTimerAction() const -> KernelIdleTimerAction {
    std::lock_guard lock(mLock);

    const Fps deviceMinFps = mMinRefreshRateModeIt->second->getFps();
    const DisplayModePtr& minByPolicy = getMinRefreshRateByPolicyLocked();

    // Kernel idle timer will set the refresh rate to the device min. If DisplayManager says that
    // the min allowed refresh rate is higher than the device min, we do not want to enable the
    // timer.
    if (isStrictlyLess(deviceMinFps, minByPolicy->getFps())) {
        return KernelIdleTimerAction::TurnOff;
    }

    const DisplayModePtr& maxByPolicy =
            getMaxRefreshRateByPolicyLocked(getActiveModeItLocked()->second->getGroup());
    if (minByPolicy == maxByPolicy) {
        // Turn on the timer when the min of the primary range is below the device min.
        if (const Policy* currentPolicy = getCurrentPolicyLocked();
            isApproxLess(currentPolicy->primaryRange.min, deviceMinFps)) {
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

    const auto activeModeId = getActiveModeItLocked()->first;
    dumper.dump("activeModeId"sv, std::to_string(activeModeId.value()));

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

    dumper.dump("supportsFrameRateOverrideByContent"sv, mSupportsFrameRateOverrideByContent);

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
    return mConfig.idleTimerTimeout;
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
