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
#include <map>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <ftl/match.h>
#include <ftl/unit.h>
#include <gui/TraceUtils.h>
#include <scheduler/FrameRateMode.h>
#include <utils/Trace.h>

#include "RefreshRateSelector.h"

#include <com_android_graphics_surfaceflinger_flags.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateSelector"

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

std::pair<unsigned, unsigned> divisorRange(Fps vsyncRate, Fps peakFps, FpsRange range,
                                           RefreshRateSelector::Config::FrameRateOverride config) {
    if (config != RefreshRateSelector::Config::FrameRateOverride::Enabled) {
        return {1, 1};
    }

    using fps_approx_ops::operator/;
    // use signed type as `fps / range.max` might be 0
    auto start = std::max(1, static_cast<int>(peakFps / range.max) - 1);
    if (FlagManager::getInstance().vrr_config()) {
        start = std::max(1,
                         static_cast<int>(vsyncRate /
                                          std::min(range.max, peakFps, fps_approx_ops::operator<)) -
                                 1);
    }
    const auto end = vsyncRate /
            std::max(range.min, RefreshRateSelector::kMinSupportedFrameRate,
                     fps_approx_ops::operator<);

    return {start, end};
}

bool shouldEnableFrameRateOverride(const std::vector<DisplayModeIterator>& sortedModes) {
    for (const auto it1 : sortedModes) {
        const auto& mode1 = it1->second;
        for (const auto it2 : sortedModes) {
            const auto& mode2 = it2->second;

            if (RefreshRateSelector::getFrameRateDivisor(mode1->getPeakFps(),
                                                         mode2->getPeakFps()) >= 2) {
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

auto RefreshRateSelector::createFrameRateModes(
        const Policy& policy, std::function<bool(const DisplayMode&)>&& filterModes,
        const FpsRange& renderRange) const -> std::vector<FrameRateMode> {
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

    std::map<Key, DisplayModeIterator, KeyLess> ratesMap;
    for (auto it = mDisplayModes.begin(); it != mDisplayModes.end(); ++it) {
        const auto& [id, mode] = *it;

        if (!filterModes(*mode)) {
            continue;
        }
        const auto vsyncRate = mode->getVsyncRate();
        const auto peakFps = mode->getPeakFps();
        const auto [start, end] =
                divisorRange(vsyncRate, peakFps, renderRange, mConfig.enableFrameRateOverride);
        for (auto divisor = start; divisor <= end; divisor++) {
            const auto fps = vsyncRate / divisor;
            using fps_approx_ops::operator<;
            if (divisor > 1 && fps < kMinSupportedFrameRate) {
                break;
            }

            if (mConfig.enableFrameRateOverride == Config::FrameRateOverride::Enabled &&
                !renderRange.includes(fps)) {
                continue;
            }

            if (mConfig.enableFrameRateOverride ==
                        Config::FrameRateOverride::AppOverrideNativeRefreshRates &&
                !isNativeRefreshRate(fps)) {
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

        std::string name = to_string(frameRateMode);

        ALOGV("%s sorting scores %.2f", name.c_str(), overallScore);

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
                              ", primaryRanges=%s, appRequestRanges=%s}",
                              ftl::to_underlying(defaultMode),
                              allowGroupSwitching ? "true" : "false",
                              to_string(primaryRanges).c_str(),
                              to_string(appRequestRanges).c_str());
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

auto RefreshRateSelector::getRankedFrameRates(const std::vector<LayerRequirement>& layers,
                                              GlobalSignals signals) const -> RankedFrameRates {
    std::lock_guard lock(mLock);

    if (mGetRankedFrameRatesCache &&
        mGetRankedFrameRatesCache->arguments == std::make_pair(layers, signals)) {
        return mGetRankedFrameRatesCache->result;
    }

    const auto result = getRankedFrameRatesLocked(layers, signals);
    mGetRankedFrameRatesCache = GetRankedFrameRatesCache{{layers, signals}, result};
    return result;
}

auto RefreshRateSelector::getRankedFrameRatesLocked(const std::vector<LayerRequirement>& layers,
                                                    GlobalSignals signals) const
        -> RankedFrameRates {
    using namespace fps_approx_ops;
    ATRACE_CALL();
    ALOGV("%s: %zu layers", __func__, layers.size());

    const auto& activeMode = *getActiveModeLocked().modePtr;

    // Keep the display at max frame rate for the duration of powering on the display.
    if (signals.powerOnImminent) {
        ALOGV("Power On Imminent");
        const auto ranking = rankFrameRates(activeMode.getGroup(), RefreshRateOrder::Descending);
        ATRACE_FORMAT_INSTANT("%s (Power On Imminent)",
                              to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, GlobalSignals{.powerOnImminent = true}};
    }

    int noVoteLayers = 0;
    int minVoteLayers = 0;
    int maxVoteLayers = 0;
    int explicitDefaultVoteLayers = 0;
    int explicitExactOrMultipleVoteLayers = 0;
    int explicitExact = 0;
    int explicitGteLayers = 0;
    int explicitCategoryVoteLayers = 0;
    int interactiveLayers = 0;
    int seamedFocusedLayers = 0;
    int categorySmoothSwitchOnlyLayers = 0;

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
            case LayerVoteType::ExplicitGte:
                explicitGteLayers++;
                break;
            case LayerVoteType::ExplicitCategory:
                if (layer.frameRateCategory == FrameRateCategory::HighHint) {
                    // HighHint does not count as an explicit signal from an app. It may be
                    // be a touch signal.
                    interactiveLayers++;
                } else {
                    explicitCategoryVoteLayers++;
                }
                if (layer.frameRateCategory == FrameRateCategory::NoPreference) {
                    // Count this layer for Min vote as well. The explicit vote avoids
                    // touch boost and idle for choosing a category, while Min vote is for correct
                    // behavior when all layers are Min or no vote.
                    minVoteLayers++;
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
        ATRACE_FORMAT_INSTANT("%s (Touch Boost)",
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
        ATRACE_FORMAT_INSTANT("%s (Idle)", to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, GlobalSignals{.idle = true}};
    }

    if (layers.empty() || noVoteLayers == layers.size()) {
        ALOGV("No layers with votes");
        const auto ranking = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
        ATRACE_FORMAT_INSTANT("%s (No layers with votes)",
                              to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, kNoSignals};
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
        ATRACE_FORMAT_INSTANT("%s (All layers Min)",
                              to_string(ranking.front().frameRateMode.fps).c_str());
        return {ranking, kNoSignals};
    }

    // Find the best refresh rate based on score
    std::vector<RefreshRateScore> scores;
    scores.reserve(mAppRequestFrameRates.size());

    for (const FrameRateMode& it : mAppRequestFrameRates) {
        scores.emplace_back(RefreshRateScore{it, 0.0f});
    }

    for (const auto& layer : layers) {
        ALOGV("Calculating score for %s (%s, weight %.2f, desired %.2f, category %s) ",
              layer.name.c_str(), ftl::enum_string(layer.vote).c_str(), layer.weight,
              layer.desiredRefreshRate.getValue(),
              ftl::enum_string(layer.frameRateCategory).c_str());
        if (layer.isNoVote() || layer.frameRateCategory == FrameRateCategory::NoPreference ||
            layer.vote == LayerVoteType::Min) {
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

    if (policy->primaryRangeIsSingleRate()) {
        // If we never scored any layers, then choose the rate from the primary
        // range instead of picking a random score from the app range.
        if (noLayerScore) {
            ALOGV("Layers not scored");
            const auto descending = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
            ATRACE_FORMAT_INSTANT("%s (Layers not scored)",
                                  to_string(descending.front().frameRateMode.fps).c_str());
            return {descending, kNoSignals};
        } else {
            ALOGV("primaryRangeIsSingleRate");
            ATRACE_FORMAT_INSTANT("%s (primaryRangeIsSingleRate)",
                                  to_string(ranking.front().frameRateMode.fps).c_str());
            return {ranking, kNoSignals};
        }
    }

    // Consider the touch event if there are no ExplicitDefault layers. ExplicitDefault are mostly
    // interactive (as opposed to ExplicitExactOrMultiple) and therefore if those posted an explicit
    // vote we should not change it if we get a touch event. Only apply touch boost if it will
    // actually increase the refresh rate over the normal selection.
    const bool touchBoostForExplicitExact = [&] {
        if (supportsAppFrameRateOverrideByContent()) {
            // Enable touch boost if there are other layers besides exact
            return explicitExact + noVoteLayers != layers.size();
        } else {
            // Enable touch boost if there are no exact layers
            return explicitExact == 0;
        }
    }();

    const auto touchRefreshRates = rankFrameRates(anchorGroup, RefreshRateOrder::Descending);
    using fps_approx_ops::operator<;

    // A method for UI Toolkit to send the touch signal via "HighHint" category vote,
    // which will touch boost when there are no ExplicitDefault layer votes. This is an
    // incomplete solution but accounts for cases such as games that use `setFrameRate` with default
    // compatibility to limit the frame rate, which should not have touch boost.
    const bool hasInteraction = signals.touch || interactiveLayers > 0;

    if (hasInteraction && explicitDefaultVoteLayers == 0 && touchBoostForExplicitExact &&
        scores.front().frameRateMode.fps < touchRefreshRates.front().frameRateMode.fps) {
        ALOGV("Touch Boost");
        ATRACE_FORMAT_INSTANT("%s (Touch Boost [late])",
                              to_string(touchRefreshRates.front().frameRateMode.fps).c_str());
        return {touchRefreshRates, GlobalSignals{.touch = true}};
    }

    // If we never scored any layers, and we don't favor high refresh rates, prefer to stay with the
    // current config
    if (noLayerScore && refreshRateOrder == RefreshRateOrder::Ascending) {
        ALOGV("preferredDisplayMode");
        const auto ascendingWithPreferred =
                rankFrameRates(anchorGroup, RefreshRateOrder::Ascending, activeMode.getId());
        ATRACE_FORMAT_INSTANT("%s (preferredDisplayMode)",
                              to_string(ascendingWithPreferred.front().frameRateMode.fps).c_str());
        return {ascendingWithPreferred, kNoSignals};
    }

    ALOGV("%s (scored))", to_string(ranking.front().frameRateMode.fps).c_str());
    ATRACE_FORMAT_INSTANT("%s (scored))", to_string(ranking.front().frameRateMode.fps).c_str());
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
    if (mConfig.enableFrameRateOverride == Config::FrameRateOverride::Disabled) {
        return {};
    }

    ALOGV("%s: %zu layers", __func__, layers.size());
    std::lock_guard lock(mLock);

    const auto* policyPtr = getCurrentPolicyLocked();
    // We don't want to run lower than 30fps
    // TODO(b/297600226): revise this for dVRR
    const Fps minFrameRate = std::max(policyPtr->appRequestRanges.render.min, 30_Hz, isApproxLess);

    using fps_approx_ops::operator/;
    const unsigned numMultiples = displayRefreshRate / minFrameRate;

    std::vector<std::pair<Fps, float>> scoredFrameRates;
    scoredFrameRates.reserve(numMultiples);

    for (unsigned n = numMultiples; n > 0; n--) {
        const Fps divisor = displayRefreshRate / n;
        if (mConfig.enableFrameRateOverride ==
                    Config::FrameRateOverride::AppOverrideNativeRefreshRates &&
            !isNativeRefreshRate(divisor)) {
            continue;
        }

        if (policyPtr->appRequestRanges.render.includes(divisor)) {
            ALOGV("%s: adding %s as a potential frame rate", __func__, to_string(divisor).c_str());
            scoredFrameRates.emplace_back(divisor, 0);
        }
    }

    const auto layersByUid = groupLayersByUid(layers);
    UidToFrameRateOverride frameRateOverrides;
    for (const auto& [uid, layersWithSameUid] : layersByUid) {
        // Look for cases that should not have frame rate overrides.
        bool hasExplicitExactOrMultiple = false;
        bool hasExplicitDefault = false;
        bool hasHighHint = false;
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
                default:
                    // No action
                    break;
            }
            if (hasExplicitExactOrMultiple && hasExplicitDefault && hasHighHint) {
                break;
            }
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
        ATRACE_FORMAT_INSTANT("%s: overriding to %s for uid=%d", __func__,
                              to_string(overrideFps).c_str(), uid);
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

    const DisplayModePtr& min = mMinRefreshRateModeIt->second;
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

auto RefreshRateSelector::rankFrameRates(std::optional<int> anchorGroupOpt,
                                         RefreshRateOrder refreshRateOrder,
                                         std::optional<DisplayModeId> preferredDisplayModeOpt,
                                         const RankFrameRatesPredicate& predicate) const
        -> FrameRateRanking {
    using fps_approx_ops::operator<;
    const char* const whence = __func__;

    // find the highest frame rate for each display mode
    ftl::SmallMap<DisplayModeId, Fps, 8> maxRenderRateForMode;
    const bool ascending = (refreshRateOrder == RefreshRateOrder::Ascending);
    if (ascending) {
        // TODO(b/266481656): Once this bug is fixed, we can remove this workaround and actually
        //  use a lower frame rate when we want Ascending frame rates.
        for (const auto& frameRateMode : mPrimaryFrameRates) {
            if (anchorGroupOpt && frameRateMode.modePtr->getGroup() != anchorGroupOpt) {
                continue;
            }

            const auto [iter, _] = maxRenderRateForMode.try_emplace(frameRateMode.modePtr->getId(),
                                                                    frameRateMode.fps);
            if (iter->second < frameRateMode.fps) {
                iter->second = frameRateMode.fps;
            }
        }
    }

    std::deque<ScoredFrameRate> ranking;
    const auto rankFrameRate = [&](const FrameRateMode& frameRateMode) REQUIRES(mLock) {
        const auto& modePtr = frameRateMode.modePtr;
        if ((anchorGroupOpt && modePtr->getGroup() != anchorGroupOpt) ||
            !predicate(frameRateMode)) {
            return;
        }

        const bool ascending = (refreshRateOrder == RefreshRateOrder::Ascending);
        const auto id = modePtr->getId();
        if (ascending && frameRateMode.fps < *maxRenderRateForMode.get(id)) {
            // TODO(b/266481656): Once this bug is fixed, we can remove this workaround and actually
            //  use a lower frame rate when we want Ascending frame rates.
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
            // TODO(b/266481656): Once this bug is fixed, we can remove this workaround
            //  and actually use a lower frame rate when we want Ascending frame rates.
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

    // Invalidate the cached invocation to getRankedFrameRates. This forces
    // the refresh rate to be recomputed on the next call to getRankedFrameRates.
    mGetRankedFrameRatesCache.reset();

    mDisplayModes = std::move(modes);
    const auto activeModeOpt = mDisplayModes.get(activeModeId);
    LOG_ALWAYS_FATAL_IF(!activeModeOpt);
    mActiveModeOpt = FrameRateMode{activeModeOpt->get()->getPeakFps(),
                                   ftl::as_non_null(activeModeOpt->get())};

    const auto sortedModes = sortByRefreshRate(mDisplayModes);
    mMinRefreshRateModeIt = sortedModes.front();
    mMaxRefreshRateModeIt = sortedModes.back();

    // Reset the policy because the old one may no longer be valid.
    mDisplayManagerPolicy = {};
    mDisplayManagerPolicy.defaultMode = activeModeId;

    mFrameRateOverrideConfig = [&] {
        switch (mConfig.enableFrameRateOverride) {
            case Config::FrameRateOverride::Disabled:
            case Config::FrameRateOverride::AppOverride:
            case Config::FrameRateOverride::Enabled:
                return mConfig.enableFrameRateOverride;
            case Config::FrameRateOverride::AppOverrideNativeRefreshRates:
                return shouldEnableFrameRateOverride(sortedModes)
                        ? Config::FrameRateOverride::AppOverrideNativeRefreshRates
                        : Config::FrameRateOverride::Disabled;
        }
    }();

    if (mConfig.enableFrameRateOverride ==
        Config::FrameRateOverride::AppOverrideNativeRefreshRates) {
        for (const auto& [_, mode] : mDisplayModes) {
            mAppOverrideNativeRefreshRates.try_emplace(mode->getPeakFps(), ftl::unit);
        }
    }

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

        if (*getCurrentPolicyLocked() == oldPolicy) {
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

    const auto filterRefreshRates = [&](const FpsRanges& ranges,
                                        const char* rangeName) REQUIRES(mLock) {
        const auto filterModes = [&](const DisplayMode& mode) {
            return mode.getResolution() == defaultMode->getResolution() &&
                    mode.getDpi() == defaultMode->getDpi() &&
                    (policy->allowGroupSwitching || mode.getGroup() == defaultMode->getGroup()) &&
                    ranges.physical.includes(mode.getPeakFps()) &&
                    (supportsFrameRateOverride() || ranges.render.includes(mode.getPeakFps()));
        };

        auto frameRateModes = createFrameRateModes(*policy, filterModes, ranges.render);
        if (frameRateModes.empty()) {
            ALOGW("No matching frame rate modes for %s range. policy: %s", rangeName,
                  policy->toString().c_str());
            // TODO(b/292105422): Ideally DisplayManager should not send render ranges smaller than
            // the min supported. See b/292047939.
            //  For not we just ignore the render ranges.
            frameRateModes = createFrameRateModes(*policy, filterModes, {});
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
        ALOGV("%s render rates: %s", rangeName, stringifyModes().c_str());

        return frameRateModes;
    };

    mPrimaryFrameRates = filterRefreshRates(policy->primaryRanges, "primary");
    mAppRequestFrameRates = filterRefreshRates(policy->appRequestRanges, "app request");
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

    const Fps deviceMinFps = mMinRefreshRateModeIt->second->getPeakFps();
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
    dumper.dump("activeMode"sv, to_string(activeMode));

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

    dumper.dump("frameRateOverrideConfig"sv, *ftl::enum_name(mFrameRateOverrideConfig));

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

// TODO(b/293651105): Extract category FpsRange mapping to OEM-configurable config.
FpsRange RefreshRateSelector::getFrameRateCategoryRange(FrameRateCategory category) {
    switch (category) {
        case FrameRateCategory::High:
            return FpsRange{90_Hz, 120_Hz};
        case FrameRateCategory::Normal:
            return FpsRange{60_Hz, 90_Hz};
        case FrameRateCategory::Low:
            return FpsRange{30_Hz, 30_Hz};
        case FrameRateCategory::HighHint:
        case FrameRateCategory::NoPreference:
        case FrameRateCategory::Default:
            LOG_ALWAYS_FATAL("Should not get fps range for frame rate category: %s",
                             ftl::enum_string(category).c_str());
            return FpsRange{0_Hz, 0_Hz};
        default:
            LOG_ALWAYS_FATAL("Invalid frame rate category for range: %s",
                             ftl::enum_string(category).c_str());
            return FpsRange{0_Hz, 0_Hz};
    }
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
