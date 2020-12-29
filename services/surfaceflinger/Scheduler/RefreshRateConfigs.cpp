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

#include "RefreshRateConfigs.h"
#include <android-base/stringprintf.h>
#include <utils/Trace.h>
#include <chrono>
#include <cmath>

#undef LOG_TAG
#define LOG_TAG "RefreshRateConfigs"

namespace android::scheduler {
namespace {
std::string formatLayerInfo(const RefreshRateConfigs::LayerRequirement& layer, float weight) {
    return base::StringPrintf("%s (type=%s, weight=%.2f seamlessness=%s) %s", layer.name.c_str(),
                              RefreshRateConfigs::layerVoteTypeString(layer.vote).c_str(), weight,
                              toString(layer.seamlessness).c_str(),
                              to_string(layer.desiredRefreshRate).c_str());
}
} // namespace

using AllRefreshRatesMapType = RefreshRateConfigs::AllRefreshRatesMapType;
using RefreshRate = RefreshRateConfigs::RefreshRate;

std::string RefreshRate::toString() const {
    return base::StringPrintf("{id=%d, hwcId=%d, fps=%.2f, width=%d, height=%d group=%d}",
                              getConfigId().value(), hwcConfig->getId(), getFps().getValue(),
                              hwcConfig->getWidth(), hwcConfig->getHeight(), getConfigGroup());
}

std::string RefreshRateConfigs::layerVoteTypeString(LayerVoteType vote) {
    switch (vote) {
        case LayerVoteType::NoVote:
            return "NoVote";
        case LayerVoteType::Min:
            return "Min";
        case LayerVoteType::Max:
            return "Max";
        case LayerVoteType::Heuristic:
            return "Heuristic";
        case LayerVoteType::ExplicitDefault:
            return "ExplicitDefault";
        case LayerVoteType::ExplicitExactOrMultiple:
            return "ExplicitExactOrMultiple";
    }
}

std::string RefreshRateConfigs::Policy::toString() const {
    return base::StringPrintf("default config ID: %d, allowGroupSwitching = %d"
                              ", primary range: %s, app request range: %s",
                              defaultConfig.value(), allowGroupSwitching,
                              primaryRange.toString().c_str(), appRequestRange.toString().c_str());
}

std::pair<nsecs_t, nsecs_t> RefreshRateConfigs::getDisplayFrames(nsecs_t layerPeriod,
                                                                 nsecs_t displayPeriod) const {
    auto [quotient, remainder] = std::div(layerPeriod, displayPeriod);
    if (remainder <= MARGIN_FOR_PERIOD_CALCULATION ||
        std::abs(remainder - displayPeriod) <= MARGIN_FOR_PERIOD_CALCULATION) {
        quotient++;
        remainder = 0;
    }

    return {quotient, remainder};
}

float RefreshRateConfigs::calculateLayerScoreLocked(const LayerRequirement& layer,
                                                    const RefreshRate& refreshRate,
                                                    bool isSeamlessSwitch) const {
    // Slightly prefer seamless switches.
    constexpr float kSeamedSwitchPenalty = 0.95f;
    const float seamlessness = isSeamlessSwitch ? 1.0f : kSeamedSwitchPenalty;

    // If the layer wants Max, give higher score to the higher refresh rate
    if (layer.vote == LayerVoteType::Max) {
        const auto ratio =
                refreshRate.fps.getValue() / mAppRequestRefreshRates.back()->fps.getValue();
        // use ratio^2 to get a lower score the more we get further from peak
        return ratio * ratio;
    }

    const auto displayPeriod = refreshRate.getVsyncPeriod();
    const auto layerPeriod = layer.desiredRefreshRate.getPeriodNsecs();
    if (layer.vote == LayerVoteType::ExplicitDefault) {
        // Find the actual rate the layer will render, assuming
        // that layerPeriod is the minimal time to render a frame
        auto actualLayerPeriod = displayPeriod;
        int multiplier = 1;
        while (layerPeriod > actualLayerPeriod + MARGIN_FOR_PERIOD_CALCULATION) {
            multiplier++;
            actualLayerPeriod = displayPeriod * multiplier;
        }
        return std::min(1.0f,
                        static_cast<float>(layerPeriod) / static_cast<float>(actualLayerPeriod));
    }

    if (layer.vote == LayerVoteType::ExplicitExactOrMultiple ||
        layer.vote == LayerVoteType::Heuristic) {
        // Calculate how many display vsyncs we need to present a single frame for this
        // layer
        const auto [displayFramesQuotient, displayFramesRemainder] =
                getDisplayFrames(layerPeriod, displayPeriod);
        static constexpr size_t MAX_FRAMES_TO_FIT = 10; // Stop calculating when score < 0.1
        if (displayFramesRemainder == 0) {
            // Layer desired refresh rate matches the display rate.
            return 1.0f * seamlessness;
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

        return (1.0f / iter) * seamlessness;
    }

    return 0;
}

struct RefreshRateScore {
    const RefreshRate* refreshRate;
    float score;
};

const RefreshRate& RefreshRateConfigs::getBestRefreshRate(
        const std::vector<LayerRequirement>& layers, const GlobalSignals& globalSignals,
        GlobalSignals* outSignalsConsidered) const {
    ATRACE_CALL();
    ALOGV("getBestRefreshRate %zu layers", layers.size());

    if (outSignalsConsidered) *outSignalsConsidered = {};
    const auto setTouchConsidered = [&] {
        if (outSignalsConsidered) {
            outSignalsConsidered->touch = true;
        }
    };

    const auto setIdleConsidered = [&] {
        if (outSignalsConsidered) {
            outSignalsConsidered->idle = true;
        }
    };

    std::lock_guard lock(mLock);

    int noVoteLayers = 0;
    int minVoteLayers = 0;
    int maxVoteLayers = 0;
    int explicitDefaultVoteLayers = 0;
    int explicitExactOrMultipleVoteLayers = 0;
    float maxExplicitWeight = 0;
    int seamedLayers = 0;
    for (const auto& layer : layers) {
        if (layer.vote == LayerVoteType::NoVote) {
            noVoteLayers++;
        } else if (layer.vote == LayerVoteType::Min) {
            minVoteLayers++;
        } else if (layer.vote == LayerVoteType::Max) {
            maxVoteLayers++;
        } else if (layer.vote == LayerVoteType::ExplicitDefault) {
            explicitDefaultVoteLayers++;
            maxExplicitWeight = std::max(maxExplicitWeight, layer.weight);
        } else if (layer.vote == LayerVoteType::ExplicitExactOrMultiple) {
            explicitExactOrMultipleVoteLayers++;
            maxExplicitWeight = std::max(maxExplicitWeight, layer.weight);
        }

        if (layer.seamlessness == Seamlessness::SeamedAndSeamless) {
            seamedLayers++;
        }
    }

    const bool hasExplicitVoteLayers =
            explicitDefaultVoteLayers > 0 || explicitExactOrMultipleVoteLayers > 0;

    // Consider the touch event if there are no Explicit* layers. Otherwise wait until after we've
    // selected a refresh rate to see if we should apply touch boost.
    if (globalSignals.touch && !hasExplicitVoteLayers) {
        ALOGV("TouchBoost - choose %s", getMaxRefreshRateByPolicyLocked().getName().c_str());
        setTouchConsidered();
        return getMaxRefreshRateByPolicyLocked();
    }

    // If the primary range consists of a single refresh rate then we can only
    // move out the of range if layers explicitly request a different refresh
    // rate.
    const Policy* policy = getCurrentPolicyLocked();
    const bool primaryRangeIsSingleRate =
            policy->primaryRange.min.equalsWithMargin(policy->primaryRange.max);

    if (!globalSignals.touch && globalSignals.idle &&
        !(primaryRangeIsSingleRate && hasExplicitVoteLayers)) {
        ALOGV("Idle - choose %s", getMinRefreshRateByPolicyLocked().getName().c_str());
        setIdleConsidered();
        return getMinRefreshRateByPolicyLocked();
    }

    if (layers.empty() || noVoteLayers == layers.size()) {
        return getMaxRefreshRateByPolicyLocked();
    }

    // Only if all layers want Min we should return Min
    if (noVoteLayers + minVoteLayers == layers.size()) {
        ALOGV("all layers Min - choose %s", getMinRefreshRateByPolicyLocked().getName().c_str());
        return getMinRefreshRateByPolicyLocked();
    }

    // Find the best refresh rate based on score
    std::vector<RefreshRateScore> scores;
    scores.reserve(mAppRequestRefreshRates.size());

    for (const auto refreshRate : mAppRequestRefreshRates) {
        scores.emplace_back(RefreshRateScore{refreshRate, 0.0f});
    }

    const auto& defaultConfig = mRefreshRates.at(policy->defaultConfig);

    for (const auto& layer : layers) {
        ALOGV("Calculating score for %s (%s, weight %.2f)", layer.name.c_str(),
              layerVoteTypeString(layer.vote).c_str(), layer.weight);
        if (layer.vote == LayerVoteType::NoVote || layer.vote == LayerVoteType::Min) {
            continue;
        }

        auto weight = layer.weight;

        for (auto i = 0u; i < scores.size(); i++) {
            const bool isSeamlessSwitch = scores[i].refreshRate->getConfigGroup() ==
                    mCurrentRefreshRate->getConfigGroup();

            if (layer.seamlessness == Seamlessness::OnlySeamless && !isSeamlessSwitch) {
                ALOGV("%s ignores %s to avoid non-seamless switch. Current config = %s",
                      formatLayerInfo(layer, weight).c_str(),
                      scores[i].refreshRate->toString().c_str(),
                      mCurrentRefreshRate->toString().c_str());
                continue;
            }

            if (layer.seamlessness == Seamlessness::SeamedAndSeamless && !isSeamlessSwitch &&
                !layer.focused) {
                ALOGV("%s ignores %s because it's not focused and the switch is going to be seamed."
                      " Current config = %s",
                      formatLayerInfo(layer, weight).c_str(),
                      scores[i].refreshRate->toString().c_str(),
                      mCurrentRefreshRate->toString().c_str());
                continue;
            }

            // Layers with default seamlessness vote for the current config group if
            // there are layers with seamlessness=SeamedAndSeamless and for the default
            // config group otherwise. In second case, if the current config group is different
            // from the default, this means a layer with seamlessness=SeamedAndSeamless has just
            // disappeared.
            const bool isInPolicyForDefault = seamedLayers > 0
                    ? scores[i].refreshRate->getConfigGroup() ==
                            mCurrentRefreshRate->getConfigGroup()
                    : scores[i].refreshRate->getConfigGroup() == defaultConfig->getConfigGroup();

            if (layer.seamlessness == Seamlessness::Default && !isInPolicyForDefault &&
                !layer.focused) {
                ALOGV("%s ignores %s. Current config = %s", formatLayerInfo(layer, weight).c_str(),
                      scores[i].refreshRate->toString().c_str(),
                      mCurrentRefreshRate->toString().c_str());
                continue;
            }

            bool inPrimaryRange = scores[i].refreshRate->inPolicy(policy->primaryRange.min,
                                                                  policy->primaryRange.max);
            if ((primaryRangeIsSingleRate || !inPrimaryRange) &&
                !(layer.focused && layer.vote == LayerVoteType::ExplicitDefault)) {
                // Only focused layers with ExplicitDefault frame rate settings are allowed to score
                // refresh rates outside the primary range.
                continue;
            }

            const auto layerScore =
                    calculateLayerScoreLocked(layer, *scores[i].refreshRate, isSeamlessSwitch);
            ALOGV("%s gives %s score of %.2f", formatLayerInfo(layer, weight).c_str(),
                  scores[i].refreshRate->getName().c_str(), layerScore);
            scores[i].score += weight * layerScore;
        }
    }

    // Now that we scored all the refresh rates we need to pick the one that got the highest score.
    // In case of a tie we will pick the higher refresh rate if any of the layers wanted Max,
    // or the lower otherwise.
    const RefreshRate* bestRefreshRate = maxVoteLayers > 0
            ? getBestRefreshRate(scores.rbegin(), scores.rend())
            : getBestRefreshRate(scores.begin(), scores.end());

    if (primaryRangeIsSingleRate) {
        // If we never scored any layers, then choose the rate from the primary
        // range instead of picking a random score from the app range.
        if (std::all_of(scores.begin(), scores.end(),
                        [](RefreshRateScore score) { return score.score == 0; })) {
            ALOGV("layers not scored - choose %s",
                  getMaxRefreshRateByPolicyLocked().getName().c_str());
            return getMaxRefreshRateByPolicyLocked();
        } else {
            return *bestRefreshRate;
        }
    }

    // Consider the touch event if there are no ExplicitDefault layers. ExplicitDefault are mostly
    // interactive (as opposed to ExplicitExactOrMultiple) and therefore if those posted an explicit
    // vote we should not change it if we get a touch event. Only apply touch boost if it will
    // actually increase the refresh rate over the normal selection.
    const RefreshRate& touchRefreshRate = getMaxRefreshRateByPolicyLocked();

    if (globalSignals.touch && explicitDefaultVoteLayers == 0 &&
        bestRefreshRate->fps.lessThanWithMargin(touchRefreshRate.fps)) {
        setTouchConsidered();
        ALOGV("TouchBoost - choose %s", touchRefreshRate.getName().c_str());
        return touchRefreshRate;
    }

    return *bestRefreshRate;
}

std::unordered_map<uid_t, std::vector<const RefreshRateConfigs::LayerRequirement*>>
groupLayersByUid(const std::vector<RefreshRateConfigs::LayerRequirement>& layers) {
    std::unordered_map<uid_t, std::vector<const RefreshRateConfigs::LayerRequirement*>> layersByUid;
    for (const auto& layer : layers) {
        auto iter = layersByUid.emplace(layer.ownerUid,
                                        std::vector<const RefreshRateConfigs::LayerRequirement*>());
        auto& layersWithSameUid = iter.first->second;
        layersWithSameUid.push_back(&layer);
    }

    // Remove uids that can't have a frame rate override
    for (auto iter = layersByUid.begin(); iter != layersByUid.end();) {
        const auto& layersWithSameUid = iter->second;
        bool skipUid = false;
        for (const auto& layer : layersWithSameUid) {
            if (layer->vote == RefreshRateConfigs::LayerVoteType::Max ||
                layer->vote == RefreshRateConfigs::LayerVoteType::Heuristic) {
                skipUid = true;
                break;
            }
        }
        if (skipUid) {
            iter = layersByUid.erase(iter);
        } else {
            ++iter;
        }
    }

    return layersByUid;
}

std::vector<RefreshRateScore> initializeScoresForAllRefreshRates(
        const AllRefreshRatesMapType& refreshRates) {
    std::vector<RefreshRateScore> scores;
    scores.reserve(refreshRates.size());
    for (const auto& [ignored, refreshRate] : refreshRates) {
        scores.emplace_back(RefreshRateScore{refreshRate.get(), 0.0f});
    }
    std::sort(scores.begin(), scores.end(),
              [](const auto& a, const auto& b) { return *a.refreshRate < *b.refreshRate; });
    return scores;
}

RefreshRateConfigs::UidToFrameRateOverride RefreshRateConfigs::getFrameRateOverrides(
        const std::vector<LayerRequirement>& layers, Fps displayFrameRate) const {
    ATRACE_CALL();
    if (!mSupportsFrameRateOverride) return {};

    ALOGV("getFrameRateOverrides %zu layers", layers.size());
    std::lock_guard lock(mLock);
    std::vector<RefreshRateScore> scores = initializeScoresForAllRefreshRates(mRefreshRates);
    std::unordered_map<uid_t, std::vector<const LayerRequirement*>> layersByUid =
            groupLayersByUid(layers);
    UidToFrameRateOverride frameRateOverrides;
    for (const auto& [uid, layersWithSameUid] : layersByUid) {
        for (auto& score : scores) {
            score.score = 0;
        }

        for (const auto& layer : layersWithSameUid) {
            if (layer->vote == LayerVoteType::NoVote || layer->vote == LayerVoteType::Min) {
                continue;
            }

            LOG_ALWAYS_FATAL_IF(layer->vote != LayerVoteType::ExplicitDefault &&
                                layer->vote != LayerVoteType::ExplicitExactOrMultiple);
            for (RefreshRateScore& score : scores) {
                const auto layerScore = calculateLayerScoreLocked(*layer, *score.refreshRate,
                                                                  /*isSeamlessSwitch*/ true);
                score.score += layer->weight * layerScore;
            }
        }

        // We just care about the refresh rates which are a divider of the
        // display refresh rate
        auto iter =
                std::remove_if(scores.begin(), scores.end(), [&](const RefreshRateScore& score) {
                    return getFrameRateDivider(displayFrameRate, score.refreshRate->getFps()) == 0;
                });
        scores.erase(iter, scores.end());

        // If we never scored any layers, we don't have a preferred frame rate
        if (std::all_of(scores.begin(), scores.end(),
                        [](const RefreshRateScore& score) { return score.score == 0; })) {
            continue;
        }

        // Now that we scored all the refresh rates we need to pick the one that got the highest
        // score.
        const RefreshRate* bestRefreshRate = getBestRefreshRate(scores.begin(), scores.end());

        // If the nest refresh rate is the current one, we don't have an override
        if (!bestRefreshRate->getFps().equalsWithMargin(displayFrameRate)) {
            frameRateOverrides.emplace(uid, bestRefreshRate->getFps());
        }
    }

    return frameRateOverrides;
}

template <typename Iter>
const RefreshRate* RefreshRateConfigs::getBestRefreshRate(Iter begin, Iter end) const {
    constexpr auto EPSILON = 0.001f;
    const RefreshRate* bestRefreshRate = begin->refreshRate;
    float max = begin->score;
    for (auto i = begin; i != end; ++i) {
        const auto [refreshRate, score] = *i;
        ALOGV("%s scores %.2f", refreshRate->getName().c_str(), score);

        ATRACE_INT(refreshRate->getName().c_str(), round<int>(score * 100));

        if (score > max * (1 + EPSILON)) {
            max = score;
            bestRefreshRate = refreshRate;
        }
    }

    return bestRefreshRate;
}

const RefreshRate& RefreshRateConfigs::getMinRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    return getMinRefreshRateByPolicyLocked();
}

const RefreshRate& RefreshRateConfigs::getMinRefreshRateByPolicyLocked() const {
    for (auto refreshRate : mPrimaryRefreshRates) {
        if (mCurrentRefreshRate->getConfigGroup() == refreshRate->getConfigGroup()) {
            return *refreshRate;
        }
    }
    ALOGE("Can't find min refresh rate by policy with the same config group"
          " as the current config %s",
          mCurrentRefreshRate->toString().c_str());
    // Defaulting to the lowest refresh rate
    return *mPrimaryRefreshRates.front();
}

const RefreshRate& RefreshRateConfigs::getMaxRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    return getMaxRefreshRateByPolicyLocked();
}

const RefreshRate& RefreshRateConfigs::getMaxRefreshRateByPolicyLocked() const {
    for (auto it = mPrimaryRefreshRates.rbegin(); it != mPrimaryRefreshRates.rend(); it++) {
        const auto& refreshRate = (**it);
        if (mCurrentRefreshRate->getConfigGroup() == refreshRate.getConfigGroup()) {
            return refreshRate;
        }
    }
    ALOGE("Can't find max refresh rate by policy with the same config group"
          " as the current config %s",
          mCurrentRefreshRate->toString().c_str());
    // Defaulting to the highest refresh rate
    return *mPrimaryRefreshRates.back();
}

const RefreshRate& RefreshRateConfigs::getCurrentRefreshRate() const {
    std::lock_guard lock(mLock);
    return *mCurrentRefreshRate;
}

const RefreshRate& RefreshRateConfigs::getCurrentRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    return getCurrentRefreshRateByPolicyLocked();
}

const RefreshRate& RefreshRateConfigs::getCurrentRefreshRateByPolicyLocked() const {
    if (std::find(mAppRequestRefreshRates.begin(), mAppRequestRefreshRates.end(),
                  mCurrentRefreshRate) != mAppRequestRefreshRates.end()) {
        return *mCurrentRefreshRate;
    }
    return *mRefreshRates.at(getCurrentPolicyLocked()->defaultConfig);
}

void RefreshRateConfigs::setCurrentConfigId(HwcConfigIndexType configId) {
    std::lock_guard lock(mLock);
    mCurrentRefreshRate = mRefreshRates.at(configId).get();
}

RefreshRateConfigs::RefreshRateConfigs(
        const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs,
        HwcConfigIndexType currentConfigId)
      : mKnownFrameRates(constructKnownFrameRates(configs)) {
    LOG_ALWAYS_FATAL_IF(configs.empty());
    LOG_ALWAYS_FATAL_IF(currentConfigId.value() >= configs.size());

    for (auto configId = HwcConfigIndexType(0); configId.value() < configs.size(); configId++) {
        const auto& config = configs.at(static_cast<size_t>(configId.value()));
        mRefreshRates.emplace(configId,
                              std::make_unique<RefreshRate>(configId, config,
                                                            Fps::fromPeriodNsecs(
                                                                    config->getVsyncPeriod()),
                                                            RefreshRate::ConstructorTag(0)));
        if (configId == currentConfigId) {
            mCurrentRefreshRate = mRefreshRates.at(configId).get();
        }
    }

    std::vector<const RefreshRate*> sortedConfigs;
    getSortedRefreshRateList([](const RefreshRate&) { return true; }, &sortedConfigs);
    mDisplayManagerPolicy.defaultConfig = currentConfigId;
    mMinSupportedRefreshRate = sortedConfigs.front();
    mMaxSupportedRefreshRate = sortedConfigs.back();

    mSupportsFrameRateOverride = false;
    for (const auto& config1 : sortedConfigs) {
        for (const auto& config2 : sortedConfigs) {
            if (getFrameRateDivider(config1->getFps(), config2->getFps()) >= 2) {
                mSupportsFrameRateOverride = true;
                break;
            }
        }
    }
    constructAvailableRefreshRates();
}

bool RefreshRateConfigs::isPolicyValid(const Policy& policy) {
    // defaultConfig must be a valid config, and within the given refresh rate range.
    auto iter = mRefreshRates.find(policy.defaultConfig);
    if (iter == mRefreshRates.end()) {
        ALOGE("Default config is not found.");
        return false;
    }
    const RefreshRate& refreshRate = *iter->second;
    if (!refreshRate.inPolicy(policy.primaryRange.min, policy.primaryRange.max)) {
        ALOGE("Default config is not in the primary range.");
        return false;
    }
    return policy.appRequestRange.min.lessThanOrEqualWithMargin(policy.primaryRange.min) &&
            policy.appRequestRange.max.greaterThanOrEqualWithMargin(policy.primaryRange.max);
}

status_t RefreshRateConfigs::setDisplayManagerPolicy(const Policy& policy) {
    std::lock_guard lock(mLock);
    if (!isPolicyValid(policy)) {
        ALOGE("Invalid refresh rate policy: %s", policy.toString().c_str());
        return BAD_VALUE;
    }
    Policy previousPolicy = *getCurrentPolicyLocked();
    mDisplayManagerPolicy = policy;
    if (*getCurrentPolicyLocked() == previousPolicy) {
        return CURRENT_POLICY_UNCHANGED;
    }
    constructAvailableRefreshRates();
    return NO_ERROR;
}

status_t RefreshRateConfigs::setOverridePolicy(const std::optional<Policy>& policy) {
    std::lock_guard lock(mLock);
    if (policy && !isPolicyValid(*policy)) {
        return BAD_VALUE;
    }
    Policy previousPolicy = *getCurrentPolicyLocked();
    mOverridePolicy = policy;
    if (*getCurrentPolicyLocked() == previousPolicy) {
        return CURRENT_POLICY_UNCHANGED;
    }
    constructAvailableRefreshRates();
    return NO_ERROR;
}

const RefreshRateConfigs::Policy* RefreshRateConfigs::getCurrentPolicyLocked() const {
    return mOverridePolicy ? &mOverridePolicy.value() : &mDisplayManagerPolicy;
}

RefreshRateConfigs::Policy RefreshRateConfigs::getCurrentPolicy() const {
    std::lock_guard lock(mLock);
    return *getCurrentPolicyLocked();
}

RefreshRateConfigs::Policy RefreshRateConfigs::getDisplayManagerPolicy() const {
    std::lock_guard lock(mLock);
    return mDisplayManagerPolicy;
}

bool RefreshRateConfigs::isConfigAllowed(HwcConfigIndexType config) const {
    std::lock_guard lock(mLock);
    for (const RefreshRate* refreshRate : mAppRequestRefreshRates) {
        if (refreshRate->configId == config) {
            return true;
        }
    }
    return false;
}

void RefreshRateConfigs::getSortedRefreshRateList(
        const std::function<bool(const RefreshRate&)>& shouldAddRefreshRate,
        std::vector<const RefreshRate*>* outRefreshRates) {
    outRefreshRates->clear();
    outRefreshRates->reserve(mRefreshRates.size());
    for (const auto& [type, refreshRate] : mRefreshRates) {
        if (shouldAddRefreshRate(*refreshRate)) {
            ALOGV("getSortedRefreshRateList: config %d added to list policy",
                  refreshRate->configId.value());
            outRefreshRates->push_back(refreshRate.get());
        }
    }

    std::sort(outRefreshRates->begin(), outRefreshRates->end(),
              [](const auto refreshRate1, const auto refreshRate2) {
                  if (refreshRate1->hwcConfig->getVsyncPeriod() !=
                      refreshRate2->hwcConfig->getVsyncPeriod()) {
                      return refreshRate1->hwcConfig->getVsyncPeriod() >
                              refreshRate2->hwcConfig->getVsyncPeriod();
                  } else {
                      return refreshRate1->hwcConfig->getConfigGroup() >
                              refreshRate2->hwcConfig->getConfigGroup();
                  }
              });
}

void RefreshRateConfigs::constructAvailableRefreshRates() {
    // Filter configs based on current policy and sort based on vsync period
    const Policy* policy = getCurrentPolicyLocked();
    const auto& defaultConfig = mRefreshRates.at(policy->defaultConfig)->hwcConfig;
    ALOGV("constructAvailableRefreshRates: %s ", policy->toString().c_str());

    auto filterRefreshRates = [&](Fps min, Fps max, const char* listName,
                                  std::vector<const RefreshRate*>* outRefreshRates) {
        getSortedRefreshRateList(
                [&](const RefreshRate& refreshRate) REQUIRES(mLock) {
                    const auto& hwcConfig = refreshRate.hwcConfig;

                    return hwcConfig->getHeight() == defaultConfig->getHeight() &&
                            hwcConfig->getWidth() == defaultConfig->getWidth() &&
                            hwcConfig->getDpiX() == defaultConfig->getDpiX() &&
                            hwcConfig->getDpiY() == defaultConfig->getDpiY() &&
                            (policy->allowGroupSwitching ||
                             hwcConfig->getConfigGroup() == defaultConfig->getConfigGroup()) &&
                            refreshRate.inPolicy(min, max);
                },
                outRefreshRates);

        LOG_ALWAYS_FATAL_IF(outRefreshRates->empty(),
                            "No matching configs for %s range: min=%s max=%s", listName,
                            to_string(min).c_str(), to_string(max).c_str());
        auto stringifyRefreshRates = [&]() -> std::string {
            std::string str;
            for (auto refreshRate : *outRefreshRates) {
                base::StringAppendF(&str, "%s ", refreshRate->getName().c_str());
            }
            return str;
        };
        ALOGV("%s refresh rates: %s", listName, stringifyRefreshRates().c_str());
    };

    filterRefreshRates(policy->primaryRange.min, policy->primaryRange.max, "primary",
                       &mPrimaryRefreshRates);
    filterRefreshRates(policy->appRequestRange.min, policy->appRequestRange.max, "app request",
                       &mAppRequestRefreshRates);
}

std::vector<Fps> RefreshRateConfigs::constructKnownFrameRates(
        const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs) {
    std::vector<Fps> knownFrameRates = {Fps(24.0f), Fps(30.0f), Fps(45.0f), Fps(60.0f), Fps(72.0f)};
    knownFrameRates.reserve(knownFrameRates.size() + configs.size());

    // Add all supported refresh rates to the set
    for (const auto& config : configs) {
        const auto refreshRate = Fps::fromPeriodNsecs(config->getVsyncPeriod());
        knownFrameRates.emplace_back(refreshRate);
    }

    // Sort and remove duplicates
    std::sort(knownFrameRates.begin(), knownFrameRates.end(), Fps::comparesLess);
    knownFrameRates.erase(std::unique(knownFrameRates.begin(), knownFrameRates.end(),
                                      Fps::EqualsWithMargin()),
                          knownFrameRates.end());
    return knownFrameRates;
}

Fps RefreshRateConfigs::findClosestKnownFrameRate(Fps frameRate) const {
    if (frameRate.lessThanOrEqualWithMargin(*mKnownFrameRates.begin())) {
        return *mKnownFrameRates.begin();
    }

    if (frameRate.greaterThanOrEqualWithMargin(*std::prev(mKnownFrameRates.end()))) {
        return *std::prev(mKnownFrameRates.end());
    }

    auto lowerBound = std::lower_bound(mKnownFrameRates.begin(), mKnownFrameRates.end(), frameRate,
                                       Fps::comparesLess);

    const auto distance1 = std::abs((frameRate.getValue() - lowerBound->getValue()));
    const auto distance2 = std::abs((frameRate.getValue() - std::prev(lowerBound)->getValue()));
    return distance1 < distance2 ? *lowerBound : *std::prev(lowerBound);
}

RefreshRateConfigs::KernelIdleTimerAction RefreshRateConfigs::getIdleTimerAction() const {
    std::lock_guard lock(mLock);
    const auto& deviceMin = getMinRefreshRate();
    const auto& minByPolicy = getMinRefreshRateByPolicyLocked();
    const auto& maxByPolicy = getMaxRefreshRateByPolicyLocked();

    // Kernel idle timer will set the refresh rate to the device min. If DisplayManager says that
    // the min allowed refresh rate is higher than the device min, we do not want to enable the
    // timer.
    if (deviceMin < minByPolicy) {
        return RefreshRateConfigs::KernelIdleTimerAction::TurnOff;
    }
    if (minByPolicy == maxByPolicy) {
        // Do not sent the call to toggle off kernel idle timer if the device min and policy min and
        // max are all the same. This saves us extra unnecessary calls to sysprop.
        if (deviceMin == minByPolicy) {
            return RefreshRateConfigs::KernelIdleTimerAction::NoChange;
        }
        return RefreshRateConfigs::KernelIdleTimerAction::TurnOff;
    }
    // Turn on the timer in all other cases.
    return RefreshRateConfigs::KernelIdleTimerAction::TurnOn;
}

int RefreshRateConfigs::getFrameRateDivider(Fps displayFrameRate, Fps layerFrameRate) {
    // This calculation needs to be in sync with the java code
    // in DisplayManagerService.getDisplayInfoForFrameRateOverride
    constexpr float kThreshold = 0.1f;
    const auto numPeriods = displayFrameRate.getValue() / layerFrameRate.getValue();
    const auto numPeriodsRounded = std::round(numPeriods);
    if (std::abs(numPeriods - numPeriodsRounded) > kThreshold) {
        return 0;
    }

    return static_cast<int>(numPeriodsRounded);
}

int RefreshRateConfigs::getRefreshRateDivider(Fps frameRate) const {
    std::lock_guard lock(mLock);
    return getFrameRateDivider(mCurrentRefreshRate->getFps(), frameRate);
}

void RefreshRateConfigs::dump(std::string& result) const {
    std::lock_guard lock(mLock);
    base::StringAppendF(&result, "DesiredDisplayConfigSpecs (DisplayManager): %s\n\n",
                        mDisplayManagerPolicy.toString().c_str());
    scheduler::RefreshRateConfigs::Policy currentPolicy = *getCurrentPolicyLocked();
    if (mOverridePolicy && currentPolicy != mDisplayManagerPolicy) {
        base::StringAppendF(&result, "DesiredDisplayConfigSpecs (Override): %s\n\n",
                            currentPolicy.toString().c_str());
    }

    auto config = mCurrentRefreshRate->hwcConfig;
    base::StringAppendF(&result, "Current config: %s\n", mCurrentRefreshRate->toString().c_str());

    result.append("Refresh rates:\n");
    for (const auto& [id, refreshRate] : mRefreshRates) {
        config = refreshRate->hwcConfig;
        base::StringAppendF(&result, "\t%s\n", refreshRate->toString().c_str());
    }

    base::StringAppendF(&result, "Supports Frame Rate Override: %s\n",
                        mSupportsFrameRateOverride ? "yes" : "no");
    result.append("\n");
}

} // namespace android::scheduler
