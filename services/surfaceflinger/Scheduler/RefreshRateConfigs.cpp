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

using AllRefreshRatesMapType = RefreshRateConfigs::AllRefreshRatesMapType;
using RefreshRate = RefreshRateConfigs::RefreshRate;

const RefreshRate& RefreshRateConfigs::getRefreshRateForContent(
        const std::vector<LayerRequirement>& layers) const {
    std::lock_guard lock(mLock);
    int contentFramerate = 0;
    int explicitContentFramerate = 0;
    for (const auto& layer : layers) {
        const auto desiredRefreshRateRound = round<int>(layer.desiredRefreshRate);
        if (layer.vote == LayerVoteType::ExplicitDefault ||
            layer.vote == LayerVoteType::ExplicitExactOrMultiple) {
            if (desiredRefreshRateRound > explicitContentFramerate) {
                explicitContentFramerate = desiredRefreshRateRound;
            }
        } else {
            if (desiredRefreshRateRound > contentFramerate) {
                contentFramerate = desiredRefreshRateRound;
            }
        }
    }

    if (explicitContentFramerate != 0) {
        contentFramerate = explicitContentFramerate;
    } else if (contentFramerate == 0) {
        contentFramerate = round<int>(mMaxSupportedRefreshRate->fps);
    }
    ATRACE_INT("ContentFPS", contentFramerate);

    // Find the appropriate refresh rate with minimal error
    auto iter = min_element(mAvailableRefreshRates.cbegin(), mAvailableRefreshRates.cend(),
                            [contentFramerate](const auto& lhs, const auto& rhs) -> bool {
                                return std::abs(lhs->fps - contentFramerate) <
                                        std::abs(rhs->fps - contentFramerate);
                            });

    // Some content aligns better on higher refresh rate. For example for 45fps we should choose
    // 90Hz config. However we should still prefer a lower refresh rate if the content doesn't
    // align well with both
    const RefreshRate* bestSoFar = *iter;
    constexpr float MARGIN = 0.05f;
    float ratio = (*iter)->fps / contentFramerate;
    if (std::abs(std::round(ratio) - ratio) > MARGIN) {
        while (iter != mAvailableRefreshRates.cend()) {
            ratio = (*iter)->fps / contentFramerate;

            if (std::abs(std::round(ratio) - ratio) <= MARGIN) {
                bestSoFar = *iter;
                break;
            }
            ++iter;
        }
    }

    return *bestSoFar;
}

std::pair<nsecs_t, nsecs_t> RefreshRateConfigs::getDisplayFrames(nsecs_t layerPeriod,
                                                                 nsecs_t displayPeriod) const {
    auto [displayFramesQuot, displayFramesRem] = std::div(layerPeriod, displayPeriod);
    if (displayFramesRem <= MARGIN_FOR_PERIOD_CALCULATION ||
        std::abs(displayFramesRem - displayPeriod) <= MARGIN_FOR_PERIOD_CALCULATION) {
        displayFramesQuot++;
        displayFramesRem = 0;
    }

    return {displayFramesQuot, displayFramesRem};
}

const RefreshRate& RefreshRateConfigs::getRefreshRateForContentV2(
        const std::vector<LayerRequirement>& layers, bool touchActive,
        bool* touchConsidered) const {
    ATRACE_CALL();
    ALOGV("getRefreshRateForContent %zu layers", layers.size());

    *touchConsidered = false;
    std::lock_guard lock(mLock);

    // If there are not layers, there is not content detection, so return the current
    // refresh rate.
    if (layers.empty()) {
        *touchConsidered = touchActive;
        return touchActive ? *mAvailableRefreshRates.back() : getCurrentRefreshRateByPolicyLocked();
    }

    int noVoteLayers = 0;
    int minVoteLayers = 0;
    int maxVoteLayers = 0;
    int explicitDefaultVoteLayers = 0;
    int explicitExactOrMultipleVoteLayers = 0;
    float maxExplicitWeight = 0;
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
    }

    // Consider the touch event if there are no ExplicitDefault layers.
    // ExplicitDefault are mostly interactive (as opposed to ExplicitExactOrMultiple)
    // and therefore if those posted an explicit vote we should not change it
    // if get get a touch event.
    if (touchActive && explicitDefaultVoteLayers == 0) {
        *touchConsidered = true;
        return *mAvailableRefreshRates.back();
    }

    // Only if all layers want Min we should return Min
    if (noVoteLayers + minVoteLayers == layers.size()) {
        return *mAvailableRefreshRates.front();
    }

    // Find the best refresh rate based on score
    std::vector<std::pair<const RefreshRate*, float>> scores;
    scores.reserve(mAvailableRefreshRates.size());

    for (const auto refreshRate : mAvailableRefreshRates) {
        scores.emplace_back(refreshRate, 0.0f);
    }

    for (const auto& layer : layers) {
        ALOGV("Calculating score for %s (type: %d)", layer.name.c_str(), layer.vote);
        if (layer.vote == LayerVoteType::NoVote || layer.vote == LayerVoteType::Min) {
            continue;
        }

        auto weight = layer.weight;

        for (auto i = 0u; i < scores.size(); i++) {
            // If the layer wants Max, give higher score to the higher refresh rate
            if (layer.vote == LayerVoteType::Max) {
                const auto ratio = scores[i].first->fps / scores.back().first->fps;
                // use ratio^2 to get a lower score the more we get further from peak
                const auto layerScore = ratio * ratio;
                ALOGV("%s (Max, weight %.2f) gives %s score of %.2f", layer.name.c_str(), weight,
                      scores[i].first->name.c_str(), layerScore);
                scores[i].second += weight * layerScore;
                continue;
            }

            const auto displayPeriod = scores[i].first->vsyncPeriod;
            const auto layerPeriod = round<nsecs_t>(1e9f / layer.desiredRefreshRate);
            if (layer.vote == LayerVoteType::ExplicitDefault) {
                const auto layerScore = [&]() {
                    // Find the actual rate the layer will render, assuming
                    // that layerPeriod is the minimal time to render a frame
                    auto actualLayerPeriod = displayPeriod;
                    int multiplier = 1;
                    while (layerPeriod > actualLayerPeriod + MARGIN_FOR_PERIOD_CALCULATION) {
                        multiplier++;
                        actualLayerPeriod = displayPeriod * multiplier;
                    }
                    return std::min(1.0f,
                                    static_cast<float>(layerPeriod) /
                                            static_cast<float>(actualLayerPeriod));
                }();

                ALOGV("%s (ExplicitDefault, weight %.2f) %.2fHz gives %s score of %.2f",
                      layer.name.c_str(), weight, 1e9f / layerPeriod, scores[i].first->name.c_str(),
                      layerScore);
                scores[i].second += weight * layerScore;
                continue;
            }

            if (layer.vote == LayerVoteType::ExplicitExactOrMultiple ||
                layer.vote == LayerVoteType::Heuristic) {
                const auto layerScore = [&]() {
                    // Calculate how many display vsyncs we need to present a single frame for this
                    // layer
                    const auto [displayFramesQuot, displayFramesRem] =
                            getDisplayFrames(layerPeriod, displayPeriod);
                    static constexpr size_t MAX_FRAMES_TO_FIT =
                            10; // Stop calculating when score < 0.1
                    if (displayFramesRem == 0) {
                        // Layer desired refresh rate matches the display rate.
                        return 1.0f;
                    }

                    if (displayFramesQuot == 0) {
                        // Layer desired refresh rate is higher the display rate.
                        return (static_cast<float>(layerPeriod) /
                                static_cast<float>(displayPeriod)) *
                                (1.0f / (MAX_FRAMES_TO_FIT + 1));
                    }

                    // Layer desired refresh rate is lower the display rate. Check how well it fits
                    // the cadence
                    auto diff = std::abs(displayFramesRem - (displayPeriod - displayFramesRem));
                    int iter = 2;
                    while (diff > MARGIN_FOR_PERIOD_CALCULATION && iter < MAX_FRAMES_TO_FIT) {
                        diff = diff - (displayPeriod - diff);
                        iter++;
                    }

                    return 1.0f / iter;
                }();
                ALOGV("%s (ExplicitExactOrMultiple, weight %.2f) %.2fHz gives %s score of %.2f",
                      layer.name.c_str(), weight, 1e9f / layerPeriod, scores[i].first->name.c_str(),
                      layerScore);
                scores[i].second += weight * layerScore;
                continue;
            }
        }
    }

    // Now that we scored all the refresh rates we need to pick the one that got the highest score.
    // In case of a tie we will pick the higher refresh rate if any of the layers wanted Max,
    // or the lower otherwise.
    const RefreshRate* bestRefreshRate = maxVoteLayers > 0
            ? getBestRefreshRate(scores.rbegin(), scores.rend())
            : getBestRefreshRate(scores.begin(), scores.end());

    return *bestRefreshRate;
}

template <typename Iter>
const RefreshRate* RefreshRateConfigs::getBestRefreshRate(Iter begin, Iter end) const {
    constexpr auto EPSILON = 0.001f;
    const RefreshRate* bestRefreshRate = begin->first;
    float max = begin->second;
    for (auto i = begin; i != end; ++i) {
        const auto [refreshRate, score] = *i;
        ALOGV("%s scores %.2f", refreshRate->name.c_str(), score);

        ATRACE_INT(refreshRate->name.c_str(), round<int>(score * 100));

        if (score > max * (1 + EPSILON)) {
            max = score;
            bestRefreshRate = refreshRate;
        }
    }

    return bestRefreshRate;
}

const AllRefreshRatesMapType& RefreshRateConfigs::getAllRefreshRates() const {
    return mRefreshRates;
}

const RefreshRate& RefreshRateConfigs::getMinRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    return *mAvailableRefreshRates.front();
}

const RefreshRate& RefreshRateConfigs::getMaxRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
        return *mAvailableRefreshRates.back();
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
    if (std::find(mAvailableRefreshRates.begin(), mAvailableRefreshRates.end(),
                  mCurrentRefreshRate) != mAvailableRefreshRates.end()) {
        return *mCurrentRefreshRate;
    }
    return *mRefreshRates.at(getCurrentPolicyLocked()->defaultConfig);
}

void RefreshRateConfigs::setCurrentConfigId(HwcConfigIndexType configId) {
    std::lock_guard lock(mLock);
    mCurrentRefreshRate = mRefreshRates.at(configId).get();
}

RefreshRateConfigs::RefreshRateConfigs(const std::vector<InputConfig>& configs,
                                       HwcConfigIndexType currentHwcConfig) {
    init(configs, currentHwcConfig);
}

RefreshRateConfigs::RefreshRateConfigs(
        const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs,
        HwcConfigIndexType currentConfigId) {
    std::vector<InputConfig> inputConfigs;
    for (size_t configId = 0; configId < configs.size(); ++configId) {
        auto configGroup = HwcConfigGroupType(configs[configId]->getConfigGroup());
        inputConfigs.push_back({HwcConfigIndexType(static_cast<int>(configId)), configGroup,
                                configs[configId]->getVsyncPeriod()});
    }
    init(inputConfigs, currentConfigId);
}

bool RefreshRateConfigs::isPolicyValid(const Policy& policy) {
    // defaultConfig must be a valid config, and within the given refresh rate range.
    auto iter = mRefreshRates.find(policy.defaultConfig);
    if (iter == mRefreshRates.end()) {
        return false;
    }
    const RefreshRate& refreshRate = *iter->second;
    if (!refreshRate.inPolicy(policy.minRefreshRate, policy.maxRefreshRate)) {
        return false;
    }
    return true;
}

status_t RefreshRateConfigs::setDisplayManagerPolicy(const Policy& policy) {
    std::lock_guard lock(mLock);
    if (!isPolicyValid(policy)) {
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
    for (const RefreshRate* refreshRate : mAvailableRefreshRates) {
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
                  if (refreshRate1->vsyncPeriod != refreshRate2->vsyncPeriod) {
                      return refreshRate1->vsyncPeriod > refreshRate2->vsyncPeriod;
                  } else {
                      return refreshRate1->configGroup > refreshRate2->configGroup;
                  }
              });
}

void RefreshRateConfigs::constructAvailableRefreshRates() {
    // Filter configs based on current policy and sort based on vsync period
    const Policy* policy = getCurrentPolicyLocked();
    HwcConfigGroupType group = mRefreshRates.at(policy->defaultConfig)->configGroup;
    ALOGV("constructAvailableRefreshRates: default %d group %d min %.2f max %.2f",
          policy->defaultConfig.value(), group.value(), policy->minRefreshRate,
          policy->maxRefreshRate);
    getSortedRefreshRateList(
            [&](const RefreshRate& refreshRate) REQUIRES(mLock) {
                return (policy->allowGroupSwitching || refreshRate.configGroup == group) &&
                        refreshRate.inPolicy(policy->minRefreshRate, policy->maxRefreshRate);
            },
            &mAvailableRefreshRates);

    std::string availableRefreshRates;
    for (const auto& refreshRate : mAvailableRefreshRates) {
        base::StringAppendF(&availableRefreshRates, "%s ", refreshRate->name.c_str());
    }

    ALOGV("Available refresh rates: %s", availableRefreshRates.c_str());
    LOG_ALWAYS_FATAL_IF(mAvailableRefreshRates.empty(),
                        "No compatible display configs for default=%d min=%.0f max=%.0f",
                        policy->defaultConfig.value(), policy->minRefreshRate,
                        policy->maxRefreshRate);
}

// NO_THREAD_SAFETY_ANALYSIS since this is called from the constructor
void RefreshRateConfigs::init(const std::vector<InputConfig>& configs,
                              HwcConfigIndexType currentHwcConfig) NO_THREAD_SAFETY_ANALYSIS {
    LOG_ALWAYS_FATAL_IF(configs.empty());
    LOG_ALWAYS_FATAL_IF(currentHwcConfig.value() >= configs.size());

    for (const auto& config : configs) {
        const float fps = 1e9f / config.vsyncPeriod;
        mRefreshRates.emplace(config.configId,
                              std::make_unique<RefreshRate>(config.configId, config.vsyncPeriod,
                                                            config.configGroup,
                                                            base::StringPrintf("%2.ffps", fps),
                                                            fps));
        if (config.configId == currentHwcConfig) {
            mCurrentRefreshRate = mRefreshRates.at(config.configId).get();
        }
    }

    std::vector<const RefreshRate*> sortedConfigs;
    getSortedRefreshRateList([](const RefreshRate&) { return true; }, &sortedConfigs);
    mDisplayManagerPolicy.defaultConfig = currentHwcConfig;
    mMinSupportedRefreshRate = sortedConfigs.front();
    mMaxSupportedRefreshRate = sortedConfigs.back();
    constructAvailableRefreshRates();
}

} // namespace android::scheduler
