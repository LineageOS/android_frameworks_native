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
#include "RefreshRateConfigs.h"

namespace android::scheduler {

using AllRefreshRatesMapType = RefreshRateConfigs::AllRefreshRatesMapType;
using RefreshRate = RefreshRateConfigs::RefreshRate;

// Returns the refresh rate map. This map won't be modified at runtime, so it's safe to access
// from multiple threads. This can only be called if refreshRateSwitching() returns true.
// TODO(b/122916473): Get this information from configs prepared by vendors, instead of
// baking them in.
const RefreshRate& RefreshRateConfigs::getRefreshRateForContent(float contentFramerate) const {
    std::lock_guard lock(mLock);
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

const AllRefreshRatesMapType& RefreshRateConfigs::getAllRefreshRates() const {
    return mRefreshRates;
}

const RefreshRate& RefreshRateConfigs::getMinRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    if (!mRefreshRateSwitching) {
        return *mCurrentRefreshRate;
    } else {
        return *mAvailableRefreshRates.front();
    }
}

const RefreshRate& RefreshRateConfigs::getMaxRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    if (!mRefreshRateSwitching) {
        return *mCurrentRefreshRate;
    } else {
        return *mAvailableRefreshRates.back();
    }
}

const RefreshRate& RefreshRateConfigs::getCurrentRefreshRate() const {
    std::lock_guard lock(mLock);
    return *mCurrentRefreshRate;
}

void RefreshRateConfigs::setCurrentConfigId(HwcConfigIndexType configId) {
    std::lock_guard lock(mLock);
    mCurrentRefreshRate = &mRefreshRates.at(configId);
}

RefreshRateConfigs::RefreshRateConfigs(bool refreshRateSwitching,
                                       const std::vector<InputConfig>& configs,
                                       HwcConfigIndexType currentHwcConfig)
      : mRefreshRateSwitching(refreshRateSwitching) {
    init(configs, currentHwcConfig);
}

RefreshRateConfigs::RefreshRateConfigs(
        bool refreshRateSwitching,
        const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs,
        HwcConfigIndexType currentConfigId)
      : mRefreshRateSwitching(refreshRateSwitching) {
    std::vector<InputConfig> inputConfigs;
    for (auto configId = HwcConfigIndexType(0); configId < HwcConfigIndexType(configs.size());
         ++configId) {
        auto configGroup = HwcConfigGroupType(configs[configId.value()]->getConfigGroup());
        inputConfigs.push_back(
                {configId, configGroup, configs[configId.value()]->getVsyncPeriod()});
    }
    init(inputConfigs, currentConfigId);
}

void RefreshRateConfigs::setPolicy(HwcConfigIndexType defaultConfigId, float minRefreshRate,
                                   float maxRefreshRate) {
    std::lock_guard lock(mLock);
    mCurrentGroupId = mRefreshRates.at(defaultConfigId).configGroup;
    mMinRefreshRateFps = minRefreshRate;
    mMaxRefreshRateFps = maxRefreshRate;
    constructAvailableRefreshRates();
}

void RefreshRateConfigs::getSortedRefreshRateList(
        const std::function<bool(const RefreshRate&)>& shouldAddRefreshRate,
        std::vector<const RefreshRate*>* outRefreshRates) {
    outRefreshRates->clear();
    outRefreshRates->reserve(mRefreshRates.size());
    for (const auto& [type, refreshRate] : mRefreshRates) {
        if (shouldAddRefreshRate(refreshRate)) {
            ALOGV("getSortedRefreshRateList: config %d added to list policy",
                  refreshRate.configId.value());
            outRefreshRates->push_back(&refreshRate);
        }
    }

    std::sort(outRefreshRates->begin(), outRefreshRates->end(),
              [](const auto refreshRate1, const auto refreshRate2) {
                  return refreshRate1->vsyncPeriod > refreshRate2->vsyncPeriod;
              });
}

void RefreshRateConfigs::constructAvailableRefreshRates() {
    // Filter configs based on current policy and sort based on vsync period
    ALOGV("constructRefreshRateMap: group %d min %.2f max %.2f", mCurrentGroupId.value(),
          mMinRefreshRateFps, mMaxRefreshRateFps);
    getSortedRefreshRateList(
            [this](const RefreshRate& refreshRate) REQUIRES(mLock) {
                return refreshRate.configGroup == mCurrentGroupId &&
                        refreshRate.fps >= mMinRefreshRateFps &&
                        refreshRate.fps <= mMaxRefreshRateFps;
            },
            &mAvailableRefreshRates);
}

// NO_THREAD_SAFETY_ANALYSIS since this is called from the constructor
void RefreshRateConfigs::init(const std::vector<InputConfig>& configs,
                              HwcConfigIndexType currentHwcConfig) NO_THREAD_SAFETY_ANALYSIS {
    LOG_ALWAYS_FATAL_IF(configs.empty());
    LOG_ALWAYS_FATAL_IF(currentHwcConfig.value() >= configs.size());

    auto buildRefreshRate = [&](InputConfig config) -> RefreshRate {
        const float fps = 1e9f / config.vsyncPeriod;
        return RefreshRate(config.configId, config.vsyncPeriod, config.configGroup,
                           base::StringPrintf("%2.ffps", fps), fps);
    };

    for (const auto& config : configs) {
        mRefreshRates.emplace(config.configId, buildRefreshRate(config));
        if (config.configId == currentHwcConfig) {
            mCurrentRefreshRate = &mRefreshRates.at(config.configId);
            mCurrentGroupId = config.configGroup;
        }
    }

    std::vector<const RefreshRate*> sortedConfigs;
    getSortedRefreshRateList([](const RefreshRate&) { return true; }, &sortedConfigs);
    mMinSupportedRefreshRate = sortedConfigs.front();
    mMaxSupportedRefreshRate = sortedConfigs.back();
    constructAvailableRefreshRates();
}

} // namespace android::scheduler
