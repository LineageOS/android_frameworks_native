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
#include "RefreshRateConfigs.h"

namespace android::scheduler {
using RefreshRate = RefreshRateConfigs::RefreshRate;
using RefreshRateType = RefreshRateConfigs::RefreshRateType;

// Returns the refresh rate map. This map won't be modified at runtime, so it's safe to access
// from multiple threads. This can only be called if refreshRateSwitching() returns true.
// TODO(b/122916473): Get this information from configs prepared by vendors, instead of
// baking them in.
const std::map<RefreshRateType, RefreshRate>& RefreshRateConfigs::getRefreshRateMap() const {
    LOG_ALWAYS_FATAL_IF(!mRefreshRateSwitchingSupported);
    return mRefreshRateMap;
}

const RefreshRate& RefreshRateConfigs::getRefreshRateFromType(RefreshRateType type) const {
    if (!mRefreshRateSwitchingSupported) {
        return getCurrentRefreshRate().second;
    } else {
        auto refreshRate = mRefreshRateMap.find(type);
        LOG_ALWAYS_FATAL_IF(refreshRate == mRefreshRateMap.end());
        return refreshRate->second;
    }
}

std::pair<RefreshRateType, const RefreshRate&> RefreshRateConfigs::getCurrentRefreshRate() const {
    int currentConfig = mCurrentConfig;
    if (mRefreshRateSwitchingSupported) {
        for (const auto& [type, refresh] : mRefreshRateMap) {
            if (refresh.configId == currentConfig) {
                return {type, refresh};
            }
        }
        LOG_ALWAYS_FATAL();
    }
    return {RefreshRateType::DEFAULT, mRefreshRates[currentConfig]};
}

const RefreshRate& RefreshRateConfigs::getRefreshRateFromConfigId(int configId) const {
    LOG_ALWAYS_FATAL_IF(configId >= mRefreshRates.size());
    return mRefreshRates[configId];
}

RefreshRateType RefreshRateConfigs::getRefreshRateTypeFromHwcConfigId(hwc2_config_t hwcId) const {
    if (!mRefreshRateSwitchingSupported) return RefreshRateType::DEFAULT;

    for (const auto& [type, refreshRate] : mRefreshRateMap) {
        if (refreshRate.hwcId == hwcId) {
            return type;
        }
    }

    return RefreshRateType::DEFAULT;
}

void RefreshRateConfigs::setCurrentConfig(int config) {
    LOG_ALWAYS_FATAL_IF(config >= mRefreshRates.size());
    mCurrentConfig = config;
}

RefreshRateConfigs::RefreshRateConfigs(bool refreshRateSwitching,
                                       const std::vector<InputConfig>& configs, int currentConfig) {
    init(refreshRateSwitching, configs, currentConfig);
}

RefreshRateConfigs::RefreshRateConfigs(
        bool refreshRateSwitching,
        const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs,
        int currentConfig) {
    std::vector<InputConfig> inputConfigs;
    for (const auto& config : configs) {
        inputConfigs.push_back({config->getId(), config->getVsyncPeriod()});
    }
    init(refreshRateSwitching, inputConfigs, currentConfig);
}

void RefreshRateConfigs::init(bool refreshRateSwitching, const std::vector<InputConfig>& configs,
                              int currentConfig) {
    mRefreshRateSwitchingSupported = refreshRateSwitching;
    LOG_ALWAYS_FATAL_IF(configs.empty());
    LOG_ALWAYS_FATAL_IF(currentConfig >= configs.size());
    mCurrentConfig = currentConfig;

    auto buildRefreshRate = [&](int configId) -> RefreshRate {
        const nsecs_t vsyncPeriod = configs[configId].vsyncPeriod;
        const float fps = 1e9 / vsyncPeriod;
        return {configId, base::StringPrintf("%2.ffps", fps), static_cast<uint32_t>(fps),
                vsyncPeriod, configs[configId].hwcId};
    };

    for (int i = 0; i < configs.size(); ++i) {
        mRefreshRates.push_back(buildRefreshRate(i));
    }

    if (!mRefreshRateSwitchingSupported) return;

    auto findDefaultAndPerfConfigs = [&]() -> std::optional<std::pair<int, int>> {
        if (configs.size() < 2) {
            return {};
        }

        std::vector<const RefreshRate*> sortedRefreshRates;
        for (const auto& refreshRate : mRefreshRates) {
            sortedRefreshRates.push_back(&refreshRate);
        }
        std::sort(sortedRefreshRates.begin(), sortedRefreshRates.end(),
                  [](const RefreshRate* refreshRate1, const RefreshRate* refreshRate2) {
                      return refreshRate1->vsyncPeriod > refreshRate2->vsyncPeriod;
                  });

        // When the configs are ordered by the resync rate, we assume that
        // the first one is DEFAULT and the second one is PERFORMANCE,
        // i.e. the higher rate.
        if (sortedRefreshRates[0]->vsyncPeriod == 0 || sortedRefreshRates[1]->vsyncPeriod == 0) {
            return {};
        }

        return std::pair<int, int>(sortedRefreshRates[0]->configId,
                                   sortedRefreshRates[1]->configId);
    };

    auto defaultAndPerfConfigs = findDefaultAndPerfConfigs();
    if (!defaultAndPerfConfigs) {
        mRefreshRateSwitchingSupported = false;
        return;
    }

    mRefreshRateMap[RefreshRateType::DEFAULT] = mRefreshRates[defaultAndPerfConfigs->first];
    mRefreshRateMap[RefreshRateType::PERFORMANCE] = mRefreshRates[defaultAndPerfConfigs->second];
}

} // namespace android::scheduler