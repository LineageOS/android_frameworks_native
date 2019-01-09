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

#pragma once

#include <algorithm>
#include <numeric>

#include "Scheduler/SchedulerUtils.h"
#include "android-base/stringprintf.h"

namespace android {
namespace scheduler {

/**
 * This class is used to encapsulate configuration for refresh rates. It holds infomation
 * about available refresh rates on the device, and the mapping between the numbers and human
 * readable names.
 */
class RefreshRateConfigs {
public:
    // Enum to indicate which vsync rate to run at. Power saving is intended to be the lowest
    // (eg. when the screen is in AOD mode or off), default is the old 60Hz, and performance
    // is the new 90Hz. Eventually we want to have a way for vendors to map these in the configs.
    enum class RefreshRateType { POWER_SAVING, DEFAULT, PERFORMANCE };

    struct RefreshRate {
        // Type of the refresh rate.
        RefreshRateType type;
        // This config ID corresponds to the position of the config in the vector that is stored
        // on the device.
        int configId;
        // Human readable name of the refresh rate.
        std::string name;
    };

    // TODO(b/122916473): Get this information from configs prepared by vendors, instead of
    // baking them in.
    explicit RefreshRateConfigs(
            const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs) {
        // This is the rate that HWC encapsulates right now when the screen is off.
        RefreshRate rate;
        rate.type = RefreshRateType::POWER_SAVING;
        rate.configId = SCREEN_OFF_CONFIG_ID;
        rate.name = "ScreenOff";
        mRefreshRates.push_back(rate);

        if (configs.size() < 1) {
            return;
        }

        std::vector<std::pair<int, nsecs_t>> configIdToVsyncPeriod;
        for (int i = 0; i < configs.size(); ++i) {
            configIdToVsyncPeriod.push_back(std::make_pair(i, configs.at(i)->getVsyncPeriod()));
        }
        std::sort(configIdToVsyncPeriod.begin(), configIdToVsyncPeriod.end(),
                  [](const std::pair<int, nsecs_t>& a, const std::pair<int, nsecs_t>& b) {
                      return a.second > b.second;
                  });

        nsecs_t vsyncPeriod = configIdToVsyncPeriod.at(0).second;
        if (vsyncPeriod != 0) {
            const float fps = std::chrono::nanoseconds(1).count() / vsyncPeriod;
            rate.type = RefreshRateType::DEFAULT;
            rate.configId = configIdToVsyncPeriod.at(0).first;
            rate.name = base::StringPrintf("%2.ffps", fps);
            mRefreshRates.push_back(rate);
        }
        if (configs.size() < 2) {
            return;
        }

        vsyncPeriod = configIdToVsyncPeriod.at(1).second;
        if (vsyncPeriod != 0) {
            const float fps = std::chrono::nanoseconds(1).count() / vsyncPeriod;
            rate.type = RefreshRateType::PERFORMANCE;
            rate.configId = configIdToVsyncPeriod.at(1).first;
            rate.name = base::StringPrintf("%2.ffps", fps);
            mRefreshRates.push_back(rate);
        }

        for (auto refreshRate : mRefreshRates) {
            ALOGV("type: %d, id: %d, name: %s", refreshRate.type, refreshRate.configId,
                  refreshRate.name.c_str());
        }
    }
    ~RefreshRateConfigs() = default;

    const std::vector<RefreshRate>& getRefreshRates() { return mRefreshRates; }

private:
    std::vector<RefreshRate> mRefreshRates;
};

} // namespace scheduler
} // namespace android