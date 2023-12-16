/*
 * Copyright 2023 The Android Open Source Project
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
#include <sys/types.h>

#include "SmallAreaDetectionAllowMappings.h"

namespace android::scheduler {
void SmallAreaDetectionAllowMappings::update(
        std::vector<std::pair<int32_t, float>>& appIdThresholdMappings) {
    std::lock_guard lock(mLock);
    mMap.clear();
    for (std::pair<int32_t, float> row : appIdThresholdMappings) {
        if (!isValidThreshold(row.second)) continue;

        mMap.emplace(row.first, row.second);
    }
}

void SmallAreaDetectionAllowMappings::setThresholdForAppId(int32_t appId, float threshold) {
    if (!isValidThreshold(threshold)) return;

    std::lock_guard lock(mLock);
    mMap.emplace(appId, threshold);
}

std::optional<float> SmallAreaDetectionAllowMappings::getThresholdForAppId(int32_t appId) {
    std::lock_guard lock(mLock);
    const auto iter = mMap.find(appId);
    if (iter != mMap.end()) {
        return iter->second;
    }
    return std::nullopt;
}
} // namespace android::scheduler
