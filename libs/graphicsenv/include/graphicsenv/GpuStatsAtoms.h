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

#include <string>
#include <vector>

namespace android {

struct GpuStatsGlobalAtom {
    std::string driverPackageName = "";
    std::string driverVersionName = "";
    uint64_t driverVersionCode = 0;
    int64_t driverBuildTime = 0;
    int32_t glLoadingCount = 0;
    int32_t glLoadingFailureCount = 0;
    int32_t vkLoadingCount = 0;
    int32_t vkLoadingFailureCount = 0;
};

struct GpuStatsAppAtom {
    std::string appPackageName = "";
    uint64_t driverVersionCode = 0;
    std::vector<int64_t> glDriverLoadingTime = {};
    std::vector<int64_t> vkDriverLoadingTime = {};
};

} // namespace android
