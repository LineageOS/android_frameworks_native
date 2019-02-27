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

#include <mutex>
#include <unordered_map>
#include <vector>

#include <graphicsenv/GpuStatsAtoms.h>
#include <graphicsenv/GraphicsEnv.h>
#include <utils/String16.h>
#include <utils/Vector.h>

namespace android {

class GpuStats {
public:
    GpuStats() = default;
    ~GpuStats() = default;

    // Insert new gpu stats into global stats and app stats.
    void insert(const std::string& driverPackageName, const std::string& driverVersionName,
                uint64_t driverVersionCode, int64_t driverBuildTime,
                const std::string& appPackageName, GraphicsEnv::Driver driver, bool isDriverLoaded,
                int64_t driverLoadingTime);
    // dumpsys interface
    void dump(const Vector<String16>& args, std::string* result);

private:
    // Dump global stats
    void dumpGlobalLocked(std::string* result);
    // Dump app stats
    void dumpAppLocked(std::string* result);

    // This limits the memory usage of GpuStats to be less than 30KB. This is
    // the maximum atom size statsd could afford.
    static const size_t MAX_NUM_APP_RECORDS = 300;
    // GpuStats access should be guarded by mLock.
    std::mutex mLock;
    // Key is driver version code.
    std::unordered_map<uint64_t, GpuStatsGlobalAtom> mGlobalStats;
    // Key is <app package name>+<driver version code>.
    std::unordered_map<std::string, GpuStatsAppAtom> mAppStats;
};

} // namespace android
