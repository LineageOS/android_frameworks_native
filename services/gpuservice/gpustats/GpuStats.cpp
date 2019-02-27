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
#undef LOG_TAG
#define LOG_TAG "GpuStats"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "GpuStats.h"

#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/Trace.h>

#include <unordered_set>

namespace android {

using base::StringAppendF;

static bool addLoadingCount(GraphicsEnv::Driver driver, bool isDriverLoaded,
                            GpuStatsGlobalAtom* const outGlobalAtom) {
    switch (driver) {
        case GraphicsEnv::Driver::GL:
        case GraphicsEnv::Driver::GL_UPDATED:
            outGlobalAtom->glLoadingCount++;
            if (!isDriverLoaded) outGlobalAtom->glLoadingFailureCount++;
            break;
        case GraphicsEnv::Driver::VULKAN:
        case GraphicsEnv::Driver::VULKAN_UPDATED:
            outGlobalAtom->vkLoadingCount++;
            if (!isDriverLoaded) outGlobalAtom->vkLoadingFailureCount++;
            break;
        default:
            // Currently we don't support GraphicsEnv::Driver::ANGLE because the
            // basic driver package info only belongs to system or updated driver.
            return false;
    }

    return true;
}

static void addLoadingTime(GraphicsEnv::Driver driver, int64_t driverLoadingTime,
                           GpuStatsAppAtom* const outAppAtom) {
    switch (driver) {
        case GraphicsEnv::Driver::GL:
        case GraphicsEnv::Driver::GL_UPDATED:
            outAppAtom->glDriverLoadingTime.emplace_back(driverLoadingTime);
            break;
        case GraphicsEnv::Driver::VULKAN:
        case GraphicsEnv::Driver::VULKAN_UPDATED:
            outAppAtom->vkDriverLoadingTime.emplace_back(driverLoadingTime);
            break;
        default:
            break;
    }
}

void GpuStats::insert(const std::string& driverPackageName, const std::string& driverVersionName,
                      uint64_t driverVersionCode, int64_t driverBuildTime,
                      const std::string& appPackageName, GraphicsEnv::Driver driver,
                      bool isDriverLoaded, int64_t driverLoadingTime) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mLock);
    ALOGV("Received:\n"
          "\tdriverPackageName[%s]\n"
          "\tdriverVersionName[%s]\n"
          "\tdriverVersionCode[%" PRIu64 "]\n"
          "\tdriverBuildTime[%" PRId64 "]\n"
          "\tappPackageName[%s]\n"
          "\tdriver[%d]\n"
          "\tisDriverLoaded[%d]\n"
          "\tdriverLoadingTime[%" PRId64 "]",
          driverPackageName.c_str(), driverVersionName.c_str(), driverVersionCode, driverBuildTime,
          appPackageName.c_str(), static_cast<int32_t>(driver), isDriverLoaded, driverLoadingTime);

    if (!mGlobalStats.count(driverVersionCode)) {
        GpuStatsGlobalAtom globalAtom;
        if (!addLoadingCount(driver, isDriverLoaded, &globalAtom)) {
            return;
        }
        globalAtom.driverPackageName = driverPackageName;
        globalAtom.driverVersionName = driverVersionName;
        globalAtom.driverVersionCode = driverVersionCode;
        globalAtom.driverBuildTime = driverBuildTime;
        mGlobalStats.insert({driverVersionCode, globalAtom});
    } else if (!addLoadingCount(driver, isDriverLoaded, &mGlobalStats[driverVersionCode])) {
        return;
    }

    if (mAppStats.size() >= MAX_NUM_APP_RECORDS) {
        ALOGV("GpuStatsAppAtom has reached maximum size. Ignore new stats.");
        return;
    }

    const std::string appStatsKey = appPackageName + std::to_string(driverVersionCode);
    if (!mAppStats.count(appStatsKey)) {
        GpuStatsAppAtom appAtom;
        addLoadingTime(driver, driverLoadingTime, &appAtom);
        appAtom.appPackageName = appPackageName;
        appAtom.driverVersionCode = driverVersionCode;
        mAppStats.insert({appStatsKey, appAtom});
        return;
    }

    addLoadingTime(driver, driverLoadingTime, &mAppStats[appStatsKey]);
}

void GpuStats::dump(const Vector<String16>& args, std::string* result) {
    ATRACE_CALL();

    if (!result) {
        ALOGE("Dump result shouldn't be nullptr.");
        return;
    }

    std::lock_guard<std::mutex> lock(mLock);
    bool dumpAll = true;

    std::unordered_set<std::string> argsSet;
    for (size_t i = 0; i < args.size(); i++) {
        argsSet.insert(String8(args[i]).c_str());
    }

    const bool dumpGlobal = argsSet.count("--global") != 0;
    if (dumpGlobal) {
        dumpGlobalLocked(result);
        dumpAll = false;
    }

    const bool dumpApp = argsSet.count("--app") != 0;
    if (dumpApp) {
        dumpAppLocked(result);
        dumpAll = false;
    }

    if (argsSet.count("--clear")) {
        bool clearAll = true;

        if (dumpGlobal) {
            mGlobalStats.clear();
            clearAll = false;
        }

        if (dumpApp) {
            mAppStats.clear();
            clearAll = false;
        }

        if (clearAll) {
            mGlobalStats.clear();
            mAppStats.clear();
        }

        dumpAll = false;
    }

    if (dumpAll) {
        dumpGlobalLocked(result);
        dumpAppLocked(result);
    }
}

void GpuStats::dumpGlobalLocked(std::string* result) {
    result->append("GpuStats global:\n");

    for (const auto& ele : mGlobalStats) {
        StringAppendF(result, "  driverPackageName = %s\n", ele.second.driverPackageName.c_str());
        StringAppendF(result, "  driverVersionName = %s\n", ele.second.driverVersionName.c_str());
        StringAppendF(result, "  driverVersionCode = %" PRIu64 "\n", ele.second.driverVersionCode);
        StringAppendF(result, "  driverBuildTime = %" PRId64 "\n", ele.second.driverBuildTime);
        StringAppendF(result, "  glLoadingCount = %d\n", ele.second.glLoadingCount);
        StringAppendF(result, "  glLoadingFailureCount = %d\n", ele.second.glLoadingFailureCount);
        StringAppendF(result, "  vkLoadingCount = %d\n", ele.second.vkLoadingCount);
        StringAppendF(result, "  vkLoadingFailureCount = %d\n", ele.second.vkLoadingFailureCount);
        result->append("\n");
    }
}

void GpuStats::dumpAppLocked(std::string* result) {
    result->append("GpuStats app:\n");

    for (const auto& ele : mAppStats) {
        StringAppendF(result, "  appPackageName = %s\n", ele.second.appPackageName.c_str());
        StringAppendF(result, "  driverVersionCode = %" PRIu64 "\n", ele.second.driverVersionCode);

        result->append("  glDriverLoadingTime:");
        for (int32_t loadingTime : ele.second.glDriverLoadingTime) {
            StringAppendF(result, " %d", loadingTime);
        }
        result->append("\n");

        result->append("  vkDriverLoadingTime:");
        for (int32_t loadingTime : ele.second.vkDriverLoadingTime) {
            StringAppendF(result, " %d", loadingTime);
        }
        result->append("\n\n");
    }
}

} // namespace android
