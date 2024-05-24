/*
 * Copyright 2016 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "gpuservice/GpuService.h"

#include <android-base/stringprintf.h>
#include <android-base/properties.h>
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/Parcel.h>
#include <binder/PermissionCache.h>
#include <cutils/properties.h>
#include <gpumem/GpuMem.h>
#include <gpuwork/GpuWork.h>
#include <gpustats/GpuStats.h>
#include <private/android_filesystem_config.h>
#include <tracing/GpuMemTracer.h>
#include <utils/String8.h>
#include <utils/Trace.h>
#include <vkjson.h>
#include <vkprofiles.h>

#include <thread>
#include <memory>

namespace android {

using base::StringAppendF;

namespace {
status_t cmdHelp(int out);
status_t cmdVkjson(int out, int err);
status_t cmdVkprofiles(int out, int err);
void dumpGameDriverInfo(std::string* result);
} // namespace

const String16 sDump("android.permission.DUMP");
const String16 sAccessGpuServicePermission("android.permission.ACCESS_GPU_SERVICE");
const std::string sAngleGlesDriverSuffix = "angle";

const char* const GpuService::SERVICE_NAME = "gpu";

GpuService::GpuService()
      : mGpuMem(std::make_shared<GpuMem>()),
        mGpuWork(std::make_shared<gpuwork::GpuWork>()),
        mGpuStats(std::make_unique<GpuStats>()),
        mGpuMemTracer(std::make_unique<GpuMemTracer>()) {

    mGpuMemAsyncInitThread = std::make_unique<std::thread>([this] (){
        mGpuMem->initialize();
        mGpuMemTracer->initialize(mGpuMem);
    });

    mGpuWorkAsyncInitThread = std::make_unique<std::thread>([this]() {
        mGpuWork->initialize();
    });
};

GpuService::~GpuService() {
    mGpuMem->stop();
    mGpuWork->stop();

    mGpuWorkAsyncInitThread->join();
    mGpuMemAsyncInitThread->join();
}

void GpuService::setGpuStats(const std::string& driverPackageName,
                             const std::string& driverVersionName, uint64_t driverVersionCode,
                             int64_t driverBuildTime, const std::string& appPackageName,
                             const int32_t vulkanVersion, GpuStatsInfo::Driver driver,
                             bool isDriverLoaded, int64_t driverLoadingTime) {
    mGpuStats->insertDriverStats(driverPackageName, driverVersionName, driverVersionCode,
                                 driverBuildTime, appPackageName, vulkanVersion, driver,
                                 isDriverLoaded, driverLoadingTime);
}

void GpuService::setTargetStats(const std::string& appPackageName, const uint64_t driverVersionCode,
                                const GpuStatsInfo::Stats stats, const uint64_t value) {
    mGpuStats->insertTargetStats(appPackageName, driverVersionCode, stats, value);
}

void GpuService::setTargetStatsArray(const std::string& appPackageName,
                                const uint64_t driverVersionCode, const GpuStatsInfo::Stats stats,
                                const uint64_t* values, const uint32_t valueCount) {
    mGpuStats->insertTargetStatsArray(appPackageName, driverVersionCode, stats, values, valueCount);
}

void GpuService::toggleAngleAsSystemDriver(bool enabled) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();

    // only system_server with the ACCESS_GPU_SERVICE permission is allowed to set
    // persist.graphics.egl
    if (uid != AID_SYSTEM ||
        !PermissionCache::checkPermission(sAccessGpuServicePermission, pid, uid)) {
        ALOGE("Permission Denial: can't set persist.graphics.egl from setAngleAsSystemDriver() "
                "pid=%d, uid=%d\n", pid, uid);
        return;
    }

    std::lock_guard<std::mutex> lock(mLock);
    if (enabled) {
        android::base::SetProperty("persist.graphics.egl", sAngleGlesDriverSuffix);
    } else {
        android::base::SetProperty("persist.graphics.egl", "");
    }
}


void GpuService::setUpdatableDriverPath(const std::string& driverPath) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();

    // only system_server is allowed to set updatable driver path
    if (uid != AID_SYSTEM) {
        ALOGE("Permission Denial: can't set updatable driver path from pid=%d, uid=%d\n", pid, uid);
        return;
    }

    std::lock_guard<std::mutex> lock(mLock);
    mDeveloperDriverPath = driverPath;
}

std::string GpuService::getUpdatableDriverPath() {
    std::lock_guard<std::mutex> lock(mLock);
    return mDeveloperDriverPath;
}

status_t GpuService::shellCommand(int /*in*/, int out, int err, std::vector<String16>& args) {
    ATRACE_CALL();

    ALOGV("shellCommand");
    for (size_t i = 0, n = args.size(); i < n; i++)
        ALOGV("  arg[%zu]: '%s'", i, String8(args[i]).c_str());

    if (args.size() >= 1) {
        if (args[0] == String16("vkjson")) return cmdVkjson(out, err);
        if (args[0] == String16("vkprofiles")) return cmdVkprofiles(out, err);
        if (args[0] == String16("help")) return cmdHelp(out);
    }
    // no command, or unrecognized command
    cmdHelp(err);
    return BAD_VALUE;
}

status_t GpuService::doDump(int fd, const Vector<String16>& args, bool /*asProto*/) {
    std::string result;

    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();

    if ((uid != AID_SHELL) && !PermissionCache::checkPermission(sDump, pid, uid)) {
        StringAppendF(&result, "Permission Denial: can't dump gpu from pid=%d, uid=%d\n", pid, uid);
    } else {
        bool dumpAll = true;
        bool dumpDriverInfo = false;
        bool dumpMem = false;
        bool dumpStats = false;
        bool dumpWork = false;
        size_t numArgs = args.size();

        if (numArgs) {
            for (size_t index = 0; index < numArgs; ++index) {
                if (args[index] == String16("--gpustats")) {
                    dumpStats = true;
                } else if (args[index] == String16("--gpudriverinfo")) {
                    dumpDriverInfo = true;
                } else if (args[index] == String16("--gpumem")) {
                    dumpMem = true;
                } else if (args[index] == String16("--gpuwork")) {
                    dumpWork = true;
                }
            }
            dumpAll = !(dumpDriverInfo || dumpMem || dumpStats || dumpWork);
        }

        if (dumpAll || dumpDriverInfo) {
            dumpGameDriverInfo(&result);
            result.append("\n");
        }
        if (dumpAll || dumpMem) {
            mGpuMem->dump(args, &result);
            result.append("\n");
        }
        if (dumpAll || dumpStats) {
            mGpuStats->dump(args, &result);
            result.append("\n");
        }
         if (dumpAll || dumpWork) {
            mGpuWork->dump(args, &result);
            result.append("\n");
        }
    }

    write(fd, result.c_str(), result.size());
    return NO_ERROR;
}

namespace {

status_t cmdHelp(int out) {
    FILE* outs = fdopen(out, "w");
    if (!outs) {
        ALOGE("gpuservice: failed to create out stream: %s (%d)", strerror(errno), errno);
        return BAD_VALUE;
    }
    fprintf(outs,
            "GPU Service commands:\n"
            "  vkjson      dump Vulkan properties as JSON\n"
            "  vkprofiles  print support for select Vulkan profiles\n");
    fclose(outs);
    return NO_ERROR;
}

status_t cmdVkjson(int out, int /*err*/) {
    dprintf(out, "%s\n", VkJsonInstanceToJson(VkJsonGetInstance()).c_str());
    return NO_ERROR;
}

status_t cmdVkprofiles(int out, int /*err*/) {
    dprintf(out, "%s\n", android::vkprofiles::vkProfiles().c_str());
    return NO_ERROR;
}

void dumpGameDriverInfo(std::string* result) {
    if (!result) return;

    char stableGameDriver[PROPERTY_VALUE_MAX] = {};
    property_get("ro.gfx.driver.0", stableGameDriver, "unsupported");
    StringAppendF(result, "Stable Game Driver: %s\n", stableGameDriver);

    char preReleaseGameDriver[PROPERTY_VALUE_MAX] = {};
    property_get("ro.gfx.driver.1", preReleaseGameDriver, "unsupported");
    StringAppendF(result, "Pre-release Game Driver: %s\n", preReleaseGameDriver);
}

} // anonymous namespace

} // namespace android
