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

#include "GpuService.h"

#include <android-base/stringprintf.h>
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/Parcel.h>
#include <binder/PermissionCache.h>
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>
#include <utils/String8.h>
#include <utils/Trace.h>

#include <array>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <vkjson.h>
#include <unistd.h>

#include "gpustats/GpuStats.h"

namespace android {

using base::StringAppendF;

namespace {
status_t cmdHelp(int out);
status_t cmdVkjson(int out, int err);
void dumpGameDriverInfo(std::string* result);
void dumpMemoryInfo(std::string* result, const GpuMemoryMap& memories, uint32_t pid);
} // namespace

const String16 sDump("android.permission.DUMP");

const char* const GpuService::SERVICE_NAME = "gpu";

GpuService::GpuService() : mGpuStats(std::make_unique<GpuStats>()){};

void GpuService::setGpuStats(const std::string& driverPackageName,
                             const std::string& driverVersionName, uint64_t driverVersionCode,
                             int64_t driverBuildTime, const std::string& appPackageName,
                             const int32_t vulkanVersion, GpuStatsInfo::Driver driver,
                             bool isDriverLoaded, int64_t driverLoadingTime) {
    mGpuStats->insert(driverPackageName, driverVersionName, driverVersionCode, driverBuildTime,
                      appPackageName, vulkanVersion, driver, isDriverLoaded, driverLoadingTime);
}

status_t GpuService::getGpuStatsGlobalInfo(std::vector<GpuStatsGlobalInfo>* outStats) const {
    mGpuStats->pullGlobalStats(outStats);
    return OK;
}

status_t GpuService::getGpuStatsAppInfo(std::vector<GpuStatsAppInfo>* outStats) const {
    mGpuStats->pullAppStats(outStats);
    return OK;
}

void GpuService::setTargetStats(const std::string& appPackageName, const uint64_t driverVersionCode,
                                const GpuStatsInfo::Stats stats, const uint64_t value) {
    mGpuStats->insertTargetStats(appPackageName, driverVersionCode, stats, value);
}

bool isExpectedFormat(const char* str) {
    // Should match in order:
    // gpuaddr useraddr size id flags type usage sglen mapsize eglsrf eglimg
    std::istringstream iss;
    iss.str(str);

    std::string word;
    iss >> word;
    if (word != "gpuaddr") { return false; }
    iss >> word;
    if (word != "useraddr") { return false; }
    iss >> word;
    if (word != "size") { return false; }
    iss >> word;
    if (word != "id") { return false; }
    iss >> word;
    if (word != "flags") { return false; }
    iss >> word;
    if (word != "type") { return false; }
    iss >> word;
    if (word != "usage") { return false; }
    iss >> word;
    if (word != "sglen") { return false; }
    iss >> word;
    if (word != "mapsize") { return false; }
    iss >> word;
    if (word != "eglsrf") { return false; }
    iss >> word;
    if (word != "eglimg") { return false; }
    return true;
}


// Queries gpu memory via Qualcomm's /d/kgsl/proc/*/mem interface.
status_t GpuService::getQCommGpuMemoryInfo(GpuMemoryMap* memories, std::string* result, int32_t dumpPid) const {
    const std::string kDirectoryPath = "/d/kgsl/proc";
    DIR* directory = opendir(kDirectoryPath.c_str());
    if (!directory) { return PERMISSION_DENIED; }

    // File Format:
    //          gpuaddr         useraddr     size id     flags   type          usage sglen mapsize eglsrf eglimg
    // 0000000000000000 0000000000000000  8359936 23 --w--pY-- gpumem VK/others( 38)     0       0      0      0
    // 0000000000000000 0000000000000000 16293888 24 --wL--N--    ion        surface    41       0      0      1

    const bool dumpAll = dumpPid == 0;
    static constexpr size_t kMaxLineLength = 1024;
    static char line[kMaxLineLength];
    while(dirent* subdir = readdir(directory)) {
        // Skip "." and ".." in directory.
        if (strcmp(subdir->d_name, ".") == 0 || strcmp(subdir->d_name, "..") == 0 ) { continue; }

        std::string pid_str(subdir->d_name);
        const uint32_t pid(stoi(pid_str));

        if (!dumpAll && dumpPid != pid) {
            continue;
        }

        std::string filepath(kDirectoryPath + "/" + pid_str + "/mem");
        std::ifstream file(filepath);

        // Check first line
        file.getline(line, kMaxLineLength);
        if (!isExpectedFormat(line)) {
            continue;
        }

        if (result) {
            StringAppendF(result, "%d:\n%s\n", pid, line);
        }

        while( file.getline(line, kMaxLineLength) ) {
            if (result) {
                StringAppendF(result, "%s\n", line);
            }

            std::istringstream iss;
            iss.str(line);

            // Skip gpuaddr, useraddr.
            const char delimiter = ' ';
            iss >> std::ws;
            iss.ignore(kMaxLineLength, delimiter);
            iss >> std::ws;
            iss.ignore(kMaxLineLength, delimiter);

            // Get size.
            int64_t memsize;
            iss >> memsize;

            // Skip id, flags.
            iss >> std::ws;
            iss.ignore(kMaxLineLength, delimiter);
            iss >> std::ws;
            iss.ignore(kMaxLineLength, delimiter);

            // Get type, usage.
            std::string memtype;
            std::string usage;
            iss >> memtype >> usage;

            // Adjust for the space in VK/others( #)
            if (usage == "VK/others(") {
              std::string vkTypeEnd;
              iss >> vkTypeEnd;
              usage.append(vkTypeEnd);
            }

            // Skip sglen.
            iss >> std::ws;
            iss.ignore(kMaxLineLength, delimiter);

            // Get mapsize.
            int64_t mapsize;
            iss >> mapsize;

            if (memsize == 0 && mapsize == 0) {
                continue;
            }

            if (memtype == "gpumem") {
                (*memories)[pid][usage].gpuMemory += memsize;
            } else {
                (*memories)[pid][usage].ionMemory += memsize;
            }

            if (mapsize > 0) {
                (*memories)[pid][usage].mappedMemory += mapsize;
            }
        }

        if (result) {
            StringAppendF(result, "\n");
        }
    }

    closedir(directory);

    return OK;
}

status_t GpuService::shellCommand(int /*in*/, int out, int err, std::vector<String16>& args) {
    ATRACE_CALL();

    ALOGV("shellCommand");
    for (size_t i = 0, n = args.size(); i < n; i++)
        ALOGV("  arg[%zu]: '%s'", i, String8(args[i]).string());

    if (args.size() >= 1) {
        if (args[0] == String16("vkjson")) return cmdVkjson(out, err);
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
        bool dumpStats = false;
        bool dumpMemory = false;
        size_t numArgs = args.size();
        int32_t pid = 0;

        if (numArgs) {
            dumpAll = false;
            for (size_t index = 0; index < numArgs; ++index) {
                if (args[index] == String16("--gpustats")) {
                    dumpStats = true;
                } else if (args[index] == String16("--gpudriverinfo")) {
                    dumpDriverInfo = true;
                } else if (args[index] == String16("--gpumem")) {
                    dumpMemory = true;
                } else if (args[index].compare(String16("--gpumem=")) > 0) {
                    dumpMemory = true;
                    pid = atoi(String8(&args[index][9]));
                }
            }
        }

        if (dumpAll || dumpDriverInfo) {
            dumpGameDriverInfo(&result);
            result.append("\n");
        }
        if (dumpAll || dumpStats) {
            mGpuStats->dump(Vector<String16>(), &result);
            result.append("\n");
        }
        if (dumpAll || dumpMemory) {
            GpuMemoryMap memories;
            // Currently only queries Qualcomm gpu memory. More will be added later.
            if (getQCommGpuMemoryInfo(&memories, &result, pid) == OK) {
                dumpMemoryInfo(&result, memories, pid);
                result.append("\n");
            }
        }
    }

    write(fd, result.c_str(), result.size());
    return NO_ERROR;
}

namespace {

status_t cmdHelp(int out) {
    FILE* outs = fdopen(out, "w");
    if (!outs) {
        ALOGE("vkjson: failed to create out stream: %s (%d)", strerror(errno), errno);
        return BAD_VALUE;
    }
    fprintf(outs,
            "GPU Service commands:\n"
            "  vkjson   dump Vulkan properties as JSON\n");
    fclose(outs);
    return NO_ERROR;
}

void vkjsonPrint(FILE* out) {
    std::string json = VkJsonInstanceToJson(VkJsonGetInstance());
    fwrite(json.data(), 1, json.size(), out);
    fputc('\n', out);
}

status_t cmdVkjson(int out, int /*err*/) {
    FILE* outs = fdopen(out, "w");
    if (!outs) {
        int errnum = errno;
        ALOGE("vkjson: failed to create output stream: %s", strerror(errnum));
        return -errnum;
    }
    vkjsonPrint(outs);
    fclose(outs);
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

// Read and print all memory info for each process from /d/kgsl/proc/<pid>/mem.
void dumpMemoryInfo(std::string* result, const GpuMemoryMap& memories, uint32_t pid) {
    if (!result) return;

    // Write results.
    StringAppendF(result, "GPU Memory Summary:\n");
    for(auto& mem : memories) {
        uint32_t process = mem.first;
        if (pid != 0 && pid != process) {
            continue;
        }

        StringAppendF(result, "%d:\n", process);
        for(auto& memStruct : mem.second) {
            StringAppendF(result, "  %s", memStruct.first.c_str());

            if(memStruct.second.gpuMemory > 0)
                StringAppendF(result, ", GPU memory = %" PRId64, memStruct.second.gpuMemory);
            if(memStruct.second.mappedMemory > 0)
                StringAppendF(result, ", Mapped memory = %" PRId64, memStruct.second.mappedMemory);
            if(memStruct.second.ionMemory > 0)
                StringAppendF(result, ", Ion memory = %" PRId64, memStruct.second.ionMemory);

            StringAppendF(result, "\n");
        }
    }
}

} // anonymous namespace

} // namespace android
