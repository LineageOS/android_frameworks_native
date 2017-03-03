/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef FRAMEWORK_NATIVE_CMDS_LSHAL_LSHAL_H_
#define FRAMEWORK_NATIVE_CMDS_LSHAL_LSHAL_H_

#include <stdint.h>

#include <fstream>
#include <string>
#include <vector>

#include <android/hidl/manager/1.0/IServiceManager.h>

#include "NullableOStream.h"
#include "TableEntry.h"

namespace android {
namespace lshal {

enum : unsigned int {
    OK                                      = 0,
    USAGE                                   = 1 << 0,
    NO_BINDERIZED_MANAGER                   = 1 << 1,
    NO_PASSTHROUGH_MANAGER                  = 1 << 2,
    DUMP_BINDERIZED_ERROR                   = 1 << 3,
    DUMP_PASSTHROUGH_ERROR                  = 1 << 4,
    DUMP_ALL_LIBS_ERROR                     = 1 << 5,
    IO_ERROR                                = 1 << 6,
};
using Status = unsigned int;

class Lshal {
public:
    int main(int argc, char **argv);

private:
    Status parseArgs(int argc, char **argv);
    Status fetch();
    void postprocess();
    void dump();
    void usage() const;
    void putEntry(TableEntry &&entry);
    Status fetchPassthrough(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    Status fetchBinderized(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    Status fetchAllLibraries(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    bool getReferencedPids(
        pid_t serverPid, std::map<uint64_t, Pids> *objects) const;
    void dumpTable() const;
    void dumpVintf() const;
    void printLine(
            const std::string &interfaceName,
            const std::string &transport,
            const std::string &arch,
            const std::string &server,
            const std::string &serverCmdline,
            const std::string &address, const std::string &clients,
            const std::string &clientCmdlines) const ;
    // Return /proc/{pid}/cmdline if it exists, else empty string.
    const std::string &getCmdline(pid_t pid);
    // Call getCmdline on all pid in pids. If it returns empty string, the process might
    // have died, and the pid is removed from pids.
    void removeDeadProcesses(Pids *pids);

    Table mTable{};
    NullableOStream<std::ostream> mErr = std::cerr;
    NullableOStream<std::ostream> mOut = std::cout;
    NullableOStream<std::ofstream> mFileOutput = nullptr;
    TableEntryCompare mSortColumn = nullptr;
    TableEntrySelect mSelectedColumns = 0;
    // If true, cmdlines will be printed instead of pid.
    bool mEnableCmdlines = false;
    bool mVintf = false;
    // If an entry does not exist, need to ask /proc/{pid}/cmdline to get it.
    // If an entry exist but is an empty string, process might have died.
    // If an entry exist and not empty, it contains the cached content of /proc/{pid}/cmdline.
    std::map<pid_t, std::string> mCmdlines;
};


}  // namespace lshal
}  // namespace android

#endif  // FRAMEWORK_NATIVE_CMDS_LSHAL_LSHAL_H_
