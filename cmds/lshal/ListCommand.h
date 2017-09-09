/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef FRAMEWORK_NATIVE_CMDS_LSHAL_LIST_COMMAND_H_
#define FRAMEWORK_NATIVE_CMDS_LSHAL_LIST_COMMAND_H_

#include <stdint.h>

#include <fstream>
#include <string>
#include <vector>

#include <android-base/macros.h>
#include <android/hidl/manager/1.0/IServiceManager.h>

#include "Command.h"
#include "NullableOStream.h"
#include "TableEntry.h"
#include "TextTable.h"
#include "utils.h"

namespace android {
namespace lshal {

class Lshal;

struct PidInfo {
    std::map<uint64_t, Pids> refPids; // pids that are referenced
    uint32_t threadUsage; // number of threads in use
    uint32_t threadCount; // number of threads total
};

class ListCommand : public Command {
public:
    ListCommand(Lshal &lshal) : Command(lshal) {}
    virtual ~ListCommand() = default;
    Status main(const Arg &arg) override;
    void usage() const override;
protected:
    Status parseArgs(const Arg &arg);
    Status fetch();
    void postprocess();
    Status dump();
    void putEntry(TableEntrySource source, TableEntry &&entry);
    Status fetchPassthrough(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    Status fetchBinderized(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    Status fetchAllLibraries(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);

    virtual bool getPidInfo(pid_t serverPid, PidInfo *info) const;

    void dumpTable(const NullableOStream<std::ostream>& out) const;
    void dumpVintf(const NullableOStream<std::ostream>& out) const;
    void addLine(TextTable *table, const std::string &interfaceName, const std::string &transport,
                 const std::string &arch, const std::string &threadUsage, const std::string &server,
                 const std::string &serverCmdline, const std::string &address,
                 const std::string &clients, const std::string &clientCmdlines) const;
    void addLine(TextTable *table, const TableEntry &entry);
    // Read and return /proc/{pid}/cmdline.
    virtual std::string parseCmdline(pid_t pid) const;
    // Return /proc/{pid}/cmdline if it exists, else empty string.
    const std::string &getCmdline(pid_t pid);
    // Call getCmdline on all pid in pids. If it returns empty string, the process might
    // have died, and the pid is removed from pids.
    void removeDeadProcesses(Pids *pids);
    void forEachTable(const std::function<void(Table &)> &f);
    void forEachTable(const std::function<void(const Table &)> &f) const;

    NullableOStream<std::ostream> err() const;
    NullableOStream<std::ostream> out() const;

    Table mServicesTable{};
    Table mPassthroughRefTable{};
    Table mImplementationsTable{};

    std::string mFileOutputPath;
    TableEntryCompare mSortColumn = nullptr;

    bool mEmitDebugInfo = false;

    // If true, output in VINTF format.
    bool mVintf = false;

    // If true, explanatory text are not emitted.
    bool mNeat = false;

    // If an entry does not exist, need to ask /proc/{pid}/cmdline to get it.
    // If an entry exist but is an empty string, process might have died.
    // If an entry exist and not empty, it contains the cached content of /proc/{pid}/cmdline.
    std::map<pid_t, std::string> mCmdlines;

private:
    DISALLOW_COPY_AND_ASSIGN(ListCommand);
};


}  // namespace lshal
}  // namespace android

#endif  // FRAMEWORK_NATIVE_CMDS_LSHAL_LIST_COMMAND_H_
