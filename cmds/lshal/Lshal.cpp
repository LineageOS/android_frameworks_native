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

#include "Lshal.h"

#include <getopt.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <regex>

#include <android-base/parseint.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>

using ::android::hardware::hidl_string;
using ::android::hidl::manager::V1_0::IServiceManager;

namespace android {
namespace lshal {

template <typename A, typename C, typename D, typename E, typename F>
void printColumn(std::ostream &stream,
        const A &a, const C &c, const D &d, const E &, const F &f) {
    using namespace ::std;
    stream << left
           << setw(80) << a << "\t"
           << setw(10) << c << "\t"
           << setw(5)  << d << "\t"
           // TODO(b/34984175): enable selecting columns
           // << setw(16) << e << "\t"
           << setw(0)  << f
           << endl;
}

template <typename A>
std::string join(const A &components, const std::string &separator) {
    std::stringstream out;
    bool first = true;
    for (const auto &component : components) {
        if (!first) {
            out << separator;
        }
        out << component;

        first = false;
    }
    return out.str();
}

static std::string toHexString(uint64_t t) {
    std::ostringstream os;
    os << std::hex << std::setfill('0') << std::setw(16) << t;
    return os.str();
}

static std::pair<hidl_string, hidl_string> split(const hidl_string &s, char c) {
    const char *pos = strchr(s.c_str(), c);
    if (pos == nullptr) {
        return {s, {}};
    }
    return {hidl_string(s.c_str(), pos - s.c_str()), hidl_string(pos + 1)};
}

static std::vector<std::string> split(const std::string &s, char c) {
    std::vector<std::string> components{};
    size_t startPos = 0;
    size_t matchPos;
    while ((matchPos = s.find(c, startPos)) != std::string::npos) {
        components.push_back(s.substr(startPos, matchPos - startPos));
        startPos = matchPos + 1;
    }

    if (startPos <= s.length()) {
        components.push_back(s.substr(startPos));
    }
    return components;
}

bool Lshal::getReferencedPids(
        pid_t serverPid, std::map<uint64_t, Pids> *objects) const {

    std::ifstream ifs("/d/binder/proc/" + std::to_string(serverPid));
    if (!ifs.is_open()) {
        return false;
    }

    static const std::regex prefix("^\\s*node \\d+:\\s+u([0-9a-f]+)\\s+c([0-9a-f]+)\\s+");

    std::string line;
    std::smatch match;
    while(getline(ifs, line)) {
        if (!std::regex_search(line, match, prefix)) {
            // the line doesn't start with the correct prefix
            continue;
        }
        std::string ptrString = "0x" + match.str(2); // use number after c
        uint64_t ptr;
        if (!::android::base::ParseUint(ptrString.c_str(), &ptr)) {
            // Should not reach here, but just be tolerant.
            mErr << "Could not parse number " << ptrString << std::endl;
            continue;
        }
        const std::string proc = " proc ";
        auto pos = line.rfind(proc);
        if (pos != std::string::npos) {
            for (const std::string &pidStr : split(line.substr(pos + proc.size()), ' ')) {
                int32_t pid;
                if (!::android::base::ParseInt(pidStr, &pid)) {
                    mErr << "Could not parse number " << pidStr << std::endl;
                    continue;
                }
                (*objects)[ptr].push_back(pid);
            }
        }
    }
    return true;
}

void Lshal::dump() const {
    mOut << "All services:" << std::endl;
    printColumn(mOut, "Interface", "Transport", "Server", "PTR", "Clients");
    for (const auto &entry : mTable) {
        printColumn(mOut, entry.interfaceName,
                entry.transport,
                entry.serverPid == NO_PID ? "N/A" : std::to_string(entry.serverPid),
                entry.serverObjectAddress == NO_PTR ? "N/A" : toHexString(entry.serverObjectAddress),
                join(entry.clientPids, " "));
    }
}

void Lshal::putEntry(TableEntry &&entry) {
    mTable.push_back(std::forward<TableEntry>(entry));
}

Status Lshal::fetchAllLibraries(const sp<IServiceManager> &manager) {
    using namespace ::android::hardware;
    using namespace ::android::hidl::manager::V1_0;
    using namespace ::android::hidl::base::V1_0;
    auto ret = manager->list([&] (const auto &fqInstanceNames) {
        for (const auto &fqInstanceName : fqInstanceNames) {
            putEntry({
                .interfaceName = fqInstanceName,
                .transport = "passthrough",
                .serverPid = NO_PID,
                .serverObjectAddress = NO_PTR,
                .clientPids = {}
            });
        }
    });
    if (!ret.isOk()) {
        mErr << "Error: Failed to call list on getPassthroughServiceManager(): "
             << ret.description() << std::endl;
        return DUMP_ALL_LIBS_ERROR;
    }
    return OK;
}

Status Lshal::fetchPassthrough(const sp<IServiceManager> &manager) {
    using namespace ::android::hardware;
    using namespace ::android::hidl::manager::V1_0;
    using namespace ::android::hidl::base::V1_0;
    auto ret = manager->debugDump([&] (const auto &infos) {
        for (const auto &info : infos) {
            putEntry({
                .interfaceName =
                        std::string{info.interfaceName.c_str()} + "/" +
                        std::string{info.instanceName.c_str()},
                .transport = "passthrough",
                .serverPid = info.clientPids.size() == 1 ? info.clientPids[0] : NO_PID,
                .serverObjectAddress = NO_PTR,
                .clientPids = info.clientPids
            });
        }
    });
    if (!ret.isOk()) {
        mErr << "Error: Failed to call debugDump on defaultServiceManager(): "
             << ret.description() << std::endl;
        return DUMP_PASSTHROUGH_ERROR;
    }
    return OK;
}

Status Lshal::fetchBinderized(const sp<IServiceManager> &manager) {
    using namespace ::std;
    using namespace ::android::hardware;
    using namespace ::android::hidl::manager::V1_0;
    using namespace ::android::hidl::base::V1_0;
    const std::string mode = "hwbinder";
    Status status = OK;
    auto listRet = manager->list([&] (const auto &fqInstanceNames) {
        // server pid, .ptr value of binder object, child pids
        std::map<std::string, DebugInfo> allDebugInfos;
        std::map<pid_t, std::map<uint64_t, Pids>> allPids;
        for (const auto &fqInstanceName : fqInstanceNames) {
            const auto pair = split(fqInstanceName, '/');
            const auto &serviceName = pair.first;
            const auto &instanceName = pair.second;
            auto getRet = manager->get(serviceName, instanceName);
            if (!getRet.isOk()) {
                mErr << "Warning: Skipping \"" << fqInstanceName << "\": "
                     << "cannot be fetched from service manager:"
                     << getRet.description() << std::endl;
                status |= DUMP_BINDERIZED_ERROR;
                continue;
            }
            sp<IBase> service = getRet;
            if (service == nullptr) {
                mErr << "Warning: Skipping \"" << fqInstanceName << "\": "
                     << "cannot be fetched from service manager (null)";
                status |= DUMP_BINDERIZED_ERROR;
                continue;
            }
            auto debugRet = service->getDebugInfo([&] (const auto &debugInfo) {
                allDebugInfos[fqInstanceName] = debugInfo;
                if (debugInfo.pid >= 0) {
                    allPids[static_cast<pid_t>(debugInfo.pid)].clear();
                }
            });
            if (!debugRet.isOk()) {
                mErr << "Warning: Skipping \"" << fqInstanceName << "\": "
                     << "debugging information cannot be retrieved:"
                     << debugRet.description() << std::endl;
                status |= DUMP_BINDERIZED_ERROR;
            }
        }
        for (auto &pair : allPids) {
            pid_t serverPid = pair.first;
            if (!getReferencedPids(serverPid, &allPids[serverPid])) {
                mErr << "Warning: no information for PID " << serverPid
                          << ", are you root?" << std::endl;
                status |= DUMP_BINDERIZED_ERROR;
            }
        }
        for (const auto &fqInstanceName : fqInstanceNames) {
            auto it = allDebugInfos.find(fqInstanceName);
            if (it == allDebugInfos.end()) {
                putEntry({
                    .interfaceName = fqInstanceName,
                    .transport = mode,
                    .serverPid = NO_PID,
                    .serverObjectAddress = NO_PTR,
                    .clientPids = {}
                });
                continue;
            }
            const DebugInfo &info = it->second;
            putEntry({
                .interfaceName = fqInstanceName,
                .transport = mode,
                .serverPid = info.pid,
                .serverObjectAddress = info.ptr,
                .clientPids = info.pid == NO_PID || info.ptr == NO_PTR
                        ? Pids{} : allPids[info.pid][info.ptr]
            });
        }

    });
    if (!listRet.isOk()) {
        mErr << "Error: Failed to list services for " << mode << ": "
             << listRet.description() << std::endl;
        status |= DUMP_BINDERIZED_ERROR;
    }
    return status;
}

Status Lshal::fetch() {
    Status status = OK;
    auto bManager = ::android::hardware::defaultServiceManager();
    if (bManager == nullptr) {
        mErr << "Failed to get defaultServiceManager()!" << std::endl;
        status |= NO_BINDERIZED_MANAGER;
    } else {
        status |= fetchBinderized(bManager);
        // Passthrough PIDs are registered to the binderized manager as well.
        status |= fetchPassthrough(bManager);
    }

    auto pManager = ::android::hardware::getPassthroughServiceManager();
    if (pManager == nullptr) {
        mErr << "Failed to get getPassthroughServiceManager()!" << std::endl;
        status |= NO_PASSTHROUGH_MANAGER;
    } else {
        status |= fetchAllLibraries(pManager);
    }
    return status;
}

void Lshal::usage() const {
    mErr
        << "usage: lshal" << std::endl
        << "           To dump all hals." << std::endl
        << "or:" << std::endl
        << "       lshal [-h|--help]" << std::endl
        << "           -h, --help: show this help information." << std::endl;
}

Status Lshal::parseArgs(int argc, char **argv) {
    static struct option longOptions[] = {
        {"help", no_argument, 0, 'h' },
        { 0,               0, 0,  0  }
    };

    int optionIndex;
    int c;
    optind = 1;
    for (;;) {
        // using getopt_long in case we want to add other options in the future
        c = getopt_long(argc, argv, "h", longOptions, &optionIndex);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'h': // falls through
        default: // see unrecognized options
            usage();
            return USAGE;
        }
    }
    return OK;
}

int Lshal::main(int argc, char **argv) {
    Status status = parseArgs(argc, argv);
    if (status != OK) {
        return status;
    }
    status = fetch();
    dump();
    return status;
}

}  // namespace lshal
}  // namespace android

int main(int argc, char **argv) {
    return ::android::lshal::Lshal{}.main(argc, argv);
}
