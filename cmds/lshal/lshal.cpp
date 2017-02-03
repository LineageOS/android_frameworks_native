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


#include <getopt.h>

#include <map>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <regex>

#include <android-base/parseint.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>

using ::android::hardware::hidl_string;

template <typename A, typename B, typename C, typename D, typename E, typename F>
void printColumn(std::stringstream &stream,
        const A &a, const B &b, const C &c, const D &d, const E &, const F &f) {
    using namespace ::std;
    stream << left
           << setw(70) << a << "\t"
           << setw(20) << b << "\t"
           << setw(10) << c << "\t"
           << setw(5)  << d << "\t"
           // TODO(b/34984175): enable selecting columns
           // << setw(16) << e << "\t"
           << setw(0)  << f
           << endl;
}

std::string toHexString(uint64_t t) {
    std::ostringstream os;
    os << std::hex << std::setfill('0') << std::setw(16) << t;
    return os.str();
}

std::pair<hidl_string, hidl_string> split(const hidl_string &s, char c) {
    const char *pos = strchr(s.c_str(), c);
    if (pos == nullptr) {
        return {s, {}};
    }
    return {hidl_string(s.c_str(), pos - s.c_str()), hidl_string(pos + 1)};
}

bool getReferencedPids(
        pid_t serverPid, std::map<uint64_t, std::string> *objects) {

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
            std::cerr << "Could not parse number " << ptrString << std::endl;
            continue;
        }
        const std::string proc = " proc ";
        auto pos = line.rfind(proc);
        if (pos != std::string::npos) {
            (*objects)[ptr] += line.substr(pos + proc.size());
        }
    }
    return true;
}

void dumpBinderized(std::stringstream &stream, const std::string &mode,
            const sp<IServiceManager> &manager) {
    using namespace ::std;
    using namespace ::android::hardware;
    using namespace ::android::hidl::manager::V1_0;
    using namespace ::android::hidl::base::V1_0;
    auto listRet = manager->list([&] (const auto &fqInstanceNames) {
        // server pid, .ptr value of binder object, child pids
        std::map<std::string, DebugInfo> allDebugInfos;
        std::map<pid_t, std::map<uint64_t, std::string>> allPids;
        for (const auto &fqInstanceName : fqInstanceNames) {
            const auto pair = split(fqInstanceName, '/');
            const auto &serviceName = pair.first;
            const auto &instanceName = pair.second;
            auto getRet = manager->get(serviceName, instanceName);
            if (!getRet.isOk()) {
                cerr << "Warning: Skipping \"" << fqInstanceName << "\": "
                     << "cannot be fetched from service manager:"
                     << getRet.description() << endl;
                continue;
            }
            sp<IBase> service = getRet;
            if (service == nullptr) {
                cerr << "Warning: Skipping \"" << fqInstanceName << "\": "
                     << "cannot be fetched from service manager (null)";
                continue;
            }
            auto debugRet = service->getDebugInfo([&] (const auto &debugInfo) {
                allDebugInfos[fqInstanceName] = debugInfo;
                if (debugInfo.pid >= 0) {
                    allPids[static_cast<pid_t>(debugInfo.pid)].clear();
                }
            });
            if (!debugRet.isOk()) {
                cerr << "Warning: Skipping \"" << fqInstanceName << "\": "
                     << "debugging information cannot be retrieved:"
                     << debugRet.description() << endl;
            }
        }
        for (auto &pair : allPids) {
            pid_t serverPid = pair.first;
            if (!getReferencedPids(serverPid, &allPids[serverPid])) {
                std::cerr << "Warning: no information for PID " << serverPid
                          << ", are you root?" << std::endl;
            }
        }
        for (const auto &fqInstanceName : fqInstanceNames) {
            const auto pair = split(fqInstanceName, '/');
            const auto &serviceName = pair.first;
            const auto &instanceName = pair.second;
            auto it = allDebugInfos.find(fqInstanceName);
            if (it == allDebugInfos.end()) {
                printColumn(stream,
                    serviceName,
                    instanceName,
                    mode,
                    "N/A",
                    "N/A",
                    ""
                );
                continue;
            }
            const DebugInfo &info = it->second;
            printColumn(stream,
                serviceName,
                instanceName,
                mode,
                info.pid < 0 ? "N/A" : std::to_string(info.pid),
                info.ptr == 0 ? "N/A" : toHexString(info.ptr),
                info.pid < 0 || info.ptr == 0 ? "" : allPids[info.pid][info.ptr]
            );
        }

    });
    if (!listRet.isOk()) {
        cerr << "Error: Failed to list services for " << mode << ": "
             << listRet.description() << endl;
    }
}

int dump() {
    using namespace ::std;
    using namespace ::android::hardware;

    std::stringstream stream;

    stream << "All services:" << endl;
    stream << left;
    printColumn(stream, "Interface", "Instance", "Transport", "Server", "PTR", "Clients");

    auto bManager = defaultServiceManager();
    if (bManager == nullptr) {
        cerr << "Failed to get defaultServiceManager()!" << endl;
    } else {
        dumpBinderized(stream, "hwbinder", bManager);
    }

    cout << stream.rdbuf();
    return 0;
}

int usage() {
    using namespace ::std;
    cerr
        << "usage: lshal" << endl
        << "           To dump all hals." << endl
        << "or:" << endl
        << "       lshal [-h|--help]" << endl
        << "           -h, --help: show this help information." << endl;
    return -1;
}

int main(int argc, char **argv) {
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
            return usage();
        }
    }
    return dump();

}
