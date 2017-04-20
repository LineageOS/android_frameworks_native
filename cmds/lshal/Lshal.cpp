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

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>
#include <hidl-util/FQName.h>
#include <private/android_filesystem_config.h>
#include <sys/stat.h>
#include <vintf/HalManifest.h>
#include <vintf/parse_xml.h>

#include "PipeRelay.h"
#include "Timeout.h"

using ::android::hardware::hidl_string;
using ::android::hidl::manager::V1_0::IServiceManager;

namespace android {
namespace lshal {

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

template<typename String>
static std::pair<String, String> splitFirst(const String &s, char c) {
    const char *pos = strchr(s.c_str(), c);
    if (pos == nullptr) {
        return {s, {}};
    }
    return {String(s.c_str(), pos - s.c_str()), String(pos + 1)};
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

static void replaceAll(std::string *s, char from, char to) {
    for (size_t i = 0; i < s->size(); ++i) {
        if (s->at(i) == from) {
            s->at(i) = to;
        }
    }
}

std::string getCmdline(pid_t pid) {
    std::ifstream ifs("/proc/" + std::to_string(pid) + "/cmdline");
    std::string cmdline;
    if (!ifs.is_open()) {
        return "";
    }
    ifs >> cmdline;
    return cmdline;
}

const std::string &Lshal::getCmdline(pid_t pid) {
    auto pair = mCmdlines.find(pid);
    if (pair != mCmdlines.end()) {
        return pair->second;
    }
    mCmdlines[pid] = ::android::lshal::getCmdline(pid);
    return mCmdlines[pid];
}

void Lshal::removeDeadProcesses(Pids *pids) {
    static const pid_t myPid = getpid();
    std::remove_if(pids->begin(), pids->end(), [this](auto pid) {
        return pid == myPid || this->getCmdline(pid).empty();
    });
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

// Must process hwbinder services first, then passthrough services.
void Lshal::forEachTable(const std::function<void(Table &)> &f) {
    f(mServicesTable);
    f(mPassthroughRefTable);
    f(mImplementationsTable);
}
void Lshal::forEachTable(const std::function<void(const Table &)> &f) const {
    f(mServicesTable);
    f(mPassthroughRefTable);
    f(mImplementationsTable);
}

void Lshal::postprocess() {
    forEachTable([this](Table &table) {
        if (mSortColumn) {
            std::sort(table.begin(), table.end(), mSortColumn);
        }
        for (TableEntry &entry : table) {
            entry.serverCmdline = getCmdline(entry.serverPid);
            removeDeadProcesses(&entry.clientPids);
            for (auto pid : entry.clientPids) {
                entry.clientCmdlines.push_back(this->getCmdline(pid));
            }
        }
    });
    // use a double for loop here because lshal doesn't care about efficiency.
    for (TableEntry &packageEntry : mImplementationsTable) {
        std::string packageName = packageEntry.interfaceName;
        FQName fqPackageName{packageName.substr(0, packageName.find("::"))};
        if (!fqPackageName.isValid()) {
            continue;
        }
        for (TableEntry &interfaceEntry : mPassthroughRefTable) {
            if (interfaceEntry.arch != ARCH_UNKNOWN) {
                continue;
            }
            FQName interfaceName{splitFirst(interfaceEntry.interfaceName, '/').first};
            if (!interfaceName.isValid()) {
                continue;
            }
            if (interfaceName.getPackageAndVersion() == fqPackageName) {
                interfaceEntry.arch = packageEntry.arch;
            }
        }
    }
}

void Lshal::printLine(
        const std::string &interfaceName,
        const std::string &transport,
        const std::string &arch,
        const std::string &server,
        const std::string &serverCmdline,
        const std::string &address, const std::string &clients,
        const std::string &clientCmdlines) const {
    if (mSelectedColumns & ENABLE_INTERFACE_NAME)
        mOut << std::setw(80) << interfaceName << "\t";
    if (mSelectedColumns & ENABLE_TRANSPORT)
        mOut << std::setw(10) << transport << "\t";
    if (mSelectedColumns & ENABLE_ARCH)
        mOut << std::setw(5) << arch << "\t";
    if (mSelectedColumns & ENABLE_SERVER_PID) {
        if (mEnableCmdlines) {
            mOut << std::setw(15) << serverCmdline << "\t";
        } else {
            mOut << std::setw(5)  << server << "\t";
        }
    }
    if (mSelectedColumns & ENABLE_SERVER_ADDR)
        mOut << std::setw(16) << address << "\t";
    if (mSelectedColumns & ENABLE_CLIENT_PIDS) {
        if (mEnableCmdlines) {
            mOut << std::setw(0)  << clientCmdlines;
        } else {
            mOut << std::setw(0)  << clients;
        }
    }
    mOut << std::endl;
}

void Lshal::dumpVintf() const {
    mOut << "<!-- " << std::endl
         << "    This is a skeleton device manifest. Notes: " << std::endl
         << "    1. android.hidl.*, android.frameworks.*, android.system.* are not included." << std::endl
         << "    2. If a HAL is supported in both hwbinder and passthrough transport, " << std::endl
         << "       only hwbinder is shown." << std::endl
         << "    3. It is likely that HALs in passthrough transport does not have" << std::endl
         << "       <interface> declared; users will have to write them by hand." << std::endl
         << "    4. sepolicy version is set to 0.0. It is recommended that the entry" << std::endl
         << "       is removed from the manifest file and written by assemble_vintf" << std::endl
         << "       at build time." << std::endl
         << "-->" << std::endl;

    vintf::HalManifest manifest;
    forEachTable([this, &manifest] (const Table &table) {
        for (const TableEntry &entry : table) {

            std::string fqInstanceName = entry.interfaceName;

            if (&table == &mImplementationsTable) {
                // Quick hack to work around *'s
                replaceAll(&fqInstanceName, '*', 'D');
            }
            auto splittedFqInstanceName = splitFirst(fqInstanceName, '/');
            FQName fqName(splittedFqInstanceName.first);
            if (!fqName.isValid()) {
                mErr << "Warning: '" << splittedFqInstanceName.first
                     << "' is not a valid FQName." << std::endl;
                continue;
            }
            // Strip out system libs.
            if (fqName.inPackage("android.hidl") ||
                fqName.inPackage("android.frameworks") ||
                fqName.inPackage("android.system")) {
                continue;
            }
            std::string interfaceName =
                    &table == &mImplementationsTable ? "" : fqName.name();
            std::string instanceName =
                    &table == &mImplementationsTable ? "" : splittedFqInstanceName.second;

            vintf::Version version{fqName.getPackageMajorVersion(),
                                   fqName.getPackageMinorVersion()};
            vintf::Transport transport;
            vintf::Arch arch;
            if (entry.transport == "hwbinder") {
                transport = vintf::Transport::HWBINDER;
                arch = vintf::Arch::ARCH_EMPTY;
            } else if (entry.transport == "passthrough") {
                transport = vintf::Transport::PASSTHROUGH;
                switch (entry.arch) {
                    case lshal::ARCH32:
                        arch = vintf::Arch::ARCH_32;    break;
                    case lshal::ARCH64:
                        arch = vintf::Arch::ARCH_64;    break;
                    case lshal::ARCH_BOTH:
                        arch = vintf::Arch::ARCH_32_64; break;
                    case lshal::ARCH_UNKNOWN: // fallthrough
                    default:
                        mErr << "Warning: '" << fqName.package()
                             << "' doesn't have bitness info, assuming 32+64." << std::endl;
                        arch = vintf::Arch::ARCH_32_64;
                }
            } else {
                mErr << "Warning: '" << entry.transport << "' is not a valid transport." << std::endl;
                continue;
            }

            bool done = false;
            for (vintf::ManifestHal *hal : manifest.getHals(fqName.package())) {
                if (hal->transport() != transport) {
                    if (transport != vintf::Transport::PASSTHROUGH) {
                        mErr << "Fatal: should not reach here. Generated result may be wrong."
                             << std::endl;
                    }
                    done = true;
                    break;
                }
                if (hal->hasVersion(version)) {
                    hal->interfaces[interfaceName].name = interfaceName;
                    hal->interfaces[interfaceName].instances.insert(instanceName);
                    done = true;
                    break;
                }
            }
            if (done) {
                continue; // to next TableEntry
            }
            if (!manifest.add(vintf::ManifestHal{
                    .format = vintf::HalFormat::HIDL,
                    .name = fqName.package(),
                    .versions = {version},
                    .transportArch = {transport, arch},
                    .interfaces = {{interfaceName, {interfaceName, {{instanceName}}}}}})) {
                mErr << "Warning: cannot add hal '" << fqInstanceName << "'" << std::endl;
            }
        }
    });
    mOut << vintf::gHalManifestConverter(manifest);
}

static const std::string &getArchString(Architecture arch) {
    static const std::string sStr64 = "64";
    static const std::string sStr32 = "32";
    static const std::string sStrBoth = "32+64";
    static const std::string sStrUnknown = "";
    switch (arch) {
        case ARCH64:
            return sStr64;
        case ARCH32:
            return sStr32;
        case ARCH_BOTH:
            return sStrBoth;
        case ARCH_UNKNOWN: // fall through
        default:
            return sStrUnknown;
    }
}

static Architecture fromBaseArchitecture(::android::hidl::base::V1_0::DebugInfo::Architecture a) {
    switch (a) {
        case ::android::hidl::base::V1_0::DebugInfo::Architecture::IS_64BIT:
            return ARCH64;
        case ::android::hidl::base::V1_0::DebugInfo::Architecture::IS_32BIT:
            return ARCH32;
        case ::android::hidl::base::V1_0::DebugInfo::Architecture::UNKNOWN: // fallthrough
        default:
            return ARCH_UNKNOWN;
    }
}

// A unique_ptr type using a custom deleter function.
template<typename T>
using deleted_unique_ptr = std::unique_ptr<T, std::function<void(T *)> >;

void Lshal::emitDebugInfo(
        const sp<IServiceManager> &serviceManager,
        const std::string &interfaceName,
        const std::string &instanceName) const {
    using android::hidl::base::V1_0::IBase;

    hardware::Return<sp<IBase>> retBase =
        serviceManager->get(interfaceName, instanceName);

    sp<IBase> base;
    if (!retBase.isOk() || (base = retBase) == nullptr) {
        // There's a small race, where a service instantiated while collecting
        // the list of services has by now terminated, so this isn't anything
        // to be concerned about.
        return;
    }

    PipeRelay relay(mOut.buf());

    if (relay.initCheck() != OK) {
        LOG(ERROR) << "PipeRelay::initCheck() FAILED w/ " << relay.initCheck();
        return;
    }

    deleted_unique_ptr<native_handle_t> fdHandle(
        native_handle_create(1 /* numFds */, 0 /* numInts */),
        native_handle_delete);

    fdHandle->data[0] = relay.fd();

    hardware::hidl_vec<hardware::hidl_string> options;
    hardware::Return<void> ret = base->debug(fdHandle.get(), options);

    if (!ret.isOk()) {
        LOG(ERROR)
            << interfaceName
            << "::debug(...) FAILED. (instance "
            << instanceName
            << ")";
    }
}

void Lshal::dumpTable() {
    mServicesTable.description =
            "All binderized services (registered services through hwservicemanager)";
    mPassthroughRefTable.description =
            "All interfaces that getService() has ever return as a passthrough interface;\n"
            "PIDs / processes shown below might be inaccurate because the process\n"
            "might have relinquished the interface or might have died.\n"
            "The Server / Server CMD column can be ignored.\n"
            "The Clients / Clients CMD column shows all process that have ever dlopen'ed \n"
            "the library and successfully fetched the passthrough implementation.";
    mImplementationsTable.description =
            "All available passthrough implementations (all -impl.so files)";
    forEachTable([this] (const Table &table) {
        mOut << table.description << std::endl;
        mOut << std::left;
        printLine("Interface", "Transport", "Arch", "Server", "Server CMD",
                  "PTR", "Clients", "Clients CMD");

        // We're only interested in dumping debug info for already
        // instantiated services. There's little value in dumping the
        // debug info for a service we create on the fly, so we only operate
        // on the "mServicesTable".
        sp<IServiceManager> serviceManager;
        if (mEmitDebugInfo && &table == &mServicesTable) {
            serviceManager = ::android::hardware::defaultServiceManager();
        }

        for (const auto &entry : table) {
            printLine(entry.interfaceName,
                    entry.transport,
                    getArchString(entry.arch),
                    entry.serverPid == NO_PID ? "N/A" : std::to_string(entry.serverPid),
                    entry.serverCmdline,
                    entry.serverObjectAddress == NO_PTR ? "N/A" : toHexString(entry.serverObjectAddress),
                    join(entry.clientPids, " "),
                    join(entry.clientCmdlines, ";"));

            if (serviceManager != nullptr) {
                auto pair = splitFirst(entry.interfaceName, '/');
                emitDebugInfo(serviceManager, pair.first, pair.second);
            }
        }
        mOut << std::endl;
    });

}

void Lshal::dump() {
    if (mVintf) {
        dumpVintf();
        if (!!mFileOutput) {
            mFileOutput.buf().close();
            delete &mFileOutput.buf();
            mFileOutput = nullptr;
        }
        mOut = std::cout;
    } else {
        dumpTable();
    }
}

void Lshal::putEntry(TableEntrySource source, TableEntry &&entry) {
    Table *table = nullptr;
    switch (source) {
        case HWSERVICEMANAGER_LIST :
            table = &mServicesTable; break;
        case PTSERVICEMANAGER_REG_CLIENT :
            table = &mPassthroughRefTable; break;
        case LIST_DLLIB :
            table = &mImplementationsTable; break;
        default:
            mErr << "Error: Unknown source of entry " << source << std::endl;
    }
    if (table) {
        table->entries.push_back(std::forward<TableEntry>(entry));
    }
}

Status Lshal::fetchAllLibraries(const sp<IServiceManager> &manager) {
    using namespace ::android::hardware;
    using namespace ::android::hidl::manager::V1_0;
    using namespace ::android::hidl::base::V1_0;
    auto ret = timeoutIPC(manager, &IServiceManager::debugDump, [&] (const auto &infos) {
        std::map<std::string, TableEntry> entries;
        for (const auto &info : infos) {
            std::string interfaceName = std::string{info.interfaceName.c_str()} + "/" +
                    std::string{info.instanceName.c_str()};
            entries.emplace(interfaceName, TableEntry{
                .interfaceName = interfaceName,
                .transport = "passthrough",
                .serverPid = NO_PID,
                .serverObjectAddress = NO_PTR,
                .clientPids = {},
                .arch = ARCH_UNKNOWN
            }).first->second.arch |= fromBaseArchitecture(info.arch);
        }
        for (auto &&pair : entries) {
            putEntry(LIST_DLLIB, std::move(pair.second));
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
    using namespace ::android::hardware::details;
    using namespace ::android::hidl::manager::V1_0;
    using namespace ::android::hidl::base::V1_0;
    auto ret = timeoutIPC(manager, &IServiceManager::debugDump, [&] (const auto &infos) {
        for (const auto &info : infos) {
            if (info.clientPids.size() <= 0) {
                continue;
            }
            putEntry(PTSERVICEMANAGER_REG_CLIENT, {
                .interfaceName =
                        std::string{info.interfaceName.c_str()} + "/" +
                        std::string{info.instanceName.c_str()},
                .transport = "passthrough",
                .serverPid = info.clientPids.size() == 1 ? info.clientPids[0] : NO_PID,
                .serverObjectAddress = NO_PTR,
                .clientPids = info.clientPids,
                .arch = fromBaseArchitecture(info.arch)
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

    hidl_vec<hidl_string> fqInstanceNames;
    // copying out for timeoutIPC
    auto listRet = timeoutIPC(manager, &IServiceManager::list, [&] (const auto &names) {
        fqInstanceNames = names;
    });
    if (!listRet.isOk()) {
        mErr << "Error: Failed to list services for " << mode << ": "
             << listRet.description() << std::endl;
        return DUMP_BINDERIZED_ERROR;
    }

    Status status = OK;
    // server pid, .ptr value of binder object, child pids
    std::map<std::string, DebugInfo> allDebugInfos;
    std::map<pid_t, std::map<uint64_t, Pids>> allPids;
    for (const auto &fqInstanceName : fqInstanceNames) {
        const auto pair = splitFirst(fqInstanceName, '/');
        const auto &serviceName = pair.first;
        const auto &instanceName = pair.second;
        auto getRet = timeoutIPC(manager, &IServiceManager::get, serviceName, instanceName);
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
        auto debugRet = timeoutIPC(service, &IBase::getDebugInfo, [&] (const auto &debugInfo) {
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
            putEntry(HWSERVICEMANAGER_LIST, {
                .interfaceName = fqInstanceName,
                .transport = mode,
                .serverPid = NO_PID,
                .serverObjectAddress = NO_PTR,
                .clientPids = {},
                .arch = ARCH_UNKNOWN
            });
            continue;
        }
        const DebugInfo &info = it->second;
        putEntry(HWSERVICEMANAGER_LIST, {
            .interfaceName = fqInstanceName,
            .transport = mode,
            .serverPid = info.pid,
            .serverObjectAddress = info.ptr,
            .clientPids = info.pid == NO_PID || info.ptr == NO_PTR
                    ? Pids{} : allPids[info.pid][info.ptr],
            .arch = fromBaseArchitecture(info.arch),
        });
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
        << "           Dump all hals with default ordering and columns [-ipc]." << std::endl
        << "       lshal [--interface|-i] [--transport|-t] [-r|--arch]" << std::endl
        << "             [--pid|-p] [--address|-a] [--clients|-c] [--cmdline|-m]" << std::endl
        << "             [--sort={interface|i|pid|p}] [--init-vintf[=path]]" << std::endl
        << "           -i, --interface: print the interface name column" << std::endl
        << "           -n, --instance: print the instance name column" << std::endl
        << "           -t, --transport: print the transport mode column" << std::endl
        << "           -r, --arch: print if the HAL is in 64-bit or 32-bit" << std::endl
        << "           -p, --pid: print the server PID, or server cmdline if -m is set" << std::endl
        << "           -a, --address: print the server object address column" << std::endl
        << "           -c, --clients: print the client PIDs, or client cmdlines if -m is set"
                                                                              << std::endl
        << "           -m, --cmdline: print cmdline instead of PIDs" << std::endl
        << "           --sort=i, --sort=interface: sort by interface name" << std::endl
        << "           --sort=p, --sort=pid: sort by server pid" << std::endl
        << "           --init-vintf=path: form a skeleton HAL manifest to specified file " << std::endl
        << "                         (stdout if no file specified)" << std::endl
        << "       lshal [-h|--help]" << std::endl
        << "           -h, --help: show this help information." << std::endl;
}

Status Lshal::parseArgs(int argc, char **argv) {
    static struct option longOptions[] = {
        // long options with short alternatives
        {"help",      no_argument,       0, 'h' },
        {"interface", no_argument,       0, 'i' },
        {"transport", no_argument,       0, 't' },
        {"arch",      no_argument,       0, 'r' },
        {"pid",       no_argument,       0, 'p' },
        {"address",   no_argument,       0, 'a' },
        {"clients",   no_argument,       0, 'c' },
        {"cmdline",   no_argument,       0, 'm' },
        {"debug",     optional_argument, 0, 'd' },

        // long options without short alternatives
        {"sort",      required_argument, 0, 's' },
        {"init-vintf",optional_argument, 0, 'v' },
        { 0,          0,                 0,  0  }
    };

    int optionIndex;
    int c;
    optind = 1;
    for (;;) {
        // using getopt_long in case we want to add other options in the future
        c = getopt_long(argc, argv, "hitrpacmd", longOptions, &optionIndex);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 's': {
            if (strcmp(optarg, "interface") == 0 || strcmp(optarg, "i") == 0) {
                mSortColumn = TableEntry::sortByInterfaceName;
            } else if (strcmp(optarg, "pid") == 0 || strcmp(optarg, "p") == 0) {
                mSortColumn = TableEntry::sortByServerPid;
            } else {
                mErr << "Unrecognized sorting column: " << optarg << std::endl;
                usage();
                return USAGE;
            }
            break;
        }
        case 'v': {
            if (optarg) {
                mFileOutput = new std::ofstream{optarg};
                mOut = mFileOutput;
                if (!mFileOutput.buf().is_open()) {
                    mErr << "Could not open file '" << optarg << "'." << std::endl;
                    return IO_ERROR;
                }
            }
            mVintf = true;
        }
        case 'i': {
            mSelectedColumns |= ENABLE_INTERFACE_NAME;
            break;
        }
        case 't': {
            mSelectedColumns |= ENABLE_TRANSPORT;
            break;
        }
        case 'r': {
            mSelectedColumns |= ENABLE_ARCH;
            break;
        }
        case 'p': {
            mSelectedColumns |= ENABLE_SERVER_PID;
            break;
        }
        case 'a': {
            mSelectedColumns |= ENABLE_SERVER_ADDR;
            break;
        }
        case 'c': {
            mSelectedColumns |= ENABLE_CLIENT_PIDS;
            break;
        }
        case 'm': {
            mEnableCmdlines = true;
            break;
        }
        case 'd': {
            mEmitDebugInfo = true;

            if (optarg) {
                mFileOutput = new std::ofstream{optarg};
                mOut = mFileOutput;
                if (!mFileOutput.buf().is_open()) {
                    mErr << "Could not open file '" << optarg << "'." << std::endl;
                    return IO_ERROR;
                }
                chown(optarg, AID_SHELL, AID_SHELL);
            }
            break;
        }
        case 'h': // falls through
        default: // see unrecognized options
            usage();
            return USAGE;
        }
    }

    if (mSelectedColumns == 0) {
        mSelectedColumns = ENABLE_INTERFACE_NAME | ENABLE_SERVER_PID | ENABLE_CLIENT_PIDS;
    }
    return OK;
}

int Lshal::main(int argc, char **argv) {
    Status status = parseArgs(argc, argv);
    if (status != OK) {
        return status;
    }
    status = fetch();
    postprocess();
    dump();
    return status;
}

void signalHandler(int sig) {
    if (sig == SIGINT) {
        int retVal;
        pthread_exit(&retVal);
    }
}

}  // namespace lshal
}  // namespace android

int main(int argc, char **argv) {
    signal(SIGINT, ::android::lshal::signalHandler);
    return ::android::lshal::Lshal{}.main(argc, argv);
}
