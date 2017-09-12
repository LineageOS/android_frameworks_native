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
#define LOG_TAG "lshal"
#include <android-base/logging.h>

#include "TableEntry.h"

#include "TextTable.h"
#include "utils.h"

namespace android {
namespace lshal {

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

static std::string getTitle(TableColumnType type) {
    switch (type) {
        case TableColumnType::INTERFACE_NAME: {
            return "Interface";
        } break;
        case TableColumnType::TRANSPORT: {
            return "Transport";
        } break;
        case TableColumnType::SERVER_PID: {
            return "Server";
        } break;
        case TableColumnType::SERVER_CMD: {
            return "Server CMD";
        }
        case TableColumnType::SERVER_ADDR: {
            return "PTR";
        } break;
        case TableColumnType::CLIENT_PIDS: {
            return "Clients";
        } break;
        case TableColumnType::CLIENT_CMDS: {
            return "Clients CMD";
        } break;
        case TableColumnType::ARCH: {
            return "Arch";
        } break;
        case TableColumnType::THREADS: {
            return "Thread Use";
        } break;
        default: {
            LOG(FATAL) << "Should not reach here.";
            return "";
        }
    }
}

std::string TableEntry::getField(TableColumnType type) const {
    switch (type) {
        case TableColumnType::INTERFACE_NAME: {
            return interfaceName;
        } break;
        case TableColumnType::TRANSPORT: {
            return transport;
        } break;
        case TableColumnType::SERVER_PID: {
            return serverPid == NO_PID ? "N/A" : std::to_string(serverPid);
        } break;
        case TableColumnType::SERVER_CMD: {
            return serverCmdline;
        } break;
        case TableColumnType::SERVER_ADDR: {
            return serverObjectAddress == NO_PTR ? "N/A" : toHexString(serverObjectAddress);
        } break;
        case TableColumnType::CLIENT_PIDS: {
            return join(clientPids, " ");
        } break;
        case TableColumnType::CLIENT_CMDS: {
            return join(clientCmdlines, ";");
        } break;
        case TableColumnType::ARCH: {
            return getArchString(arch);
        } break;
        case TableColumnType::THREADS: {
            return getThreadUsage();
        } break;
        default: {
            LOG(FATAL) << "Should not reach here.";
            return "";
        }
    }
}

TextTable Table::createTextTable(bool neat,
    const std::function<std::string(const std::string&)>& emitDebugInfo) const {

    TextTable textTable;
    std::vector<std::string> row;
    if (!neat) {
        textTable.add(mDescription);

        row.clear();
        for (TableColumnType type : mSelectedColumns) {
            row.push_back(getTitle(type));
        }
        textTable.add(std::move(row));
    }

    for (const auto& entry : mEntries) {
        row.clear();
        for (TableColumnType type : mSelectedColumns) {
            row.push_back(entry.getField(type));
        }
        textTable.add(std::move(row));

        if (emitDebugInfo) {
            std::string debugInfo = emitDebugInfo(entry.interfaceName);
            if (!debugInfo.empty()) textTable.add(debugInfo);
        }
    }
    return textTable;
}

TextTable MergedTable::createTextTable() {
    TextTable textTable;
    for (const Table* table : mTables) {
        textTable.addAll(table->createTextTable());
    }
    return textTable;
}

bool TableEntry::operator==(const TableEntry& other) const {
    if (this == &other) {
        return true;
    }
    return interfaceName == other.interfaceName && transport == other.transport &&
        serverPid == other.serverPid && threadUsage == other.threadUsage &&
        threadCount == other.threadCount && serverCmdline == other.serverCmdline &&
        serverObjectAddress == other.serverObjectAddress && clientPids == other.clientPids &&
        clientCmdlines == other.clientCmdlines && arch == other.arch;
}

std::string TableEntry::to_string() const {
    std::stringstream ss;
    ss << "name=" << interfaceName << ";transport=" << transport << ";thread=" << getThreadUsage()
       << ";server=" << serverPid
       << "(" << serverObjectAddress << ";" << serverCmdline << ");clients=["
       << join(clientPids, ";") << "](" << join(clientCmdlines, ";") << ");arch="
       << getArchString(arch);
    return ss.str();

}

} // namespace lshal
} // namespace android
