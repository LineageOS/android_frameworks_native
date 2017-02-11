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

#ifndef FRAMEWORK_NATIVE_CMDS_LSHAL_TABLE_ENTRY_H_
#define FRAMEWORK_NATIVE_CMDS_LSHAL_TABLE_ENTRY_H_

#include <stdint.h>

#include <string>
#include <vector>

namespace android {
namespace lshal {

using Pids = std::vector<int32_t>;

struct TableEntry {
    std::string interfaceName;
    std::string transport;
    int32_t serverPid;
    uint64_t serverObjectAddress;
    Pids clientPids;
};

using Table = std::vector<TableEntry>;

enum {
    NO_PID = -1,
    NO_PTR = 0
};

}  // namespace lshal
}  // namespace android

#endif  // FRAMEWORK_NATIVE_CMDS_LSHAL_TABLE_ENTRY_H_
