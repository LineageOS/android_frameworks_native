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

#include <iostream>
#include <string>
#include <vector>

#include <android/hidl/manager/1.0/IServiceManager.h>

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
};
using Status = unsigned int;

class Lshal {
public:
    int main(int argc, char **argv);

private:
    Status parseArgs(int argc, char **argv);
    Status fetch();
    void dump() const;
    void usage() const;
    void putEntry(TableEntry &&entry);
    Status fetchPassthrough(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    Status fetchBinderized(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    Status fetchAllLibraries(const sp<::android::hidl::manager::V1_0::IServiceManager> &manager);
    bool getReferencedPids(
        pid_t serverPid, std::map<uint64_t, Pids> *objects) const;


    Table mTable;
    std::ostream &mErr = std::cerr;
    std::ostream &mOut = std::cout;
};


}  // namespace lshal
}  // namespace android

#endif  // FRAMEWORK_NATIVE_CMDS_LSHAL_LSHAL_H_
