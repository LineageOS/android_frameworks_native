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
#include <iomanip>
#include <iostream>
#include <sstream>

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>

template <typename A, typename B, typename C, typename D>
void printColumn(std::stringstream &stream,
        const A &a, const B &b, const C &c, const D &d) {
    using namespace ::std;
    stream << left
           << setw(70) << a << "\t"
           << setw(20) << b << "\t"
           << setw(10) << c << "\t"
           << setw(5)  << d << "\t"
           << endl;
}

int dump() {
    using namespace ::std;
    using namespace ::android::hardware;
    using namespace ::android::hidl::manager::V1_0;

    std::map<std::string, ::android::sp<IServiceManager>> mapping = {
            {"hwbinder", defaultServiceManager()},
            {"passthrough", getPassthroughServiceManager()}
    };

    std::stringstream stream;

    stream << "All services:" << endl;
    stream << left;
    printColumn(stream, "Interface", "Instance", "Transport", "Ref");

    for (const auto &pair : mapping) {
        const std::string &mode = pair.first;
        const ::android::sp<IServiceManager> &manager = pair.second;

        if (manager == nullptr) {
            cerr << "Failed to get IServiceManager for " << mode << "!" << endl;
            continue;
        }

        auto ret = manager->debugDump([&](const auto &registered) {
            for (const auto &info : registered) {
                printColumn(stream,
                    info.interfaceName,
                    info.instanceName.empty() ? "N/A" : info.instanceName,
                    mode,
                    info.refCount < 0 ? "N/A" : std::to_string(info.refCount));
            }
        });
        if (!ret.isOk()) {
            cerr << "Failed to list services for " << mode << ": "
                 << ret.description() << endl;
        }
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
