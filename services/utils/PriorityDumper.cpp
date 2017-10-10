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

#include "include/serviceutils/PriorityDumper.h"

namespace android {

static void getStrippedArgs(Vector<String16>& dest, const Vector<String16>& source,
                            std::size_t numArgsToStrip) {
    for (auto it = source.begin() + numArgsToStrip; it != source.end(); it++) {
        dest.add(*it);
    }
}

status_t PriorityDumper::dumpAll(int fd, const Vector<String16>& args) {
    status_t status;
    status = dumpCritical(fd, args);
    if (status != OK) return status;
    status = dumpHigh(fd, args);
    if (status != OK) return status;
    status = dumpNormal(fd, args);
    if (status != OK) return status;
    return status;
}

status_t PriorityDumper::priorityDump(int fd, const Vector<String16>& args) {
    status_t status;
    if (args.size() >= 2 && args[0] == PRIORITY_ARG) {
        String16 priority = args[1];
        Vector<String16> strippedArgs;
        getStrippedArgs(strippedArgs, args, 2);
        if (priority == PRIORITY_ARG_CRITICAL) {
            status = dumpCritical(fd, strippedArgs);
        } else if (priority == PRIORITY_ARG_HIGH) {
            status = dumpHigh(fd, strippedArgs);
        } else if (priority == PRIORITY_ARG_NORMAL) {
            status = dumpNormal(fd, strippedArgs);
        } else {
            status = dumpAll(fd, args);
        }
    } else {
        status = dumpAll(fd, args);
    }
    return status;
}
} // namespace android
