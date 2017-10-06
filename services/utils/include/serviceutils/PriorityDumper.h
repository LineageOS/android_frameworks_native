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

#ifndef ANDROID_UTILS_PRIORITYDUMPER_H
#define ANDROID_UTILS_PRIORITYDUMPER_H

#include <utils/Errors.h>
#include <utils/String16.h>
#include <utils/Vector.h>

namespace android {

constexpr const char16_t PRIORITY_ARG[] = u"--dump-priority";
constexpr const char16_t PRIORITY_ARG_CRITICAL[] = u"CRITICAL";
constexpr const char16_t PRIORITY_ARG_HIGH[] = u"HIGH";
constexpr const char16_t PRIORITY_ARG_NORMAL[] = u"NORMAL";

// Helper class to split dumps into various priority buckets.
class PriorityDumper {
public:
    // Parses the argument list checking if the first argument is --dump_priority and
    // the second argument is the priority type (HIGH, CRITICAL or NORMAL). If the
    // arguments are found, they are stripped and the appropriate PriorityDumper
    // method is called.
    // If --dump_priority argument is not passed, all supported sections are dumped.
    status_t priorityDump(int fd, const Vector<String16>& args);

    // Dumps CRITICAL priority sections.
    virtual status_t dumpCritical(int /*fd*/, const Vector<String16>& /*args*/) { return OK; }

    // Dumps HIGH priority sections.
    virtual status_t dumpHigh(int /*fd*/, const Vector<String16>& /*args*/) { return OK; }

    // Dumps normal priority sections.
    virtual status_t dumpNormal(int /*fd*/, const Vector<String16>& /*args*/) { return OK; }

    // Dumps all sections.
    // This method is called when priorityDump is called without priority
    // arguments. By default, it calls all three dump methods.
    virtual status_t dumpAll(int fd, const Vector<String16>& args);
    virtual ~PriorityDumper() = default;
};

} // namespace android

#endif // ANDROID_UTILS_PRIORITYDUMPER_H
