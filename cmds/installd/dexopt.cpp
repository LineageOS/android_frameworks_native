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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "dexopt.h"
#include "utils.h"

using android::base::StringPrintf;

namespace android {
namespace installd {

static const char* parse_null(const char* arg) {
    if (strcmp(arg, "!") == 0) {
        return nullptr;
    } else {
        return arg;
    }
}

int dexopt(const char* const params[DEXOPT_PARAM_COUNT]) {
    return dexopt(params[0],                    // apk_path
                  atoi(params[1]),              // uid
                  params[2],                    // pkgname
                  params[3],                    // instruction_set
                  atoi(params[4]),              // dexopt_needed
                  params[5],                    // oat_dir
                  atoi(params[6]),              // dexopt_flags
                  params[7],                    // compiler_filter
                  parse_null(params[8]),        // volume_uuid
                  parse_null(params[9]));       // shared_libraries
    static_assert(DEXOPT_PARAM_COUNT == 10U, "Unexpected dexopt param count");
}

}  // namespace installd
}  // namespace android
