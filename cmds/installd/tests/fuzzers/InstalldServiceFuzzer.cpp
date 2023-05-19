/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <fuzzbinder/libbinder_driver.h>

#include "InstalldNativeService.h"
#include "dexopt.h"

using ::android::fuzzService;
using ::android::sp;
using ::android::installd::InstalldNativeService;

namespace android {
namespace installd {

bool calculate_oat_file_path(char path[PKG_PATH_MAX], const char* oat_dir, const char* apk_path,
                             const char* instruction_set) {
    return calculate_oat_file_path_default(path, oat_dir, apk_path, instruction_set);
}

bool calculate_odex_file_path(char path[PKG_PATH_MAX], const char* apk_path,
                              const char* instruction_set) {
    return calculate_odex_file_path_default(path, apk_path, instruction_set);
}

bool create_cache_path(char path[PKG_PATH_MAX], const char* src, const char* instruction_set) {
    return create_cache_path_default(path, src, instruction_set);
}

bool force_compile_without_image() {
    return false;
}

} // namespace installd
} // namespace android

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto service = sp<InstalldNativeService>::make();
    fuzzService(service, FuzzedDataProvider(data, size));
    return 0;
}