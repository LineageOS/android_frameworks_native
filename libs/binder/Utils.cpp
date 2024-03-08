/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "Utils.h"

#include <string.h>

namespace android {

void zeroMemory(uint8_t* data, size_t size) {
    memset(data, 0, size);
}

std::string HexString(const void* bytes, size_t len) {
    LOG_ALWAYS_FATAL_IF(len > 0 && bytes == nullptr, "%p %zu", bytes, len);

    // b/132916539: Doing this the 'C way', std::setfill triggers ubsan implicit conversion
    const uint8_t* bytes8 = static_cast<const uint8_t*>(bytes);
    const char chars[] = "0123456789abcdef";
    std::string result;
    result.resize(len * 2);

    for (size_t i = 0; i < len; i++) {
        const auto c = bytes8[i];
        result[2 * i] = chars[c >> 4];
        result[2 * i + 1] = chars[c & 0xf];
    }

    return result;
}

} // namespace android
