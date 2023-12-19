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

#pragma once

#include <string>
#include <string_view>

#include <android-base/strings.h>

namespace android {

#ifndef VENDORSERVICEMANAGER

struct NativeName {
    std::string package;
    std::string instance;

    // Parse {package}/{instance}
    static bool fill(std::string_view name, NativeName* nname) {
        size_t slash = name.find('/');
        if (slash == std::string_view::npos) {
            return false;
        }
        // no extra slashes
        if (name.find('/', slash + 1) != std::string_view::npos) {
            return false;
        }
        // every part should be non-empty
        if (slash == 0 || slash + 1 == name.size()) {
            return false;
        }
        // no dots in package
        if (name.rfind('.', slash) != std::string_view::npos) {
            return false;
        }
        nname->package = name.substr(0, slash);
        nname->instance = name.substr(slash + 1);
        return true;
    }
};

#endif

} // namespace android
