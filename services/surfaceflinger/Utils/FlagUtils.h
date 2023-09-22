/**
 * Copyright 2023 The Android Open Source Project
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

#include <android-base/properties.h>
#include <com_android_graphics_surfaceflinger_flags.h>
#include <string>

namespace android::flagutils {

using namespace std::literals::string_literals;
using namespace com::android::graphics::surfaceflinger;

inline bool vrrConfigEnabled() {
    static const bool enable_vrr_config =
            base::GetBoolProperty("debug.sf.enable_vrr_config"s, false);
    return flags::vrr_config() || enable_vrr_config;
}
} // namespace android::flagutils
