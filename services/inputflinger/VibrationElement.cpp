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

#include "VibrationElement.h"

#include <android-base/stringprintf.h>

#include <algorithm>
#include <cinttypes>

using android::base::StringPrintf;

namespace android {

// The sentinel to use the default amplitude
static const int DEFAULT_AMPLITUDE = -1;

// The vibration magnitude for the "DEFAULT_AMPLITUDE" magnitude constant.
static const uint16_t DEFAULT_MAGNITUDE = 0xc000;

void VibrationElement::dump(std::string& dump) const {
    dump += StringPrintf("[duration=%lldms, channels=[", duration.count());

    if (channels.size()) {
        dump += std::to_string(channels[0]);
        std::for_each(channels.begin() + 1, channels.end(), [&dump](int channel) {
            dump += ", ";
            dump += std::to_string(channel);
        });
    }
    dump += "]]";
}

uint16_t VibrationElement::getChannel(int id) const {
    if (id >= (int)channels.size()) {
        return 0;
    }

    // android framework uses DEFAULT_AMPLITUDE to signal that the vibration
    // should use some built-in default value, denoted here as DEFAULT_MAGNITUDE
    if (channels[id] == DEFAULT_AMPLITUDE) {
        return DEFAULT_MAGNITUDE;
    }

    // convert range [0,255] to [0,65535] (android framework to linux ff ranges)
    return ((uint16_t)channels[id]) << 8;
}

bool VibrationElement::isOn() const {
    return std::any_of(channels.begin(), channels.end(),
                       [](uint16_t channel) { return channel != 0; });
}

} // namespace android
