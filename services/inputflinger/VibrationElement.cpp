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

const std::string VibrationElement::toString() const {
    std::string dump;
    dump += StringPrintf("[duration=%lldms, channels=[", duration.count());

    for (auto it = channels.begin(); it != channels.end(); ++it) {
        dump += std::to_string(*it);
        if (std::next(it) != channels.end()) {
            dump += ", ";
        }
    }

    dump += "]]";
    return dump;
}

uint16_t VibrationElement::getMagnitude(size_t channelIdx) const {
    if (channelIdx >= channels.size()) {
        return 0;
    }
    // convert range [0,255] to [0,65535] (android framework to linux ff ranges)
    return static_cast<uint16_t>(channels[channelIdx]) << 8;
}

bool VibrationElement::isOn() const {
    return std::any_of(channels.begin(), channels.end(),
                       [](uint16_t channel) { return channel != 0; });
}

} // namespace android
