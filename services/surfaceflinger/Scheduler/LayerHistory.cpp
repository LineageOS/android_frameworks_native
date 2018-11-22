/*
 * Copyright 2018 The Android Open Source Project
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

#include "LayerHistory.h"

#include <cinttypes>
#include <cstdint>
#include <numeric>
#include <string>
#include <unordered_map>

#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

namespace android {

LayerHistory::LayerHistory() {}

LayerHistory::~LayerHistory() = default;

void LayerHistory::insert(const std::string layerName, nsecs_t presentTime) {
    mElements[mCounter].insert(std::make_pair(layerName, presentTime));
}

void LayerHistory::incrementCounter() {
    mCounter++;
    mCounter = mCounter % ARRAY_SIZE;
    mElements[mCounter].clear();
}

const std::unordered_map<std::string, nsecs_t>& LayerHistory::get(size_t index) const {
    return mElements.at(index);
}

} // namespace android