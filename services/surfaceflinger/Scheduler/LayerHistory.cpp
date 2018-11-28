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

#include "SchedulerUtils.h"

namespace android {

LayerHistory::LayerHistory() {}

LayerHistory::~LayerHistory() = default;

void LayerHistory::insert(const std::string layerName, nsecs_t presentTime) {
    mElements[mCounter].insert(std::make_pair(layerName, presentTime));
}

void LayerHistory::incrementCounter() {
    mCounter++;
    mCounter = mCounter % scheduler::ARRAY_SIZE;
    // Clear all the previous data from the history. This is a ring buffer, so we are
    // reusing memory.
    mElements[mCounter].clear();
}

const std::unordered_map<std::string, nsecs_t>& LayerHistory::get(size_t index) const {
    // For the purposes of the layer history, the index = 0 always needs to start at the
    // current counter, and then decrement to access the layers in correct historical order.
    return mElements.at((scheduler::ARRAY_SIZE + (mCounter - (index % scheduler::ARRAY_SIZE))) %
                        scheduler::ARRAY_SIZE);
}

} // namespace android