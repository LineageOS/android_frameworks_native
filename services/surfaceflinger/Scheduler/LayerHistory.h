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

#pragma once

#include <array>
#include <cinttypes>
#include <cstdint>
#include <numeric>
#include <string>
#include <unordered_map>

#include <utils/Timers.h>

#include "SchedulerUtils.h"

namespace android {

/*
 * This class represents a circular buffer in which we keep layer history for
 * the past ARRAY_SIZE frames. Each time, a signal for new frame comes, the counter
 * gets incremented and includes all the layers that are requested to draw in that
 * frame.
 *
 * Once the buffer reaches the end of the array, it starts overriding the elements
 * at the beginning of the array.
 */
class LayerHistory {
public:
    LayerHistory();
    ~LayerHistory();

    // Method for inserting layers and their requested present time into the ring buffer.
    // The elements are going to be inserted into an unordered_map at the position 'now'.
    void insert(const std::string layerName, nsecs_t presentTime);
    // Method for incrementing the current slot in the ring buffer. It also clears the
    // unordered_map, if it was created previously.
    void incrementCounter();
    // Returns unordered_map at the given at index. The index is decremented from 'now'. For
    // example, 0 is now, 1 is previous frame.
    const std::unordered_map<std::string, nsecs_t>& get(size_t index) const;
    // Returns the total size of the ring buffer. The value is always the same regardless
    // of how many slots we filled in.
    static constexpr size_t getSize() { return scheduler::ARRAY_SIZE; }

private:
    size_t mCounter = 0;
    std::array<std::unordered_map<std::string, nsecs_t>, scheduler::ARRAY_SIZE> mElements;
};

} // namespace android