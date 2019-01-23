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

#include <cinttypes>
#include <numeric>
#include <vector>

namespace android {
namespace scheduler {
// This number is used to set the size of the arrays in scheduler that hold information
// about layers.
static constexpr size_t ARRAY_SIZE = 30;

// This number is used to have a place holder for when the screen is not NORMAL/ON. Currently
// the config is not visible to SF, and is completely maintained by HWC. However, we would
// still like to keep track of time when the device is in this config.
static constexpr int SCREEN_OFF_CONFIG_ID = -1;

// Calculates the statistical mean (average) in the data structure (array, vector). The
// function does not modify the contents of the array.
template <typename T>
auto calculate_mean(const T& v) {
    using V = typename T::value_type;
    V sum = std::accumulate(v.begin(), v.end(), 0);
    return sum / static_cast<V>(v.size());
}

// Calculates the statistical median in the vector. Return 0 if the vector is empty. The
// function modifies the vector contents.
int64_t calculate_median(std::vector<int64_t>* v);

// Calculates the statistical mode in the vector. Return 0 if the vector is empty.
int64_t calculate_mode(const std::vector<int64_t>& v);

} // namespace scheduler
} // namespace android