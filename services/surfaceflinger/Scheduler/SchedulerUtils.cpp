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

#include "SchedulerUtils.h"

#include <cinttypes>
#include <numeric>
#include <unordered_map>
#include <vector>

namespace android {
namespace scheduler {

int64_t calculate_median(std::vector<int64_t>* v) {
    if (!v || v->empty()) {
        return 0;
    }

    size_t n = v->size() / 2;
    nth_element(v->begin(), v->begin() + n, v->end());
    return v->at(n);
}

int64_t calculate_mode(const std::vector<int64_t>& v) {
    if (v.empty()) {
        return 0;
    }

    // Create a map with all the counts for the indivicual values in the vector.
    std::unordered_map<int64_t, int64_t> counts;
    for (int64_t value : v) {
        counts[value]++;
    }

    // Sort the map, and return the number with the highest count. If two numbers have
    // the same count, first one is returned.
    using ValueType = const decltype(counts)::value_type&;
    const auto compareCounts = [](ValueType l, ValueType r) { return l.second <= r.second; };
    return std::max_element(counts.begin(), counts.end(), compareCounts)->first;
}

} // namespace scheduler
} // namespace android
