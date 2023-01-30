/*
 * Copyright 2022 The Android Open Source Project
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

#include <vector>

namespace android::surfaceflinger::frontend {
// Erases the first element in vec that matches value. This is a more optimal way to
// remove an element from a vector that avoids relocating all the elements after the one
// that is erased.
template <typename T>
bool swapErase(std::vector<T>& vec, const T& value) {
    bool found = false;
    auto it = std::find(vec.begin(), vec.end(), value);
    if (it != vec.end()) {
        std::iter_swap(it, vec.end() - 1);
        vec.erase(vec.end() - 1);
        found = true;
    }
    return found;
}

// Similar to swapErase(std::vector<T>& vec, const T& value) but erases the first element
// that returns true for predicate.
template <typename T, class P>
void swapErase(std::vector<T>& vec, P predicate) {
    auto it = std::find_if(vec.begin(), vec.end(), predicate);
    if (it != vec.end()) {
        std::iter_swap(it, vec.end() - 1);
        vec.erase(vec.end() - 1);
    }
}

} // namespace android::surfaceflinger::frontend
