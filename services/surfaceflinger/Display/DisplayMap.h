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

#include <ftl/small_map.h>
#include <ftl/small_vector.h>

namespace android::display {

// The static capacities were chosen to exceed a typical number of physical and/or virtual displays.

template <typename Key, typename Value>
using DisplayMap = ftl::SmallMap<Key, Value, 5>;

template <typename Key, typename Value>
using PhysicalDisplayMap = ftl::SmallMap<Key, Value, 3>;

template <typename T>
using PhysicalDisplayVector = ftl::SmallVector<T, 3>;

} // namespace android::display
