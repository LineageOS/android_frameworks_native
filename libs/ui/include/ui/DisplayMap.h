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

namespace android::ui {

// The static capacities were chosen to exceed a typical number of physical and/or virtual displays.

constexpr size_t kDisplayCapacity = 5;
template <typename Key, typename Value>
using DisplayMap = ftl::SmallMap<Key, Value, kDisplayCapacity>;

constexpr size_t kPhysicalDisplayCapacity = 3;
template <typename Key, typename Value>
using PhysicalDisplayMap = ftl::SmallMap<Key, Value, kPhysicalDisplayCapacity>;

template <typename T>
using DisplayVector = ftl::SmallVector<T, kDisplayCapacity>;

template <typename T>
using PhysicalDisplayVector = ftl::SmallVector<T, kPhysicalDisplayCapacity>;

} // namespace android::ui
