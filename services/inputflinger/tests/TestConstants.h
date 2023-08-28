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

#include <chrono>

#include <utils/Timers.h>

namespace android {

using std::chrono_literals::operator""ms;

// Timeout for waiting for an expected event
static constexpr std::chrono::duration WAIT_TIMEOUT = 100ms;

// An arbitrary time value.
static constexpr nsecs_t ARBITRARY_TIME = 1234;
static constexpr nsecs_t READ_TIME = 4321;

// Error tolerance for floating point assertions.
static const float EPSILON = 0.001f;

} // namespace android
