/*
 * Copyright 2021 The Android Open Source Project
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

#include <cstdint>

#include <ftl/flags.h>

namespace android::scheduler {

enum class Feature : std::uint8_t {
    kPresentFences = 1 << 0,
    kKernelIdleTimer = 1 << 1,
    kContentDetection = 1 << 2,
    kTracePredictedVsync = 1 << 3,
    kBackpressureGpuComposition = 1 << 4,
    kSmallDirtyContentDetection = 1 << 5,
    kExpectedPresentTime = 1 << 6,
};

using FeatureFlags = ftl::Flags<Feature>;

} // namespace android::scheduler
