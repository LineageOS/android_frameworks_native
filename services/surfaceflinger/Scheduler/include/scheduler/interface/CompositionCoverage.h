/*
 * Copyright 2023 The Android Open Source Project
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
#include <ui/DisplayId.h>
#include <ui/DisplayMap.h>

namespace android {

// Whether composition was covered by HWC and/or GPU.
enum class CompositionCoverage : std::uint8_t {
    Hwc = 1 << 0,

    // Mutually exclusive: The composition either used the GPU, or reused a buffer that had been
    // composited on the GPU.
    Gpu = 1 << 1,
    GpuReuse = 1 << 2,
};

using CompositionCoverageFlags = ftl::Flags<CompositionCoverage>;

using CompositionCoveragePerDisplay = ui::DisplayMap<DisplayId, CompositionCoverageFlags>;

inline CompositionCoverageFlags multiDisplayUnion(const CompositionCoveragePerDisplay& displays) {
    CompositionCoverageFlags coverage;
    for (const auto& [id, flags] : displays) {
        coverage |= flags;
    }
    return coverage;
}

} // namespace android
