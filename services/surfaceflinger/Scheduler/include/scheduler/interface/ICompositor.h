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

#include <scheduler/Time.h>
#include <scheduler/VsyncId.h>

namespace android {

struct ICompositor {
    // Configures physical displays, processing hotplug and/or mode setting via the Composer HAL.
    virtual void configure() = 0;

    // Commits transactions for layers and displays. Returns whether any state has been invalidated,
    // i.e. whether a frame should be composited for each display.
    virtual bool commit(TimePoint frameTime, VsyncId, TimePoint expectedVsyncTime) = 0;

    // Composites a frame for each display. CompositionEngine performs GPU and/or HAL composition
    // via RenderEngine and the Composer HAL, respectively.
    virtual void composite(TimePoint frameTime, VsyncId) = 0;

    // Samples the composited frame via RegionSamplingThread.
    virtual void sample() = 0;

protected:
    ~ICompositor() = default;
};

} // namespace android
