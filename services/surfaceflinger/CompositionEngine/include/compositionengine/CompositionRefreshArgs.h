/*
 * Copyright 2019 The Android Open Source Project
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
#include <optional>
#include <vector>

#include <compositionengine/Display.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/OutputColorSetting.h>
#include <math/mat4.h>
#include <ui/FenceTime.h>
#include <ui/Transform.h>

namespace android::compositionengine {

using Layers = std::vector<sp<compositionengine::LayerFE>>;
using Outputs = std::vector<std::shared_ptr<compositionengine::Output>>;

struct BorderRenderInfo {
    float width = 0;
    half4 color;
    std::vector<int32_t> layerIds;
};

// Interface of composition engine power hint callback.
struct ICEPowerCallback {
    virtual void notifyCpuLoadUp() = 0;

protected:
    ~ICEPowerCallback() = default;
};

/**
 * A parameter object for refreshing a set of outputs
 */
struct CompositionRefreshArgs {
    // All the outputs being refreshed
    Outputs outputs;

    // All the layers that are potentially visible in the outputs. The order of
    // the layers is important, and should be in traversal order from back to
    // front.
    Layers layers;

    // All the layers that have queued updates.
    Layers layersWithQueuedFrames;

    // All graphic buffers that will no longer be used and should be removed from caches.
    std::vector<uint64_t> bufferIdsToUncache;

    // Controls how the color mode is chosen for an output
    OutputColorSetting outputColorSetting{OutputColorSetting::kEnhanced};

    // If not Dataspace::UNKNOWN, overrides the dataspace on each output
    ui::Dataspace colorSpaceAgnosticDataspace{ui::Dataspace::UNKNOWN};

    // Forces a color mode on the outputs being refreshed
    ui::ColorMode forceOutputColorMode{ui::ColorMode::NATIVE};

    // Used to correctly apply an inverse-display buffer transform if applicable
    ui::Transform::RotationFlags internalDisplayRotationFlags{ui::Transform::ROT_0};

    // If true, the complete output geometry needs to be recomputed this frame
    bool updatingOutputGeometryThisFrame{false};

    // If true, there was a geometry update this frame
    bool updatingGeometryThisFrame{false};

    // The color matrix to use for this
    // frame. Only set if the color transform is changing this frame.
    std::optional<mat4> colorTransformMatrix;

    // If true, client composition is always used.
    bool devOptForceClientComposition{false};

    // If set, causes the dirty regions to flash with the delay
    std::optional<std::chrono::microseconds> devOptFlashDirtyRegionsDelay;

    // Optional.
    // The earliest time to send the present command to the HAL.
    std::optional<std::chrono::steady_clock::time_point> earliestPresentTime;

    // The expected time for the next present
    nsecs_t expectedPresentTime{0};

    // If set, a frame has been scheduled for that time.
    std::optional<std::chrono::steady_clock::time_point> scheduledFrameTime;

    std::vector<BorderRenderInfo> borderInfoList;

    bool hasTrustedPresentationListener = false;

    ICEPowerCallback* powerCallback = nullptr;
};

} // namespace android::compositionengine
