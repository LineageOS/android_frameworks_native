/*
 * Copyright 2024 The Android Open Source Project
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

#include "DisplayDevice.h"
#include "DisplayRenderArea.h"
#include "LayerRenderArea.h"
#include "ui/Size.h"
#include "ui/Transform.h"

namespace android {
/**
 * A parameter object for creating a render area
 */
struct RenderAreaBuilder {
    // Source crop of the render area
    Rect crop;

    // Size of the physical render area
    ui::Size reqSize;

    // Composition data space of the render area
    ui::Dataspace reqDataSpace;

    ftl::Flags<RenderArea::Options> options;
    virtual std::unique_ptr<RenderArea> build() const = 0;

    RenderAreaBuilder(Rect crop, ui::Size reqSize, ui::Dataspace reqDataSpace,
                      ftl::Flags<RenderArea::Options> options)
          : crop(crop), reqSize(reqSize), reqDataSpace(reqDataSpace), options(options) {}

    virtual ~RenderAreaBuilder() = default;
};

struct DisplayRenderAreaBuilder : RenderAreaBuilder {
    DisplayRenderAreaBuilder(Rect crop, ui::Size reqSize, ui::Dataspace reqDataSpace,
                             wp<const DisplayDevice> displayWeak,
                             ftl::Flags<RenderArea::Options> options)
          : RenderAreaBuilder(crop, reqSize, reqDataSpace, options), displayWeak(displayWeak) {}

    // Display that render area will be on
    wp<const DisplayDevice> displayWeak;

    std::unique_ptr<RenderArea> build() const override {
        return DisplayRenderArea::create(displayWeak, crop, reqSize, reqDataSpace, options);
    }
};

struct LayerRenderAreaBuilder : RenderAreaBuilder {
    LayerRenderAreaBuilder(Rect crop, ui::Size reqSize, ui::Dataspace reqDataSpace, sp<Layer> layer,
                           bool childrenOnly, ftl::Flags<RenderArea::Options> options)
          : RenderAreaBuilder(crop, reqSize, reqDataSpace, options),
            layer(layer),
            childrenOnly(childrenOnly) {}

    // Root layer of the render area
    sp<Layer> layer;

    // Layer snapshot of the root layer
    frontend::LayerSnapshot layerSnapshot;

    // Transform to be applied on the layers to transform them
    // into the logical render area
    ui::Transform layerTransform{ui::Transform()};

    // Buffer bounds
    Rect layerBufferSize{Rect()};

    // If false, transform is inverted from the parent snapshot
    bool childrenOnly;

    // Uses parent snapshot to determine layer transform and buffer size
    void setLayerSnapshot(const frontend::LayerSnapshot& parentSnapshot) {
        layerSnapshot = parentSnapshot;
        if (!childrenOnly) {
            layerTransform = parentSnapshot.localTransform.inverse();
        }
        layerBufferSize = parentSnapshot.bufferSize;
    }

    std::unique_ptr<RenderArea> build() const override {
        return std::make_unique<LayerRenderArea>(layer, std::move(layerSnapshot), crop, reqSize,
                                                 reqDataSpace, layerTransform, layerBufferSize,
                                                 options);
    }
};

} // namespace android