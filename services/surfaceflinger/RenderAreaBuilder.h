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

    // If true, the secure layer would be blacked out or skipped
    // when rendered to an insecure render area
    bool allowSecureLayers;

    // If true, the render result may be used for system animations
    // that must preserve the exact colors of the display
    bool hintForSeamlessTransition;

    virtual std::unique_ptr<RenderArea> build() const = 0;

    RenderAreaBuilder(Rect crop, ui::Size reqSize, ui::Dataspace reqDataSpace,
                      bool allowSecureLayers, bool hintForSeamlessTransition)
          : crop(crop),
            reqSize(reqSize),
            reqDataSpace(reqDataSpace),
            allowSecureLayers(allowSecureLayers),
            hintForSeamlessTransition(hintForSeamlessTransition) {}

    virtual ~RenderAreaBuilder() = default;
};

struct DisplayRenderAreaBuilder : RenderAreaBuilder {
    DisplayRenderAreaBuilder(Rect crop, ui::Size reqSize, ui::Dataspace reqDataSpace,
                             bool allowSecureLayers, bool hintForSeamlessTransition,
                             wp<const DisplayDevice> displayWeak)
          : RenderAreaBuilder(crop, reqSize, reqDataSpace, allowSecureLayers,
                              hintForSeamlessTransition),
            displayWeak(displayWeak) {}

    // Display that render area will be on
    wp<const DisplayDevice> displayWeak;

    std::unique_ptr<RenderArea> build() const override {
        return DisplayRenderArea::create(displayWeak, crop, reqSize, reqDataSpace,
                                         hintForSeamlessTransition, allowSecureLayers);
    }
};

struct LayerRenderAreaBuilder : RenderAreaBuilder {
    LayerRenderAreaBuilder(Rect crop, ui::Size reqSize, ui::Dataspace reqDataSpace,
                           bool allowSecureLayers, bool hintForSeamlessTransition, sp<Layer> layer,
                           bool childrenOnly)
          : RenderAreaBuilder(crop, reqSize, reqDataSpace, allowSecureLayers,
                              hintForSeamlessTransition),
            layer(layer),
            childrenOnly(childrenOnly) {}

    // Layer that the render area will be on
    sp<Layer> layer;

    // Transform to be applied on the layers to transform them
    // into the logical render area
    ui::Transform layerTransform{ui::Transform()};

    // Buffer bounds
    Rect layerBufferSize{Rect()};

    // If false, transform is inverted from the parent snapshot
    bool childrenOnly;

    // Uses parent snapshot to determine layer transform and buffer size
    void setLayerInfo(const frontend::LayerSnapshot* parentSnapshot) {
        if (!childrenOnly) {
            layerTransform = parentSnapshot->localTransform.inverse();
        }
        layerBufferSize = parentSnapshot->bufferSize;
    }

    std::unique_ptr<RenderArea> build() const override {
        return std::make_unique<LayerRenderArea>(layer, crop, reqSize, reqDataSpace,
                                                 allowSecureLayers, layerTransform, layerBufferSize,
                                                 hintForSeamlessTransition);
    }
};

} // namespace android