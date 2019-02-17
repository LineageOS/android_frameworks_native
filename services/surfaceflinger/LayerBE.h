/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdint.h>
#include <string.h>

#include <ui/Fence.h>
#include <utils/StrongPointer.h>

#include "DisplayHardware/DisplayIdentification.h"

namespace android {

class LayerBE;

struct CompositionInfo {
    std::string layerName;
    std::shared_ptr<LayerBE> layer;
    struct {
        DisplayId displayId;
    } hwc;
};

class LayerBE {
public:
    friend class Layer;
    friend class BufferLayer;
    friend class BufferQueueLayer;
    friend class BufferStateLayer;
    friend class ColorLayer;
    friend class SurfaceFlinger;

    // For unit tests
    friend class TestableSurfaceFlinger;

    LayerBE(Layer* layer, std::string layerName);
    explicit LayerBE(const LayerBE& layer);

    void onLayerDisplayed(const sp<Fence>& releaseFence);

    Layer*const mLayer;

private:
    CompositionInfo compositionInfo;
};

}; // namespace android

