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

#include <gui/DisplayInfo.h>

#include "FrontEnd/LayerCreationArgs.h"
#include "RequestedLayerState.h"
#include "TransactionState.h"

namespace android {
struct LayerCreatedState {
    LayerCreatedState(const wp<Layer>& layer, const wp<Layer>& parent, bool addToRoot)
          : layer(layer), initialParent(parent), addToRoot(addToRoot) {}
    wp<Layer> layer;
    // Indicates the initial parent of the created layer, only used for creating layer in
    // SurfaceFlinger. If nullptr, it may add the created layer into the current root layers.
    wp<Layer> initialParent;
    // Indicates whether the layer getting created should be added at root if there's no parent
    // and has permission ACCESS_SURFACE_FLINGER. If set to false and no parent, the layer will
    // be added offscreen.
    bool addToRoot;
};
} // namespace android

namespace android::surfaceflinger::frontend {

// Atomic set of changes affecting layer state. These changes are queued in binder threads and
// applied every vsync.
struct Update {
    std::vector<TransactionState> transactions;
    std::vector<LayerCreatedState> layerCreatedStates;
    std::vector<std::unique_ptr<frontend::RequestedLayerState>> newLayers;
    std::vector<LayerCreationArgs> layerCreationArgs;
    std::vector<std::pair<uint32_t, std::string /* debugName */>> destroyedHandles;
};

} // namespace android::surfaceflinger::frontend
