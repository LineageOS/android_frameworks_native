/*
 * Copyright 2020 The Android Open Source Project
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

#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include "DisplayDevice.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "Layer.h"
#include "LayerRenderArea.h"
#include "SurfaceFlinger.h"

namespace android {

LayerRenderArea::LayerRenderArea(sp<Layer> layer, frontend::LayerSnapshot layerSnapshot,
                                 const Rect& crop, ui::Size reqSize, ui::Dataspace reqDataSpace,
                                 const ui::Transform& layerTransform, const Rect& layerBufferSize,
                                 ftl::Flags<RenderArea::Options> options)
      : RenderArea(reqSize, CaptureFill::CLEAR, reqDataSpace, options),
        mLayer(std::move(layer)),
        mLayerSnapshot(std::move(layerSnapshot)),
        mLayerBufferSize(layerBufferSize),
        mCrop(crop),
        mTransform(layerTransform) {}

const ui::Transform& LayerRenderArea::getTransform() const {
    return mTransform;
}

bool LayerRenderArea::isSecure() const {
    return mOptions.test(Options::CAPTURE_SECURE_LAYERS);
}

sp<const DisplayDevice> LayerRenderArea::getDisplayDevice() const {
    return nullptr;
}

Rect LayerRenderArea::getSourceCrop() const {
    if (mCrop.isEmpty()) {
        // TODO this should probably be mBounds instead of just buffer bounds
        return mLayerBufferSize;
    } else {
        return mCrop;
    }
}

} // namespace android
