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

#pragma once

#include <string>

#include <ui/GraphicTypes.h>
#include <ui/Transform.h>
#include <utils/StrongPointer.h>

#include "RenderArea.h"

namespace android {

class DisplayDevice;
class Layer;
class SurfaceFlinger;

class LayerRenderArea : public RenderArea {
public:
    LayerRenderArea(sp<Layer> layer, frontend::LayerSnapshot layerSnapshot, const Rect& crop,
                    ui::Size reqSize, ui::Dataspace reqDataSpace,
                    const ui::Transform& layerTransform, const Rect& layerBufferSize,
                    ftl::Flags<RenderArea::Options> options);

    const ui::Transform& getTransform() const override;
    bool isSecure() const override;
    sp<const DisplayDevice> getDisplayDevice() const override;
    Rect getSourceCrop() const override;

    sp<Layer> getParentLayer() const override { return mLayer; }
    const frontend::LayerSnapshot* getLayerSnapshot() const override { return &mLayerSnapshot; }

private:
    const sp<Layer> mLayer;
    const frontend::LayerSnapshot mLayerSnapshot;
    const Rect mLayerBufferSize;
    const Rect mCrop;

    ui::Transform mTransform;
};

} // namespace android
