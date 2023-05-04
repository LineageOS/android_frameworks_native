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
namespace {

void reparentForDrawing(const sp<Layer>& oldParent, const sp<Layer>& newParent,
                   const Rect& drawingBounds) {
        // Compute and cache the bounds for the new parent layer.
        newParent->computeBounds(drawingBounds.toFloatRect(), ui::Transform(),
            0.f /* shadowRadius */);
        newParent->updateSnapshot(true /* updateGeometry */);
        oldParent->setChildrenDrawingParent(newParent);
};

} // namespace

LayerRenderArea::LayerRenderArea(SurfaceFlinger& flinger, sp<Layer> layer, const Rect& crop,
                                 ui::Size reqSize, ui::Dataspace reqDataSpace, bool childrenOnly,
                                 bool allowSecureLayers, const ui::Transform& layerTransform,
                                 const Rect& layerBufferSize)
      : RenderArea(reqSize, CaptureFill::CLEAR, reqDataSpace, allowSecureLayers),
        mLayer(std::move(layer)),
        mLayerTransform(layerTransform),
        mLayerBufferSize(layerBufferSize),
        mCrop(crop),
        mFlinger(flinger),
        mChildrenOnly(childrenOnly) {}

const ui::Transform& LayerRenderArea::getTransform() const {
    return mTransform;
}

bool LayerRenderArea::isSecure() const {
    return mAllowSecureLayers;
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

void LayerRenderArea::render(std::function<void()> drawLayers) {
    using namespace std::string_literals;

    if (!mChildrenOnly) {
        mTransform = mLayerTransform.inverse();
    }

    if (mFlinger.mLayerLifecycleManagerEnabled) {
        drawLayers();
        return;
    }
    // If layer is offscreen, update mirroring info if it exists
    if (mLayer->isRemovedFromCurrentState()) {
        mLayer->traverse(LayerVector::StateSet::Drawing,
                         [&](Layer* layer) { layer->updateMirrorInfo(); });
        mLayer->traverse(LayerVector::StateSet::Drawing,
                         [&](Layer* layer) { layer->updateCloneBufferInfo(); });
    }

    if (!mChildrenOnly) {
        // If the layer is offscreen, compute bounds since we don't compute bounds for offscreen
        // layers in a regular cycles.
        if (mLayer->isRemovedFromCurrentState()) {
            FloatRect maxBounds = mFlinger.getMaxDisplayBounds();
            mLayer->computeBounds(maxBounds, ui::Transform(), 0.f /* shadowRadius */);
        }
        drawLayers();
    } else {
        // In the "childrenOnly" case we reparent the children to a screenshot
        // layer which has no properties set and which does not draw.
        //  We hold the statelock as the reparent-for-drawing operation modifies the
        //  hierarchy and there could be readers on Binder threads, like dump.
        auto screenshotParentLayer = mFlinger.getFactory().createEffectLayer(
                {&mFlinger, nullptr, "Screenshot Parent"s, ISurfaceComposerClient::eNoColorFill,
                 LayerMetadata()});
        {
            Mutex::Autolock _l(mFlinger.mStateLock);
            reparentForDrawing(mLayer, screenshotParentLayer, getSourceCrop());
        }
        drawLayers();
        {
            Mutex::Autolock _l(mFlinger.mStateLock);
            mLayer->setChildrenDrawingParent(mLayer);
        }
    }
}

} // namespace android
