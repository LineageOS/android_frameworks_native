/*
 * Copyright (C) 2007 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "ColorLayer"

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <renderengine/RenderEngine.h>
#include <ui/GraphicBuffer.h>
#include <utils/Errors.h>
#include <utils/Log.h>

#include "ColorLayer.h"
#include "DisplayDevice.h"
#include "SurfaceFlinger.h"

namespace android {
// ---------------------------------------------------------------------------

ColorLayer::ColorLayer(const LayerCreationArgs& args) : Layer(args) {}

ColorLayer::~ColorLayer() = default;

void ColorLayer::onDraw(const RenderArea& renderArea, const Region& /* clip */,
                        bool useIdentityTransform) {
    half4 color = getColor();
    if (color.a > 0) {
        renderengine::Mesh mesh(renderengine::Mesh::TRIANGLE_FAN, 4, 2);
        computeGeometry(renderArea, mesh, useIdentityTransform);
        auto& engine(mFlinger->getRenderEngine());
        engine.setupLayerBlending(getPremultipledAlpha(), false /* opaque */,
                                  true /* disableTexture */, color);
        engine.setSourceDataSpace(mCurrentDataSpace);
        engine.drawMesh(mesh);
        engine.disableBlending();
    }
}

bool ColorLayer::isVisible() const {
    return !isHiddenByPolicy() && getAlpha() > 0.0f;
}

void ColorLayer::setPerFrameData(DisplayId displayId, const ui::Transform& transform,
                                 const Rect& viewport, int32_t /* supportedPerFrameMetadata */) {
    RETURN_IF_NO_HWC_LAYER(displayId);

    Region visible = transform.transform(visibleRegion.intersect(viewport));

    auto& hwcInfo = getBE().mHwcLayers[displayId];
    auto& hwcLayer = hwcInfo.layer;
    auto error = hwcLayer->setVisibleRegion(visible);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set visible region: %s (%d)", mName.string(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        visible.dump(LOG_TAG);
    }
    getBE().compositionInfo.hwc.visibleRegion = visible;

    setCompositionType(displayId, HWC2::Composition::SolidColor);

    error = hwcLayer->setDataspace(mCurrentDataSpace);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set dataspace %d: %s (%d)", mName.string(), mCurrentDataSpace,
              to_string(error).c_str(), static_cast<int32_t>(error));
    }
    getBE().compositionInfo.hwc.dataspace = mCurrentDataSpace;

    half4 color = getColor();
    error = hwcLayer->setColor({static_cast<uint8_t>(std::round(255.0f * color.r)),
                                static_cast<uint8_t>(std::round(255.0f * color.g)),
                                static_cast<uint8_t>(std::round(255.0f * color.b)), 255});
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set color: %s (%d)", mName.string(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
    getBE().compositionInfo.hwc.color = { static_cast<uint8_t>(std::round(255.0f * color.r)),
                                      static_cast<uint8_t>(std::round(255.0f * color.g)),
                                      static_cast<uint8_t>(std::round(255.0f * color.b)), 255 };

    // Clear out the transform, because it doesn't make sense absent a source buffer
    error = hwcLayer->setTransform(HWC2::Transform::None);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to clear transform: %s (%d)", mName.string(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
    getBE().compositionInfo.hwc.transform = HWC2::Transform::None;

    error = hwcLayer->setColorTransform(getColorTransform());
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to setColorTransform: %s (%d)", mName.string(),
                to_string(error).c_str(), static_cast<int32_t>(error));
    }
    getBE().compositionInfo.hwc.colorTransform = getColorTransform();

    error = hwcLayer->setSurfaceDamage(surfaceDamageRegion);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set surface damage: %s (%d)", mName.string(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        surfaceDamageRegion.dump(LOG_TAG);
    }
    getBE().compositionInfo.hwc.surfaceDamage = surfaceDamageRegion;
}

// ---------------------------------------------------------------------------

}; // namespace android
