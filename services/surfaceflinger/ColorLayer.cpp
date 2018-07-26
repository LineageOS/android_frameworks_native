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

#include <utils/Errors.h>
#include <utils/Log.h>

#include <ui/GraphicBuffer.h>

#include "ColorLayer.h"
#include "DisplayDevice.h"
#include "RenderEngine/RenderEngine.h"
#include "SurfaceFlinger.h"

namespace android {
// ---------------------------------------------------------------------------

ColorLayer::ColorLayer(SurfaceFlinger* flinger, const sp<Client>& client, const String8& name,
                       uint32_t w, uint32_t h, uint32_t flags)
      : Layer(flinger, client, name, w, h, flags) {
    // drawing state & current state are identical
    mDrawingState = mCurrentState;
}

void ColorLayer::onDraw(const RenderArea& renderArea, const Region& /* clip */,
                        bool useIdentityTransform) const {
    half4 color = getColor();
    if (color.a > 0) {
        computeGeometry(renderArea, getBE().mMesh, useIdentityTransform);
        getBE().compositionInfo.re.preMultipliedAlpha = getPremultipledAlpha();
        getBE().compositionInfo.re.opaque = false;
        getBE().compositionInfo.re.disableTexture = true;
        getBE().compositionInfo.re.color = color;
    }
}

void ColorLayer::drawNow(const RenderArea& renderArea, bool useIdentityTransform) const {
    CompositionInfo& compositionInfo = getBE().compositionInfo;
    auto& engine(mFlinger->getRenderEngine());

    draw(renderArea, useIdentityTransform);

    engine.setupLayerBlending(compositionInfo.re.preMultipliedAlpha, compositionInfo.re.opaque,
            compositionInfo.re.disableTexture, compositionInfo.re.color);
    engine.setSourceDataSpace(compositionInfo.hwc.dataspace);
    engine.drawMesh(getBE().getMesh());
    engine.disableBlending();
}

bool ColorLayer::isVisible() const {
    return !isHiddenByPolicy() && getAlpha() > 0.0f;
}

void ColorLayer::setPerFrameData(const sp<const DisplayDevice>& display) {
    const Transform& tr = display->getTransform();
    const auto& viewport = display->getViewport();
    Region visible = tr.transform(visibleRegion.intersect(viewport));
    const auto displayId = display->getId();
    if (!hasHwcLayer(displayId)) {
        ALOGE("[%s] failed to setPerFrameData: no HWC layer found (%d)",
              mName.string(), displayId);
        return;
    }
    auto& hwcInfo = getBE().mHwcLayers[displayId];
    auto& hwcLayer = hwcInfo.layer;
    auto error = hwcLayer->setVisibleRegion(visible);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set visible region: %s (%d)", mName.string(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        visible.dump(LOG_TAG);
    }

    setCompositionType(displayId, HWC2::Composition::SolidColor);

    error = hwcLayer->setDataspace(mCurrentDataSpace);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set dataspace %d: %s (%d)", mName.string(), mCurrentDataSpace,
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    half4 color = getColor();
    error = hwcLayer->setColor({static_cast<uint8_t>(std::round(255.0f * color.r)),
                                static_cast<uint8_t>(std::round(255.0f * color.g)),
                                static_cast<uint8_t>(std::round(255.0f * color.b)), 255});
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set color: %s (%d)", mName.string(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    // Clear out the transform, because it doesn't make sense absent a source buffer
    error = hwcLayer->setTransform(HWC2::Transform::None);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to clear transform: %s (%d)", mName.string(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

// ---------------------------------------------------------------------------

}; // namespace android
