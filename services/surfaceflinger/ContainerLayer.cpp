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

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "ContainerLayer"

#include "ContainerLayer.h"

namespace android {

ContainerLayer::ContainerLayer(const LayerCreationArgs& args) : Layer(args) {}

ContainerLayer::~ContainerLayer() = default;

bool ContainerLayer::prepareClientLayer(const RenderArea&, const Region&, bool, Region&, const bool,
                                        renderengine::LayerSettings&) {
    return false;
}

bool ContainerLayer::isVisible() const {
    return false;
}

bool ContainerLayer::canReceiveInput() const {
    return !isHiddenByPolicy();
}

void ContainerLayer::setPerFrameData(const sp<const DisplayDevice>&, const ui::Transform&,
                                     const Rect&, int32_t, const ui::Dataspace) {}

Layer::RoundedCornerState ContainerLayer::getRoundedCornerStateInternal(
        const FloatRect bounds) const {
    const auto& p = mDrawingParent.promote();
    if (p != nullptr) {
        RoundedCornerState parentState = p->getRoundedCornerStateInternal(bounds);
        if (parentState.radius > 0) {
            ui::Transform t = getActiveTransform(getDrawingState());
            t = t.inverse();
            parentState.cropRect = t.transform(parentState.cropRect);
            // The rounded corners shader only accepts 1 corner radius for performance reasons,
            // but a transform matrix can define horizontal and vertical scales.
            // Let's take the average between both of them and pass into the shader, practically we
            // never do this type of transformation on windows anyway.
            parentState.radius *= (t[0][0] + t[1][1]) / 2.0f;
            return parentState;
        }
    }
    const float radius = getDrawingState().cornerRadius;
    if (radius > 0) {
        const Rect crop = getCrop(getDrawingState());
        if (!crop.isEmpty()) {
            return RoundedCornerState(bounds.intersect(crop.toFloatRect()), radius);
        }
        return RoundedCornerState(bounds, radius);
    }
    return RoundedCornerState();
}

} // namespace android
