/*
 * Copyright 2022 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#undef LOG_TAG
#define LOG_TAG "LayerSnapshot"

#include "LayerSnapshot.h"

namespace android::surfaceflinger::frontend {

using namespace ftl::flag_operators;

LayerSnapshot::LayerSnapshot(const RequestedLayerState& state,
                             const LayerHierarchy::TraversalPath& path)
      : path(path) {
    sequence = static_cast<int32_t>(state.id);
    name = state.name;
    textureName = state.textureName;
    premultipliedAlpha = state.premultipliedAlpha;
    inputInfo.name = state.name;
    inputInfo.id = static_cast<int32_t>(state.id);
    inputInfo.ownerUid = static_cast<int32_t>(state.ownerUid);
    inputInfo.ownerPid = state.ownerPid;
}

// As documented in libhardware header, formats in the range
// 0x100 - 0x1FF are specific to the HAL implementation, and
// are known to have no alpha channel
// TODO: move definition for device-specific range into
// hardware.h, instead of using hard-coded values here.
#define HARDWARE_IS_DEVICE_FORMAT(f) ((f) >= 0x100 && (f) <= 0x1FF)

bool LayerSnapshot::isOpaqueFormat(PixelFormat format) {
    if (HARDWARE_IS_DEVICE_FORMAT(format)) {
        return true;
    }
    switch (format) {
        case PIXEL_FORMAT_RGBA_8888:
        case PIXEL_FORMAT_BGRA_8888:
        case PIXEL_FORMAT_RGBA_FP16:
        case PIXEL_FORMAT_RGBA_1010102:
        case PIXEL_FORMAT_R_8:
            return false;
    }
    // in all other case, we have no blending (also for unknown formats)
    return true;
}

bool LayerSnapshot::hasBufferOrSidebandStream() const {
    return ((sidebandStream != nullptr) || (buffer != nullptr));
}

bool LayerSnapshot::drawShadows() const {
    return shadowSettings.length > 0.f;
}

bool LayerSnapshot::fillsColor() const {
    return !hasBufferOrSidebandStream() && color.r >= 0.0_hf && color.g >= 0.0_hf &&
            color.b >= 0.0_hf;
}

bool LayerSnapshot::hasBlur() const {
    return backgroundBlurRadius > 0 || blurRegions.size() > 0;
}

bool LayerSnapshot::hasEffect() const {
    return fillsColor() || drawShadows() || hasBlur();
}

bool LayerSnapshot::hasSomethingToDraw() const {
    return hasEffect() || hasBufferOrSidebandStream();
}

bool LayerSnapshot::isContentOpaque() const {
    // if we don't have a buffer or sidebandStream yet, we're translucent regardless of the
    // layer's opaque flag.
    if (!hasSomethingToDraw()) {
        return false;
    }

    // if the layer has the opaque flag, then we're always opaque
    if (layerOpaqueFlagSet) {
        return true;
    }

    // If the buffer has no alpha channel, then we are opaque
    if (hasBufferOrSidebandStream() &&
        isOpaqueFormat(buffer ? buffer->getPixelFormat() : PIXEL_FORMAT_NONE)) {
        return true;
    }

    // Lastly consider the layer opaque if drawing a color with alpha == 1.0
    return fillsColor() && color.a == 1.0_hf;
}

bool LayerSnapshot::isHiddenByPolicy() const {
    if (CC_UNLIKELY(invalidTransform)) {
        ALOGW("Hide layer %s because it has invalid transformation.", name.c_str());
        return true;
    }
    return isHiddenByPolicyFromParent || isHiddenByPolicyFromRelativeParent;
}

bool LayerSnapshot::getIsVisible() const {
    if (!hasSomethingToDraw()) {
        return false;
    }

    if (isHiddenByPolicy()) {
        return false;
    }

    return color.a > 0.0f || hasBlur();
}

std::string LayerSnapshot::getIsVisibleReason() const {
    if (!hasSomethingToDraw()) {
        return "!hasSomethingToDraw";
    }

    if (isHiddenByPolicy()) {
        return "isHiddenByPolicy";
    }

    if (color.a > 0.0f || hasBlur()) {
        return "";
    }

    return "alpha = 0 and !hasBlur";
}

bool LayerSnapshot::canReceiveInput() const {
    return !isHiddenByPolicy() && (!hasBufferOrSidebandStream() || color.a > 0.0f);
}

bool LayerSnapshot::isTransformValid(const ui::Transform& t) {
    float transformDet = t.det();
    return transformDet != 0 && !isinf(transformDet) && !isnan(transformDet);
}

std::string LayerSnapshot::getDebugString() const {
    return "Snapshot(" + base::StringPrintf("%p", this) + "){" + path.toString() + name +
            " isHidden=" + std::to_string(isHiddenByPolicyFromParent) +
            " isHiddenRelative=" + std::to_string(isHiddenByPolicyFromRelativeParent) +
            " isVisible=" + std::to_string(isVisible) + " " + getIsVisibleReason() + "}";
}

} // namespace android::surfaceflinger::frontend
