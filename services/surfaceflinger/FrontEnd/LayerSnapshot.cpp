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
    // Provide a unique id for all snapshots.
    // A front end layer can generate multiple snapshots if its mirrored.
    // Additionally, if the layer is not reachable, we may choose to destroy
    // and recreate the snapshot in which case the unique sequence id will
    // change. The consumer shouldn't tie any lifetimes to this unique id but
    // register a LayerLifecycleManager::ILifecycleListener or get a list of
    // destroyed layers from LayerLifecycleManager.
    if (path.isClone()) {
        uniqueSequence =
                LayerCreationArgs::getInternalLayerId(LayerCreationArgs::sInternalSequence++);
    } else {
        uniqueSequence = state.id;
    }
    sequence = static_cast<int32_t>(state.id);
    name = state.name;
    textureName = state.textureName;
    premultipliedAlpha = state.premultipliedAlpha;
    inputInfo.name = state.name;
    inputInfo.id = static_cast<int32_t>(uniqueSequence);
    inputInfo.ownerUid = gui::Uid{state.ownerUid};
    inputInfo.ownerPid = state.ownerPid;
    uid = state.ownerUid;
    pid = state.ownerPid;
    changes = RequestedLayerState::Changes::Created;
    mirrorRootPath = path.variant == LayerHierarchy::Variant::Mirror
            ? path
            : LayerHierarchy::TraversalPath::ROOT;
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
    return ((sidebandStream != nullptr) || (externalTexture != nullptr));
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
        isOpaqueFormat(externalTexture ? externalTexture->getPixelFormat() : PIXEL_FORMAT_NONE)) {
        return true;
    }

    // Lastly consider the layer opaque if drawing a color with alpha == 1.0
    return fillsColor() && color.a == 1.0_hf;
}

bool LayerSnapshot::isHiddenByPolicy() const {
    return invalidTransform || isHiddenByPolicyFromParent || isHiddenByPolicyFromRelativeParent;
}

bool LayerSnapshot::getIsVisible() const {
    if (handleSkipScreenshotFlag & outputFilter.toInternalDisplay) {
        return false;
    }

    if (!hasSomethingToDraw()) {
        return false;
    }

    if (isHiddenByPolicy()) {
        return false;
    }

    return color.a > 0.0f || hasBlur();
}

std::string LayerSnapshot::getIsVisibleReason() const {
    // not visible
    if (handleSkipScreenshotFlag & outputFilter.toInternalDisplay) return "eLayerSkipScreenshot";
    if (!hasSomethingToDraw()) return "!hasSomethingToDraw";
    if (invalidTransform) return "invalidTransform";
    if (isHiddenByPolicyFromParent) return "hidden by parent or layer flag";
    if (isHiddenByPolicyFromRelativeParent) return "hidden by relative parent";
    if (color.a == 0.0f && !hasBlur()) return "alpha = 0 and no blur";

    // visible
    std::stringstream reason;
    if (sidebandStream != nullptr) reason << " sidebandStream";
    if (externalTexture != nullptr)
        reason << " buffer:" << externalTexture->getId() << " frame:" << frameNumber;
    if (fillsColor() || color.a > 0.0f) reason << " color{" << color << "}";
    if (drawShadows()) reason << " shadowSettings.length=" << shadowSettings.length;
    if (backgroundBlurRadius > 0) reason << " backgroundBlurRadius=" << backgroundBlurRadius;
    if (blurRegions.size() > 0) reason << " blurRegions.size()=" << blurRegions.size();
    return reason.str();
}

bool LayerSnapshot::canReceiveInput() const {
    return !isHiddenByPolicy() && (!hasBufferOrSidebandStream() || color.a > 0.0f);
}

bool LayerSnapshot::isTransformValid(const ui::Transform& t) {
    float transformDet = t.det();
    return transformDet != 0 && !isinf(transformDet) && !isnan(transformDet);
}

bool LayerSnapshot::hasInputInfo() const {
    return inputInfo.token != nullptr ||
            inputInfo.inputConfig.test(gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL);
}

std::string LayerSnapshot::getDebugString() const {
    std::stringstream debug;
    debug << "Snapshot{" << path.toString() << name << " isVisible=" << isVisible << " {"
          << getIsVisibleReason() << "} changes=" << changes.string()
          << " layerStack=" << outputFilter.layerStack.id << " geomLayerBounds={"
          << geomLayerBounds.left << "," << geomLayerBounds.top << "," << geomLayerBounds.bottom
          << "," << geomLayerBounds.right << "}"
          << " geomLayerTransform={tx=" << geomLayerTransform.tx()
          << ",ty=" << geomLayerTransform.ty() << "}"
          << "}";
    debug << " input{ touchCropId=" << touchCropId
          << " replaceTouchableRegionWithCrop=" << inputInfo.replaceTouchableRegionWithCrop << "}";
    return debug.str();
}

FloatRect LayerSnapshot::sourceBounds() const {
    if (!externalTexture) {
        return geomLayerBounds;
    }
    return geomBufferSize.toFloatRect();
}

} // namespace android::surfaceflinger::frontend
