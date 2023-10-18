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
#define LOG_TAG "SurfaceFlinger"

#include "LayerSnapshot.h"

namespace android::surfaceflinger::frontend {

using namespace ftl::flag_operators;

namespace {

void updateSurfaceDamage(const RequestedLayerState& requested, bool hasReadyFrame,
                         bool forceFullDamage, Region& outSurfaceDamageRegion) {
    if (!hasReadyFrame) {
        outSurfaceDamageRegion.clear();
        return;
    }
    if (forceFullDamage) {
        outSurfaceDamageRegion = Region::INVALID_REGION;
    } else {
        outSurfaceDamageRegion = requested.surfaceDamageRegion;
    }
}

} // namespace

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
    inputInfo.ownerPid = gui::Pid{state.ownerPid};
    uid = state.ownerUid;
    pid = state.ownerPid;
    changes = RequestedLayerState::Changes::Created;
    clientChanges = 0;
    mirrorRootPath = path.variant == LayerHierarchy::Variant::Mirror
            ? path
            : LayerHierarchy::TraversalPath::ROOT;
    reachablilty = LayerSnapshot::Reachablilty::Unreachable;
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
    if (reachablilty != LayerSnapshot::Reachablilty::Reachable) {
        return false;
    }

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
    if (reachablilty == LayerSnapshot::Reachablilty::Unreachable)
        return "layer not reachable from root";
    if (reachablilty == LayerSnapshot::Reachablilty::ReachableByRelativeParent)
        return "layer only reachable via relative parent";
    if (isHiddenByPolicyFromParent) return "hidden by parent or layer flag";
    if (isHiddenByPolicyFromRelativeParent) return "hidden by relative parent";
    if (handleSkipScreenshotFlag & outputFilter.toInternalDisplay) return "eLayerSkipScreenshot";
    if (invalidTransform) return "invalidTransform";
    if (color.a == 0.0f && !hasBlur()) return "alpha = 0 and no blur";
    if (!hasSomethingToDraw()) return "!hasSomethingToDraw";

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
    return (inputInfo.token != nullptr ||
            inputInfo.inputConfig.test(gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL)) &&
            reachablilty == Reachablilty::Reachable;
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
    if (hasInputInfo()) {
        debug << " input{"
              << "(" << inputInfo.inputConfig.string() << ")";
        if (touchCropId != UNASSIGNED_LAYER_ID) debug << " touchCropId=" << touchCropId;
        if (inputInfo.replaceTouchableRegionWithCrop) debug << " replaceTouchableRegionWithCrop";
        auto touchableRegion = inputInfo.touchableRegion.getBounds();
        debug << " touchableRegion={" << touchableRegion.left << "," << touchableRegion.top << ","
              << touchableRegion.bottom << "," << touchableRegion.right << "}"
              << "}";
    }
    return debug.str();
}

FloatRect LayerSnapshot::sourceBounds() const {
    if (!externalTexture) {
        return geomLayerBounds;
    }
    return geomBufferSize.toFloatRect();
}

Hwc2::IComposerClient::BlendMode LayerSnapshot::getBlendMode(
        const RequestedLayerState& requested) const {
    auto blendMode = Hwc2::IComposerClient::BlendMode::NONE;
    if (alpha != 1.0f || !contentOpaque) {
        blendMode = requested.premultipliedAlpha ? Hwc2::IComposerClient::BlendMode::PREMULTIPLIED
                                                 : Hwc2::IComposerClient::BlendMode::COVERAGE;
    }
    return blendMode;
}

void LayerSnapshot::merge(const RequestedLayerState& requested, bool forceUpdate,
                          bool displayChanges, bool forceFullDamage,
                          uint32_t displayRotationFlags) {
    clientChanges = requested.what;
    changes = requested.changes;
    contentDirty = requested.what & layer_state_t::CONTENT_DIRTY;
    // TODO(b/238781169) scope down the changes to only buffer updates.
    hasReadyFrame = requested.hasReadyFrame();
    sidebandStreamHasFrame = requested.hasSidebandStreamFrame();
    updateSurfaceDamage(requested, hasReadyFrame, forceFullDamage, surfaceDamage);

    if (forceUpdate || requested.what & layer_state_t::eTransparentRegionChanged) {
        transparentRegionHint = requested.transparentRegion;
    }
    if (forceUpdate || requested.what & layer_state_t::eFlagsChanged) {
        layerOpaqueFlagSet =
                (requested.flags & layer_state_t::eLayerOpaque) == layer_state_t::eLayerOpaque;
    }
    if (forceUpdate || requested.what & layer_state_t::eBufferTransformChanged) {
        geomBufferTransform = requested.bufferTransform;
    }
    if (forceUpdate || requested.what & layer_state_t::eTransformToDisplayInverseChanged) {
        geomBufferUsesDisplayInverseTransform = requested.transformToDisplayInverse;
    }
    if (forceUpdate || requested.what & layer_state_t::eDataspaceChanged) {
        dataspace = requested.dataspace;
    }
    if (forceUpdate || requested.what & layer_state_t::eExtendedRangeBrightnessChanged) {
        currentHdrSdrRatio = requested.currentHdrSdrRatio;
        desiredHdrSdrRatio = requested.desiredHdrSdrRatio;
    }
    if (forceUpdate || requested.what & layer_state_t::eCachingHintChanged) {
        cachingHint = requested.cachingHint;
    }
    if (forceUpdate || requested.what & layer_state_t::eHdrMetadataChanged) {
        hdrMetadata = requested.hdrMetadata;
    }
    if (forceUpdate || requested.what & layer_state_t::eSidebandStreamChanged) {
        sidebandStream = requested.sidebandStream;
    }
    if (forceUpdate || requested.what & layer_state_t::eShadowRadiusChanged) {
        shadowRadius = requested.shadowRadius;
        shadowSettings.length = requested.shadowRadius;
    }
    if (forceUpdate || requested.what & layer_state_t::eFrameRateSelectionPriority) {
        frameRateSelectionPriority = requested.frameRateSelectionPriority;
    }
    if (forceUpdate || requested.what & layer_state_t::eColorSpaceAgnosticChanged) {
        isColorspaceAgnostic = requested.colorSpaceAgnostic;
    }
    if (forceUpdate || requested.what & layer_state_t::eDimmingEnabledChanged) {
        dimmingEnabled = requested.dimmingEnabled;
    }
    if (forceUpdate || requested.what & layer_state_t::eCropChanged) {
        geomCrop = requested.crop;
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eFlagsChanged | layer_state_t::eBufferChanged |
                 layer_state_t::eSidebandStreamChanged)) {
        compositionType = requested.getCompositionType();
    }

    if (forceUpdate || requested.what & layer_state_t::eInputInfoChanged) {
        if (requested.windowInfoHandle) {
            inputInfo = *requested.windowInfoHandle->getInfo();
        } else {
            inputInfo = {};
            // b/271132344 revisit this and see if we can always use the layers uid/pid
            inputInfo.name = requested.name;
            inputInfo.ownerUid = requested.ownerUid;
            inputInfo.ownerPid = requested.ownerPid;
        }
        inputInfo.id = static_cast<int32_t>(uniqueSequence);
        touchCropId = requested.touchCropId;
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eColorChanged | layer_state_t::eBufferChanged |
                 layer_state_t::eSidebandStreamChanged)) {
        color.rgb = requested.getColor().rgb;
    }

    if (forceUpdate || requested.what & layer_state_t::eBufferChanged) {
        acquireFence =
                (requested.externalTexture &&
                 requested.bufferData->flags.test(BufferData::BufferDataChange::fenceChanged))
                ? requested.bufferData->acquireFence
                : Fence::NO_FENCE;
        buffer = requested.externalTexture ? requested.externalTexture->getBuffer() : nullptr;
        externalTexture = requested.externalTexture;
        frameNumber = (requested.bufferData) ? requested.bufferData->frameNumber : 0;
        hasProtectedContent = requested.externalTexture &&
                requested.externalTexture->getUsage() & GRALLOC_USAGE_PROTECTED;
        geomUsesSourceCrop = hasBufferOrSidebandStream();
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eCropChanged | layer_state_t::eBufferCropChanged |
                 layer_state_t::eBufferTransformChanged |
                 layer_state_t::eTransformToDisplayInverseChanged) ||
        requested.changes.test(RequestedLayerState::Changes::BufferSize) || displayChanges) {
        bufferSize = requested.getBufferSize(displayRotationFlags);
        geomBufferSize = bufferSize;
        croppedBufferSize = requested.getCroppedBufferSize(bufferSize);
        geomContentCrop = requested.getBufferCrop();
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eFlagsChanged | layer_state_t::eDestinationFrameChanged |
                 layer_state_t::ePositionChanged | layer_state_t::eMatrixChanged |
                 layer_state_t::eBufferTransformChanged |
                 layer_state_t::eTransformToDisplayInverseChanged) ||
        requested.changes.test(RequestedLayerState::Changes::BufferSize) || displayChanges) {
        localTransform = requested.getTransform(displayRotationFlags);
        localTransformInverse = localTransform.inverse();
    }

    if (forceUpdate || requested.what & (layer_state_t::eColorChanged) ||
        requested.changes.test(RequestedLayerState::Changes::BufferSize)) {
        color.rgb = requested.getColor().rgb;
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eBufferChanged | layer_state_t::eDataspaceChanged |
                 layer_state_t::eApiChanged)) {
        isHdrY410 = requested.dataspace == ui::Dataspace::BT2020_ITU_PQ &&
                requested.api == NATIVE_WINDOW_API_MEDIA &&
                requested.bufferData->getPixelFormat() == HAL_PIXEL_FORMAT_RGBA_1010102;
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eBufferChanged | layer_state_t::eDataspaceChanged |
                 layer_state_t::eApiChanged | layer_state_t::eShadowRadiusChanged |
                 layer_state_t::eBlurRegionsChanged | layer_state_t::eStretchChanged)) {
        forceClientComposition = isHdrY410 || shadowSettings.length > 0 ||
                requested.blurRegions.size() > 0 || stretchEffect.hasEffect();
    }

    if (forceUpdate ||
        requested.what &
                (layer_state_t::eColorChanged | layer_state_t::eShadowRadiusChanged |
                 layer_state_t::eBlurRegionsChanged | layer_state_t::eBackgroundBlurRadiusChanged |
                 layer_state_t::eCornerRadiusChanged | layer_state_t::eAlphaChanged |
                 layer_state_t::eFlagsChanged | layer_state_t::eBufferChanged |
                 layer_state_t::eSidebandStreamChanged)) {
        contentOpaque = isContentOpaque();
        isOpaque = contentOpaque && !roundedCorner.hasRoundedCorners() && color.a == 1.f;
        blendMode = getBlendMode(requested);
    }
}

} // namespace android::surfaceflinger::frontend
