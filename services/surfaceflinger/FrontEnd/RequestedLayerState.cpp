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

#include "FrontEnd/LayerCreationArgs.h"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#undef LOG_TAG
#define LOG_TAG "RequestedLayerState"

#include <private/android_filesystem_config.h>
#include <sys/types.h>

#include "Layer.h"
#include "LayerHandle.h"
#include "RequestedLayerState.h"

namespace android::surfaceflinger::frontend {
using ftl::Flags;
using namespace ftl::flag_operators;

namespace {
uint32_t getLayerIdFromSurfaceControl(sp<SurfaceControl> surfaceControl) {
    if (!surfaceControl) {
        return UNASSIGNED_LAYER_ID;
    }

    return LayerHandle::getLayerId(surfaceControl->getHandle());
}

std::string layerIdToString(uint32_t layerId) {
    return layerId == UNASSIGNED_LAYER_ID ? "none" : std::to_string(layerId);
}

} // namespace

RequestedLayerState::RequestedLayerState(const LayerCreationArgs& args)
      : id(args.sequence),
        name(args.name),
        canBeRoot(args.addToRoot),
        layerCreationFlags(args.flags),
        textureName(args.textureName),
        ownerUid(args.ownerUid),
        ownerPid(args.ownerPid) {
    layerId = static_cast<int32_t>(args.sequence);
    changes |= RequestedLayerState::Changes::Created;
    metadata.merge(args.metadata);
    changes |= RequestedLayerState::Changes::Metadata;
    handleAlive = true;
    parentId = LayerHandle::getLayerId(args.parentHandle.promote());
    mirrorId = LayerHandle::getLayerId(args.mirrorLayerHandle.promote());
    if (mirrorId != UNASSIGNED_LAYER_ID) {
        changes |= RequestedLayerState::Changes::Mirror;
    }

    flags = 0;
    if (args.flags & ISurfaceComposerClient::eHidden) flags |= layer_state_t::eLayerHidden;
    if (args.flags & ISurfaceComposerClient::eOpaque) flags |= layer_state_t::eLayerOpaque;
    if (args.flags & ISurfaceComposerClient::eSecure) flags |= layer_state_t::eLayerSecure;
    if (args.flags & ISurfaceComposerClient::eSkipScreenshot) {
        flags |= layer_state_t::eLayerSkipScreenshot;
    }
    premultipliedAlpha = !(args.flags & ISurfaceComposerClient::eNonPremultiplied);
    potentialCursor = args.flags & ISurfaceComposerClient::eCursorWindow;
    protectedByApp = args.flags & ISurfaceComposerClient::eProtectedByApp;
    if (args.flags & ISurfaceComposerClient::eNoColorFill) {
        // Set an invalid color so there is no color fill.
        // (b/259981098) use an explicit flag instead of relying on invalid values.
        color.r = -1.0_hf;
        color.g = -1.0_hf;
        color.b = -1.0_hf;
    } else {
        color.rgb = {0.0_hf, 0.0_hf, 0.0_hf};
    }
    color.a = 1.0f;

    crop.makeInvalid();
    z = 0;
    layerStack = ui::DEFAULT_LAYER_STACK;
    transformToDisplayInverse = false;
    dataspace = ui::Dataspace::UNKNOWN;
    dataspaceRequested = false;
    hdrMetadata.validTypes = 0;
    surfaceDamageRegion = Region::INVALID_REGION;
    cornerRadius = 0.0f;
    backgroundBlurRadius = 0;
    api = -1;
    hasColorTransform = false;
    bufferTransform = 0;
    requestedTransform.reset();
    bufferData = std::make_shared<BufferData>();
    bufferData->frameNumber = 0;
    bufferData->acquireFence = sp<Fence>::make(-1);
    acquireFenceTime = std::make_shared<FenceTime>(bufferData->acquireFence);
    colorSpaceAgnostic = false;
    frameRateSelectionPriority = Layer::PRIORITY_UNSET;
    shadowRadius = 0.f;
    fixedTransformHint = ui::Transform::ROT_INVALID;
    destinationFrame.makeInvalid();
    isTrustedOverlay = false;
    dropInputMode = gui::DropInputMode::NONE;
    dimmingEnabled = true;
    defaultFrameRateCompatibility =
            static_cast<int8_t>(scheduler::LayerInfo::FrameRateCompatibility::Default);
    dataspace = ui::Dataspace::V0_SRGB;
}

void RequestedLayerState::merge(const ResolvedComposerState& resolvedComposerState) {
    bool oldFlags = flags;
    Rect oldBufferSize = getBufferSize(0);
    const layer_state_t& clientState = resolvedComposerState.state;

    uint64_t clientChanges = what | layer_state_t::diff(clientState);
    layer_state_t::merge(clientState);
    what = clientChanges;

    if (clientState.what & layer_state_t::eFlagsChanged) {
        if ((oldFlags ^ flags) & layer_state_t::eLayerHidden) {
            changes |= RequestedLayerState::Changes::Visibility;
        }
        if ((oldFlags ^ flags) & layer_state_t::eIgnoreDestinationFrame) {
            changes |= RequestedLayerState::Changes::Geometry;
        }
    }
    if (clientState.what & layer_state_t::eBufferChanged && oldBufferSize != getBufferSize(0)) {
        changes |= RequestedLayerState::Changes::Geometry;
    }
    if (clientChanges & layer_state_t::HIERARCHY_CHANGES)
        changes |= RequestedLayerState::Changes::Hierarchy;
    if (clientChanges & layer_state_t::CONTENT_CHANGES)
        changes |= RequestedLayerState::Changes::Content;
    if (clientChanges & layer_state_t::GEOMETRY_CHANGES)
        changes |= RequestedLayerState::Changes::Geometry;
    if (clientChanges & layer_state_t::AFFECTS_CHILDREN)
        changes |= RequestedLayerState::Changes::AffectsChildren;

    if (clientState.what & layer_state_t::eColorTransformChanged) {
        static const mat4 identityMatrix = mat4();
        hasColorTransform = colorTransform != identityMatrix;
    }
    if (clientState.what & (layer_state_t::eLayerChanged | layer_state_t::eRelativeLayerChanged)) {
        changes |= RequestedLayerState::Changes::Z;
    }
    if (clientState.what & layer_state_t::eReparent) {
        changes |= RequestedLayerState::Changes::Parent;
        parentId = getLayerIdFromSurfaceControl(clientState.parentSurfaceControlForChild);
        parentSurfaceControlForChild = nullptr;
        // Once a layer has be reparented, it cannot be placed at the root. It sounds odd
        // but thats the existing logic and until we make this behavior more explicit, we need
        // to maintain this logic.
        canBeRoot = false;
    }
    if (clientState.what & layer_state_t::eRelativeLayerChanged) {
        changes |= RequestedLayerState::Changes::RelativeParent;
        relativeParentId = getLayerIdFromSurfaceControl(clientState.relativeLayerSurfaceControl);
        isRelativeOf = true;
        relativeLayerSurfaceControl = nullptr;
    }
    if ((clientState.what & layer_state_t::eLayerChanged ||
         (clientState.what & layer_state_t::eReparent && parentId == UNASSIGNED_LAYER_ID)) &&
        isRelativeOf) {
        // clear out relz data
        relativeParentId = UNASSIGNED_LAYER_ID;
        isRelativeOf = false;
        changes |= RequestedLayerState::Changes::RelativeParent;
    }
    if (clientState.what & layer_state_t::eReparent && parentId == relativeParentId) {
        // provide a hint that we are are now a direct child and not a relative child.
        changes |= RequestedLayerState::Changes::RelativeParent;
    }
    if (clientState.what & layer_state_t::eInputInfoChanged) {
        wp<IBinder>& touchableRegionCropHandle =
                windowInfoHandle->editInfo()->touchableRegionCropHandle;
        touchCropId = LayerHandle::getLayerId(touchableRegionCropHandle.promote());
        changes |= RequestedLayerState::Changes::Input;
        touchableRegionCropHandle.clear();
    }
    if (clientState.what & layer_state_t::eStretchChanged) {
        stretchEffect.sanitize();
    }

    if (clientState.what & layer_state_t::eHasListenerCallbacksChanged) {
        // TODO(b/238781169) handle callbacks
    }

    if (clientState.what & layer_state_t::eBufferChanged) {
        externalTexture = resolvedComposerState.externalTexture;
    }

    if (clientState.what & layer_state_t::ePositionChanged) {
        requestedTransform.set(x, y);
    }

    if (clientState.what & layer_state_t::eMatrixChanged) {
        requestedTransform.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);
    }
}

ui::Size RequestedLayerState::getUnrotatedBufferSize(uint32_t displayRotationFlags) const {
    uint32_t bufferWidth = externalTexture->getWidth();
    uint32_t bufferHeight = externalTexture->getHeight();
    // Undo any transformations on the buffer.
    if (bufferTransform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }
    if (transformToDisplayInverse) {
        if (displayRotationFlags & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }
    return {bufferWidth, bufferHeight};
}

ui::Transform RequestedLayerState::getTransform(uint32_t displayRotationFlags) const {
    if ((flags & layer_state_t::eIgnoreDestinationFrame) || destinationFrame.isEmpty()) {
        // If destination frame is not set, use the requested transform set via
        // Transaction::setPosition and Transaction::setMatrix.
        return requestedTransform;
    }

    Rect destRect = destinationFrame;
    int32_t destW = destRect.width();
    int32_t destH = destRect.height();
    if (destRect.left < 0) {
        destRect.left = 0;
        destRect.right = destW;
    }
    if (destRect.top < 0) {
        destRect.top = 0;
        destRect.bottom = destH;
    }

    if (!externalTexture) {
        ui::Transform transform;
        transform.set(static_cast<float>(destRect.left), static_cast<float>(destRect.top));
        return transform;
    }

    ui::Size bufferSize = getUnrotatedBufferSize(displayRotationFlags);

    float sx = static_cast<float>(destW) / static_cast<float>(bufferSize.width);
    float sy = static_cast<float>(destH) / static_cast<float>(bufferSize.height);
    ui::Transform transform;
    transform.set(sx, 0, 0, sy);
    transform.set(static_cast<float>(destRect.left), static_cast<float>(destRect.top));
    return transform;
}

std::string RequestedLayerState::getDebugString() const {
    return "[" + std::to_string(id) + "]" + name + ",parent=" + layerIdToString(parentId) +
            ",relativeParent=" + layerIdToString(relativeParentId) +
            ",isRelativeOf=" + std::to_string(isRelativeOf) +
            ",mirrorId=" + layerIdToString(mirrorId) +
            ",handleAlive=" + std::to_string(handleAlive) + ",z=" + std::to_string(z);
}

std::string RequestedLayerState::getDebugStringShort() const {
    return "[" + std::to_string(id) + "]" + name;
}

bool RequestedLayerState::canBeDestroyed() const {
    return !handleAlive && parentId == UNASSIGNED_LAYER_ID;
}
bool RequestedLayerState::isRoot() const {
    return canBeRoot && parentId == UNASSIGNED_LAYER_ID;
}
bool RequestedLayerState::isHiddenByPolicy() const {
    return (flags & layer_state_t::eLayerHidden) == layer_state_t::eLayerHidden;
};
half4 RequestedLayerState::getColor() const {
    if ((sidebandStream != nullptr) || (externalTexture != nullptr)) {
        return {0._hf, 0._hf, 0._hf, color.a};
    }
    return color;
}
Rect RequestedLayerState::getBufferSize(uint32_t displayRotationFlags) const {
    // for buffer state layers we use the display frame size as the buffer size.
    if (!externalTexture) {
        return Rect::INVALID_RECT;
    }

    uint32_t bufWidth = externalTexture->getWidth();
    uint32_t bufHeight = externalTexture->getHeight();

    // Undo any transformations on the buffer and return the result.
    if (bufferTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }

    if (transformToDisplayInverse) {
        uint32_t invTransform = displayRotationFlags;
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufWidth, bufHeight);
        }
    }

    return Rect(0, 0, static_cast<int32_t>(bufWidth), static_cast<int32_t>(bufHeight));
}

Rect RequestedLayerState::getCroppedBufferSize(const Rect& bufferSize) const {
    Rect size = bufferSize;
    if (!crop.isEmpty() && size.isValid()) {
        size.intersect(crop, &size);
    } else if (!crop.isEmpty()) {
        size = crop;
    }
    return size;
}

Rect RequestedLayerState::getBufferCrop() const {
    // this is the crop rectangle that applies to the buffer
    // itself (as opposed to the window)
    if (!bufferCrop.isEmpty()) {
        // if the buffer crop is defined, we use that
        return bufferCrop;
    } else if (externalTexture != nullptr) {
        // otherwise we use the whole buffer
        return externalTexture->getBounds();
    } else {
        // if we don't have a buffer yet, we use an empty/invalid crop
        return Rect();
    }
}

aidl::android::hardware::graphics::composer3::Composition RequestedLayerState::getCompositionType()
        const {
    using aidl::android::hardware::graphics::composer3::Composition;
    // TODO(b/238781169) check about sidestream ready flag
    if (sidebandStream.get()) {
        return Composition::SIDEBAND;
    }
    if (!externalTexture) {
        return Composition::SOLID_COLOR;
    }
    if (flags & layer_state_t::eLayerIsDisplayDecoration) {
        return Composition::DISPLAY_DECORATION;
    }
    if (potentialCursor) {
        return Composition::CURSOR;
    }
    return Composition::DEVICE;
}

Rect RequestedLayerState::reduce(const Rect& win, const Region& exclude) {
    if (CC_LIKELY(exclude.isEmpty())) {
        return win;
    }
    if (exclude.isRect()) {
        return win.reduce(exclude.getBounds());
    }
    return Region(win).subtract(exclude).getBounds();
}

// Returns true if the layer has a relative parent that is not its own parent. This is an input
// error from the client, and this check allows us to handle it gracefully. If both parentId and
// relativeParentId is unassigned then the layer does not have a valid relative parent.
// If the relative parentid is unassigned, the layer will be considered relative but won't be
// reachable.
bool RequestedLayerState::hasValidRelativeParent() const {
    return isRelativeOf && parentId != relativeParentId;
}

bool RequestedLayerState::hasInputInfo() const {
    if (!windowInfoHandle) {
        return false;
    }
    const auto windowInfo = windowInfoHandle->getInfo();
    return windowInfo->token != nullptr ||
            windowInfo->inputConfig.test(gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL);
}

} // namespace android::surfaceflinger::frontend
