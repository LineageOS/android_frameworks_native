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
// #define LOG_NDEBUG 0

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#undef LOG_TAG
#define LOG_TAG "SurfaceFlinger"

#include <gui/TraceUtils.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <sys/types.h>

#include <scheduler/Fps.h>

#include "Layer.h"
#include "LayerCreationArgs.h"
#include "LayerLog.h"
#include "RequestedLayerState.h"

namespace android::surfaceflinger::frontend {
using ftl::Flags;
using namespace ftl::flag_operators;

namespace {
std::string layerIdsToString(const std::vector<uint32_t>& layerIds) {
    std::stringstream stream;
    stream << "{";
    for (auto layerId : layerIds) {
        stream << layerId << ",";
    }
    stream << "}";
    return stream.str();
}

} // namespace

RequestedLayerState::RequestedLayerState(const LayerCreationArgs& args)
      : id(args.sequence),
        name(args.name + "#" + std::to_string(args.sequence)),
        canBeRoot(args.addToRoot),
        layerCreationFlags(args.flags),
        ownerUid(args.ownerUid),
        ownerPid(args.ownerPid),
        parentId(args.parentId),
        layerIdToMirror(args.layerIdToMirror) {
    layerId = static_cast<int32_t>(args.sequence);
    changes |= RequestedLayerState::Changes::Created;
    metadata.merge(args.metadata);
    changes |= RequestedLayerState::Changes::Metadata;
    handleAlive = true;
    if (parentId != UNASSIGNED_LAYER_ID) {
        canBeRoot = false;
    }
    if (layerIdToMirror != UNASSIGNED_LAYER_ID) {
        changes |= RequestedLayerState::Changes::Mirror;
    } else if (args.layerStackToMirror != ui::INVALID_LAYER_STACK) {
        layerStackToMirror = args.layerStackToMirror;
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
    LLOGV(layerId, "Created %s flags=%d", getDebugString().c_str(), flags);
    color.a = 1.0f;

    crop.makeInvalid();
    z = 0;
    layerStack = ui::DEFAULT_LAYER_STACK;
    transformToDisplayInverse = false;
    desiredHdrSdrRatio = -1.f;
    currentHdrSdrRatio = 1.f;
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
    defaultFrameRateCompatibility = static_cast<int8_t>(scheduler::FrameRateCompatibility::Default);
    frameRateCategory = static_cast<int8_t>(FrameRateCategory::Default);
    frameRateCategorySmoothSwitchOnly = false;
    frameRateSelectionStrategy =
            static_cast<int8_t>(scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    dataspace = ui::Dataspace::V0_SRGB;
    gameMode = gui::GameMode::Unsupported;
    requestedFrameRate = {};
    cachingHint = gui::CachingHint::Enabled;

    if (name.length() > 77) {
        std::string shortened;
        shortened.append(name, 0, 36);
        shortened.append("[...]");
        shortened.append(name, name.length() - 36);
        debugName = std::move(shortened);
    } else {
        debugName = name;
    }
}

void RequestedLayerState::merge(const ResolvedComposerState& resolvedComposerState) {
    const uint32_t oldFlags = flags;
    const half oldAlpha = color.a;
    const bool hadBuffer = externalTexture != nullptr;
    uint64_t oldFramenumber = hadBuffer ? bufferData->frameNumber : 0;
    const ui::Size oldBufferSize = hadBuffer
            ? ui::Size(externalTexture->getWidth(), externalTexture->getHeight())
            : ui::Size();
    const uint64_t oldUsageFlags = hadBuffer ? externalTexture->getUsage() : 0;
    const bool oldBufferFormatOpaque = LayerSnapshot::isOpaqueFormat(
            externalTexture ? externalTexture->getPixelFormat() : PIXEL_FORMAT_NONE);

    const bool hadSideStream = sidebandStream != nullptr;
    const layer_state_t& clientState = resolvedComposerState.state;
    const bool hadSomethingToDraw = hasSomethingToDraw();
    uint64_t clientChanges = what | layer_state_t::diff(clientState);
    layer_state_t::merge(clientState);
    what = clientChanges;
    LLOGV(layerId, "requested=%" PRIu64 "flags=%" PRIu64, clientState.what, clientChanges);

    if (clientState.what & layer_state_t::eFlagsChanged) {
        if ((oldFlags ^ flags) & (layer_state_t::eLayerHidden | layer_state_t::eLayerOpaque)) {
            changes |= RequestedLayerState::Changes::Visibility |
                    RequestedLayerState::Changes::VisibleRegion;
        }
        if ((oldFlags ^ flags) & layer_state_t::eIgnoreDestinationFrame) {
            changes |= RequestedLayerState::Changes::Geometry;
        }
        if ((oldFlags ^ flags) & layer_state_t::eCanOccludePresentation) {
            changes |= RequestedLayerState::Changes::Input;
        }
    }

    if (clientState.what & layer_state_t::eBufferChanged) {
        externalTexture = resolvedComposerState.externalTexture;
        const bool hasBuffer = externalTexture != nullptr;
        if (hasBuffer || hasBuffer != hadBuffer) {
            changes |= RequestedLayerState::Changes::Buffer;
            const ui::Size newBufferSize = hasBuffer
                    ? ui::Size(externalTexture->getWidth(), externalTexture->getHeight())
                    : ui::Size();
            if (oldBufferSize != newBufferSize) {
                changes |= RequestedLayerState::Changes::BufferSize;
                changes |= RequestedLayerState::Changes::Geometry;
            }
            const uint64_t usageFlags = hasBuffer ? externalTexture->getUsage() : 0;
            if (oldUsageFlags != usageFlags) {
                changes |= RequestedLayerState::Changes::BufferUsageFlags;
            }
        }

        if (hasBuffer != hadBuffer) {
            changes |= RequestedLayerState::Changes::Geometry |
                    RequestedLayerState::Changes::VisibleRegion |
                    RequestedLayerState::Changes::Visibility | RequestedLayerState::Changes::Input;
        }

        if (hasBuffer) {
            const bool frameNumberChanged =
                    bufferData->flags.test(BufferData::BufferDataChange::frameNumberChanged);
            const uint64_t frameNumber =
                    frameNumberChanged ? bufferData->frameNumber : oldFramenumber + 1;
            bufferData->frameNumber = frameNumber;

            if ((barrierProducerId > bufferData->producerId) ||
                ((barrierProducerId == bufferData->producerId) &&
                 (barrierFrameNumber > bufferData->frameNumber))) {
                ALOGE("Out of order buffers detected for %s producedId=%d frameNumber=%" PRIu64
                      " -> producedId=%d frameNumber=%" PRIu64,
                      getDebugString().c_str(), barrierProducerId, barrierFrameNumber,
                      bufferData->producerId, frameNumber);
                TransactionTraceWriter::getInstance().invoke("out_of_order_buffers_",
                                                             /*overwrite=*/false);
            }

            barrierProducerId = std::max(bufferData->producerId, barrierProducerId);
            barrierFrameNumber = std::max(bufferData->frameNumber, barrierFrameNumber);
        }

        const bool newBufferFormatOpaque = LayerSnapshot::isOpaqueFormat(
                externalTexture ? externalTexture->getPixelFormat() : PIXEL_FORMAT_NONE);
        if (newBufferFormatOpaque != oldBufferFormatOpaque) {
            changes |= RequestedLayerState::Changes::Visibility |
                    RequestedLayerState::Changes::VisibleRegion;
        }
    }

    if (clientState.what & layer_state_t::eSidebandStreamChanged) {
        changes |= RequestedLayerState::Changes::SidebandStream;
        const bool hasSideStream = sidebandStream != nullptr;
        if (hasSideStream != hadSideStream) {
            changes |= RequestedLayerState::Changes::Geometry |
                    RequestedLayerState::Changes::VisibleRegion |
                    RequestedLayerState::Changes::Visibility | RequestedLayerState::Changes::Input;
        }
    }
    if (what & (layer_state_t::eAlphaChanged)) {
        if (oldAlpha == 0 || color.a == 0) {
            changes |= RequestedLayerState::Changes::Visibility;
        }
    }

    if (hadSomethingToDraw != hasSomethingToDraw()) {
        changes |= RequestedLayerState::Changes::Visibility |
                RequestedLayerState::Changes::VisibleRegion;
    }
    if (clientChanges & layer_state_t::HIERARCHY_CHANGES)
        changes |= RequestedLayerState::Changes::Hierarchy;
    if (clientChanges & layer_state_t::CONTENT_CHANGES)
        changes |= RequestedLayerState::Changes::Content;
    if (clientChanges & layer_state_t::GEOMETRY_CHANGES)
        changes |= RequestedLayerState::Changes::Geometry;
    if (clientChanges & layer_state_t::AFFECTS_CHILDREN)
        changes |= RequestedLayerState::Changes::AffectsChildren;
    if (clientChanges & layer_state_t::INPUT_CHANGES)
        changes |= RequestedLayerState::Changes::Input;
    if (clientChanges & layer_state_t::VISIBLE_REGION_CHANGES)
        changes |= RequestedLayerState::Changes::VisibleRegion;
    if (clientState.what & layer_state_t::eColorTransformChanged) {
        static const mat4 identityMatrix = mat4();
        hasColorTransform = colorTransform != identityMatrix;
    }
    if (clientState.what &
        (layer_state_t::eLayerChanged | layer_state_t::eRelativeLayerChanged |
         layer_state_t::eLayerStackChanged)) {
        changes |= RequestedLayerState::Changes::Z;
    }
    if (clientState.what & layer_state_t::eReparent) {
        changes |= RequestedLayerState::Changes::Parent;
        parentId = resolvedComposerState.parentId;
        parentSurfaceControlForChild = nullptr;
        // Once a layer has be reparented, it cannot be placed at the root. It sounds odd
        // but thats the existing logic and until we make this behavior more explicit, we need
        // to maintain this logic.
        canBeRoot = false;
    }
    if (clientState.what & layer_state_t::eRelativeLayerChanged) {
        changes |= RequestedLayerState::Changes::RelativeParent;
        relativeParentId = resolvedComposerState.relativeParentId;
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
        touchCropId = resolvedComposerState.touchCropId;
        windowInfoHandle->editInfo()->touchableRegionCropHandle.clear();
    }
    if (clientState.what & layer_state_t::eStretchChanged) {
        stretchEffect.sanitize();
    }

    if (clientState.what & layer_state_t::eHasListenerCallbacksChanged) {
        // TODO(b/238781169) handle callbacks
    }

    if (clientState.what & layer_state_t::ePositionChanged) {
        requestedTransform.set(x, y);
    }

    if (clientState.what & layer_state_t::eMatrixChanged) {
        requestedTransform.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);
    }
    if (clientState.what & layer_state_t::eMetadataChanged) {
        const int32_t requestedGameMode =
                clientState.metadata.getInt32(gui::METADATA_GAME_MODE, -1);
        if (requestedGameMode != -1) {
            // The transaction will be received on the Task layer and needs to be applied to all
            // child layers.
            if (static_cast<int32_t>(gameMode) != requestedGameMode) {
                gameMode = static_cast<gui::GameMode>(requestedGameMode);
                changes |= RequestedLayerState::Changes::GameMode;
            }
        }
    }
    if (clientState.what & layer_state_t::eFrameRateChanged) {
        const auto compatibility =
                Layer::FrameRate::convertCompatibility(clientState.frameRateCompatibility);
        const auto strategy = Layer::FrameRate::convertChangeFrameRateStrategy(
                clientState.changeFrameRateStrategy);
        requestedFrameRate.vote =
                Layer::FrameRate::FrameRateVote(Fps::fromValue(clientState.frameRate),
                                                compatibility, strategy);
        changes |= RequestedLayerState::Changes::FrameRate;
    }
    if (clientState.what & layer_state_t::eFrameRateCategoryChanged) {
        const auto category = Layer::FrameRate::convertCategory(clientState.frameRateCategory);
        requestedFrameRate.category = category;
        changes |= RequestedLayerState::Changes::FrameRate;
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
    std::stringstream debug;
    debug << "RequestedLayerState{" << name;
    if (parentId != UNASSIGNED_LAYER_ID) debug << " parentId=" << parentId;
    if (relativeParentId != UNASSIGNED_LAYER_ID) debug << " relativeParentId=" << relativeParentId;
    if (!mirrorIds.empty()) debug << " mirrorId=" << layerIdsToString(mirrorIds);
    if (!handleAlive) debug << " !handle";
    if (z != 0) debug << " z=" << z;
    if (layerStack.id != 0) debug << " layerStack=" << layerStack.id;
    debug << "}";
    return debug.str();
}

std::ostream& operator<<(std::ostream& out, const scheduler::LayerInfo::FrameRate& obj) {
    out << obj.vote.rate;
    out << " " << ftl::enum_string_full(obj.vote.type);
    out << " " << ftl::enum_string_full(obj.category);
    return out;
}

std::ostream& operator<<(std::ostream& out, const RequestedLayerState& obj) {
    out << obj.debugName;
    if (obj.relativeParentId != UNASSIGNED_LAYER_ID) out << " parent=" << obj.parentId;
    if (!obj.handleAlive) out << " handleNotAlive";
    if (obj.requestedFrameRate.isValid())
        out << " requestedFrameRate: {" << obj.requestedFrameRate << "}";
    if (obj.dropInputMode != gui::DropInputMode::NONE)
        out << " dropInputMode=" << static_cast<uint32_t>(obj.dropInputMode);
    return out;
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
    if (sidebandStream || externalTexture) {
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
    if (!bufferCrop.isEmpty() && externalTexture != nullptr) {
        // if the buffer crop is defined and there's a valid buffer, intersect buffer size and crop
        // since the crop should never exceed the size of the buffer.
        Rect sizeAndCrop;
        externalTexture->getBounds().intersect(bufferCrop, &sizeAndCrop);
        return sizeAndCrop;
    } else if (externalTexture != nullptr) {
        // otherwise we use the whole buffer
        return externalTexture->getBounds();
    } else if (!bufferCrop.isEmpty()) {
        // if the buffer crop is defined, we use that
        return bufferCrop;
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
    if (flags & layer_state_t::eLayerIsRefreshRateIndicator) {
        return Composition::REFRESH_RATE_INDICATOR;
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
    return isRelativeOf &&
            (parentId != relativeParentId || relativeParentId == UNASSIGNED_LAYER_ID);
}

bool RequestedLayerState::hasInputInfo() const {
    if (!windowInfoHandle) {
        return false;
    }
    const auto windowInfo = windowInfoHandle->getInfo();
    return windowInfo->token != nullptr ||
            windowInfo->inputConfig.test(gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL);
}

bool RequestedLayerState::hasBlur() const {
    return backgroundBlurRadius > 0 || blurRegions.size() > 0;
}

bool RequestedLayerState::hasFrameUpdate() const {
    return what & layer_state_t::CONTENT_DIRTY &&
            (externalTexture || bgColorLayerId != UNASSIGNED_LAYER_ID);
}

bool RequestedLayerState::hasReadyFrame() const {
    return hasFrameUpdate() || changes.test(Changes::SidebandStream) || autoRefresh;
}

bool RequestedLayerState::hasSidebandStreamFrame() const {
    return hasFrameUpdate() && sidebandStream.get();
}

bool RequestedLayerState::willReleaseBufferOnLatch() const {
    return changes.test(Changes::Buffer) && !externalTexture;
}

bool RequestedLayerState::backpressureEnabled() const {
    return flags & layer_state_t::eEnableBackpressure;
}

bool RequestedLayerState::isSimpleBufferUpdate(const layer_state_t& s) const {
    static constexpr uint64_t requiredFlags = layer_state_t::eBufferChanged;
    if ((s.what & requiredFlags) != requiredFlags) {
        ATRACE_FORMAT_INSTANT("%s: false [missing required flags 0x%" PRIx64 "]", __func__,
                              (s.what | requiredFlags) & ~s.what);
        return false;
    }

    static constexpr uint64_t deniedFlags = layer_state_t::eProducerDisconnect |
            layer_state_t::eLayerChanged | layer_state_t::eRelativeLayerChanged |
            layer_state_t::eTransparentRegionChanged | layer_state_t::eFlagsChanged |
            layer_state_t::eBlurRegionsChanged | layer_state_t::eLayerStackChanged |
            layer_state_t::eAutoRefreshChanged | layer_state_t::eReparent;
    if (s.what & deniedFlags) {
        ATRACE_FORMAT_INSTANT("%s: false [has denied flags 0x%" PRIx64 "]", __func__,
                              s.what & deniedFlags);
        return false;
    }

    bool changedFlags = diff(s);
    static constexpr auto deniedChanges = layer_state_t::ePositionChanged |
            layer_state_t::eAlphaChanged | layer_state_t::eColorTransformChanged |
            layer_state_t::eBackgroundColorChanged | layer_state_t::eMatrixChanged |
            layer_state_t::eCornerRadiusChanged | layer_state_t::eBackgroundBlurRadiusChanged |
            layer_state_t::eBufferTransformChanged |
            layer_state_t::eTransformToDisplayInverseChanged | layer_state_t::eCropChanged |
            layer_state_t::eDataspaceChanged | layer_state_t::eHdrMetadataChanged |
            layer_state_t::eSidebandStreamChanged | layer_state_t::eColorSpaceAgnosticChanged |
            layer_state_t::eShadowRadiusChanged | layer_state_t::eFixedTransformHintChanged |
            layer_state_t::eTrustedOverlayChanged | layer_state_t::eStretchChanged |
            layer_state_t::eBufferCropChanged | layer_state_t::eDestinationFrameChanged |
            layer_state_t::eDimmingEnabledChanged | layer_state_t::eExtendedRangeBrightnessChanged |
            layer_state_t::eDesiredHdrHeadroomChanged;
    if (changedFlags & deniedChanges) {
        ATRACE_FORMAT_INSTANT("%s: false [has denied changes flags 0x%" PRIx64 "]", __func__,
                              s.what & deniedChanges);
        return false;
    }

    return true;
}

bool RequestedLayerState::isProtected() const {
    return externalTexture && externalTexture->getUsage() & GRALLOC_USAGE_PROTECTED;
}

bool RequestedLayerState::hasSomethingToDraw() const {
    return externalTexture != nullptr || sidebandStream != nullptr || shadowRadius > 0.f ||
            backgroundBlurRadius > 0 || blurRegions.size() > 0 ||
            (color.r >= 0.0_hf && color.g >= 0.0_hf && color.b >= 0.0_hf);
}

void RequestedLayerState::clearChanges() {
    what = 0;
    changes.clear();
}

} // namespace android::surfaceflinger::frontend
