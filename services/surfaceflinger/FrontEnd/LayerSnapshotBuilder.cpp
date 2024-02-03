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

#include <numeric>
#include <optional>

#include <ftl/small_map.h>
#include <gui/TraceUtils.h>
#include <ui/DisplayMap.h>
#include <ui/FloatRect.h>

#include "DisplayHardware/HWC2.h"
#include "DisplayHardware/Hal.h"
#include "Layer.h" // eFrameRateSelectionPriority constants
#include "LayerLog.h"
#include "LayerSnapshotBuilder.h"
#include "TimeStats/TimeStats.h"
#include "Tracing/TransactionTracing.h"

namespace android::surfaceflinger::frontend {

using namespace ftl::flag_operators;

namespace {

FloatRect getMaxDisplayBounds(const DisplayInfos& displays) {
    const ui::Size maxSize = [&displays] {
        if (displays.empty()) return ui::Size{5000, 5000};

        return std::accumulate(displays.begin(), displays.end(), ui::kEmptySize,
                               [](ui::Size size, const auto& pair) -> ui::Size {
                                   const auto& display = pair.second;
                                   return {std::max(size.getWidth(), display.info.logicalWidth),
                                           std::max(size.getHeight(), display.info.logicalHeight)};
                               });
    }();

    // Ignore display bounds for now since they will be computed later. Use a large Rect bound
    // to ensure it's bigger than an actual display will be.
    const float xMax = static_cast<float>(maxSize.getWidth()) * 10.f;
    const float yMax = static_cast<float>(maxSize.getHeight()) * 10.f;

    return {-xMax, -yMax, xMax, yMax};
}

// Applies the given transform to the region, while protecting against overflows caused by any
// offsets. If applying the offset in the transform to any of the Rects in the region would result
// in an overflow, they are not added to the output Region.
Region transformTouchableRegionSafely(const ui::Transform& t, const Region& r,
                                      const std::string& debugWindowName) {
    // Round the translation using the same rounding strategy used by ui::Transform.
    const auto tx = static_cast<int32_t>(t.tx() + 0.5);
    const auto ty = static_cast<int32_t>(t.ty() + 0.5);

    ui::Transform transformWithoutOffset = t;
    transformWithoutOffset.set(0.f, 0.f);

    const Region transformed = transformWithoutOffset.transform(r);

    // Apply the translation to each of the Rects in the region while discarding any that overflow.
    Region ret;
    for (const auto& rect : transformed) {
        Rect newRect;
        if (__builtin_add_overflow(rect.left, tx, &newRect.left) ||
            __builtin_add_overflow(rect.top, ty, &newRect.top) ||
            __builtin_add_overflow(rect.right, tx, &newRect.right) ||
            __builtin_add_overflow(rect.bottom, ty, &newRect.bottom)) {
            ALOGE("Applying transform to touchable region of window '%s' resulted in an overflow.",
                  debugWindowName.c_str());
            continue;
        }
        ret.orSelf(newRect);
    }
    return ret;
}

/*
 * We don't want to send the layer's transform to input, but rather the
 * parent's transform. This is because Layer's transform is
 * information about how the buffer is placed on screen. The parent's
 * transform makes more sense to send since it's information about how the
 * layer is placed on screen. This transform is used by input to determine
 * how to go from screen space back to window space.
 */
ui::Transform getInputTransform(const LayerSnapshot& snapshot) {
    if (!snapshot.hasBufferOrSidebandStream()) {
        return snapshot.geomLayerTransform;
    }
    return snapshot.parentTransform;
}

/**
 * Returns the bounds used to fill the input frame and the touchable region.
 *
 * Similar to getInputTransform, we need to update the bounds to include the transform.
 * This is because bounds don't include the buffer transform, where the input assumes
 * that's already included.
 */
std::pair<FloatRect, bool> getInputBounds(const LayerSnapshot& snapshot, bool fillParentBounds) {
    FloatRect inputBounds = snapshot.croppedBufferSize.toFloatRect();
    if (snapshot.hasBufferOrSidebandStream() && snapshot.croppedBufferSize.isValid() &&
        snapshot.localTransform.getType() != ui::Transform::IDENTITY) {
        inputBounds = snapshot.localTransform.transform(inputBounds);
    }

    bool inputBoundsValid = snapshot.croppedBufferSize.isValid();
    if (!inputBoundsValid) {
        /**
         * Input bounds are based on the layer crop or buffer size. But if we are using
         * the layer bounds as the input bounds (replaceTouchableRegionWithCrop flag) then
         * we can use the parent bounds as the input bounds if the layer does not have buffer
         * or a crop. We want to unify this logic but because of compat reasons we cannot always
         * use the parent bounds. A layer without a buffer can get input. So when a window is
         * initially added, its touchable region can fill its parent layer bounds and that can
         * have negative consequences.
         */
        inputBounds = fillParentBounds ? snapshot.geomLayerBounds : FloatRect{};
    }

    // Clamp surface inset to the input bounds.
    const float inset = static_cast<float>(snapshot.inputInfo.surfaceInset);
    const float xSurfaceInset = std::clamp(inset, 0.f, inputBounds.getWidth() / 2.f);
    const float ySurfaceInset = std::clamp(inset, 0.f, inputBounds.getHeight() / 2.f);

    // Apply the insets to the input bounds.
    inputBounds.left += xSurfaceInset;
    inputBounds.top += ySurfaceInset;
    inputBounds.right -= xSurfaceInset;
    inputBounds.bottom -= ySurfaceInset;
    return {inputBounds, inputBoundsValid};
}

Rect getInputBoundsInDisplaySpace(const LayerSnapshot& snapshot, const FloatRect& insetBounds,
                                  const ui::Transform& screenToDisplay) {
    // InputDispatcher works in the display device's coordinate space. Here, we calculate the
    // frame and transform used for the layer, which determines the bounds and the coordinate space
    // within which the layer will receive input.

    // Coordinate space definitions:
    //   - display: The display device's coordinate space. Correlates to pixels on the display.
    //   - screen: The post-rotation coordinate space for the display, a.k.a. logical display space.
    //   - layer: The coordinate space of this layer.
    //   - input: The coordinate space in which this layer will receive input events. This could be
    //            different than layer space if a surfaceInset is used, which changes the origin
    //            of the input space.

    // Crop the input bounds to ensure it is within the parent's bounds.
    const FloatRect croppedInsetBoundsInLayer = snapshot.geomLayerBounds.intersect(insetBounds);

    const ui::Transform layerToScreen = getInputTransform(snapshot);
    const ui::Transform layerToDisplay = screenToDisplay * layerToScreen;

    return Rect{layerToDisplay.transform(croppedInsetBoundsInLayer)};
}

void fillInputFrameInfo(gui::WindowInfo& info, const ui::Transform& screenToDisplay,
                        const LayerSnapshot& snapshot) {
    auto [inputBounds, inputBoundsValid] = getInputBounds(snapshot, /*fillParentBounds=*/false);
    if (!inputBoundsValid) {
        info.touchableRegion.clear();
    }

    info.frame = getInputBoundsInDisplaySpace(snapshot, inputBounds, screenToDisplay);

    ui::Transform inputToLayer;
    inputToLayer.set(inputBounds.left, inputBounds.top);
    const ui::Transform layerToScreen = getInputTransform(snapshot);
    const ui::Transform inputToDisplay = screenToDisplay * layerToScreen * inputToLayer;

    // InputDispatcher expects a display-to-input transform.
    info.transform = inputToDisplay.inverse();

    // The touchable region is specified in the input coordinate space. Change it to display space.
    info.touchableRegion =
            transformTouchableRegionSafely(inputToDisplay, info.touchableRegion, snapshot.name);
}

void handleDropInputMode(LayerSnapshot& snapshot, const LayerSnapshot& parentSnapshot) {
    if (snapshot.inputInfo.inputConfig.test(gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL)) {
        return;
    }

    // Check if we need to drop input unconditionally
    const gui::DropInputMode dropInputMode = snapshot.dropInputMode;
    if (dropInputMode == gui::DropInputMode::ALL) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::DROP_INPUT;
        ALOGV("Dropping input for %s as requested by policy.", snapshot.name.c_str());
        return;
    }

    // Check if we need to check if the window is obscured by parent
    if (dropInputMode != gui::DropInputMode::OBSCURED) {
        return;
    }

    // Check if the parent has set an alpha on the layer
    if (parentSnapshot.color.a != 1.0_hf) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::DROP_INPUT;
        ALOGV("Dropping input for %s as requested by policy because alpha=%f",
              snapshot.name.c_str(), static_cast<float>(parentSnapshot.color.a));
    }

    // Check if the parent has cropped the buffer
    Rect bufferSize = snapshot.croppedBufferSize;
    if (!bufferSize.isValid()) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED;
        return;
    }

    // Screenbounds are the layer bounds cropped by parents, transformed to screenspace.
    // To check if the layer has been cropped, we take the buffer bounds, apply the local
    // layer crop and apply the same set of transforms to move to screenspace. If the bounds
    // match then the layer has not been cropped by its parents.
    Rect bufferInScreenSpace(snapshot.geomLayerTransform.transform(bufferSize));
    bool croppedByParent = bufferInScreenSpace != Rect{snapshot.transformedBounds};

    if (croppedByParent) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::DROP_INPUT;
        ALOGV("Dropping input for %s as requested by policy because buffer is cropped by parent",
              snapshot.name.c_str());
    } else {
        // If the layer is not obscured by its parents (by setting an alpha or crop), then only drop
        // input if the window is obscured. This check should be done in surfaceflinger but the
        // logic currently resides in inputflinger. So pass the if_obscured check to input to only
        // drop input events if the window is obscured.
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED;
    }
}

auto getBlendMode(const LayerSnapshot& snapshot, const RequestedLayerState& requested) {
    auto blendMode = Hwc2::IComposerClient::BlendMode::NONE;
    if (snapshot.alpha != 1.0f || !snapshot.isContentOpaque()) {
        blendMode = requested.premultipliedAlpha ? Hwc2::IComposerClient::BlendMode::PREMULTIPLIED
                                                 : Hwc2::IComposerClient::BlendMode::COVERAGE;
    }
    return blendMode;
}

void updateVisibility(LayerSnapshot& snapshot, bool visible) {
    snapshot.isVisible = visible;

    // TODO(b/238781169) we are ignoring this compat for now, since we will have
    // to remove any optimization based on visibility.

    // For compatibility reasons we let layers which can receive input
    // receive input before they have actually submitted a buffer. Because
    // of this we use canReceiveInput instead of isVisible to check the
    // policy-visibility, ignoring the buffer state. However for layers with
    // hasInputInfo()==false we can use the real visibility state.
    // We are just using these layers for occlusion detection in
    // InputDispatcher, and obviously if they aren't visible they can't occlude
    // anything.
    const bool visibleForInput =
            snapshot.hasInputInfo() ? snapshot.canReceiveInput() : snapshot.isVisible;
    snapshot.inputInfo.setInputConfig(gui::WindowInfo::InputConfig::NOT_VISIBLE, !visibleForInput);
    LLOGV(snapshot.sequence, "updating visibility %s %s", visible ? "true" : "false",
          snapshot.getDebugString().c_str());
}

bool needsInputInfo(const LayerSnapshot& snapshot, const RequestedLayerState& requested) {
    if (requested.potentialCursor) {
        return false;
    }

    if (snapshot.inputInfo.token != nullptr) {
        return true;
    }

    if (snapshot.hasBufferOrSidebandStream()) {
        return true;
    }

    return requested.windowInfoHandle &&
            requested.windowInfoHandle->getInfo()->inputConfig.test(
                    gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL);
}

void updateMetadata(LayerSnapshot& snapshot, const RequestedLayerState& requested,
                    const LayerSnapshotBuilder::Args& args) {
    snapshot.metadata.clear();
    for (const auto& [key, mandatory] : args.supportedLayerGenericMetadata) {
        auto compatIter = args.genericLayerMetadataKeyMap.find(key);
        if (compatIter == std::end(args.genericLayerMetadataKeyMap)) {
            continue;
        }
        const uint32_t id = compatIter->second;
        auto it = requested.metadata.mMap.find(id);
        if (it == std::end(requested.metadata.mMap)) {
            continue;
        }

        snapshot.metadata.emplace(key,
                                  compositionengine::GenericLayerMetadataEntry{mandatory,
                                                                               it->second});
    }
}

void clearChanges(LayerSnapshot& snapshot) {
    snapshot.changes.clear();
    snapshot.clientChanges = 0;
    snapshot.contentDirty = false;
    snapshot.hasReadyFrame = false;
    snapshot.sidebandStreamHasFrame = false;
    snapshot.surfaceDamage.clear();
}

// TODO (b/259407931): Remove.
uint32_t getPrimaryDisplayRotationFlags(
        const ui::DisplayMap<ui::LayerStack, frontend::DisplayInfo>& displays) {
    for (auto& [_, display] : displays) {
        if (display.isPrimary) {
            return display.rotationFlags;
        }
    }
    return 0;
}

} // namespace

LayerSnapshot LayerSnapshotBuilder::getRootSnapshot() {
    LayerSnapshot snapshot;
    snapshot.path = LayerHierarchy::TraversalPath::ROOT;
    snapshot.changes = ftl::Flags<RequestedLayerState::Changes>();
    snapshot.clientChanges = 0;
    snapshot.isHiddenByPolicyFromParent = false;
    snapshot.isHiddenByPolicyFromRelativeParent = false;
    snapshot.parentTransform.reset();
    snapshot.geomLayerTransform.reset();
    snapshot.geomInverseLayerTransform.reset();
    snapshot.geomLayerBounds = getMaxDisplayBounds({});
    snapshot.roundedCorner = RoundedCornerState();
    snapshot.stretchEffect = {};
    snapshot.outputFilter.layerStack = ui::DEFAULT_LAYER_STACK;
    snapshot.outputFilter.toInternalDisplay = false;
    snapshot.isSecure = false;
    snapshot.color.a = 1.0_hf;
    snapshot.colorTransformIsIdentity = true;
    snapshot.shadowSettings.length = 0.f;
    snapshot.layerMetadata.mMap.clear();
    snapshot.relativeLayerMetadata.mMap.clear();
    snapshot.inputInfo.touchOcclusionMode = gui::TouchOcclusionMode::BLOCK_UNTRUSTED;
    snapshot.dropInputMode = gui::DropInputMode::NONE;
    snapshot.isTrustedOverlay = false;
    snapshot.gameMode = gui::GameMode::Unsupported;
    snapshot.frameRate = {};
    snapshot.fixedTransformHint = ui::Transform::ROT_INVALID;
    return snapshot;
}

LayerSnapshotBuilder::LayerSnapshotBuilder() {}

LayerSnapshotBuilder::LayerSnapshotBuilder(Args args) : LayerSnapshotBuilder() {
    args.forceUpdate = ForceUpdateFlags::ALL;
    updateSnapshots(args);
}

bool LayerSnapshotBuilder::tryFastUpdate(const Args& args) {
    const bool forceUpdate = args.forceUpdate != ForceUpdateFlags::NONE;

    if (args.layerLifecycleManager.getGlobalChanges().get() == 0 && !forceUpdate &&
        !args.displayChanges) {
        return true;
    }

    // There are only content changes which do not require any child layer snapshots to be updated.
    ALOGV("%s", __func__);
    ATRACE_NAME("FastPath");

    uint32_t primaryDisplayRotationFlags = getPrimaryDisplayRotationFlags(args.displays);
    if (forceUpdate || args.displayChanges) {
        for (auto& snapshot : mSnapshots) {
            const RequestedLayerState* requested =
                    args.layerLifecycleManager.getLayerFromId(snapshot->path.id);
            if (!requested) continue;
            snapshot->merge(*requested, forceUpdate, args.displayChanges, args.forceFullDamage,
                            primaryDisplayRotationFlags);
        }
        return false;
    }

    // Walk through all the updated requested layer states and update the corresponding snapshots.
    for (const RequestedLayerState* requested : args.layerLifecycleManager.getChangedLayers()) {
        auto range = mIdToSnapshots.equal_range(requested->id);
        for (auto it = range.first; it != range.second; it++) {
            it->second->merge(*requested, forceUpdate, args.displayChanges, args.forceFullDamage,
                              primaryDisplayRotationFlags);
        }
    }

    if ((args.layerLifecycleManager.getGlobalChanges().get() &
         ~(RequestedLayerState::Changes::Content | RequestedLayerState::Changes::Buffer).get()) !=
        0) {
        // We have changes that require us to walk the hierarchy and update child layers.
        // No fast path for you.
        return false;
    }
    return true;
}

void LayerSnapshotBuilder::updateSnapshots(const Args& args) {
    ATRACE_NAME("UpdateSnapshots");
    LayerSnapshot rootSnapshot = args.rootSnapshot;
    if (args.parentCrop) {
        rootSnapshot.geomLayerBounds = *args.parentCrop;
    } else if (args.forceUpdate == ForceUpdateFlags::ALL || args.displayChanges) {
        rootSnapshot.geomLayerBounds = getMaxDisplayBounds(args.displays);
    }
    if (args.displayChanges) {
        rootSnapshot.changes = RequestedLayerState::Changes::AffectsChildren |
                RequestedLayerState::Changes::Geometry;
    }
    if (args.forceUpdate == ForceUpdateFlags::HIERARCHY) {
        rootSnapshot.changes |=
                RequestedLayerState::Changes::Hierarchy | RequestedLayerState::Changes::Visibility;
        rootSnapshot.clientChanges |= layer_state_t::eReparent;
    }

    for (auto& snapshot : mSnapshots) {
        if (snapshot->reachablilty == LayerSnapshot::Reachablilty::Reachable) {
            snapshot->reachablilty = LayerSnapshot::Reachablilty::Unreachable;
        }
    }

    LayerHierarchy::TraversalPath root = LayerHierarchy::TraversalPath::ROOT;
    if (args.root.getLayer()) {
        // The hierarchy can have a root layer when used for screenshots otherwise, it will have
        // multiple children.
        LayerHierarchy::ScopedAddToTraversalPath addChildToPath(root, args.root.getLayer()->id,
                                                                LayerHierarchy::Variant::Attached);
        updateSnapshotsInHierarchy(args, args.root, root, rootSnapshot, /*depth=*/0);
    } else {
        for (auto& [childHierarchy, variant] : args.root.mChildren) {
            LayerHierarchy::ScopedAddToTraversalPath addChildToPath(root,
                                                                    childHierarchy->getLayer()->id,
                                                                    variant);
            updateSnapshotsInHierarchy(args, *childHierarchy, root, rootSnapshot, /*depth=*/0);
        }
    }

    // Update touchable region crops outside the main update pass. This is because a layer could be
    // cropped by any other layer and it requires both snapshots to be updated.
    updateTouchableRegionCrop(args);

    const bool hasUnreachableSnapshots = sortSnapshotsByZ(args);

    // Destroy unreachable snapshots for clone layers. And destroy snapshots for non-clone
    // layers if the layer have been destroyed.
    // TODO(b/238781169) consider making clone layer ids stable as well
    if (!hasUnreachableSnapshots && args.layerLifecycleManager.getDestroyedLayers().empty()) {
        return;
    }

    std::unordered_set<uint32_t> destroyedLayerIds;
    for (auto& destroyedLayer : args.layerLifecycleManager.getDestroyedLayers()) {
        destroyedLayerIds.insert(destroyedLayer->id);
    }

    auto it = mSnapshots.begin();
    while (it < mSnapshots.end()) {
        auto& traversalPath = it->get()->path;
        const bool unreachable =
                it->get()->reachablilty == LayerSnapshot::Reachablilty::Unreachable;
        const bool isClone = traversalPath.isClone();
        const bool layerIsDestroyed =
                destroyedLayerIds.find(traversalPath.id) != destroyedLayerIds.end();
        const bool destroySnapshot = (unreachable && isClone) || layerIsDestroyed;

        if (!destroySnapshot) {
            it++;
            continue;
        }

        mPathToSnapshot.erase(traversalPath);

        auto range = mIdToSnapshots.equal_range(traversalPath.id);
        auto matchingSnapshot =
                std::find_if(range.first, range.second, [&traversalPath](auto& snapshotWithId) {
                    return snapshotWithId.second->path == traversalPath;
                });
        mIdToSnapshots.erase(matchingSnapshot);
        mNeedsTouchableRegionCrop.erase(traversalPath);
        mSnapshots.back()->globalZ = it->get()->globalZ;
        std::iter_swap(it, mSnapshots.end() - 1);
        mSnapshots.erase(mSnapshots.end() - 1);
    }
}

void LayerSnapshotBuilder::update(const Args& args) {
    for (auto& snapshot : mSnapshots) {
        clearChanges(*snapshot);
    }

    if (tryFastUpdate(args)) {
        return;
    }
    updateSnapshots(args);
}

const LayerSnapshot& LayerSnapshotBuilder::updateSnapshotsInHierarchy(
        const Args& args, const LayerHierarchy& hierarchy,
        LayerHierarchy::TraversalPath& traversalPath, const LayerSnapshot& parentSnapshot,
        int depth) {
    LLOG_ALWAYS_FATAL_WITH_TRACE_IF(depth > 50,
                                    "Cycle detected in LayerSnapshotBuilder. See "
                                    "builder_stack_overflow_transactions.winscope");

    const RequestedLayerState* layer = hierarchy.getLayer();
    LayerSnapshot* snapshot = getSnapshot(traversalPath);
    const bool newSnapshot = snapshot == nullptr;
    uint32_t primaryDisplayRotationFlags = getPrimaryDisplayRotationFlags(args.displays);
    if (newSnapshot) {
        snapshot = createSnapshot(traversalPath, *layer, parentSnapshot);
        snapshot->merge(*layer, /*forceUpdate=*/true, /*displayChanges=*/true, args.forceFullDamage,
                        primaryDisplayRotationFlags);
        snapshot->changes |= RequestedLayerState::Changes::Created;
    }

    if (traversalPath.isRelative()) {
        bool parentIsRelative = traversalPath.variant == LayerHierarchy::Variant::Relative;
        updateRelativeState(*snapshot, parentSnapshot, parentIsRelative, args);
    } else {
        if (traversalPath.isAttached()) {
            resetRelativeState(*snapshot);
        }
        updateSnapshot(*snapshot, args, *layer, parentSnapshot, traversalPath);
    }

    for (auto& [childHierarchy, variant] : hierarchy.mChildren) {
        LayerHierarchy::ScopedAddToTraversalPath addChildToPath(traversalPath,
                                                                childHierarchy->getLayer()->id,
                                                                variant);
        const LayerSnapshot& childSnapshot =
                updateSnapshotsInHierarchy(args, *childHierarchy, traversalPath, *snapshot,
                                           depth + 1);
        updateFrameRateFromChildSnapshot(*snapshot, childSnapshot, args);
    }

    return *snapshot;
}

LayerSnapshot* LayerSnapshotBuilder::getSnapshot(uint32_t layerId) const {
    if (layerId == UNASSIGNED_LAYER_ID) {
        return nullptr;
    }
    LayerHierarchy::TraversalPath path{.id = layerId};
    return getSnapshot(path);
}

LayerSnapshot* LayerSnapshotBuilder::getSnapshot(const LayerHierarchy::TraversalPath& id) const {
    auto it = mPathToSnapshot.find(id);
    return it == mPathToSnapshot.end() ? nullptr : it->second;
}

LayerSnapshot* LayerSnapshotBuilder::createSnapshot(const LayerHierarchy::TraversalPath& path,
                                                    const RequestedLayerState& layer,
                                                    const LayerSnapshot& parentSnapshot) {
    mSnapshots.emplace_back(std::make_unique<LayerSnapshot>(layer, path));
    LayerSnapshot* snapshot = mSnapshots.back().get();
    snapshot->globalZ = static_cast<size_t>(mSnapshots.size()) - 1;
    if (path.isClone() && path.variant != LayerHierarchy::Variant::Mirror) {
        snapshot->mirrorRootPath = parentSnapshot.mirrorRootPath;
    }
    mPathToSnapshot[path] = snapshot;

    mIdToSnapshots.emplace(path.id, snapshot);
    return snapshot;
}

bool LayerSnapshotBuilder::sortSnapshotsByZ(const Args& args) {
    if (!mResortSnapshots && args.forceUpdate == ForceUpdateFlags::NONE &&
        !args.layerLifecycleManager.getGlobalChanges().any(
                RequestedLayerState::Changes::Hierarchy | RequestedLayerState::Changes::Visibility |
                RequestedLayerState::Changes::Input)) {
        // We are not force updating and there are no hierarchy or visibility changes. Avoid sorting
        // the snapshots.
        return false;
    }
    mResortSnapshots = false;

    size_t globalZ = 0;
    args.root.traverseInZOrder(
            [this, &globalZ](const LayerHierarchy&,
                             const LayerHierarchy::TraversalPath& traversalPath) -> bool {
                LayerSnapshot* snapshot = getSnapshot(traversalPath);
                if (!snapshot) {
                    return true;
                }

                if (snapshot->getIsVisible() || snapshot->hasInputInfo()) {
                    updateVisibility(*snapshot, snapshot->getIsVisible());
                    size_t oldZ = snapshot->globalZ;
                    size_t newZ = globalZ++;
                    snapshot->globalZ = newZ;
                    if (oldZ == newZ) {
                        return true;
                    }
                    mSnapshots[newZ]->globalZ = oldZ;
                    LLOGV(snapshot->sequence, "Made visible z=%zu -> %zu %s", oldZ, newZ,
                          snapshot->getDebugString().c_str());
                    std::iter_swap(mSnapshots.begin() + static_cast<ssize_t>(oldZ),
                                   mSnapshots.begin() + static_cast<ssize_t>(newZ));
                }
                return true;
            });
    mNumInterestingSnapshots = (int)globalZ;
    bool hasUnreachableSnapshots = false;
    while (globalZ < mSnapshots.size()) {
        mSnapshots[globalZ]->globalZ = globalZ;
        /* mark unreachable snapshots as explicitly invisible */
        updateVisibility(*mSnapshots[globalZ], false);
        if (mSnapshots[globalZ]->reachablilty == LayerSnapshot::Reachablilty::Unreachable) {
            hasUnreachableSnapshots = true;
        }
        globalZ++;
    }
    return hasUnreachableSnapshots;
}

void LayerSnapshotBuilder::updateRelativeState(LayerSnapshot& snapshot,
                                               const LayerSnapshot& parentSnapshot,
                                               bool parentIsRelative, const Args& args) {
    if (parentIsRelative) {
        snapshot.isHiddenByPolicyFromRelativeParent =
                parentSnapshot.isHiddenByPolicyFromParent || parentSnapshot.invalidTransform;
        if (args.includeMetadata) {
            snapshot.relativeLayerMetadata = parentSnapshot.layerMetadata;
        }
    } else {
        snapshot.isHiddenByPolicyFromRelativeParent =
                parentSnapshot.isHiddenByPolicyFromRelativeParent;
        if (args.includeMetadata) {
            snapshot.relativeLayerMetadata = parentSnapshot.relativeLayerMetadata;
        }
    }
    if (snapshot.reachablilty == LayerSnapshot::Reachablilty::Unreachable) {
        snapshot.reachablilty = LayerSnapshot::Reachablilty::ReachableByRelativeParent;
    }
}

void LayerSnapshotBuilder::updateFrameRateFromChildSnapshot(LayerSnapshot& snapshot,
                                                            const LayerSnapshot& childSnapshot,
                                                            const Args& args) {
    if (args.forceUpdate == ForceUpdateFlags::NONE &&
        !args.layerLifecycleManager.getGlobalChanges().any(
                RequestedLayerState::Changes::Hierarchy) &&
        !childSnapshot.changes.any(RequestedLayerState::Changes::FrameRate) &&
        !snapshot.changes.any(RequestedLayerState::Changes::FrameRate)) {
        return;
    }

    using FrameRateCompatibility = scheduler::FrameRateCompatibility;
    if (snapshot.frameRate.isValid()) {
        // we already have a valid framerate.
        return;
    }

    // We return whether this layer or its children has a vote. We ignore ExactOrMultiple votes
    // for the same reason we are allowing touch boost for those layers. See
    // RefreshRateSelector::rankFrameRates for details.
    const auto layerVotedWithDefaultCompatibility = childSnapshot.frameRate.vote.rate.isValid() &&
            childSnapshot.frameRate.vote.type == FrameRateCompatibility::Default;
    const auto layerVotedWithNoVote =
            childSnapshot.frameRate.vote.type == FrameRateCompatibility::NoVote;
    const auto layerVotedWithCategory =
            childSnapshot.frameRate.category != FrameRateCategory::Default;
    const auto layerVotedWithExactCompatibility = childSnapshot.frameRate.vote.rate.isValid() &&
            childSnapshot.frameRate.vote.type == FrameRateCompatibility::Exact;

    bool childHasValidFrameRate = layerVotedWithDefaultCompatibility || layerVotedWithNoVote ||
            layerVotedWithCategory || layerVotedWithExactCompatibility;

    // If we don't have a valid frame rate, but the children do, we set this
    // layer as NoVote to allow the children to control the refresh rate
    if (childHasValidFrameRate) {
        snapshot.frameRate = scheduler::LayerInfo::FrameRate(Fps(), FrameRateCompatibility::NoVote);
        snapshot.changes |= RequestedLayerState::Changes::FrameRate;
    }
}

void LayerSnapshotBuilder::resetRelativeState(LayerSnapshot& snapshot) {
    snapshot.isHiddenByPolicyFromRelativeParent = false;
    snapshot.relativeLayerMetadata.mMap.clear();
}

void LayerSnapshotBuilder::updateSnapshot(LayerSnapshot& snapshot, const Args& args,
                                          const RequestedLayerState& requested,
                                          const LayerSnapshot& parentSnapshot,
                                          const LayerHierarchy::TraversalPath& path) {
    // Always update flags and visibility
    ftl::Flags<RequestedLayerState::Changes> parentChanges = parentSnapshot.changes &
            (RequestedLayerState::Changes::Hierarchy | RequestedLayerState::Changes::Geometry |
             RequestedLayerState::Changes::Visibility | RequestedLayerState::Changes::Metadata |
             RequestedLayerState::Changes::AffectsChildren | RequestedLayerState::Changes::Input |
             RequestedLayerState::Changes::FrameRate | RequestedLayerState::Changes::GameMode);
    snapshot.changes |= parentChanges;
    if (args.displayChanges) snapshot.changes |= RequestedLayerState::Changes::Geometry;
    snapshot.reachablilty = LayerSnapshot::Reachablilty::Reachable;
    snapshot.clientChanges |= (parentSnapshot.clientChanges & layer_state_t::AFFECTS_CHILDREN);
    snapshot.isHiddenByPolicyFromParent = parentSnapshot.isHiddenByPolicyFromParent ||
            parentSnapshot.invalidTransform || requested.isHiddenByPolicy() ||
            (args.excludeLayerIds.find(path.id) != args.excludeLayerIds.end());

    const bool forceUpdate = args.forceUpdate == ForceUpdateFlags::ALL ||
            snapshot.clientChanges & layer_state_t::eReparent ||
            snapshot.changes.any(RequestedLayerState::Changes::Visibility |
                                 RequestedLayerState::Changes::Created);

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eLayerStackChanged) {
        // If root layer, use the layer stack otherwise get the parent's layer stack.
        snapshot.outputFilter.layerStack =
                parentSnapshot.path == LayerHierarchy::TraversalPath::ROOT
                ? requested.layerStack
                : parentSnapshot.outputFilter.layerStack;
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eTrustedOverlayChanged) {
        snapshot.isTrustedOverlay = parentSnapshot.isTrustedOverlay || requested.isTrustedOverlay;
    }

    if (snapshot.isHiddenByPolicyFromParent &&
        !snapshot.changes.test(RequestedLayerState::Changes::Created)) {
        if (forceUpdate ||
            snapshot.changes.any(RequestedLayerState::Changes::Geometry |
                                 RequestedLayerState::Changes::BufferSize |
                                 RequestedLayerState::Changes::Input)) {
            updateInput(snapshot, requested, parentSnapshot, path, args);
        }
        return;
    }

    if (forceUpdate || snapshot.changes.any(RequestedLayerState::Changes::Mirror)) {
        // Display mirrors are always placed in a VirtualDisplay so we never want to capture layers
        // marked as skip capture
        snapshot.handleSkipScreenshotFlag = parentSnapshot.handleSkipScreenshotFlag ||
                (requested.layerStackToMirror != ui::INVALID_LAYER_STACK);
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eAlphaChanged) {
        snapshot.color.a = parentSnapshot.color.a * requested.color.a;
        snapshot.alpha = snapshot.color.a;
        snapshot.inputInfo.alpha = snapshot.color.a;
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eFlagsChanged) {
        snapshot.isSecure =
                parentSnapshot.isSecure || (requested.flags & layer_state_t::eLayerSecure);
        snapshot.outputFilter.toInternalDisplay = parentSnapshot.outputFilter.toInternalDisplay ||
                (requested.flags & layer_state_t::eLayerSkipScreenshot);
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eStretchChanged) {
        snapshot.stretchEffect = (requested.stretchEffect.hasEffect())
                ? requested.stretchEffect
                : parentSnapshot.stretchEffect;
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eColorTransformChanged) {
        if (!parentSnapshot.colorTransformIsIdentity) {
            snapshot.colorTransform = parentSnapshot.colorTransform * requested.colorTransform;
            snapshot.colorTransformIsIdentity = false;
        } else {
            snapshot.colorTransform = requested.colorTransform;
            snapshot.colorTransformIsIdentity = !requested.hasColorTransform;
        }
    }

    if (forceUpdate || snapshot.changes.test(RequestedLayerState::Changes::GameMode)) {
        snapshot.gameMode = requested.metadata.has(gui::METADATA_GAME_MODE)
                ? requested.gameMode
                : parentSnapshot.gameMode;
        updateMetadata(snapshot, requested, args);
        if (args.includeMetadata) {
            snapshot.layerMetadata = parentSnapshot.layerMetadata;
            snapshot.layerMetadata.merge(requested.metadata);
        }
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eFixedTransformHintChanged ||
        args.displayChanges) {
        snapshot.fixedTransformHint = requested.fixedTransformHint != ui::Transform::ROT_INVALID
                ? requested.fixedTransformHint
                : parentSnapshot.fixedTransformHint;

        if (snapshot.fixedTransformHint != ui::Transform::ROT_INVALID) {
            snapshot.transformHint = snapshot.fixedTransformHint;
        } else {
            const auto display = args.displays.get(snapshot.outputFilter.layerStack);
            snapshot.transformHint = display.has_value()
                    ? std::make_optional<>(display->get().transformHint)
                    : std::nullopt;
        }
    }

    if (forceUpdate ||
        args.layerLifecycleManager.getGlobalChanges().any(
                RequestedLayerState::Changes::Hierarchy) ||
        snapshot.changes.any(RequestedLayerState::Changes::FrameRate |
                             RequestedLayerState::Changes::Hierarchy)) {
        const bool shouldOverrideChildren = parentSnapshot.frameRateSelectionStrategy ==
                scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren;
        const bool propagationAllowed = parentSnapshot.frameRateSelectionStrategy !=
                scheduler::LayerInfo::FrameRateSelectionStrategy::Self;
        if ((!requested.requestedFrameRate.isValid() && propagationAllowed) ||
            shouldOverrideChildren) {
            snapshot.inheritedFrameRate = parentSnapshot.inheritedFrameRate;
        } else {
            snapshot.inheritedFrameRate = requested.requestedFrameRate;
        }
        // Set the framerate as the inherited frame rate and allow children to override it if
        // needed.
        snapshot.frameRate = snapshot.inheritedFrameRate;
        snapshot.changes |= RequestedLayerState::Changes::FrameRate;
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eFrameRateSelectionStrategyChanged) {
        if (parentSnapshot.frameRateSelectionStrategy ==
            scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren) {
            snapshot.frameRateSelectionStrategy =
                    scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren;
        } else {
            const auto strategy = scheduler::LayerInfo::convertFrameRateSelectionStrategy(
                    requested.frameRateSelectionStrategy);
            snapshot.frameRateSelectionStrategy = strategy;
        }
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eFrameRateSelectionPriority) {
        snapshot.frameRateSelectionPriority =
                (requested.frameRateSelectionPriority == Layer::PRIORITY_UNSET)
                ? parentSnapshot.frameRateSelectionPriority
                : requested.frameRateSelectionPriority;
    }

    if (forceUpdate ||
        snapshot.clientChanges &
                (layer_state_t::eBackgroundBlurRadiusChanged | layer_state_t::eBlurRegionsChanged |
                 layer_state_t::eAlphaChanged)) {
        snapshot.backgroundBlurRadius = args.supportsBlur
                ? static_cast<int>(parentSnapshot.color.a * (float)requested.backgroundBlurRadius)
                : 0;
        snapshot.blurRegions = requested.blurRegions;
        for (auto& region : snapshot.blurRegions) {
            region.alpha = region.alpha * snapshot.color.a;
        }
    }

    if (forceUpdate || snapshot.changes.any(RequestedLayerState::Changes::Geometry)) {
        uint32_t primaryDisplayRotationFlags = getPrimaryDisplayRotationFlags(args.displays);
        updateLayerBounds(snapshot, requested, parentSnapshot, primaryDisplayRotationFlags);
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eCornerRadiusChanged ||
        snapshot.changes.any(RequestedLayerState::Changes::Geometry |
                             RequestedLayerState::Changes::BufferUsageFlags)) {
        updateRoundedCorner(snapshot, requested, parentSnapshot, args);
    }

    if (forceUpdate || snapshot.clientChanges & layer_state_t::eShadowRadiusChanged ||
        snapshot.changes.any(RequestedLayerState::Changes::Geometry)) {
        updateShadows(snapshot, requested, args.globalShadowSettings);
    }

    if (forceUpdate ||
        snapshot.changes.any(RequestedLayerState::Changes::Geometry |
                             RequestedLayerState::Changes::Input)) {
        updateInput(snapshot, requested, parentSnapshot, path, args);
    }

    // computed snapshot properties
    snapshot.forceClientComposition =
            snapshot.shadowSettings.length > 0 || snapshot.stretchEffect.hasEffect();
    snapshot.contentOpaque = snapshot.isContentOpaque();
    snapshot.isOpaque = snapshot.contentOpaque && !snapshot.roundedCorner.hasRoundedCorners() &&
            snapshot.color.a == 1.f;
    snapshot.blendMode = getBlendMode(snapshot, requested);
    LLOGV(snapshot.sequence,
          "%supdated %s changes:%s parent:%s requested:%s requested:%s from parent %s",
          args.forceUpdate == ForceUpdateFlags::ALL ? "Force " : "",
          snapshot.getDebugString().c_str(), snapshot.changes.string().c_str(),
          parentSnapshot.changes.string().c_str(), requested.changes.string().c_str(),
          std::to_string(requested.what).c_str(), parentSnapshot.getDebugString().c_str());
}

void LayerSnapshotBuilder::updateRoundedCorner(LayerSnapshot& snapshot,
                                               const RequestedLayerState& requested,
                                               const LayerSnapshot& parentSnapshot,
                                               const Args& args) {
    if (args.skipRoundCornersWhenProtected && requested.isProtected()) {
        snapshot.roundedCorner = RoundedCornerState();
        return;
    }
    snapshot.roundedCorner = RoundedCornerState();
    RoundedCornerState parentRoundedCorner;
    if (parentSnapshot.roundedCorner.hasRoundedCorners()) {
        parentRoundedCorner = parentSnapshot.roundedCorner;
        ui::Transform t = snapshot.localTransform.inverse();
        parentRoundedCorner.cropRect = t.transform(parentRoundedCorner.cropRect);
        parentRoundedCorner.radius.x *= t.getScaleX();
        parentRoundedCorner.radius.y *= t.getScaleY();
    }

    FloatRect layerCropRect = snapshot.croppedBufferSize.toFloatRect();
    const vec2 radius(requested.cornerRadius, requested.cornerRadius);
    RoundedCornerState layerSettings(layerCropRect, radius);
    const bool layerSettingsValid = layerSettings.hasRoundedCorners() && !layerCropRect.isEmpty();
    const bool parentRoundedCornerValid = parentRoundedCorner.hasRoundedCorners();
    if (layerSettingsValid && parentRoundedCornerValid) {
        // If the parent and the layer have rounded corner settings, use the parent settings if
        // the parent crop is entirely inside the layer crop. This has limitations and cause
        // rendering artifacts. See b/200300845 for correct fix.
        if (parentRoundedCorner.cropRect.left > layerCropRect.left &&
            parentRoundedCorner.cropRect.top > layerCropRect.top &&
            parentRoundedCorner.cropRect.right < layerCropRect.right &&
            parentRoundedCorner.cropRect.bottom < layerCropRect.bottom) {
            snapshot.roundedCorner = parentRoundedCorner;
        } else {
            snapshot.roundedCorner = layerSettings;
        }
    } else if (layerSettingsValid) {
        snapshot.roundedCorner = layerSettings;
    } else if (parentRoundedCornerValid) {
        snapshot.roundedCorner = parentRoundedCorner;
    }
}

void LayerSnapshotBuilder::updateLayerBounds(LayerSnapshot& snapshot,
                                             const RequestedLayerState& requested,
                                             const LayerSnapshot& parentSnapshot,
                                             uint32_t primaryDisplayRotationFlags) {
    snapshot.geomLayerTransform = parentSnapshot.geomLayerTransform * snapshot.localTransform;
    const bool transformWasInvalid = snapshot.invalidTransform;
    snapshot.invalidTransform = !LayerSnapshot::isTransformValid(snapshot.geomLayerTransform);
    if (snapshot.invalidTransform) {
        auto& t = snapshot.geomLayerTransform;
        auto& requestedT = requested.requestedTransform;
        std::string transformDebug =
                base::StringPrintf(" transform={%f,%f,%f,%f}  requestedTransform={%f,%f,%f,%f}",
                                   t.dsdx(), t.dsdy(), t.dtdx(), t.dtdy(), requestedT.dsdx(),
                                   requestedT.dsdy(), requestedT.dtdx(), requestedT.dtdy());
        std::string bufferDebug;
        if (requested.externalTexture) {
            auto unRotBuffer = requested.getUnrotatedBufferSize(primaryDisplayRotationFlags);
            auto& destFrame = requested.destinationFrame;
            bufferDebug = base::StringPrintf(" buffer={%d,%d}  displayRot=%d"
                                             " destFrame={%d,%d,%d,%d} unRotBuffer={%d,%d}",
                                             requested.externalTexture->getWidth(),
                                             requested.externalTexture->getHeight(),
                                             primaryDisplayRotationFlags, destFrame.left,
                                             destFrame.top, destFrame.right, destFrame.bottom,
                                             unRotBuffer.getHeight(), unRotBuffer.getWidth());
        }
        ALOGW("Resetting transform for %s because it is invalid.%s%s",
              snapshot.getDebugString().c_str(), transformDebug.c_str(), bufferDebug.c_str());
        snapshot.geomLayerTransform.reset();
    }
    if (transformWasInvalid != snapshot.invalidTransform) {
        // If transform is invalid, the layer will be hidden.
        mResortSnapshots = true;
    }
    snapshot.geomInverseLayerTransform = snapshot.geomLayerTransform.inverse();

    FloatRect parentBounds = parentSnapshot.geomLayerBounds;
    parentBounds = snapshot.localTransform.inverse().transform(parentBounds);
    snapshot.geomLayerBounds =
            (requested.externalTexture) ? snapshot.bufferSize.toFloatRect() : parentBounds;
    if (!requested.crop.isEmpty()) {
        snapshot.geomLayerBounds = snapshot.geomLayerBounds.intersect(requested.crop.toFloatRect());
    }
    snapshot.geomLayerBounds = snapshot.geomLayerBounds.intersect(parentBounds);
    snapshot.transformedBounds = snapshot.geomLayerTransform.transform(snapshot.geomLayerBounds);
    const Rect geomLayerBoundsWithoutTransparentRegion =
            RequestedLayerState::reduce(Rect(snapshot.geomLayerBounds),
                                        requested.transparentRegion);
    snapshot.transformedBoundsWithoutTransparentRegion =
            snapshot.geomLayerTransform.transform(geomLayerBoundsWithoutTransparentRegion);
    snapshot.parentTransform = parentSnapshot.geomLayerTransform;

    // Subtract the transparent region and snap to the bounds
    const Rect bounds =
            RequestedLayerState::reduce(snapshot.croppedBufferSize, requested.transparentRegion);
    if (requested.potentialCursor) {
        snapshot.cursorFrame = snapshot.geomLayerTransform.transform(bounds);
    }
}

void LayerSnapshotBuilder::updateShadows(LayerSnapshot& snapshot, const RequestedLayerState&,
                                         const ShadowSettings& globalShadowSettings) {
    if (snapshot.shadowSettings.length > 0.f) {
        snapshot.shadowSettings.ambientColor = globalShadowSettings.ambientColor;
        snapshot.shadowSettings.spotColor = globalShadowSettings.spotColor;
        snapshot.shadowSettings.lightPos = globalShadowSettings.lightPos;
        snapshot.shadowSettings.lightRadius = globalShadowSettings.lightRadius;

        // Note: this preserves existing behavior of shadowing the entire layer and not cropping
        // it if transparent regions are present. This may not be necessary since shadows are
        // typically cast by layers without transparent regions.
        snapshot.shadowSettings.boundaries = snapshot.geomLayerBounds;

        // If the casting layer is translucent, we need to fill in the shadow underneath the
        // layer. Otherwise the generated shadow will only be shown around the casting layer.
        snapshot.shadowSettings.casterIsTranslucent =
                !snapshot.isContentOpaque() || (snapshot.alpha < 1.0f);
        snapshot.shadowSettings.ambientColor *= snapshot.alpha;
        snapshot.shadowSettings.spotColor *= snapshot.alpha;
    }
}

void LayerSnapshotBuilder::updateInput(LayerSnapshot& snapshot,
                                       const RequestedLayerState& requested,
                                       const LayerSnapshot& parentSnapshot,
                                       const LayerHierarchy::TraversalPath& path,
                                       const Args& args) {
    if (requested.windowInfoHandle) {
        snapshot.inputInfo = *requested.windowInfoHandle->getInfo();
    } else {
        snapshot.inputInfo = {};
        // b/271132344 revisit this and see if we can always use the layers uid/pid
        snapshot.inputInfo.name = requested.name;
        snapshot.inputInfo.ownerUid = gui::Uid{requested.ownerUid};
        snapshot.inputInfo.ownerPid = gui::Pid{requested.ownerPid};
    }
    snapshot.touchCropId = requested.touchCropId;

    snapshot.inputInfo.id = static_cast<int32_t>(snapshot.uniqueSequence);
    snapshot.inputInfo.displayId = static_cast<int32_t>(snapshot.outputFilter.layerStack.id);
    snapshot.inputInfo.touchOcclusionMode = requested.hasInputInfo()
            ? requested.windowInfoHandle->getInfo()->touchOcclusionMode
            : parentSnapshot.inputInfo.touchOcclusionMode;
    snapshot.inputInfo.canOccludePresentation = parentSnapshot.inputInfo.canOccludePresentation ||
            (requested.flags & layer_state_t::eCanOccludePresentation);
    if (requested.dropInputMode == gui::DropInputMode::ALL ||
        parentSnapshot.dropInputMode == gui::DropInputMode::ALL) {
        snapshot.dropInputMode = gui::DropInputMode::ALL;
    } else if (requested.dropInputMode == gui::DropInputMode::OBSCURED ||
               parentSnapshot.dropInputMode == gui::DropInputMode::OBSCURED) {
        snapshot.dropInputMode = gui::DropInputMode::OBSCURED;
    } else {
        snapshot.dropInputMode = gui::DropInputMode::NONE;
    }

    updateVisibility(snapshot, snapshot.isVisible);
    if (!needsInputInfo(snapshot, requested)) {
        return;
    }

    static frontend::DisplayInfo sDefaultInfo = {.isSecure = false};
    const std::optional<frontend::DisplayInfo> displayInfoOpt =
            args.displays.get(snapshot.outputFilter.layerStack);
    bool noValidDisplay = !displayInfoOpt.has_value();
    auto displayInfo = displayInfoOpt.value_or(sDefaultInfo);

    if (!requested.windowInfoHandle) {
        snapshot.inputInfo.inputConfig = gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL;
    }
    fillInputFrameInfo(snapshot.inputInfo, displayInfo.transform, snapshot);

    if (noValidDisplay) {
        // Do not let the window receive touches if it is not associated with a valid display
        // transform. We still allow the window to receive keys and prevent ANRs.
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::NOT_TOUCHABLE;
    }

    snapshot.inputInfo.alpha = snapshot.color.a;

    handleDropInputMode(snapshot, parentSnapshot);

    // If the window will be blacked out on a display because the display does not have the secure
    // flag and the layer has the secure flag set, then drop input.
    if (!displayInfo.isSecure && snapshot.isSecure) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::DROP_INPUT;
    }

    if (requested.touchCropId != UNASSIGNED_LAYER_ID || path.isClone()) {
        mNeedsTouchableRegionCrop.insert(path);
    }
    auto cropLayerSnapshot = getSnapshot(requested.touchCropId);
    if (!cropLayerSnapshot && snapshot.inputInfo.replaceTouchableRegionWithCrop) {
        FloatRect inputBounds = getInputBounds(snapshot, /*fillParentBounds=*/true).first;
        Rect inputBoundsInDisplaySpace =
                getInputBoundsInDisplaySpace(snapshot, inputBounds, displayInfo.transform);
        snapshot.inputInfo.touchableRegion = Region(inputBoundsInDisplaySpace);
    }

    // Inherit the trusted state from the parent hierarchy, but don't clobber the trusted state
    // if it was set by WM for a known system overlay
    if (snapshot.isTrustedOverlay) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::TRUSTED_OVERLAY;
    }

    snapshot.inputInfo.contentSize = snapshot.croppedBufferSize.getSize();

    // If the layer is a clone, we need to crop the input region to cloned root to prevent
    // touches from going outside the cloned area.
    if (path.isClone()) {
        snapshot.inputInfo.inputConfig |= gui::WindowInfo::InputConfig::CLONE;
        // Cloned layers shouldn't handle watch outside since their z order is not determined by
        // WM or the client.
        snapshot.inputInfo.inputConfig.clear(gui::WindowInfo::InputConfig::WATCH_OUTSIDE_TOUCH);
    }
}

std::vector<std::unique_ptr<LayerSnapshot>>& LayerSnapshotBuilder::getSnapshots() {
    return mSnapshots;
}

void LayerSnapshotBuilder::forEachVisibleSnapshot(const ConstVisitor& visitor) const {
    for (int i = 0; i < mNumInterestingSnapshots; i++) {
        LayerSnapshot& snapshot = *mSnapshots[(size_t)i];
        if (!snapshot.isVisible) continue;
        visitor(snapshot);
    }
}

// Visit each visible snapshot in z-order
void LayerSnapshotBuilder::forEachVisibleSnapshot(const ConstVisitor& visitor,
                                                  const LayerHierarchy& root) const {
    root.traverseInZOrder(
            [this, visitor](const LayerHierarchy&,
                            const LayerHierarchy::TraversalPath& traversalPath) -> bool {
                LayerSnapshot* snapshot = getSnapshot(traversalPath);
                if (snapshot && snapshot->isVisible) {
                    visitor(*snapshot);
                }
                return true;
            });
}

void LayerSnapshotBuilder::forEachVisibleSnapshot(const Visitor& visitor) {
    for (int i = 0; i < mNumInterestingSnapshots; i++) {
        std::unique_ptr<LayerSnapshot>& snapshot = mSnapshots.at((size_t)i);
        if (!snapshot->isVisible) continue;
        visitor(snapshot);
    }
}

void LayerSnapshotBuilder::forEachInputSnapshot(const ConstVisitor& visitor) const {
    for (int i = mNumInterestingSnapshots - 1; i >= 0; i--) {
        LayerSnapshot& snapshot = *mSnapshots[(size_t)i];
        if (!snapshot.hasInputInfo()) continue;
        visitor(snapshot);
    }
}

void LayerSnapshotBuilder::updateTouchableRegionCrop(const Args& args) {
    if (mNeedsTouchableRegionCrop.empty()) {
        return;
    }

    static constexpr ftl::Flags<RequestedLayerState::Changes> AFFECTS_INPUT =
            RequestedLayerState::Changes::Visibility | RequestedLayerState::Changes::Created |
            RequestedLayerState::Changes::Hierarchy | RequestedLayerState::Changes::Geometry |
            RequestedLayerState::Changes::Input;

    if (args.forceUpdate != ForceUpdateFlags::ALL &&
        !args.layerLifecycleManager.getGlobalChanges().any(AFFECTS_INPUT) && !args.displayChanges) {
        return;
    }

    for (auto& path : mNeedsTouchableRegionCrop) {
        frontend::LayerSnapshot* snapshot = getSnapshot(path);
        if (!snapshot) {
            continue;
        }
        LLOGV(snapshot->sequence, "updateTouchableRegionCrop=%s",
              snapshot->getDebugString().c_str());
        const std::optional<frontend::DisplayInfo> displayInfoOpt =
                args.displays.get(snapshot->outputFilter.layerStack);
        static frontend::DisplayInfo sDefaultInfo = {.isSecure = false};
        auto displayInfo = displayInfoOpt.value_or(sDefaultInfo);

        bool needsUpdate =
                args.forceUpdate == ForceUpdateFlags::ALL || snapshot->changes.any(AFFECTS_INPUT);
        auto cropLayerSnapshot = getSnapshot(snapshot->touchCropId);
        needsUpdate =
                needsUpdate || (cropLayerSnapshot && cropLayerSnapshot->changes.any(AFFECTS_INPUT));
        auto clonedRootSnapshot = path.isClone() ? getSnapshot(snapshot->mirrorRootPath) : nullptr;
        needsUpdate = needsUpdate ||
                (clonedRootSnapshot && clonedRootSnapshot->changes.any(AFFECTS_INPUT));

        if (!needsUpdate) {
            continue;
        }

        if (snapshot->inputInfo.replaceTouchableRegionWithCrop) {
            Rect inputBoundsInDisplaySpace;
            if (!cropLayerSnapshot) {
                FloatRect inputBounds = getInputBounds(*snapshot, /*fillParentBounds=*/true).first;
                inputBoundsInDisplaySpace =
                        getInputBoundsInDisplaySpace(*snapshot, inputBounds, displayInfo.transform);
            } else {
                FloatRect inputBounds =
                        getInputBounds(*cropLayerSnapshot, /*fillParentBounds=*/true).first;
                inputBoundsInDisplaySpace =
                        getInputBoundsInDisplaySpace(*cropLayerSnapshot, inputBounds,
                                                     displayInfo.transform);
            }
            snapshot->inputInfo.touchableRegion = Region(inputBoundsInDisplaySpace);
        } else if (cropLayerSnapshot) {
            FloatRect inputBounds =
                    getInputBounds(*cropLayerSnapshot, /*fillParentBounds=*/true).first;
            Rect inputBoundsInDisplaySpace =
                    getInputBoundsInDisplaySpace(*cropLayerSnapshot, inputBounds,
                                                 displayInfo.transform);
            snapshot->inputInfo.touchableRegion =
                    snapshot->inputInfo.touchableRegion.intersect(inputBoundsInDisplaySpace);
        }

        // If the layer is a clone, we need to crop the input region to cloned root to prevent
        // touches from going outside the cloned area.
        if (clonedRootSnapshot) {
            const Rect rect =
                    displayInfo.transform.transform(Rect{clonedRootSnapshot->transformedBounds});
            snapshot->inputInfo.touchableRegion =
                    snapshot->inputInfo.touchableRegion.intersect(rect);
        }
    }
}

} // namespace android::surfaceflinger::frontend
