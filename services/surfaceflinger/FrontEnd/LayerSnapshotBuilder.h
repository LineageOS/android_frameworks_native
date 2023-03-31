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

#pragma once

#include "Display/DisplayMap.h"
#include "FrontEnd/DisplayInfo.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "LayerHierarchy.h"
#include "LayerSnapshot.h"
#include "RequestedLayerState.h"

namespace android::surfaceflinger::frontend {

// Walks through the layer hierarchy to build an ordered list
// of LayerSnapshots that can be passed on to CompositionEngine.
// This builder does a minimum amount of work to update
// an existing set of snapshots based on hierarchy changes
// and RequestedLayerState changes.

// The builder also uses a fast path to update
// snapshots when there are only buffer updates.
class LayerSnapshotBuilder {
public:
    enum class ForceUpdateFlags {
        NONE,
        ALL,
        HIERARCHY,
    };
    struct Args {
        LayerHierarchy root;
        const LayerLifecycleManager& layerLifecycleManager;
        ForceUpdateFlags forceUpdate = ForceUpdateFlags::NONE;
        bool includeMetadata = false;
        const display::DisplayMap<ui::LayerStack, frontend::DisplayInfo>& displays;
        // Set to true if there were display changes since last update.
        bool displayChanges = false;
        const renderengine::ShadowSettings& globalShadowSettings;
        bool supportsBlur = true;
        bool forceFullDamage = false;
        std::optional<FloatRect> parentCrop = std::nullopt;
        std::unordered_set<uint32_t> excludeLayerIds;
        const std::unordered_map<std::string, bool>& supportedLayerGenericMetadata;
        const std::unordered_map<std::string, uint32_t>& genericLayerMetadataKeyMap;
    };
    LayerSnapshotBuilder();

    // Rebuild the snapshots from scratch.
    LayerSnapshotBuilder(Args);

    // Update an existing set of snapshot using change flags in RequestedLayerState
    // and LayerLifecycleManager. This needs to be called before
    // LayerLifecycleManager.commitChanges is called as that function will clear all
    // change flags.
    void update(const Args&);
    std::vector<std::unique_ptr<LayerSnapshot>>& getSnapshots();
    LayerSnapshot* getSnapshot(uint32_t layerId) const;
    LayerSnapshot* getSnapshot(const LayerHierarchy::TraversalPath& id) const;

    typedef std::function<void(const LayerSnapshot& snapshot)> ConstVisitor;

    // Visit each visible snapshot in z-order
    void forEachVisibleSnapshot(const ConstVisitor& visitor) const;

    // Visit each visible snapshot in z-order
    void forEachVisibleSnapshot(const ConstVisitor& visitor, const LayerHierarchy& root) const;

    typedef std::function<void(std::unique_ptr<LayerSnapshot>& snapshot)> Visitor;
    // Visit each visible snapshot in z-order and move the snapshot if needed
    void forEachVisibleSnapshot(const Visitor& visitor);

    // Visit each snapshot interesting to input reverse z-order
    void forEachInputSnapshot(const ConstVisitor& visitor) const;

private:
    friend class LayerSnapshotTest;
    static LayerSnapshot getRootSnapshot();

    // return true if we were able to successfully update the snapshots via
    // the fast path.
    bool tryFastUpdate(const Args& args);

    void updateSnapshots(const Args& args);

    const LayerSnapshot& updateSnapshotsInHierarchy(const Args&, const LayerHierarchy& hierarchy,
                                                    LayerHierarchy::TraversalPath& traversalPath,
                                                    const LayerSnapshot& parentSnapshot);
    void updateSnapshot(LayerSnapshot&, const Args&, const RequestedLayerState&,
                        const LayerSnapshot& parentSnapshot, const LayerHierarchy::TraversalPath&);
    static void updateRelativeState(LayerSnapshot& snapshot, const LayerSnapshot& parentSnapshot,
                                    bool parentIsRelative, const Args& args);
    static void resetRelativeState(LayerSnapshot& snapshot);
    static void updateRoundedCorner(LayerSnapshot& snapshot, const RequestedLayerState& layerState,
                                    const LayerSnapshot& parentSnapshot);
    void updateLayerBounds(LayerSnapshot& snapshot, const RequestedLayerState& layerState,
                           const LayerSnapshot& parentSnapshot, uint32_t displayRotationFlags);
    static void updateShadows(LayerSnapshot& snapshot, const RequestedLayerState& requested,
                              const renderengine::ShadowSettings& globalShadowSettings);
    void updateInput(LayerSnapshot& snapshot, const RequestedLayerState& requested,
                     const LayerSnapshot& parentSnapshot, const LayerHierarchy::TraversalPath& path,
                     const Args& args);
    // Return true if there are unreachable snapshots
    bool sortSnapshotsByZ(const Args& args);
    LayerSnapshot* createSnapshot(const LayerHierarchy::TraversalPath& id,
                                  const RequestedLayerState& layer,
                                  const LayerSnapshot& parentSnapshot);
    void updateChildState(LayerSnapshot& snapshot, const LayerSnapshot& childSnapshot,
                          const Args& args);
    void updateTouchableRegionCrop(const Args& args);

    std::unordered_map<LayerHierarchy::TraversalPath, LayerSnapshot*,
                       LayerHierarchy::TraversalPathHash>
            mIdToSnapshot;
    // Track snapshots that needs touchable region crop from other snapshots
    std::unordered_set<LayerHierarchy::TraversalPath, LayerHierarchy::TraversalPathHash>
            mNeedsTouchableRegionCrop;
    std::vector<std::unique_ptr<LayerSnapshot>> mSnapshots;
    LayerSnapshot mRootSnapshot;
    bool mResortSnapshots = false;
    int mNumInterestingSnapshots = 0;
};

} // namespace android::surfaceflinger::frontend
