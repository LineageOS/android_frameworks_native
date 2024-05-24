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

#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "RequestedLayerState.h"
#include "ftl/small_vector.h"

namespace android::surfaceflinger::frontend {
class LayerHierarchyBuilder;

// LayerHierarchy allows us to navigate the layer hierarchy in z-order, or depth first traversal.
// The hierarchy is created from a set of RequestedLayerStates. The hierarchy itself does not
// contain additional states. Instead, it is a representation of RequestedLayerStates as a graph.
//
// Each node in the hierarchy can be visited by multiple parents (making this a graph). While
// traversing the hierarchy, a new concept called Variant can be used to understand the
// relationship of the layer to its parent. The following variants are possible:
// Attached - child of the parent
// Detached - child of the parent but currently relative parented to another layer
// Relative - relative child of the parent
// Mirror - mirrored from another layer
//
// By representing the hierarchy as a graph, we can represent mirrored layer hierarchies without
// cloning the layer requested state. The mirrored hierarchy and its corresponding
// RequestedLayerStates are kept in sync because the mirrored hierarchy does not clone any
// states.
class LayerHierarchy {
public:
    enum Variant : uint32_t {
        Attached, // child of the parent
        Detached, // child of the parent but currently relative parented to another layer
        Relative, // relative child of the parent
        Mirror,   // mirrored from another layer
        ftl_first = Attached,
        ftl_last = Mirror,
    };
    // Represents a unique path to a node.
    // The layer hierarchy is represented as a graph. Each node can be visited by multiple parents.
    // This allows us to represent mirroring in an efficient way. See the example below:
    // root
    // ├─ A {Traversal path id = 1}
    // ├─ B {Traversal path id = 2}
    // │  ├─ C {Traversal path id = 3}
    // │  ├─ D {Traversal path id = 4}
    // │  └─ E (Mirrors C) {Traversal path id = 5}
    // └─ F (Mirrors B) {Traversal path id = 6}
    //
    // C can be traversed via B or E or F and or via F then E.
    // Depending on how the node is reached, its properties such as geometry or visibility might be
    // different. And we can uniquely identify the node by keeping track of the nodes leading up to
    // it. But to be more efficient we only need to track the nodes id and the top mirror root path.
    // So C for example, would have the following unique traversal paths:
    //  - {Traversal path id = 3}
    //  - {Traversal path id = 3, mirrorRootIds = 5}
    //  - {Traversal path id = 3, mirrorRootIds = 6}
    //  - {Traversal path id = 3, mirrorRootIds = 6, 5}

    struct TraversalPath {
        uint32_t id;
        LayerHierarchy::Variant variant;
        // Mirrored layers can have a different geometry than their parents so we need to track
        // the mirror roots in the traversal.
        ftl::SmallVector<uint32_t, 5> mirrorRootIds;
        // Relative layers can be visited twice, once by their parent and then once again by
        // their relative parent. We keep track of the roots here to detect any loops in the
        // hierarchy. If a relative root already exists in the list while building the
        // TraversalPath, it means that somewhere in the hierarchy two layers are relatively
        // parented to each other.
        ftl::SmallVector<uint32_t, 5> relativeRootIds;
        // First duplicate relative root id found. If this is a valid layer id that means we are
        // in a loop.
        uint32_t invalidRelativeRootId = UNASSIGNED_LAYER_ID;
        // See isAttached()
        bool detached = false;
        bool hasRelZLoop() const { return invalidRelativeRootId != UNASSIGNED_LAYER_ID; }
        // Returns true if this node is reached via one or more relative parents.
        bool isRelative() const { return !relativeRootIds.empty(); }
        // Returns true if the node or its parents are not Detached.
        bool isAttached() const { return !detached; }
        // Returns true if the node is a clone.
        bool isClone() const { return !mirrorRootIds.empty(); }

        bool operator==(const TraversalPath& other) const {
            return id == other.id && mirrorRootIds == other.mirrorRootIds;
        }
        std::string toString() const;

        static const TraversalPath ROOT;
    };

    struct TraversalPathHash {
        std::size_t operator()(const LayerHierarchy::TraversalPath& key) const {
            uint32_t hashCode = key.id * 31;
            for (uint32_t mirrorRootId : key.mirrorRootIds) {
                hashCode += mirrorRootId * 31;
            }
            return std::hash<size_t>{}(hashCode);
        }
    };

    // Helper class to add nodes to an existing traversal id and removes the
    // node when it goes out of scope.
    class ScopedAddToTraversalPath {
    public:
        ScopedAddToTraversalPath(TraversalPath& traversalPath, uint32_t layerId,
                                 LayerHierarchy::Variant variantArg);
        ~ScopedAddToTraversalPath();

    private:
        TraversalPath& mTraversalPath;
        TraversalPath mParentPath;
    };
    LayerHierarchy(RequestedLayerState* layer);

    // Visitor function that provides the hierarchy node and a traversal id which uniquely
    // identifies how was visited. The hierarchy contains a pointer to the RequestedLayerState.
    // Return false to stop traversing down the hierarchy.
    typedef std::function<bool(const LayerHierarchy& hierarchy,
                               const LayerHierarchy::TraversalPath& traversalPath)>
            Visitor;

    // Traverse the hierarchy and visit all child variants.
    void traverse(const Visitor& visitor) const {
        TraversalPath root = TraversalPath::ROOT;
        if (mLayer) {
            root.id = mLayer->id;
        }
        traverse(visitor, root);
    }

    // Traverse the hierarchy in z-order, skipping children that have relative parents.
    void traverseInZOrder(const Visitor& visitor) const {
        TraversalPath root = TraversalPath::ROOT;
        if (mLayer) {
            root.id = mLayer->id;
        }
        traverseInZOrder(visitor, root);
    }

    const RequestedLayerState* getLayer() const;
    const LayerHierarchy* getRelativeParent() const;
    const LayerHierarchy* getParent() const;
    friend std::ostream& operator<<(std::ostream& os, const LayerHierarchy& obj) {
        std::string prefix = " ";
        obj.dump(os, prefix, LayerHierarchy::Variant::Attached, /*isLastChild=*/false,
                 /*includeMirroredHierarchy*/ false);
        return os;
    }
    std::string dump() const {
        std::string prefix = " ";
        std::ostringstream os;
        dump(os, prefix, LayerHierarchy::Variant::Attached, /*isLastChild=*/false,
             /*includeMirroredHierarchy*/ true);
        return os.str();
    }

    std::string getDebugStringShort() const;
    // Traverse the hierarchy and return true if loops are found. The outInvalidRelativeRoot
    // will contain the first relative root that was visited twice in a traversal.
    bool hasRelZLoop(uint32_t& outInvalidRelativeRoot) const;
    std::vector<std::pair<LayerHierarchy*, Variant>> mChildren;

private:
    friend LayerHierarchyBuilder;
    LayerHierarchy(const LayerHierarchy& hierarchy, bool childrenOnly);
    void addChild(LayerHierarchy*, LayerHierarchy::Variant);
    void removeChild(LayerHierarchy*);
    void sortChildrenByZOrder();
    void updateChild(LayerHierarchy*, LayerHierarchy::Variant);
    void traverseInZOrder(const Visitor& visitor, LayerHierarchy::TraversalPath& parent) const;
    void traverse(const Visitor& visitor, LayerHierarchy::TraversalPath& parent) const;
    void dump(std::ostream& out, const std::string& prefix, LayerHierarchy::Variant variant,
              bool isLastChild, bool includeMirroredHierarchy) const;

    const RequestedLayerState* mLayer;
    LayerHierarchy* mParent = nullptr;
    LayerHierarchy* mRelativeParent = nullptr;
};

// Given a list of RequestedLayerState, this class will build a root hierarchy and an
// offscreen hierarchy. The builder also has an update method which can update an existing
// hierarchy from a list of RequestedLayerState and associated change flags.
class LayerHierarchyBuilder {
public:
    LayerHierarchyBuilder() = default;
    void update(LayerLifecycleManager& layerLifecycleManager);
    LayerHierarchy getPartialHierarchy(uint32_t, bool childrenOnly) const;
    const LayerHierarchy& getHierarchy() const;
    const LayerHierarchy& getOffscreenHierarchy() const;
    std::string getDebugString(uint32_t layerId, uint32_t depth = 0) const;

private:
    void onLayerAdded(RequestedLayerState* layer);
    void attachToParent(LayerHierarchy*);
    void detachFromParent(LayerHierarchy*);
    void attachToRelativeParent(LayerHierarchy*);
    void detachFromRelativeParent(LayerHierarchy*);
    void attachHierarchyToRelativeParent(LayerHierarchy*);
    void detachHierarchyFromRelativeParent(LayerHierarchy*);
    void init(const std::vector<std::unique_ptr<RequestedLayerState>>&);
    void doUpdate(const std::vector<std::unique_ptr<RequestedLayerState>>& layers,
                  const std::vector<std::unique_ptr<RequestedLayerState>>& destroyedLayers);
    void onLayerDestroyed(RequestedLayerState* layer);
    void updateMirrorLayer(RequestedLayerState* layer);
    LayerHierarchy* getHierarchyFromId(uint32_t layerId, bool crashOnFailure = true);

    std::unordered_map<uint32_t, LayerHierarchy*> mLayerIdToHierarchy;
    std::vector<std::unique_ptr<LayerHierarchy>> mHierarchies;
    LayerHierarchy mRoot{nullptr};
    LayerHierarchy mOffscreenRoot{nullptr};
    bool mInitialized = false;
};

} // namespace android::surfaceflinger::frontend
