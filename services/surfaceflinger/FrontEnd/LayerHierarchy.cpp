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

#include "LayerHierarchy.h"
#include "LayerLog.h"
#include "SwapErase.h"

namespace android::surfaceflinger::frontend {

namespace {
auto layerZCompare = [](const std::pair<LayerHierarchy*, LayerHierarchy::Variant>& lhs,
                        const std::pair<LayerHierarchy*, LayerHierarchy::Variant>& rhs) {
    auto lhsLayer = lhs.first->getLayer();
    auto rhsLayer = rhs.first->getLayer();
    if (lhsLayer->layerStack.id != rhsLayer->layerStack.id) {
        return lhsLayer->layerStack.id < rhsLayer->layerStack.id;
    }
    if (lhsLayer->z != rhsLayer->z) {
        return lhsLayer->z < rhsLayer->z;
    }
    return lhsLayer->id < rhsLayer->id;
};

void insertSorted(std::vector<std::pair<LayerHierarchy*, LayerHierarchy::Variant>>& vec,
                  std::pair<LayerHierarchy*, LayerHierarchy::Variant> value) {
    auto it = std::upper_bound(vec.begin(), vec.end(), value, layerZCompare);
    vec.insert(it, std::move(value));
}
} // namespace

LayerHierarchy::LayerHierarchy(RequestedLayerState* layer) : mLayer(layer) {}

LayerHierarchy::LayerHierarchy(const LayerHierarchy& hierarchy, bool childrenOnly) {
    mLayer = (childrenOnly) ? nullptr : hierarchy.mLayer;
    mChildren = hierarchy.mChildren;
}

void LayerHierarchy::traverse(const Visitor& visitor,
                              LayerHierarchy::TraversalPath& traversalPath) const {
    if (mLayer) {
        bool breakTraversal = !visitor(*this, traversalPath);
        if (breakTraversal) {
            return;
        }
    }

    LLOG_ALWAYS_FATAL_WITH_TRACE_IF(traversalPath.hasRelZLoop(), "Found relative z loop layerId:%d",
                                    traversalPath.invalidRelativeRootId);
    for (auto& [child, childVariant] : mChildren) {
        ScopedAddToTraversalPath addChildToTraversalPath(traversalPath, child->mLayer->id,
                                                         childVariant);
        child->traverse(visitor, traversalPath);
    }
}

void LayerHierarchy::traverseInZOrder(const Visitor& visitor,
                                      LayerHierarchy::TraversalPath& traversalPath) const {
    bool traverseThisLayer = (mLayer != nullptr);
    for (auto it = mChildren.begin(); it < mChildren.end(); it++) {
        auto& [child, childVariant] = *it;
        if (traverseThisLayer && child->getLayer()->z >= 0) {
            traverseThisLayer = false;
            bool breakTraversal = !visitor(*this, traversalPath);
            if (breakTraversal) {
                return;
            }
        }
        if (childVariant == LayerHierarchy::Variant::Detached) {
            continue;
        }
        ScopedAddToTraversalPath addChildToTraversalPath(traversalPath, child->mLayer->id,
                                                         childVariant);
        child->traverseInZOrder(visitor, traversalPath);
    }

    if (traverseThisLayer) {
        visitor(*this, traversalPath);
    }
}

void LayerHierarchy::addChild(LayerHierarchy* child, LayerHierarchy::Variant variant) {
    insertSorted(mChildren, {child, variant});
}

void LayerHierarchy::removeChild(LayerHierarchy* child) {
    auto it = std::find_if(mChildren.begin(), mChildren.end(),
                           [child](const std::pair<LayerHierarchy*, Variant>& x) {
                               return x.first == child;
                           });
    LLOG_ALWAYS_FATAL_WITH_TRACE_IF(it == mChildren.end(), "Could not find child!");
    mChildren.erase(it);
}

void LayerHierarchy::sortChildrenByZOrder() {
    std::sort(mChildren.begin(), mChildren.end(), layerZCompare);
}

void LayerHierarchy::updateChild(LayerHierarchy* hierarchy, LayerHierarchy::Variant variant) {
    auto it = std::find_if(mChildren.begin(), mChildren.end(),
                           [hierarchy](std::pair<LayerHierarchy*, Variant>& child) {
                               return child.first == hierarchy;
                           });
    LLOG_ALWAYS_FATAL_WITH_TRACE_IF(it == mChildren.end(), "Could not find child!");
    it->second = variant;
}

const RequestedLayerState* LayerHierarchy::getLayer() const {
    return mLayer;
}

const LayerHierarchy* LayerHierarchy::getRelativeParent() const {
    return mRelativeParent;
}

const LayerHierarchy* LayerHierarchy::getParent() const {
    return mParent;
}

std::string LayerHierarchy::getDebugStringShort() const {
    std::string debug = "LayerHierarchy{";
    debug += ((mLayer) ? mLayer->getDebugString() : "root") + " ";
    if (mChildren.empty()) {
        debug += "no children";
    } else {
        debug += std::to_string(mChildren.size()) + " children";
    }
    return debug + "}";
}

void LayerHierarchy::dump(std::ostream& out, const std::string& prefix,
                          LayerHierarchy::Variant variant, bool isLastChild,
                          bool includeMirroredHierarchy) const {
    if (!mLayer) {
        out << " ROOT";
    } else {
        out << prefix + (isLastChild ? "└─ " : "├─ ");
        if (variant == LayerHierarchy::Variant::Relative) {
            out << "(Relative) ";
        } else if (variant == LayerHierarchy::Variant::Mirror) {
            if (!includeMirroredHierarchy) {
                out << "(Mirroring) " << *mLayer << "\n" + prefix + "   └─ ...";
                return;
            }
            out << "(Mirroring) ";
        }
        out << *mLayer;
    }

    for (size_t i = 0; i < mChildren.size(); i++) {
        auto& [child, childVariant] = mChildren[i];
        if (childVariant == LayerHierarchy::Variant::Detached) continue;
        const bool lastChild = i == (mChildren.size() - 1);
        std::string childPrefix = prefix;
        if (mLayer) {
            childPrefix += (isLastChild ? "   " : "│  ");
        }
        out << "\n";
        child->dump(out, childPrefix, childVariant, lastChild, includeMirroredHierarchy);
    }
    return;
}

bool LayerHierarchy::hasRelZLoop(uint32_t& outInvalidRelativeRoot) const {
    outInvalidRelativeRoot = UNASSIGNED_LAYER_ID;
    traverse([&outInvalidRelativeRoot](const LayerHierarchy&,
                                       const LayerHierarchy::TraversalPath& traversalPath) -> bool {
        if (traversalPath.hasRelZLoop()) {
            outInvalidRelativeRoot = traversalPath.invalidRelativeRootId;
            return false;
        }
        return true;
    });
    return outInvalidRelativeRoot != UNASSIGNED_LAYER_ID;
}

void LayerHierarchyBuilder::init(const std::vector<std::unique_ptr<RequestedLayerState>>& layers) {
    mLayerIdToHierarchy.clear();
    mHierarchies.clear();
    mRoot = nullptr;
    mOffscreenRoot = nullptr;

    mHierarchies.reserve(layers.size());
    mLayerIdToHierarchy.reserve(layers.size());
    for (auto& layer : layers) {
        mHierarchies.emplace_back(std::make_unique<LayerHierarchy>(layer.get()));
        mLayerIdToHierarchy[layer->id] = mHierarchies.back().get();
    }
    for (const auto& layer : layers) {
        onLayerAdded(layer.get());
    }
    detachHierarchyFromRelativeParent(&mOffscreenRoot);
    mInitialized = true;
}

void LayerHierarchyBuilder::attachToParent(LayerHierarchy* hierarchy) {
    auto layer = hierarchy->mLayer;
    LayerHierarchy::Variant type = layer->hasValidRelativeParent()
            ? LayerHierarchy::Variant::Detached
            : LayerHierarchy::Variant::Attached;

    LayerHierarchy* parent;

    if (layer->parentId != UNASSIGNED_LAYER_ID) {
        parent = getHierarchyFromId(layer->parentId);
    } else if (layer->canBeRoot) {
        parent = &mRoot;
    } else {
        parent = &mOffscreenRoot;
    }
    parent->addChild(hierarchy, type);
    hierarchy->mParent = parent;
}

void LayerHierarchyBuilder::detachFromParent(LayerHierarchy* hierarchy) {
    hierarchy->mParent->removeChild(hierarchy);
    hierarchy->mParent = nullptr;
}

void LayerHierarchyBuilder::attachToRelativeParent(LayerHierarchy* hierarchy) {
    auto layer = hierarchy->mLayer;
    if (!layer->hasValidRelativeParent() || hierarchy->mRelativeParent) {
        return;
    }

    if (layer->relativeParentId != UNASSIGNED_LAYER_ID) {
        hierarchy->mRelativeParent = getHierarchyFromId(layer->relativeParentId);
    } else {
        hierarchy->mRelativeParent = &mOffscreenRoot;
    }
    hierarchy->mRelativeParent->addChild(hierarchy, LayerHierarchy::Variant::Relative);
    hierarchy->mParent->updateChild(hierarchy, LayerHierarchy::Variant::Detached);
}

void LayerHierarchyBuilder::detachFromRelativeParent(LayerHierarchy* hierarchy) {
    if (hierarchy->mRelativeParent) {
        hierarchy->mRelativeParent->removeChild(hierarchy);
    }
    hierarchy->mRelativeParent = nullptr;
    hierarchy->mParent->updateChild(hierarchy, LayerHierarchy::Variant::Attached);
}

void LayerHierarchyBuilder::attachHierarchyToRelativeParent(LayerHierarchy* root) {
    if (root->mLayer) {
        attachToRelativeParent(root);
    }
    for (auto& [child, childVariant] : root->mChildren) {
        if (childVariant == LayerHierarchy::Variant::Detached ||
            childVariant == LayerHierarchy::Variant::Attached) {
            attachHierarchyToRelativeParent(child);
        }
    }
}

void LayerHierarchyBuilder::detachHierarchyFromRelativeParent(LayerHierarchy* root) {
    if (root->mLayer) {
        detachFromRelativeParent(root);
    }
    for (auto& [child, childVariant] : root->mChildren) {
        if (childVariant == LayerHierarchy::Variant::Detached ||
            childVariant == LayerHierarchy::Variant::Attached) {
            detachHierarchyFromRelativeParent(child);
        }
    }
}

void LayerHierarchyBuilder::onLayerAdded(RequestedLayerState* layer) {
    LayerHierarchy* hierarchy = getHierarchyFromId(layer->id);
    attachToParent(hierarchy);
    attachToRelativeParent(hierarchy);

    for (uint32_t mirrorId : layer->mirrorIds) {
        LayerHierarchy* mirror = getHierarchyFromId(mirrorId);
        hierarchy->addChild(mirror, LayerHierarchy::Variant::Mirror);
    }
}

void LayerHierarchyBuilder::onLayerDestroyed(RequestedLayerState* layer) {
    LLOGV(layer->id, "");
    LayerHierarchy* hierarchy = getHierarchyFromId(layer->id, /*crashOnFailure=*/false);
    if (!hierarchy) {
        // Layer was never part of the hierarchy if it was created and destroyed in the same
        // transaction.
        return;
    }
    // detach from parent
    detachFromRelativeParent(hierarchy);
    detachFromParent(hierarchy);

    // detach children
    for (auto& [child, variant] : hierarchy->mChildren) {
        if (variant == LayerHierarchy::Variant::Attached ||
            variant == LayerHierarchy::Variant::Detached) {
            mOffscreenRoot.addChild(child, LayerHierarchy::Variant::Attached);
            child->mParent = &mOffscreenRoot;
        } else if (variant == LayerHierarchy::Variant::Relative) {
            mOffscreenRoot.addChild(child, LayerHierarchy::Variant::Attached);
            child->mRelativeParent = &mOffscreenRoot;
        }
    }

    swapErase(mHierarchies, [hierarchy](std::unique_ptr<LayerHierarchy>& layerHierarchy) {
        return layerHierarchy.get() == hierarchy;
    });
    mLayerIdToHierarchy.erase(layer->id);
}

void LayerHierarchyBuilder::updateMirrorLayer(RequestedLayerState* layer) {
    LayerHierarchy* hierarchy = getHierarchyFromId(layer->id);
    auto it = hierarchy->mChildren.begin();
    while (it != hierarchy->mChildren.end()) {
        if (it->second == LayerHierarchy::Variant::Mirror) {
            it = hierarchy->mChildren.erase(it);
        } else {
            it++;
        }
    }

    for (uint32_t mirrorId : layer->mirrorIds) {
        hierarchy->addChild(getHierarchyFromId(mirrorId), LayerHierarchy::Variant::Mirror);
    }
}

void LayerHierarchyBuilder::doUpdate(
        const std::vector<std::unique_ptr<RequestedLayerState>>& layers,
        const std::vector<std::unique_ptr<RequestedLayerState>>& destroyedLayers) {
    // rebuild map
    for (auto& layer : layers) {
        if (layer->changes.test(RequestedLayerState::Changes::Created)) {
            mHierarchies.emplace_back(std::make_unique<LayerHierarchy>(layer.get()));
            mLayerIdToHierarchy[layer->id] = mHierarchies.back().get();
        }
    }

    for (auto& layer : layers) {
        if (layer->changes.get() == 0) {
            continue;
        }
        if (layer->changes.test(RequestedLayerState::Changes::Created)) {
            onLayerAdded(layer.get());
            continue;
        }
        LayerHierarchy* hierarchy = getHierarchyFromId(layer->id);
        if (layer->changes.test(RequestedLayerState::Changes::Parent)) {
            detachFromParent(hierarchy);
            attachToParent(hierarchy);
        }
        if (layer->changes.test(RequestedLayerState::Changes::RelativeParent)) {
            detachFromRelativeParent(hierarchy);
            attachToRelativeParent(hierarchy);
        }
        if (layer->changes.test(RequestedLayerState::Changes::Z)) {
            hierarchy->mParent->sortChildrenByZOrder();
            if (hierarchy->mRelativeParent) {
                hierarchy->mRelativeParent->sortChildrenByZOrder();
            }
        }
        if (layer->changes.test(RequestedLayerState::Changes::Mirror)) {
            updateMirrorLayer(layer.get());
        }
    }

    for (auto& layer : destroyedLayers) {
        onLayerDestroyed(layer.get());
    }
    // When moving from onscreen to offscreen and vice versa, we need to attach and detach
    // from our relative parents. This walks down both trees to do so. We can optimize this
    // further by tracking onscreen, offscreen state in LayerHierarchy.
    detachHierarchyFromRelativeParent(&mOffscreenRoot);
    attachHierarchyToRelativeParent(&mRoot);
}

void LayerHierarchyBuilder::update(LayerLifecycleManager& layerLifecycleManager) {
    if (!mInitialized) {
        ATRACE_NAME("LayerHierarchyBuilder:init");
        init(layerLifecycleManager.getLayers());
    } else if (layerLifecycleManager.getGlobalChanges().test(
                       RequestedLayerState::Changes::Hierarchy)) {
        ATRACE_NAME("LayerHierarchyBuilder:update");
        doUpdate(layerLifecycleManager.getLayers(), layerLifecycleManager.getDestroyedLayers());
    } else {
        return; // nothing to do
    }

    uint32_t invalidRelativeRoot;
    bool hasRelZLoop = mRoot.hasRelZLoop(invalidRelativeRoot);
    while (hasRelZLoop) {
        ATRACE_NAME("FixRelZLoop");
        TransactionTraceWriter::getInstance().invoke("relz_loop_detected",
                                                     /*overwrite=*/false);
        layerLifecycleManager.fixRelativeZLoop(invalidRelativeRoot);
        // reinitialize the hierarchy with the updated layer data
        init(layerLifecycleManager.getLayers());
        // check if we have any remaining loops
        hasRelZLoop = mRoot.hasRelZLoop(invalidRelativeRoot);
    }
}

const LayerHierarchy& LayerHierarchyBuilder::getHierarchy() const {
    return mRoot;
}

const LayerHierarchy& LayerHierarchyBuilder::getOffscreenHierarchy() const {
    return mOffscreenRoot;
}

std::string LayerHierarchyBuilder::getDebugString(uint32_t layerId, uint32_t depth) const {
    if (depth > 10) return "too deep, loop?";
    if (layerId == UNASSIGNED_LAYER_ID) return "";
    auto it = mLayerIdToHierarchy.find(layerId);
    if (it == mLayerIdToHierarchy.end()) return "not found";

    LayerHierarchy* hierarchy = it->second;
    if (!hierarchy->mLayer) return "none";

    std::string debug =
            "[" + std::to_string(hierarchy->mLayer->id) + "] " + hierarchy->mLayer->name;
    if (hierarchy->mRelativeParent) {
        debug += " Relative:" + hierarchy->mRelativeParent->getDebugStringShort();
    }
    if (hierarchy->mParent) {
        debug += " Parent:" + hierarchy->mParent->getDebugStringShort();
    }
    return debug;
}

LayerHierarchy LayerHierarchyBuilder::getPartialHierarchy(uint32_t layerId,
                                                          bool childrenOnly) const {
    auto it = mLayerIdToHierarchy.find(layerId);
    if (it == mLayerIdToHierarchy.end()) return {nullptr};

    LayerHierarchy hierarchy(*it->second, childrenOnly);
    return hierarchy;
}

LayerHierarchy* LayerHierarchyBuilder::getHierarchyFromId(uint32_t layerId, bool crashOnFailure) {
    auto it = mLayerIdToHierarchy.find(layerId);
    if (it == mLayerIdToHierarchy.end()) {
        LLOG_ALWAYS_FATAL_WITH_TRACE_IF(crashOnFailure, "Could not find hierarchy for layer id %d",
                                        layerId);
        return nullptr;
    };

    return it->second;
}

const LayerHierarchy::TraversalPath LayerHierarchy::TraversalPath::ROOT =
        {.id = UNASSIGNED_LAYER_ID, .variant = LayerHierarchy::Attached};

std::string LayerHierarchy::TraversalPath::toString() const {
    if (id == UNASSIGNED_LAYER_ID) {
        return "TraversalPath{ROOT}";
    }
    std::stringstream ss;
    ss << "TraversalPath{.id = " << id;

    if (!mirrorRootIds.empty()) {
        ss << ", .mirrorRootIds=";
        for (auto rootId : mirrorRootIds) {
            ss << rootId << ",";
        }
    }

    if (!relativeRootIds.empty()) {
        ss << ", .relativeRootIds=";
        for (auto rootId : relativeRootIds) {
            ss << rootId << ",";
        }
    }

    if (hasRelZLoop()) {
        ss << "hasRelZLoop=true invalidRelativeRootId=" << invalidRelativeRootId << ",";
    }
    ss << "}";
    return ss.str();
}

// Helper class to update a passed in TraversalPath when visiting a child. When the object goes out
// of scope the TraversalPath is reset to its original state.
LayerHierarchy::ScopedAddToTraversalPath::ScopedAddToTraversalPath(TraversalPath& traversalPath,
                                                                   uint32_t layerId,
                                                                   LayerHierarchy::Variant variant)
      : mTraversalPath(traversalPath), mParentPath(traversalPath) {
    // Update the traversal id with the child layer id and variant. Parent id and variant are
    // stored to reset the id upon destruction.
    traversalPath.id = layerId;
    traversalPath.variant = variant;
    if (variant == LayerHierarchy::Variant::Mirror) {
        traversalPath.mirrorRootIds.emplace_back(mParentPath.id);
    } else if (variant == LayerHierarchy::Variant::Relative) {
        if (std::find(traversalPath.relativeRootIds.begin(), traversalPath.relativeRootIds.end(),
                      layerId) != traversalPath.relativeRootIds.end()) {
            traversalPath.invalidRelativeRootId = layerId;
        }
        traversalPath.relativeRootIds.emplace_back(layerId);
    } else if (variant == LayerHierarchy::Variant::Detached) {
        traversalPath.detached = true;
    }
}
LayerHierarchy::ScopedAddToTraversalPath::~ScopedAddToTraversalPath() {
    // Reset the traversal id to its original parent state using the state that was saved in
    // the constructor.
    if (mTraversalPath.variant == LayerHierarchy::Variant::Mirror) {
        mTraversalPath.mirrorRootIds.pop_back();
    } else if (mTraversalPath.variant == LayerHierarchy::Variant::Relative) {
        mTraversalPath.relativeRootIds.pop_back();
    }
    if (mTraversalPath.invalidRelativeRootId == mTraversalPath.id) {
        mTraversalPath.invalidRelativeRootId = UNASSIGNED_LAYER_ID;
    }
    mTraversalPath.id = mParentPath.id;
    mTraversalPath.variant = mParentPath.variant;
    mTraversalPath.detached = mParentPath.detached;
}

} // namespace android::surfaceflinger::frontend
