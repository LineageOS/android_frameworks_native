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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "FrontEnd/LayerHandle.h"
#include "FrontEnd/LayerHierarchy.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "Layer.h"
#include "gui/SurfaceComposerClient.h"

namespace android::surfaceflinger::frontend {

class LayerHierarchyTestBase : public testing::Test {
protected:
    LayerHierarchyTestBase() {
        // tree with 3 levels of children
        // ROOT
        // ├── 1
        // │   ├── 11
        // │   │   └── 111
        // │   ├── 12
        // │   │   ├── 121
        // │   │   └── 122
        // │   │       └── 1221
        // │   └── 13
        // └── 2

        createRootLayer(1);
        createRootLayer(2);
        createLayer(11, 1);
        createLayer(12, 1);
        createLayer(13, 1);
        createLayer(111, 11);
        createLayer(121, 12);
        createLayer(122, 12);
        createLayer(1221, 122);
    }

    LayerCreationArgs createArgs(uint32_t id, bool canBeRoot, wp<IBinder> parent,
                                 wp<IBinder> mirror) {
        LayerCreationArgs args(nullptr, nullptr, "testlayer", 0, {}, std::make_optional(id));
        args.addToRoot = canBeRoot;
        args.parentHandle = parent;
        args.mirrorLayerHandle = mirror;
        return args;
    }

    LayerCreationArgs createDisplayMirrorArgs(uint32_t id, ui::LayerStack layerStack) {
        LayerCreationArgs args(nullptr, nullptr, "testlayer", 0, {}, std::make_optional(id));
        args.addToRoot = true;
        args.parentHandle.clear();
        args.layerStackToMirror = layerStack;
        return args;
    }

    std::vector<uint32_t> getTraversalPath(const LayerHierarchy& hierarchy) const {
        std::vector<uint32_t> layerIds;
        hierarchy.traverse([&layerIds = layerIds](const LayerHierarchy& hierarchy,
                                                  const LayerHierarchy::TraversalPath&) -> bool {
            layerIds.emplace_back(hierarchy.getLayer()->id);
            return true;
        });
        return layerIds;
    }

    std::vector<uint32_t> getTraversalPathInZOrder(const LayerHierarchy& hierarchy) const {
        std::vector<uint32_t> layerIds;
        hierarchy.traverseInZOrder(
                [&layerIds = layerIds](const LayerHierarchy& hierarchy,
                                       const LayerHierarchy::TraversalPath&) -> bool {
                    layerIds.emplace_back(hierarchy.getLayer()->id);
                    return true;
                });
        return layerIds;
    }

    virtual void createRootLayer(uint32_t id) {
        sp<LayerHandle> handle = sp<LayerHandle>::make(id);
        mHandles[id] = handle;
        std::vector<std::unique_ptr<RequestedLayerState>> layers;
        layers.emplace_back(std::make_unique<RequestedLayerState>(
                createArgs(/*id=*/id, /*canBeRoot=*/true, /*parent=*/nullptr, /*mirror=*/nullptr)));
        mLifecycleManager.addLayers(std::move(layers));
    }

    void createDisplayMirrorLayer(uint32_t id, ui::LayerStack layerStack) {
        sp<LayerHandle> handle = sp<LayerHandle>::make(id);
        mHandles[id] = handle;
        std::vector<std::unique_ptr<RequestedLayerState>> layers;
        layers.emplace_back(std::make_unique<RequestedLayerState>(
                createDisplayMirrorArgs(/*id=*/id, layerStack)));
        mLifecycleManager.addLayers(std::move(layers));
    }

    virtual void createLayer(uint32_t id, uint32_t parentId) {
        sp<LayerHandle> handle = sp<LayerHandle>::make(id);
        mHandles[id] = handle;
        std::vector<std::unique_ptr<RequestedLayerState>> layers;
        layers.emplace_back(std::make_unique<RequestedLayerState>(
                createArgs(/*id=*/id, /*canBeRoot=*/false, /*parent=*/mHandles[parentId],
                           /*mirror=*/nullptr)));
        mLifecycleManager.addLayers(std::move(layers));
    }

    void reparentLayer(uint32_t id, uint32_t newParentId) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        if (newParentId == UNASSIGNED_LAYER_ID) {
            transactions.back().states.front().state.parentSurfaceControlForChild = nullptr;
        } else {
            auto parentHandle = mHandles[newParentId];
            transactions.back().states.front().state.parentSurfaceControlForChild =
                    sp<SurfaceControl>::make(SurfaceComposerClient::getDefault(), parentHandle,
                                             static_cast<int32_t>(newParentId), "Test");
        }
        transactions.back().states.front().state.what = layer_state_t::eReparent;
        transactions.back().states.front().state.surface = mHandles[id];
        mLifecycleManager.applyTransactions(transactions);
    }

    void reparentRelativeLayer(uint32_t id, uint32_t relativeParentId) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        if (relativeParentId == UNASSIGNED_LAYER_ID) {
            transactions.back().states.front().state.what = layer_state_t::eLayerChanged;
        } else {
            auto parentHandle = mHandles[relativeParentId];
            transactions.back().states.front().state.relativeLayerSurfaceControl =
                    sp<SurfaceControl>::make(SurfaceComposerClient::getDefault(), parentHandle,
                                             static_cast<int32_t>(relativeParentId), "test");
            transactions.back().states.front().state.what = layer_state_t::eRelativeLayerChanged;
        }
        transactions.back().states.front().state.surface = mHandles[id];
        mLifecycleManager.applyTransactions(transactions);
    }

    virtual void mirrorLayer(uint32_t id, uint32_t parent, uint32_t layerToMirror) {
        auto parentHandle = (parent == UNASSIGNED_LAYER_ID) ? nullptr : mHandles[parent];
        auto mirrorHandle =
                (layerToMirror == UNASSIGNED_LAYER_ID) ? nullptr : mHandles[layerToMirror];

        sp<LayerHandle> handle = sp<LayerHandle>::make(id);
        mHandles[id] = handle;
        std::vector<std::unique_ptr<RequestedLayerState>> layers;
        layers.emplace_back(std::make_unique<RequestedLayerState>(
                createArgs(/*id=*/id, /*canBeRoot=*/false, /*parent=*/parentHandle,
                           /*mirror=*/mHandles[layerToMirror])));
        mLifecycleManager.addLayers(std::move(layers));
    }

    void updateBackgroundColor(uint32_t id, half alpha) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});
        transactions.back().states.front().state.what = layer_state_t::eBackgroundColorChanged;
        transactions.back().states.front().state.bgColor.a = alpha;
        transactions.back().states.front().state.surface = mHandles[id];
        mLifecycleManager.applyTransactions(transactions);
    }

    void destroyLayerHandle(uint32_t id) { mLifecycleManager.onHandlesDestroyed({id}); }

    void updateAndVerify(LayerHierarchyBuilder& hierarchyBuilder) {
        if (mLifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy)) {
            hierarchyBuilder.update(mLifecycleManager.getLayers(),
                                    mLifecycleManager.getDestroyedLayers());
        }
        mLifecycleManager.commitChanges();

        // rebuild layer hierarchy from scratch and verify that it matches the updated state.
        LayerHierarchyBuilder newBuilder(mLifecycleManager.getLayers());
        EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()),
                  getTraversalPath(newBuilder.getHierarchy()));
        EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()),
                  getTraversalPathInZOrder(newBuilder.getHierarchy()));
        EXPECT_FALSE(
                mLifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    }

    void setZ(uint32_t id, int32_t z) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        transactions.back().states.front().state.what = layer_state_t::eLayerChanged;
        transactions.back().states.front().state.surface = mHandles[id];
        transactions.back().states.front().state.layerId = static_cast<int32_t>(id);
        transactions.back().states.front().state.z = z;
        mLifecycleManager.applyTransactions(transactions);
    }

    void setCrop(uint32_t id, const Rect& crop) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        transactions.back().states.front().state.what = layer_state_t::eCropChanged;
        transactions.back().states.front().state.surface = mHandles[id];
        transactions.back().states.front().state.layerId = static_cast<int32_t>(id);
        transactions.back().states.front().state.crop = crop;
        mLifecycleManager.applyTransactions(transactions);
    }

    void setFlags(uint32_t id, uint32_t mask, uint32_t flags) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        transactions.back().states.front().state.what = layer_state_t::eFlagsChanged;
        transactions.back().states.front().state.flags = flags;
        transactions.back().states.front().state.mask = mask;
        transactions.back().states.front().state.surface = mHandles[id];
        transactions.back().states.front().state.layerId = static_cast<int32_t>(id);
        mLifecycleManager.applyTransactions(transactions);
    }

    void setAlpha(uint32_t id, float alpha) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        transactions.back().states.front().state.what = layer_state_t::eAlphaChanged;
        transactions.back().states.front().state.surface = mHandles[id];
        transactions.back().states.front().state.layerId = static_cast<int32_t>(id);
        transactions.back().states.front().state.color.a = static_cast<half>(alpha);
        mLifecycleManager.applyTransactions(transactions);
    }

    void hideLayer(uint32_t id) {
        setFlags(id, layer_state_t::eLayerHidden, layer_state_t::eLayerHidden);
    }

    void showLayer(uint32_t id) { setFlags(id, layer_state_t::eLayerHidden, 0); }

    void setColor(uint32_t id, half3 rgb = half3(1._hf, 1._hf, 1._hf)) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});
        transactions.back().states.front().state.what = layer_state_t::eColorChanged;
        transactions.back().states.front().state.color.rgb = rgb;
        transactions.back().states.front().state.surface = mHandles[id];
        transactions.back().states.front().state.layerId = static_cast<int32_t>(id);
        mLifecycleManager.applyTransactions(transactions);
    }

    void setLayerStack(uint32_t id, int32_t layerStack) {
        std::vector<TransactionState> transactions;
        transactions.emplace_back();
        transactions.back().states.push_back({});

        transactions.back().states.front().state.what = layer_state_t::eLayerStackChanged;
        transactions.back().states.front().state.surface = mHandles[id];
        transactions.back().states.front().state.layerId = static_cast<int32_t>(id);
        transactions.back().states.front().state.layerStack = ui::LayerStack::fromValue(layerStack);
        mLifecycleManager.applyTransactions(transactions);
    }

    LayerLifecycleManager mLifecycleManager;
    std::unordered_map<uint32_t, sp<LayerHandle>> mHandles;
};

} // namespace android::surfaceflinger::frontend
