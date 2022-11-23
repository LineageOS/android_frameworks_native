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
#include "FrontEnd/LayerLifecycleManager.h"
#include "Layer.h"
#include "gui/SurfaceComposerClient.h"

using namespace android::surfaceflinger;

namespace android::surfaceflinger::frontend {

namespace {
LayerCreationArgs createArgs(uint32_t id, bool canBeRoot, wp<IBinder> parent, wp<IBinder> mirror) {
    LayerCreationArgs args(nullptr, nullptr, "testlayer", 0, {}, std::make_optional(id));
    args.addToRoot = canBeRoot;
    args.parentHandle = parent;
    args.mirrorLayerHandle = mirror;
    return args;
}
} // namespace

// To run test:
/**
 mp :libsurfaceflinger_unittest && adb sync; adb shell \
    /data/nativetest/libsurfaceflinger_unittest/libsurfaceflinger_unittest \
    --gtest_filter="LayerLifecycleManagerTest.*" --gtest_repeat=100 \
    --gtest_shuffle \
    --gtest_brief=1
*/
class ExpectLayerLifecycleListener : public LayerLifecycleManager::ILifecycleListener {
public:
    void onLayerAdded(const RequestedLayerState& layer) override {
        mActualLayersAdded.emplace(layer.id);
    };
    void onLayerDestroyed(const RequestedLayerState& layer) override {
        mActualLayersDestroyed.emplace(layer.id);
    };

    void expectLayersAdded(const std::unordered_set<uint32_t>& expectedLayersAdded) {
        EXPECT_EQ(expectedLayersAdded, mActualLayersAdded);
        mActualLayersAdded.clear();
    }
    void expectLayersDestroyed(const std::unordered_set<uint32_t>& expectedLayersDestroyed) {
        EXPECT_EQ(expectedLayersDestroyed, mActualLayersDestroyed);
        mActualLayersDestroyed.clear();
    }

    std::unordered_set<uint32_t> mActualLayersAdded;
    std::unordered_set<uint32_t> mActualLayersDestroyed;
};

class LayerLifecycleManagerTest : public testing::Test {
protected:
    std::unique_ptr<RequestedLayerState> rootLayer(uint32_t id) {
        return std::make_unique<RequestedLayerState>(
                createArgs(/*id=*/id, /*canBeRoot=*/true, /*parent=*/nullptr, /*mirror=*/nullptr));
    }

    std::unique_ptr<RequestedLayerState> childLayer(uint32_t id, uint32_t parentId) {
        mHandles[parentId] = sp<LayerHandle>::make(parentId);
        return std::make_unique<RequestedLayerState>(createArgs(/*id=*/id, /*canBeRoot=*/false,
                                                                /*parent=*/mHandles[parentId],
                                                                /*mirror=*/nullptr));
    }

    TransactionState reparentLayer(uint32_t id, uint32_t newParentId) {
        TransactionState transaction;
        transaction.states.push_back({});

        if (newParentId == UNASSIGNED_LAYER_ID) {
            transaction.states.front().state.parentSurfaceControlForChild = nullptr;
        } else {
            transaction.states.front().state.parentSurfaceControlForChild =
                    sp<SurfaceControl>::make(SurfaceComposerClient::getDefault(),
                                             sp<LayerHandle>::make(newParentId),
                                             static_cast<int32_t>(newParentId), "Test");
        }
        transaction.states.front().state.what = layer_state_t::eReparent;
        transaction.states.front().state.surface = sp<LayerHandle>::make(id);
        return transaction;
    }

    TransactionState setLayer(uint32_t id, int32_t z) {
        TransactionState transaction;
        transaction.states.push_back({});
        transaction.states.front().state.z = z;
        transaction.states.front().state.what = layer_state_t::eLayerChanged;
        transaction.states.front().state.surface = sp<LayerHandle>::make(id);
        return transaction;
    }

    TransactionState makeRelative(uint32_t id, uint32_t relativeParentId) {
        TransactionState transaction;
        transaction.states.push_back({});

        if (relativeParentId == UNASSIGNED_LAYER_ID) {
            transaction.states.front().state.relativeLayerSurfaceControl = nullptr;
        } else {
            transaction.states.front().state.relativeLayerSurfaceControl =
                    sp<SurfaceControl>::make(SurfaceComposerClient::getDefault(),
                                             sp<LayerHandle>::make(relativeParentId),
                                             static_cast<int32_t>(relativeParentId), "Test");
        }
        transaction.states.front().state.what = layer_state_t::eRelativeLayerChanged;
        transaction.states.front().state.surface = sp<LayerHandle>::make(id);
        return transaction;
    }

    RequestedLayerState* getRequestedLayerState(LayerLifecycleManager& lifecycleManager,
                                                uint32_t layerId) {
        return lifecycleManager.getLayerFromId(layerId);
    }

    std::unordered_map<uint32_t, sp<LayerHandle>> mHandles;
};

TEST_F(LayerLifecycleManagerTest, addLayers) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(rootLayer(3));
    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.onHandlesDestroyed({1, 2, 3});
    EXPECT_TRUE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    lifecycleManager.commitChanges();
    EXPECT_FALSE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    listener->expectLayersAdded({1, 2, 3});
    listener->expectLayersDestroyed({1, 2, 3});
}

TEST_F(LayerLifecycleManagerTest, updateLayerStates) {
    LayerLifecycleManager lifecycleManager;
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    lifecycleManager.addLayers(std::move(layers));

    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.z = 2;
    transactions.back().states.front().state.what = layer_state_t::eLayerChanged;
    sp<LayerHandle> handle = sp<LayerHandle>::make(1u);
    transactions.back().states.front().state.surface = handle;
    lifecycleManager.applyTransactions(transactions);
    transactions.clear();

    auto& managedLayers = lifecycleManager.getLayers();
    ASSERT_EQ(managedLayers.size(), 1u);

    EXPECT_EQ(managedLayers.front()->z, 2);
    EXPECT_TRUE(managedLayers.front()->changes.test(RequestedLayerState::Changes::Z));

    EXPECT_TRUE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    lifecycleManager.commitChanges();
    EXPECT_FALSE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    ASSERT_EQ(managedLayers.size(), 1u);
    EXPECT_FALSE(managedLayers.front()->changes.test(RequestedLayerState::Changes::Z));

    // apply transactions that do not affect the hierarchy
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.backgroundBlurRadius = 22;
    transactions.back().states.front().state.what = layer_state_t::eBackgroundBlurRadiusChanged;
    transactions.back().states.front().state.surface = handle;
    lifecycleManager.applyTransactions(transactions);
    EXPECT_FALSE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    lifecycleManager.commitChanges();
    EXPECT_FALSE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    EXPECT_EQ(managedLayers.front()->backgroundBlurRadius, 22u);
}

TEST_F(LayerLifecycleManagerTest, layerWithoutHandleIsDestroyed) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.onHandlesDestroyed({1});
    lifecycleManager.commitChanges();

    SCOPED_TRACE("layerWithoutHandleIsDestroyed");
    listener->expectLayersAdded({1, 2});
    listener->expectLayersDestroyed({1});
}

TEST_F(LayerLifecycleManagerTest, rootLayerWithoutHandleIsDestroyed) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.onHandlesDestroyed({1});
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2});
    listener->expectLayersDestroyed({1});
}

TEST_F(LayerLifecycleManagerTest, offscreenLayerIsDestroyed) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(childLayer(3, /*parent*/ 2));
    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2, 3});
    listener->expectLayersDestroyed({});

    lifecycleManager.applyTransactions({reparentLayer(3, UNASSIGNED_LAYER_ID)});
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({});

    lifecycleManager.onHandlesDestroyed({3});
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({3});
}

TEST_F(LayerLifecycleManagerTest, offscreenChildLayerWithHandleIsNotDestroyed) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(childLayer(3, /*parent*/ 2));
    layers.emplace_back(childLayer(4, /*parent*/ 3));
    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2, 3, 4});
    listener->expectLayersDestroyed({});

    lifecycleManager.applyTransactions({reparentLayer(3, UNASSIGNED_LAYER_ID)});
    lifecycleManager.onHandlesDestroyed({3});
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({3});
}

TEST_F(LayerLifecycleManagerTest, offscreenChildLayerWithoutHandleIsDestroyed) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(childLayer(3, /*parent*/ 2));
    layers.emplace_back(childLayer(4, /*parent*/ 3));
    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2, 3, 4});
    listener->expectLayersDestroyed({});

    lifecycleManager.applyTransactions({reparentLayer(3, UNASSIGNED_LAYER_ID)});
    lifecycleManager.onHandlesDestroyed({3, 4});
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({3, 4});
}

TEST_F(LayerLifecycleManagerTest, reparentingDoesNotAffectRelativeZ) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(childLayer(3, /*parent*/ 2));
    layers.emplace_back(childLayer(4, /*parent*/ 3));

    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2, 3, 4});
    listener->expectLayersDestroyed({});

    lifecycleManager.applyTransactions({makeRelative(4, 1)});
    EXPECT_TRUE(getRequestedLayerState(lifecycleManager, 4)->isRelativeOf);
    lifecycleManager.applyTransactions({reparentLayer(4, 2)});
    EXPECT_TRUE(getRequestedLayerState(lifecycleManager, 4)->isRelativeOf);

    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({});
}

TEST_F(LayerLifecycleManagerTest, reparentingToNullRemovesRelativeZ) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(childLayer(3, /*parent*/ 2));
    layers.emplace_back(childLayer(4, /*parent*/ 3));

    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2, 3, 4});
    listener->expectLayersDestroyed({});

    lifecycleManager.applyTransactions({makeRelative(4, 1)});
    EXPECT_TRUE(getRequestedLayerState(lifecycleManager, 4)->isRelativeOf);
    lifecycleManager.applyTransactions({reparentLayer(4, UNASSIGNED_LAYER_ID)});
    EXPECT_FALSE(getRequestedLayerState(lifecycleManager, 4)->isRelativeOf);

    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({});
}

TEST_F(LayerLifecycleManagerTest, setZRemovesRelativeZ) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);
    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    layers.emplace_back(rootLayer(2));
    layers.emplace_back(childLayer(3, /*parent*/ 2));
    layers.emplace_back(childLayer(4, /*parent*/ 3));

    lifecycleManager.addLayers(std::move(layers));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2, 3, 4});
    listener->expectLayersDestroyed({});

    lifecycleManager.applyTransactions({makeRelative(4, 1)});
    EXPECT_TRUE(getRequestedLayerState(lifecycleManager, 4)->isRelativeOf);
    lifecycleManager.applyTransactions({setLayer(4, 1)});
    EXPECT_FALSE(getRequestedLayerState(lifecycleManager, 4)->isRelativeOf);

    lifecycleManager.commitChanges();
    listener->expectLayersAdded({});
    listener->expectLayersDestroyed({});
}

TEST_F(LayerLifecycleManagerTest, canAddBackgroundLayer) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);

    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    lifecycleManager.addLayers(std::move(layers));

    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.bgColorAlpha = 0.5;
    transactions.back().states.front().state.what = layer_state_t::eBackgroundColorChanged;
    sp<LayerHandle> handle = sp<LayerHandle>::make(1u);
    transactions.back().states.front().state.surface = handle;
    lifecycleManager.applyTransactions(transactions);

    auto& managedLayers = lifecycleManager.getLayers();
    ASSERT_EQ(managedLayers.size(), 2u);

    EXPECT_TRUE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2});
    listener->expectLayersDestroyed({});
    EXPECT_EQ(getRequestedLayerState(lifecycleManager, 2)->color.a, 0.5_hf);
}

TEST_F(LayerLifecycleManagerTest, canDestroyBackgroundLayer) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);

    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    lifecycleManager.addLayers(std::move(layers));

    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.bgColorAlpha = 0.5;
    transactions.back().states.front().state.what = layer_state_t::eBackgroundColorChanged;
    sp<LayerHandle> handle = sp<LayerHandle>::make(1u);
    transactions.back().states.front().state.surface = handle;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.bgColorAlpha = 0;
    transactions.back().states.front().state.what = layer_state_t::eBackgroundColorChanged;
    transactions.back().states.front().state.surface = handle;

    lifecycleManager.applyTransactions(transactions);

    ASSERT_EQ(lifecycleManager.getLayers().size(), 1u);
    ASSERT_EQ(lifecycleManager.getDestroyedLayers().size(), 1u);

    EXPECT_TRUE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2});
    listener->expectLayersDestroyed({2});
}

TEST_F(LayerLifecycleManagerTest, onParentDestroyDestroysBackgroundLayer) {
    LayerLifecycleManager lifecycleManager;
    auto listener = std::make_shared<ExpectLayerLifecycleListener>();
    lifecycleManager.addLifecycleListener(listener);

    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(rootLayer(1));
    lifecycleManager.addLayers(std::move(layers));

    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.bgColorAlpha = 0.5;
    transactions.back().states.front().state.what = layer_state_t::eBackgroundColorChanged;
    sp<LayerHandle> handle = sp<LayerHandle>::make(1u);
    transactions.back().states.front().state.surface = handle;
    transactions.emplace_back();
    lifecycleManager.applyTransactions(transactions);
    lifecycleManager.onHandlesDestroyed({1});

    ASSERT_EQ(lifecycleManager.getLayers().size(), 0u);
    ASSERT_EQ(lifecycleManager.getDestroyedLayers().size(), 2u);

    EXPECT_TRUE(lifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy));
    lifecycleManager.commitChanges();
    listener->expectLayersAdded({1, 2});
    listener->expectLayersDestroyed({1, 2});
}

} // namespace android::surfaceflinger::frontend
