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

#include "RequestedLayerState.h"
#include "TransactionState.h"

namespace android::surfaceflinger::frontend {

// Owns a collection of RequestedLayerStates and manages their lifecycle
// and state changes.
//
// RequestedLayerStates are tracked and destroyed if they have no parent and
// no handle left to keep them alive. The handle does not keep a reference to
// the RequestedLayerState but a layer id associated with the RequestedLayerState.
// If the handle is destroyed and the RequestedLayerState does not have a parent,
// the LayerLifecycleManager destroys the RequestedLayerState.
//
// Threading: This class is not thread safe, it requires external synchronization.
//
// Typical usage: Input states (new layers, transactions, destroyed layer handles)
// are collected in the background passed into the LayerLifecycleManager to update
// layer lifecycle and layer state at start of composition.
class LayerLifecycleManager {
public:
    // External state changes should be updated in the following order:
    void addLayers(std::vector<std::unique_ptr<RequestedLayerState>>);
    void applyTransactions(const std::vector<TransactionState>&);
    void onHandlesDestroyed(const std::vector<uint32_t>&);

    // Destroys RequestedLayerStates that are marked to be destroyed. Invokes all
    // ILifecycleListener callbacks and clears any change flags from previous state
    // updates. This function should be called outside the hot path since it's not
    // critical to composition.
    void commitChanges();

    class ILifecycleListener {
    public:
        virtual ~ILifecycleListener() = default;
        // Called on commitChanges when a layer is added. The callback includes
        // the layer state the client was created with as well as any state updates
        // until changes were committed.
        virtual void onLayerAdded(const RequestedLayerState&) = 0;
        // Called on commitChanges when a layer has been destroyed. The callback
        // includes the final state before the layer was destroyed.
        virtual void onLayerDestroyed(const RequestedLayerState&) = 0;
    };
    void addLifecycleListener(std::shared_ptr<ILifecycleListener>);
    void removeLifecycleListener(std::shared_ptr<ILifecycleListener>);
    const std::vector<std::unique_ptr<RequestedLayerState>>& getLayers() const;
    const std::vector<std::unique_ptr<RequestedLayerState>>& getDestroyedLayers() const;
    const ftl::Flags<RequestedLayerState::Changes> getGlobalChanges() const;

private:
    friend class LayerLifecycleManagerTest;
    friend class HierarchyBuilderTest;
    friend class android::SurfaceFlinger;

    RequestedLayerState* getLayerFromId(uint32_t);
    std::vector<uint32_t>* getLinkedLayersFromId(uint32_t);
    void linkLayer(uint32_t layerId, uint32_t layerToLink);
    void unlinkLayer(uint32_t& inOutLayerId, uint32_t linkedLayer);

    struct References {
        // Lifetime tied to mLayers
        RequestedLayerState& owner;
        std::vector<uint32_t> references;
        std::string getDebugString() const;
    };
    std::unordered_map<uint32_t, References> mIdToLayer;
    // Listeners are invoked once changes are committed.
    std::vector<std::shared_ptr<ILifecycleListener>> mListeners;

    // Aggregation of changes since last commit.
    ftl::Flags<RequestedLayerState::Changes> mGlobalChanges;
    std::vector<std::unique_ptr<RequestedLayerState>> mLayers;
    // Layers pending destruction. Layers will be destroyed once changes are committed.
    std::vector<std::unique_ptr<RequestedLayerState>> mDestroyedLayers;
};

} // namespace android::surfaceflinger::frontend
