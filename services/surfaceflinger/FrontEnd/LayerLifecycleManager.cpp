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

#include "LayerLifecycleManager.h"
#include "Client.h" // temporarily needed for LayerCreationArgs
#include "LayerLog.h"
#include "SwapErase.h"

namespace android::surfaceflinger::frontend {

using namespace ftl::flag_operators;

namespace {
// Returns true if the layer is root of a display and can be mirrored by mirroringLayer
bool canMirrorRootLayer(RequestedLayerState& mirroringLayer, RequestedLayerState& rootLayer) {
    return rootLayer.isRoot() && rootLayer.layerStack == mirroringLayer.layerStackToMirror &&
            rootLayer.id != mirroringLayer.id;
}
} // namespace

void LayerLifecycleManager::addLayers(std::vector<std::unique_ptr<RequestedLayerState>> newLayers) {
    if (newLayers.empty()) {
        return;
    }

    mGlobalChanges |= RequestedLayerState::Changes::Hierarchy;
    for (auto& newLayer : newLayers) {
        RequestedLayerState& layer = *newLayer.get();
        auto [it, inserted] = mIdToLayer.try_emplace(layer.id, References{.owner = layer});
        if (!inserted) {
            LOG_ALWAYS_FATAL("Duplicate layer id found. New layer: %s Existing layer: %s",
                             layer.getDebugString().c_str(),
                             it->second.owner.getDebugString().c_str());
        }
        mAddedLayers.push_back(newLayer.get());
        mChangedLayers.push_back(newLayer.get());
        layer.parentId = linkLayer(layer.parentId, layer.id);
        layer.relativeParentId = linkLayer(layer.relativeParentId, layer.id);
        if (layer.layerStackToMirror != ui::INVALID_LAYER_STACK) {
            // Set mirror layer's default layer stack to -1 so it doesn't end up rendered on a
            // display accidentally.
            layer.layerStack = ui::INVALID_LAYER_STACK;

            // if this layer is mirroring a display, then walk though all the existing root layers
            // for the layer stack and add them as children to be mirrored.
            mDisplayMirroringLayers.emplace_back(layer.id);
            for (auto& rootLayer : mLayers) {
                if (canMirrorRootLayer(layer, *rootLayer)) {
                    layer.mirrorIds.emplace_back(rootLayer->id);
                    linkLayer(rootLayer->id, layer.id);
                }
            }
        } else {
            // Check if we are mirroring a single layer, and if so add it to the list of children
            // to be mirrored.
            layer.layerIdToMirror = linkLayer(layer.layerIdToMirror, layer.id);
            if (layer.layerIdToMirror != UNASSIGNED_LAYER_ID) {
                layer.mirrorIds.emplace_back(layer.layerIdToMirror);
            }
        }
        layer.touchCropId = linkLayer(layer.touchCropId, layer.id);
        if (layer.isRoot()) {
            updateDisplayMirrorLayers(layer);
        }
        LLOGV(layer.id, "%s", layer.getDebugString().c_str());
        mLayers.emplace_back(std::move(newLayer));
    }
}

void LayerLifecycleManager::onHandlesDestroyed(const std::vector<uint32_t>& destroyedHandles,
                                               bool ignoreUnknownHandles) {
    std::vector<uint32_t> layersToBeDestroyed;
    for (const auto& layerId : destroyedHandles) {
        auto it = mIdToLayer.find(layerId);
        if (it == mIdToLayer.end()) {
            LOG_ALWAYS_FATAL_IF(!ignoreUnknownHandles, "%s Layerid not found %d", __func__,
                                layerId);
            continue;
        }
        RequestedLayerState& layer = it->second.owner;
        LLOGV(layer.id, "%s", layer.getDebugString().c_str());
        layer.handleAlive = false;
        if (!layer.canBeDestroyed()) {
            continue;
        }
        layer.changes |= RequestedLayerState::Changes::Destroyed;
        layersToBeDestroyed.emplace_back(layerId);
    }

    if (layersToBeDestroyed.empty()) {
        return;
    }

    mGlobalChanges |= RequestedLayerState::Changes::Hierarchy;
    for (size_t i = 0; i < layersToBeDestroyed.size(); i++) {
        uint32_t layerId = layersToBeDestroyed[i];
        auto it = mIdToLayer.find(layerId);
        if (it == mIdToLayer.end()) {
            LOG_ALWAYS_FATAL("%s Layer with id %d not found", __func__, layerId);
            continue;
        }

        RequestedLayerState& layer = it->second.owner;

        layer.parentId = unlinkLayer(layer.parentId, layer.id);
        layer.relativeParentId = unlinkLayer(layer.relativeParentId, layer.id);
        if (layer.layerStackToMirror != ui::INVALID_LAYER_STACK) {
            layer.mirrorIds = unlinkLayers(layer.mirrorIds, layer.id);
            swapErase(mDisplayMirroringLayers, layer.id);
        } else {
            layer.layerIdToMirror = unlinkLayer(layer.layerIdToMirror, layer.id);
            layer.mirrorIds.clear();
        }

        layer.touchCropId = unlinkLayer(layer.touchCropId, layer.id);

        auto& references = it->second.references;
        for (uint32_t linkedLayerId : references) {
            RequestedLayerState* linkedLayer = getLayerFromId(linkedLayerId);
            if (!linkedLayer) {
                LOG_ALWAYS_FATAL("%s Layerid reference %d not found for %d", __func__,
                                 linkedLayerId, layer.id);
                continue;
            };
            if (linkedLayer->parentId == layer.id) {
                linkedLayer->parentId = UNASSIGNED_LAYER_ID;
                if (linkedLayer->canBeDestroyed()) {
                    linkedLayer->changes |= RequestedLayerState::Changes::Destroyed;
                    layersToBeDestroyed.emplace_back(linkedLayer->id);
                }
            }
            if (linkedLayer->relativeParentId == layer.id) {
                linkedLayer->relativeParentId = UNASSIGNED_LAYER_ID;
            }
            if (swapErase(linkedLayer->mirrorIds, layer.id)) {
                linkedLayer->changes |= RequestedLayerState::Changes::Mirror;
            }
            if (linkedLayer->touchCropId == layer.id) {
                linkedLayer->touchCropId = UNASSIGNED_LAYER_ID;
            }
        }
        mIdToLayer.erase(it);
    }

    auto it = mLayers.begin();
    while (it != mLayers.end()) {
        RequestedLayerState* layer = it->get();
        if (layer->changes.test(RequestedLayerState::Changes::Destroyed)) {
            LLOGV(layer->id, "destroyed %s", layer->getDebugStringShort().c_str());
            std::iter_swap(it, mLayers.end() - 1);
            mDestroyedLayers.emplace_back(std::move(mLayers.back()));
            if (it == mLayers.end() - 1) {
                it = mLayers.erase(mLayers.end() - 1);
            } else {
                mLayers.erase(mLayers.end() - 1);
            }
        } else {
            it++;
        }
    }
}

void LayerLifecycleManager::applyTransactions(const std::vector<TransactionState>& transactions,
                                              bool ignoreUnknownLayers) {
    for (const auto& transaction : transactions) {
        for (const auto& resolvedComposerState : transaction.states) {
            const auto& clientState = resolvedComposerState.state;
            uint32_t layerId = resolvedComposerState.layerId;
            if (layerId == UNASSIGNED_LAYER_ID) {
                ALOGW("%s Handle %p is not valid", __func__, clientState.surface.get());
                continue;
            }

            RequestedLayerState* layer = getLayerFromId(layerId);
            if (layer == nullptr) {
                LOG_ALWAYS_FATAL_IF(!ignoreUnknownLayers, "%s Layer with layerid=%d not found",
                                    __func__, layerId);
                continue;
            }

            if (!layer->handleAlive) {
                LOG_ALWAYS_FATAL("%s Layer's with layerid=%d) is not alive. Possible out of "
                                 "order LayerLifecycleManager updates",
                                 __func__, layerId);
                continue;
            }

            if (layer->changes.get() == 0) {
                mChangedLayers.push_back(layer);
            }

            if (transaction.flags & ISurfaceComposer::eAnimation) {
                layer->changes |= RequestedLayerState::Changes::Animation;
            }

            uint32_t oldParentId = layer->parentId;
            uint32_t oldRelativeParentId = layer->relativeParentId;
            uint32_t oldTouchCropId = layer->touchCropId;
            layer->merge(resolvedComposerState);

            if (layer->what & layer_state_t::eBackgroundColorChanged) {
                if (layer->bgColorLayerId == UNASSIGNED_LAYER_ID && layer->bgColor.a != 0) {
                    LayerCreationArgs
                            backgroundLayerArgs(LayerCreationArgs::getInternalLayerId(
                                                        LayerCreationArgs::sInternalSequence++),
                                                /*internalLayer=*/true);
                    backgroundLayerArgs.parentId = layer->id;
                    backgroundLayerArgs.name = layer->name + "BackgroundColorLayer";
                    backgroundLayerArgs.flags = ISurfaceComposerClient::eFXSurfaceEffect;
                    std::vector<std::unique_ptr<RequestedLayerState>> newLayers;
                    newLayers.emplace_back(
                            std::make_unique<RequestedLayerState>(backgroundLayerArgs));
                    RequestedLayerState* backgroundLayer = newLayers.back().get();
                    backgroundLayer->bgColorLayer = true;
                    backgroundLayer->handleAlive = false;
                    backgroundLayer->parentId = layer->id;
                    backgroundLayer->z = std::numeric_limits<int32_t>::min();
                    backgroundLayer->color = layer->bgColor;
                    backgroundLayer->dataspace = layer->bgColorDataspace;
                    layer->bgColorLayerId = backgroundLayer->id;
                    addLayers({std::move(newLayers)});
                } else if (layer->bgColorLayerId != UNASSIGNED_LAYER_ID && layer->bgColor.a == 0) {
                    RequestedLayerState* bgColorLayer = getLayerFromId(layer->bgColorLayerId);
                    layer->bgColorLayerId = UNASSIGNED_LAYER_ID;
                    bgColorLayer->parentId = unlinkLayer(bgColorLayer->parentId, bgColorLayer->id);
                    onHandlesDestroyed({bgColorLayer->id});
                } else if (layer->bgColorLayerId != UNASSIGNED_LAYER_ID) {
                    RequestedLayerState* bgColorLayer = getLayerFromId(layer->bgColorLayerId);
                    bgColorLayer->color = layer->bgColor;
                    bgColorLayer->dataspace = layer->bgColorDataspace;
                    bgColorLayer->what |= layer_state_t::eColorChanged |
                            layer_state_t::eDataspaceChanged | layer_state_t::eAlphaChanged;
                    bgColorLayer->changes |= RequestedLayerState::Changes::Content;
                    mChangedLayers.push_back(bgColorLayer);
                    mGlobalChanges |= RequestedLayerState::Changes::Content;
                }
            }

            if (oldParentId != layer->parentId) {
                unlinkLayer(oldParentId, layer->id);
                layer->parentId = linkLayer(layer->parentId, layer->id);
                if (oldParentId == UNASSIGNED_LAYER_ID) {
                    updateDisplayMirrorLayers(*layer);
                }
            }
            if (layer->what & layer_state_t::eLayerStackChanged && layer->isRoot()) {
                updateDisplayMirrorLayers(*layer);
            }
            if (oldRelativeParentId != layer->relativeParentId) {
                unlinkLayer(oldRelativeParentId, layer->id);
                layer->relativeParentId = linkLayer(layer->relativeParentId, layer->id);
            }
            if (oldTouchCropId != layer->touchCropId) {
                unlinkLayer(oldTouchCropId, layer->id);
                layer->touchCropId = linkLayer(layer->touchCropId, layer->id);
            }

            mGlobalChanges |= layer->changes;
        }
    }
}

void LayerLifecycleManager::commitChanges() {
    for (auto layer : mAddedLayers) {
        for (auto& listener : mListeners) {
            listener->onLayerAdded(*layer);
        }
    }
    mAddedLayers.clear();

    for (auto& layer : mLayers) {
        layer->clearChanges();
    }

    for (auto& destroyedLayer : mDestroyedLayers) {
        for (auto& listener : mListeners) {
            listener->onLayerDestroyed(*destroyedLayer);
        }
    }
    mDestroyedLayers.clear();
    mChangedLayers.clear();
    mGlobalChanges.clear();
}

void LayerLifecycleManager::addLifecycleListener(std::shared_ptr<ILifecycleListener> listener) {
    mListeners.emplace_back(std::move(listener));
}

void LayerLifecycleManager::removeLifecycleListener(std::shared_ptr<ILifecycleListener> listener) {
    swapErase(mListeners, listener);
}

const std::vector<std::unique_ptr<RequestedLayerState>>& LayerLifecycleManager::getLayers() const {
    return mLayers;
}

const std::vector<std::unique_ptr<RequestedLayerState>>& LayerLifecycleManager::getDestroyedLayers()
        const {
    return mDestroyedLayers;
}

const std::vector<RequestedLayerState*>& LayerLifecycleManager::getChangedLayers() const {
    return mChangedLayers;
}

const ftl::Flags<RequestedLayerState::Changes> LayerLifecycleManager::getGlobalChanges() const {
    return mGlobalChanges;
}

const RequestedLayerState* LayerLifecycleManager::getLayerFromId(uint32_t id) const {
    if (id == UNASSIGNED_LAYER_ID) {
        return nullptr;
    }
    auto it = mIdToLayer.find(id);
    if (it == mIdToLayer.end()) {
        return nullptr;
    }
    return &it->second.owner;
}

RequestedLayerState* LayerLifecycleManager::getLayerFromId(uint32_t id) {
    if (id == UNASSIGNED_LAYER_ID) {
        return nullptr;
    }
    auto it = mIdToLayer.find(id);
    if (it == mIdToLayer.end()) {
        return nullptr;
    }
    return &it->second.owner;
}

std::vector<uint32_t>* LayerLifecycleManager::getLinkedLayersFromId(uint32_t id) {
    if (id == UNASSIGNED_LAYER_ID) {
        return nullptr;
    }
    auto it = mIdToLayer.find(id);
    if (it == mIdToLayer.end()) {
        return nullptr;
    }
    return &it->second.references;
}

uint32_t LayerLifecycleManager::linkLayer(uint32_t layerId, uint32_t layerToLink) {
    if (layerId == UNASSIGNED_LAYER_ID) {
        return UNASSIGNED_LAYER_ID;
    }

    std::vector<uint32_t>* linkedLayers = getLinkedLayersFromId(layerId);
    if (!linkedLayers) {
        ALOGV("Could not find layer id %d to link %d. Parent is probably destroyed", layerId,
              layerToLink);
        return UNASSIGNED_LAYER_ID;
    }
    linkedLayers->emplace_back(layerToLink);
    return layerId;
}

uint32_t LayerLifecycleManager::unlinkLayer(uint32_t layerId, uint32_t linkedLayer) {
    std::vector<uint32_t>* linkedLayers = getLinkedLayersFromId(layerId);
    if (!linkedLayers) {
        return UNASSIGNED_LAYER_ID;
    }
    swapErase(*linkedLayers, linkedLayer);
    return UNASSIGNED_LAYER_ID;
}

std::vector<uint32_t> LayerLifecycleManager::unlinkLayers(const std::vector<uint32_t>& layerIds,
                                                          uint32_t linkedLayer) {
    for (uint32_t layerId : layerIds) {
        unlinkLayer(layerId, linkedLayer);
    }
    return {};
}

std::string LayerLifecycleManager::References::getDebugString() const {
    std::string debugInfo = owner.name + "[" + std::to_string(owner.id) + "] refs:";
    std::for_each(references.begin(), references.end(),
                  [&debugInfo = debugInfo](const uint32_t& reference) mutable {
                      debugInfo += std::to_string(reference) + ",";
                  });
    return debugInfo;
}

void LayerLifecycleManager::fixRelativeZLoop(uint32_t relativeRootId) {
    auto it = mIdToLayer.find(relativeRootId);
    if (it == mIdToLayer.end()) {
        return;
    }
    RequestedLayerState& layer = it->second.owner;
    layer.relativeParentId = unlinkLayer(layer.relativeParentId, layer.id);
    layer.changes |=
            RequestedLayerState::Changes::Hierarchy | RequestedLayerState::Changes::RelativeParent;
    mGlobalChanges |= RequestedLayerState::Changes::Hierarchy;
}

// Some layers mirror the entire display stack. Since we don't have a single root layer per display
// we have to track all these layers and update what they mirror when the list of root layers
// on a display changes. This function walks through the list of display mirroring layers
// and updates its list of layers that its mirroring. This function should be called when a new
// root layer is added, removed or moved to another display.
void LayerLifecycleManager::updateDisplayMirrorLayers(RequestedLayerState& rootLayer) {
    for (uint32_t mirroringLayerId : mDisplayMirroringLayers) {
        RequestedLayerState* mirrorLayer = getLayerFromId(mirroringLayerId);
        bool canBeMirrored = canMirrorRootLayer(*mirrorLayer, rootLayer);
        bool currentlyMirrored =
                std::find(mirrorLayer->mirrorIds.begin(), mirrorLayer->mirrorIds.end(),
                          rootLayer.id) != mirrorLayer->mirrorIds.end();

        if (canBeMirrored && !currentlyMirrored) {
            mirrorLayer->mirrorIds.emplace_back(rootLayer.id);
            linkLayer(rootLayer.id, mirrorLayer->id);
            mirrorLayer->changes |= RequestedLayerState::Changes::Mirror;
        } else if (!canBeMirrored && currentlyMirrored) {
            swapErase(mirrorLayer->mirrorIds, rootLayer.id);
            unlinkLayer(rootLayer.id, mirrorLayer->id);
            mirrorLayer->changes |= RequestedLayerState::Changes::Mirror;
        }
    }
}

} // namespace android::surfaceflinger::frontend
