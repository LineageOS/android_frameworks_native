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
#define LOG_TAG "LayerLifecycleManager"

#include "LayerLifecycleManager.h"
#include "Layer.h" // temporarily needed for LayerHandle
#include "LayerHandle.h"
#include "SwapErase.h"

namespace android::surfaceflinger::frontend {

using namespace ftl::flag_operators;

void LayerLifecycleManager::addLayers(std::vector<std::unique_ptr<RequestedLayerState>> newLayers) {
    if (newLayers.empty()) {
        return;
    }

    mGlobalChanges |= RequestedLayerState::Changes::Hierarchy;
    for (auto& newLayer : newLayers) {
        RequestedLayerState& layer = *newLayer.get();
        auto [it, inserted] = mIdToLayer.try_emplace(layer.id, References{.owner = layer});
        if (!inserted) {
            LOG_ALWAYS_FATAL("Duplicate layer id %d found. Existing layer: %s", layer.id,
                             it->second.owner.getDebugString().c_str());
        }

        layer.parentId = linkLayer(layer.parentId, layer.id);
        layer.relativeParentId = linkLayer(layer.relativeParentId, layer.id);
        layer.mirrorId = linkLayer(layer.mirrorId, layer.id);
        layer.touchCropId = linkLayer(layer.touchCropId, layer.id);

        mLayers.emplace_back(std::move(newLayer));
    }
}

void LayerLifecycleManager::onHandlesDestroyed(const std::vector<uint32_t>& destroyedHandles) {
    std::vector<uint32_t> layersToBeDestroyed;
    for (const auto& layerId : destroyedHandles) {
        auto it = mIdToLayer.find(layerId);
        if (it == mIdToLayer.end()) {
            LOG_ALWAYS_FATAL("%s Layerid not found %d", __func__, layerId);
            continue;
        }
        RequestedLayerState& layer = it->second.owner;
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
        layer.mirrorId = unlinkLayer(layer.mirrorId, layer.id);
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
            if (linkedLayer->mirrorId == layer.id) {
                linkedLayer->mirrorId = UNASSIGNED_LAYER_ID;
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
            ALOGV("%s destroyed layer %s", __func__, layer->getDebugStringShort().c_str());
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

void LayerLifecycleManager::applyTransactions(const std::vector<TransactionState>& transactions) {
    for (const auto& transaction : transactions) {
        for (const auto& resolvedComposerState : transaction.states) {
            const auto& clientState = resolvedComposerState.state;
            uint32_t layerId = LayerHandle::getLayerId(clientState.surface);
            if (layerId == UNASSIGNED_LAYER_ID) {
                ALOGW("%s Handle %p is not valid", __func__, clientState.surface.get());
                continue;
            }

            RequestedLayerState* layer = getLayerFromId(layerId);
            if (layer == nullptr) {
                LOG_ALWAYS_FATAL("%s Layer with handle %p (layerid=%d) not found", __func__,
                                 clientState.surface.get(), layerId);
                continue;
            }

            if (!layer->handleAlive) {
                LOG_ALWAYS_FATAL("%s Layer's handle %p (layerid=%d) is not alive. Possible out of "
                                 "order LayerLifecycleManager updates",
                                 __func__, clientState.surface.get(), layerId);
                continue;
            }

            uint32_t oldParentId = layer->parentId;
            uint32_t oldRelativeParentId = layer->relativeParentId;
            uint32_t oldTouchCropId = layer->touchCropId;
            layer->merge(resolvedComposerState);

            if (layer->what & layer_state_t::eBackgroundColorChanged) {
                if (layer->bgColorLayerId == UNASSIGNED_LAYER_ID && layer->bgColorAlpha != 0) {
                    LayerCreationArgs backgroundLayerArgs{nullptr,
                                                          nullptr,
                                                          layer->name + "BackgroundColorLayer",
                                                          ISurfaceComposerClient::eFXSurfaceEffect,
                                                          {}};
                    std::vector<std::unique_ptr<RequestedLayerState>> newLayers;
                    newLayers.emplace_back(
                            std::make_unique<RequestedLayerState>(backgroundLayerArgs));
                    RequestedLayerState* backgroundLayer = newLayers.back().get();
                    backgroundLayer->handleAlive = false;
                    backgroundLayer->parentId = layer->id;
                    backgroundLayer->z = std::numeric_limits<int32_t>::min();
                    backgroundLayer->color.rgb = layer->color.rgb;
                    backgroundLayer->color.a = layer->bgColorAlpha;
                    backgroundLayer->dataspace = layer->bgColorDataspace;

                    layer->bgColorLayerId = backgroundLayer->id;
                    addLayers({std::move(newLayers)});
                } else if (layer->bgColorLayerId != UNASSIGNED_LAYER_ID &&
                           layer->bgColorAlpha == 0) {
                    RequestedLayerState* bgColorLayer = getLayerFromId(layer->bgColorLayerId);
                    bgColorLayer->parentId = UNASSIGNED_LAYER_ID;
                    onHandlesDestroyed({layer->bgColorLayerId});
                } else if (layer->bgColorLayerId != UNASSIGNED_LAYER_ID) {
                    RequestedLayerState* bgColorLayer = getLayerFromId(layer->bgColorLayerId);
                    bgColorLayer->color.rgb = layer->color.rgb;
                    bgColorLayer->color.a = layer->bgColorAlpha;
                    bgColorLayer->dataspace = layer->bgColorDataspace;
                    mGlobalChanges |= RequestedLayerState::Changes::Content;
                }
            }

            if (oldParentId != layer->parentId) {
                unlinkLayer(oldParentId, layer->id);
                layer->parentId = linkLayer(layer->parentId, layer->id);
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
    for (auto& layer : mLayers) {
        if (layer->changes.test(RequestedLayerState::Changes::Created)) {
            for (auto listener : mListeners) {
                listener->onLayerAdded(*layer);
            }
        }
        layer->what = 0;
        layer->changes.clear();
    }

    for (auto& destroyedLayer : mDestroyedLayers) {
        if (destroyedLayer->changes.test(RequestedLayerState::Changes::Created)) {
            for (auto listener : mListeners) {
                listener->onLayerAdded(*destroyedLayer);
            }
        }

        for (auto listener : mListeners) {
            listener->onLayerDestroyed(*destroyedLayer);
        }
    }
    mDestroyedLayers.clear();
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

const ftl::Flags<RequestedLayerState::Changes> LayerLifecycleManager::getGlobalChanges() const {
    return mGlobalChanges;
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

} // namespace android::surfaceflinger::frontend
