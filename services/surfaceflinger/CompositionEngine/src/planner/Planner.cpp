/*
 * Copyright 2021 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "Planner"

#include <compositionengine/impl/planner/Planner.h>

namespace android::compositionengine::impl::planner {

void Planner::plan(
        compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers) {
    std::unordered_set<LayerId> removedLayers;
    removedLayers.reserve(mPreviousLayers.size());

    std::transform(mPreviousLayers.begin(), mPreviousLayers.end(),
                   std::inserter(removedLayers, removedLayers.begin()),
                   [](const auto& layer) { return layer.first; });

    for (auto layer : layers) {
        LayerId id = layer->getLayerFE().getSequence();
        if (const auto layerEntry = mPreviousLayers.find(id); layerEntry != mPreviousLayers.end()) {
            // Track changes from previous info
            LayerState& state = layerEntry->second;
            Flags<LayerStateField> differences = state.update(layer);
            if (differences.get() != 0) {
                ALOGV("Layer %s changed: %s", state.getName().c_str(),
                      differences.string().c_str());

                if (differences.test(LayerStateField::Buffer)) {
                    state.resetFramesSinceBufferUpdate();
                } else {
                    state.incrementFramesSinceBufferUpdate();
                }
            }
        } else {
            LayerState state(layer);
            ALOGV("Added layer %s", state.getName().c_str());
            mPreviousLayers.emplace(std::make_pair(id, std::move(state)));
        }

        if (const auto found = removedLayers.find(id); found != removedLayers.end()) {
            removedLayers.erase(found);
        }
    }

    for (LayerId removedLayer : removedLayers) {
        if (const auto layerEntry = mPreviousLayers.find(removedLayer);
            layerEntry != mPreviousLayers.end()) {
            const auto& [id, state] = *layerEntry;
            ALOGV("Removed layer %s", state.getName().c_str());
            mPreviousLayers.erase(removedLayer);
        }
    }
}

void Planner::dump(const Vector<String16>& /* args */, std::string& result) {
    result.append("Dumping Planner state");
}

} // namespace android::compositionengine::impl::planner
