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

#pragma once

#include <compositionengine/impl/planner/CachedSet.h>
#include <compositionengine/impl/planner/LayerState.h>

#include <vector>

namespace android {

namespace renderengine {
class RenderEngine;
} // namespace renderengine

namespace compositionengine::impl::planner {
using namespace std::chrono_literals;

class LayerState;
class Predictor;

class Flattener {
public:
    Flattener(Predictor& predictor) : mPredictor(predictor) {}

    void setDisplaySize(ui::Size size) { mDisplaySize = size; }

    NonBufferHash flattenLayers(const std::vector<const LayerState*>& layers, NonBufferHash,
                                std::chrono::steady_clock::time_point now);

    void renderCachedSets(renderengine::RenderEngine&);

    void reset();

    void dump(std::string& result) const;

private:
    size_t calculateDisplayCost(const std::vector<const LayerState*>& layers) const;

    void resetActivities(NonBufferHash, std::chrono::steady_clock::time_point now);

    void updateLayersHash();

    bool mergeWithCachedSets(const std::vector<const LayerState*>& layers,
                             std::chrono::steady_clock::time_point now);

    void buildCachedSets(std::chrono::steady_clock::time_point now);

    Predictor& mPredictor;

    ui::Size mDisplaySize;

    NonBufferHash mCurrentGeometry;
    std::chrono::steady_clock::time_point mLastGeometryUpdate;

    std::vector<CachedSet> mLayers;
    NonBufferHash mLayersHash = 0;
    std::optional<CachedSet> mNewCachedSet;

    // Statistics
    size_t mUnflattenedDisplayCost = 0;
    size_t mFlattenedDisplayCost = 0;
    std::unordered_map<size_t, size_t> mInitialLayerCounts;
    std::unordered_map<size_t, size_t> mFinalLayerCounts;
    size_t mCachedSetCreationCount = 0;
    size_t mCachedSetCreationCost = 0;
    std::unordered_map<size_t, size_t> mInvalidatedCachedSetAges;

    static constexpr auto kActiveLayerTimeout = std::chrono::nanoseconds(150ms);
};

} // namespace compositionengine::impl::planner
} // namespace android
