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

#include <compositionengine/Output.h>
#include <compositionengine/ProjectionSpace.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <renderengine/RenderEngine.h>

#include <chrono>

namespace android {

namespace compositionengine::impl::planner {

std::string durationString(std::chrono::milliseconds duration);

class LayerState;

class CachedSet {
public:
    class Layer {
    public:
        Layer(const LayerState*, std::chrono::steady_clock::time_point lastUpdate);

        const LayerState* getState() const { return mState; }
        const std::string& getName() const { return mState->getName(); }
        Rect getDisplayFrame() const { return mState->getDisplayFrame(); }
        const Region& getVisibleRegion() const { return mState->getVisibleRegion(); }
        const sp<GraphicBuffer>& getBuffer() const {
            return mState->getOutputLayer()->getLayerFE().getCompositionState()->buffer;
        }
        int64_t getFramesSinceBufferUpdate() const { return mState->getFramesSinceBufferUpdate(); }
        NonBufferHash getHash() const { return mHash; }
        std::chrono::steady_clock::time_point getLastUpdate() const { return mLastUpdate; }

    private:
        const LayerState* mState;
        NonBufferHash mHash;
        std::chrono::steady_clock::time_point mLastUpdate;
    };

    CachedSet(const LayerState*, std::chrono::steady_clock::time_point lastUpdate);
    CachedSet(Layer layer);

    void addLayer(const LayerState*, std::chrono::steady_clock::time_point lastUpdate);

    std::chrono::steady_clock::time_point getLastUpdate() const { return mLastUpdate; }
    NonBufferHash getFingerprint() const { return mFingerprint; }
    size_t getLayerCount() const { return mLayers.size(); }
    const Layer& getFirstLayer() const { return mLayers[0]; }
    const Rect& getBounds() const { return mBounds; }
    const Region& getVisibleRegion() const { return mVisibleRegion; }
    size_t getAge() const { return mAge; }
    const std::shared_ptr<renderengine::ExternalTexture>& getBuffer() const { return mTexture; }
    const sp<Fence>& getDrawFence() const { return mDrawFence; }
    const ProjectionSpace& getOutputSpace() const { return mOutputSpace; }
    ui::Dataspace getOutputDataspace() const { return mOutputDataspace; }

    NonBufferHash getNonBufferHash() const;

    size_t getComponentDisplayCost() const;
    size_t getCreationCost() const;
    size_t getDisplayCost() const;

    bool hasBufferUpdate() const;
    bool hasReadyBuffer() const;

    // Decomposes this CachedSet into a vector of its layers as individual CachedSets
    std::vector<CachedSet> decompose() const;

    void updateAge(std::chrono::steady_clock::time_point now);

    void setLastUpdate(std::chrono::steady_clock::time_point now) { mLastUpdate = now; }
    void append(const CachedSet& other) {
        mTexture = nullptr;
        mOutputDataspace = ui::Dataspace::UNKNOWN;
        mDrawFence = nullptr;

        mLayers.insert(mLayers.end(), other.mLayers.cbegin(), other.mLayers.cend());
        Region boundingRegion;
        boundingRegion.orSelf(mBounds);
        boundingRegion.orSelf(other.mBounds);
        mBounds = boundingRegion.getBounds();
        mVisibleRegion.orSelf(other.mVisibleRegion);
    }
    void incrementAge() { ++mAge; }

    // Renders the cached set with the supplied output composition state.
    void render(renderengine::RenderEngine& re, const OutputCompositionState& outputState);

    void dump(std::string& result) const;

    // Whether this represents a single layer with a buffer and rounded corners.
    // If it is, we can draw it by placing it behind another CachedSet and
    // punching a hole.
    bool requiresHolePunch() const;

    // Add a layer that will be drawn behind this one. ::render() will render a
    // hole in this CachedSet's buffer, allowing the supplied layer to peek
    // through. Must be called before ::render().
    void addHolePunchLayer(const LayerState*);

    // Retrieve the layer that will be drawn behind this one.
    OutputLayer* getHolePunchLayer() const;

private:
    CachedSet() = default;

    const NonBufferHash mFingerprint;
    std::chrono::steady_clock::time_point mLastUpdate = std::chrono::steady_clock::now();
    std::vector<Layer> mLayers;

    // Unowned.
    const LayerState* mHolePunchLayer = nullptr;
    Rect mBounds = Rect::EMPTY_RECT;
    Region mVisibleRegion;
    size_t mAge = 0;

    std::shared_ptr<renderengine::ExternalTexture> mTexture;
    sp<Fence> mDrawFence;
    ProjectionSpace mOutputSpace;
    ui::Dataspace mOutputDataspace;
    ui::Transform::RotationFlags mOrientation = ui::Transform::ROT_0;

    static const bool sDebugHighlighLayers;
};

} // namespace compositionengine::impl::planner
} // namespace android
