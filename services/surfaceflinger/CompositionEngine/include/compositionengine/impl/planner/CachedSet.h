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

#include <compositionengine/impl/planner/LayerState.h>

#include <chrono>

namespace android {

namespace renderengine {
class RenderEngine;
} // namespace renderengine

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
        const sp<GraphicBuffer>& getBuffer() const { return mState->getBuffer(); }
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
    size_t getAge() const { return mAge; }
    const sp<GraphicBuffer>& getBuffer() const { return mBuffer; }
    const sp<Fence>& getDrawFence() const { return mDrawFence; }

    NonBufferHash getNonBufferHash() const;

    size_t getComponentDisplayCost() const;
    size_t getCreationCost() const;
    size_t getDisplayCost() const;

    bool hasBufferUpdate(std::vector<const LayerState*>::const_iterator layers) const;
    bool hasReadyBuffer() const;

    // Decomposes this CachedSet into a vector of its layers as individual CachedSets
    std::vector<CachedSet> decompose() const;

    void updateAge(std::chrono::steady_clock::time_point now);

    void setLastUpdate(std::chrono::steady_clock::time_point now) { mLastUpdate = now; }
    void append(const CachedSet& other) {
        mBuffer = nullptr;
        mDrawFence = nullptr;

        mLayers.insert(mLayers.end(), other.mLayers.cbegin(), other.mLayers.cend());
        Region boundingRegion;
        boundingRegion.orSelf(mBounds);
        boundingRegion.orSelf(other.mBounds);
        mBounds = boundingRegion.getBounds();
    }
    void incrementAge() { ++mAge; }

    void render(renderengine::RenderEngine&);

    void dump(std::string& result) const;

private:
    CachedSet() = default;

    NonBufferHash mFingerprint = 0;
    std::chrono::steady_clock::time_point mLastUpdate = std::chrono::steady_clock::now();
    std::vector<Layer> mLayers;
    Rect mBounds = Rect::EMPTY_RECT;
    size_t mAge = 0;
    sp<GraphicBuffer> mBuffer;
    sp<Fence> mDrawFence;

    static const bool sDebugHighlighLayers;
};

} // namespace compositionengine::impl::planner
} // namespace android
