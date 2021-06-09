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
#include <compositionengine/impl/planner/CachedSet.h>
#include <compositionengine/impl/planner/LayerState.h>

#include <numeric>
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
    Flattener(bool enableHolePunch = false);

    void setDisplaySize(ui::Size size) { mDisplaySize = size; }

    NonBufferHash flattenLayers(const std::vector<const LayerState*>& layers, NonBufferHash,
                                std::chrono::steady_clock::time_point now);

    // Renders the newest cached sets with the supplied output composition state
    void renderCachedSets(renderengine::RenderEngine& re,
                          const OutputCompositionState& outputState);

    void dump(std::string& result) const;
    void dumpLayers(std::string& result) const;

    const std::optional<CachedSet>& getNewCachedSetForTesting() const { return mNewCachedSet; }

protected:
    std::optional<CachedSet> mNewCachedSet;

private:
    size_t calculateDisplayCost(const std::vector<const LayerState*>& layers) const;

    void resetActivities(NonBufferHash, std::chrono::steady_clock::time_point now);

    NonBufferHash computeLayersHash() const;

    bool mergeWithCachedSets(const std::vector<const LayerState*>& layers,
                             std::chrono::steady_clock::time_point now);

    // A Run is a sequence of CachedSets, which is a candidate for flattening into a single
    // CachedSet. Because it is wasteful to flatten 1 CachedSet, a Run must contain more than 1
    // CachedSet
    class Run {
    public:
        // A builder for a Run, to aid in construction
        class Builder {
        private:
            std::vector<CachedSet>::const_iterator mStart;
            std::vector<size_t> mLengths;
            const CachedSet* mHolePunchCandidate = nullptr;
            const CachedSet* mBlurringLayer = nullptr;

        public:
            // Initializes a Builder a CachedSet to start from.
            // This start iterator must be an iterator for mLayers
            void init(const std::vector<CachedSet>::const_iterator& start) {
                mStart = start;
                mLengths.push_back(start->getLayerCount());
            }

            // Appends a new CachedSet to the end of the run
            // The provided length must be the size of the next sequential CachedSet in layers
            void append(size_t length) { mLengths.push_back(length); }

            // Sets the hole punch candidate for the Run.
            void setHolePunchCandidate(const CachedSet* holePunchCandidate) {
                mHolePunchCandidate = holePunchCandidate;
            }

            void setBlurringLayer(const CachedSet* blurringLayer) {
                mBlurringLayer = blurringLayer;
            }

            // Builds a Run instance, if a valid Run may be built.
            std::optional<Run> validateAndBuild() {
                if (mLengths.size() <= 1) {
                    return std::nullopt;
                }

                return Run(mStart,
                           std::reduce(mLengths.cbegin(), mLengths.cend(), 0u,
                                       [](size_t left, size_t right) { return left + right; }),
                           mHolePunchCandidate, mBlurringLayer);
            }

            void reset() { *this = {}; }
        };

        // Gets the starting CachedSet of this run.
        // This is an iterator into mLayers
        const std::vector<CachedSet>::const_iterator& getStart() const { return mStart; }
        // Gets the total number of layers encompassing this Run.
        size_t getLayerLength() const { return mLength; }
        // Gets the hole punch candidate for this Run.
        const CachedSet* getHolePunchCandidate() const { return mHolePunchCandidate; }
        const CachedSet* getBlurringLayer() const { return mBlurringLayer; }

    private:
        Run(std::vector<CachedSet>::const_iterator start, size_t length,
            const CachedSet* holePunchCandidate, const CachedSet* blurringLayer)
              : mStart(start),
                mLength(length),
                mHolePunchCandidate(holePunchCandidate),
                mBlurringLayer(blurringLayer) {}
        const std::vector<CachedSet>::const_iterator mStart;
        const size_t mLength;
        const CachedSet* const mHolePunchCandidate;
        const CachedSet* const mBlurringLayer;

        friend class Builder;
    };

    std::vector<Run> findCandidateRuns(std::chrono::steady_clock::time_point now) const;

    std::optional<Run> findBestRun(std::vector<Run>& runs) const;

    void buildCachedSets(std::chrono::steady_clock::time_point now);

    const bool mEnableHolePunch;

    ui::Size mDisplaySize;

    NonBufferHash mCurrentGeometry;
    std::chrono::steady_clock::time_point mLastGeometryUpdate;

    std::vector<CachedSet> mLayers;

    // Statistics
    size_t mUnflattenedDisplayCost = 0;
    size_t mFlattenedDisplayCost = 0;
    std::unordered_map<size_t, size_t> mInitialLayerCounts;
    std::unordered_map<size_t, size_t> mFinalLayerCounts;
    size_t mCachedSetCreationCount = 0;
    size_t mCachedSetCreationCost = 0;
    std::unordered_map<size_t, size_t> mInvalidatedCachedSetAges;
    std::chrono::nanoseconds mActiveLayerTimeout = kActiveLayerTimeout;

    static constexpr auto kActiveLayerTimeout = std::chrono::nanoseconds(150ms);
};

} // namespace compositionengine::impl::planner
} // namespace android
