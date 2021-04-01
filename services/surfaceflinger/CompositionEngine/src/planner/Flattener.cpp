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

#undef LOG_TAG
#define LOG_TAG "Planner"
// #define LOG_NDEBUG 0

#include <compositionengine/impl/planner/Flattener.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/impl/planner/Predictor.h>

using time_point = std::chrono::steady_clock::time_point;
using namespace std::chrono_literals;

namespace android::compositionengine::impl::planner {

NonBufferHash Flattener::flattenLayers(const std::vector<const LayerState*>& layers,
                                       NonBufferHash hash, time_point now) {
    const size_t unflattenedDisplayCost = calculateDisplayCost(layers);
    mUnflattenedDisplayCost += unflattenedDisplayCost;

    if (mCurrentGeometry != hash) {
        resetActivities(hash, now);
        mFlattenedDisplayCost += unflattenedDisplayCost;
        return hash;
    }

    ++mInitialLayerCounts[layers.size()];

    // Only buildCachedSets if these layers are already stored in mLayers.
    // Otherwise (i.e. mergeWithCachedSets returns false), the time has not
    // changed, so buildCachedSets will never find any runs.
    const bool alreadyHadCachedSets = mergeWithCachedSets(layers, now);

    ++mFinalLayerCounts[mLayers.size()];

    if (alreadyHadCachedSets) {
        buildCachedSets(now);
        hash = computeLayersHash();
    }

    return hash;
}

void Flattener::renderCachedSets(renderengine::RenderEngine& renderEngine,
                                 const OutputCompositionState& outputState) {
    if (!mNewCachedSet) {
        return;
    }

    mNewCachedSet->render(renderEngine, outputState);
}

void Flattener::dump(std::string& result) const {
    const auto now = std::chrono::steady_clock::now();

    base::StringAppendF(&result, "Flattener state:\n");

    result.append("\n  Statistics:\n");

    result.append("    Display cost (in screen-size buffers):\n");
    const size_t displayArea = static_cast<size_t>(mDisplaySize.width * mDisplaySize.height);
    base::StringAppendF(&result, "      Unflattened: %.2f\n",
                        static_cast<float>(mUnflattenedDisplayCost) / displayArea);
    base::StringAppendF(&result, "      Flattened:   %.2f\n",
                        static_cast<float>(mFlattenedDisplayCost) / displayArea);

    const auto compareLayerCounts = [](const std::pair<size_t, size_t>& left,
                                       const std::pair<size_t, size_t>& right) {
        return left.first < right.first;
    };

    const size_t maxLayerCount = std::max_element(mInitialLayerCounts.cbegin(),
                                                  mInitialLayerCounts.cend(), compareLayerCounts)
                                         ->first;

    result.append("\n    Initial counts:\n");
    for (size_t count = 1; count < maxLayerCount; ++count) {
        size_t initial = mInitialLayerCounts.count(count) > 0 ? mInitialLayerCounts.at(count) : 0;
        base::StringAppendF(&result, "      % 2zd: %zd\n", count, initial);
    }

    result.append("\n    Final counts:\n");
    for (size_t count = 1; count < maxLayerCount; ++count) {
        size_t final = mFinalLayerCounts.count(count) > 0 ? mFinalLayerCounts.at(count) : 0;
        base::StringAppendF(&result, "      % 2zd: %zd\n", count, final);
    }

    base::StringAppendF(&result, "\n    Cached sets created: %zd\n", mCachedSetCreationCount);
    base::StringAppendF(&result, "    Cost: %.2f\n",
                        static_cast<float>(mCachedSetCreationCost) / displayArea);

    const auto lastUpdate =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastGeometryUpdate);
    base::StringAppendF(&result, "\n  Current hash %016zx, last update %sago\n\n", mCurrentGeometry,
                        durationString(lastUpdate).c_str());

    result.append("  Current layers:");
    for (const CachedSet& layer : mLayers) {
        result.append("\n");
        layer.dump(result);
    }
}

size_t Flattener::calculateDisplayCost(const std::vector<const LayerState*>& layers) const {
    Region coveredRegion;
    size_t displayCost = 0;
    bool hasClientComposition = false;

    for (const LayerState* layer : layers) {
        coveredRegion.orSelf(layer->getDisplayFrame());

        // Regardless of composition type, we always have to read each input once
        displayCost += static_cast<size_t>(layer->getDisplayFrame().width() *
                                           layer->getDisplayFrame().height());

        hasClientComposition |= layer->getCompositionType() == hal::Composition::CLIENT;
    }

    if (hasClientComposition) {
        // If there is client composition, the client target buffer has to be both written by the
        // GPU and read by the DPU, so we pay its cost twice
        displayCost += 2 *
                static_cast<size_t>(coveredRegion.bounds().width() *
                                    coveredRegion.bounds().height());
    }

    return displayCost;
}

void Flattener::resetActivities(NonBufferHash hash, time_point now) {
    ALOGV("[%s]", __func__);

    mCurrentGeometry = hash;
    mLastGeometryUpdate = now;

    for (const CachedSet& cachedSet : mLayers) {
        if (cachedSet.getLayerCount() > 1) {
            ++mInvalidatedCachedSetAges[cachedSet.getAge()];
        }
    }

    mLayers.clear();

    if (mNewCachedSet) {
        ++mInvalidatedCachedSetAges[mNewCachedSet->getAge()];
        mNewCachedSet = std::nullopt;
    }
}

NonBufferHash Flattener::computeLayersHash() const{
    size_t hash = 0;
    for (const auto& layer : mLayers) {
        android::hashCombineSingleHashed(hash, layer.getNonBufferHash());
    }
    return hash;
}

// Only called if the geometry matches the last frame. Return true if mLayers
// was already populated with these layers, i.e. on the second and following
// calls with the same geometry.
bool Flattener::mergeWithCachedSets(const std::vector<const LayerState*>& layers, time_point now) {
    std::vector<CachedSet> merged;

    if (mLayers.empty()) {
        merged.reserve(layers.size());
        for (const LayerState* layer : layers) {
            merged.emplace_back(layer, now);
            mFlattenedDisplayCost += merged.back().getDisplayCost();
        }
        mLayers = std::move(merged);
        return false;
    }

    ALOGV("[%s] Incoming layers:", __func__);
    for (const LayerState* layer : layers) {
        ALOGV("%s", layer->getName().c_str());
    }

    ALOGV("[%s] Current layers:", __func__);
    for (const CachedSet& layer : mLayers) {
        std::string dump;
        layer.dump(dump);
        ALOGV("%s", dump.c_str());
    }

    auto currentLayerIter = mLayers.begin();
    auto incomingLayerIter = layers.begin();
    while (incomingLayerIter != layers.end()) {
        if (mNewCachedSet && mNewCachedSet->getFingerprint() == (*incomingLayerIter)->getHash()) {
            if (mNewCachedSet->hasBufferUpdate()) {
                ALOGV("[%s] Dropping new cached set", __func__);
                ++mInvalidatedCachedSetAges[0];
                mNewCachedSet = std::nullopt;
            } else if (mNewCachedSet->hasReadyBuffer()) {
                ALOGV("[%s] Found ready buffer", __func__);
                size_t skipCount = mNewCachedSet->getLayerCount();
                while (skipCount != 0) {
                    const size_t layerCount = currentLayerIter->getLayerCount();
                    for (size_t i = 0; i < layerCount; ++i) {
                        OutputLayer::CompositionState& state =
                                (*incomingLayerIter)->getOutputLayer()->editState();
                        state.overrideInfo = {
                                .buffer = mNewCachedSet->getBuffer(),
                                .acquireFence = mNewCachedSet->getDrawFence(),
                                .displayFrame = mNewCachedSet->getBounds(),
                                .dataspace = mNewCachedSet->getOutputDataspace(),
                                .displaySpace = mNewCachedSet->getOutputSpace(),
                                .damageRegion = Region::INVALID_REGION,
                                .visibleRegion = mNewCachedSet->getVisibleRegion(),
                        };
                        ++incomingLayerIter;
                    }

                    if (currentLayerIter->getLayerCount() > 1) {
                        ++mInvalidatedCachedSetAges[currentLayerIter->getAge()];
                    }
                    ++currentLayerIter;

                    skipCount -= layerCount;
                }
                merged.emplace_back(std::move(*mNewCachedSet));
                mNewCachedSet = std::nullopt;
                continue;
            }
        }

        if (!currentLayerIter->hasBufferUpdate()) {
            currentLayerIter->incrementAge();
            merged.emplace_back(*currentLayerIter);

            // Skip the incoming layers corresponding to this valid current layer
            const size_t layerCount = currentLayerIter->getLayerCount();
            for (size_t i = 0; i < layerCount; ++i) {
                OutputLayer::CompositionState& state =
                        (*incomingLayerIter)->getOutputLayer()->editState();
                state.overrideInfo = {
                        .buffer = currentLayerIter->getBuffer(),
                        .acquireFence = currentLayerIter->getDrawFence(),
                        .displayFrame = currentLayerIter->getBounds(),
                        .dataspace = currentLayerIter->getOutputDataspace(),
                        .displaySpace = currentLayerIter->getOutputSpace(),
                        .damageRegion = Region(),
                        .visibleRegion = currentLayerIter->getVisibleRegion(),
                };
                ++incomingLayerIter;
            }
        } else if (currentLayerIter->getLayerCount() > 1) {
            // Break the current layer into its constituent layers
            ++mInvalidatedCachedSetAges[currentLayerIter->getAge()];
            for (CachedSet& layer : currentLayerIter->decompose()) {
                layer.updateAge(now);
                merged.emplace_back(layer);
                ++incomingLayerIter;
            }
        } else {
            currentLayerIter->updateAge(now);
            merged.emplace_back(*currentLayerIter);
            ++incomingLayerIter;
        }
        ++currentLayerIter;
    }

    for (const CachedSet& layer : merged) {
        mFlattenedDisplayCost += layer.getDisplayCost();
    }

    mLayers = std::move(merged);
    return true;
}

void Flattener::buildCachedSets(time_point now) {
    struct Run {
        Run(std::vector<CachedSet>::const_iterator start, size_t length)
              : start(start), length(length) {}

        std::vector<CachedSet>::const_iterator start;
        size_t length;
    };

    if (mLayers.empty()) {
        ALOGV("[%s] No layers found, returning", __func__);
        return;
    }

    std::vector<Run> runs;
    bool isPartOfRun = false;

    // Keep track of the layer that follows a run. It's possible that we will
    // render it with a hole-punch.
    const CachedSet* holePunchLayer = nullptr;

    for (auto currentSet = mLayers.cbegin(); currentSet != mLayers.cend(); ++currentSet) {
        if (now - currentSet->getLastUpdate() > kActiveLayerTimeout) {
            // Layer is inactive
            if (isPartOfRun) {
                runs.back().length += currentSet->getLayerCount();
            } else {
                // Runs can't start with a non-buffer layer
                if (currentSet->getFirstLayer().getBuffer() == nullptr) {
                    ALOGV("[%s] Skipping initial non-buffer layer", __func__);
                } else {
                    runs.emplace_back(currentSet, currentSet->getLayerCount());
                    isPartOfRun = true;
                }
            }
        } else if (isPartOfRun) {
            // Runs must be at least 2 sets long or there's nothing to combine
            if (runs.back().start->getLayerCount() == runs.back().length) {
                runs.pop_back();
            } else {
                // The prior run contained at least two sets. Currently, we'll
                // only possibly merge a single run, so only keep track of a
                // holePunchLayer if this is the first run.
                if (runs.size() == 1) {
                    holePunchLayer = &(*currentSet);
                }

                // TODO(b/185114532: Break out of the loop? We may find more runs, but we
                // won't do anything with them.
            }

            isPartOfRun = false;
        }
    }

    // Check for at least 2 sets one more time in case the set includes the last layer
    if (isPartOfRun && runs.back().start->getLayerCount() == runs.back().length) {
        runs.pop_back();
    }

    ALOGV("[%s] Found %zu candidate runs", __func__, runs.size());

    if (runs.empty()) {
        return;
    }

    mNewCachedSet.emplace(*runs[0].start);
    mNewCachedSet->setLastUpdate(now);
    auto currentSet = runs[0].start;
    while (mNewCachedSet->getLayerCount() < runs[0].length) {
        ++currentSet;
        mNewCachedSet->append(*currentSet);
    }

    if (mEnableHolePunch && holePunchLayer && holePunchLayer->requiresHolePunch()) {
        // Add the pip layer to mNewCachedSet, but in a special way - it should
        // replace the buffer with a clear round rect.
        mNewCachedSet->addHolePunchLayer(holePunchLayer->getFirstLayer().getState());
    }

    // TODO(b/181192467): Actually compute new LayerState vector and corresponding hash for each run
    mPredictor.getPredictedPlan({}, 0);

    ++mCachedSetCreationCount;
    mCachedSetCreationCost += mNewCachedSet->getCreationCost();
    std::string setDump;
    mNewCachedSet->dump(setDump);
    ALOGV("[%s] Added new cached set:\n%s", __func__, setDump.c_str());
}

} // namespace android::compositionengine::impl::planner
