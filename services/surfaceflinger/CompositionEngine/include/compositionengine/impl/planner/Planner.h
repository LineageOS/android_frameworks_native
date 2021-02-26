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
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/impl/planner/Predictor.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <optional>
#include <string>
#include <unordered_map>

namespace android {

namespace compositionengine::impl::planner {

// This is the top level class for layer caching. It is responsible for
// heuristically determining the composition strategy of the current layer stack,
// and flattens inactive layers into an override buffer so it can be used
// as a more efficient representation of parts of the layer stack.
class Planner {
public:
    // Updates the Planner with the current set of layers before a composition strategy is
    // determined.
    void plan(
            compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers);

    // Updates the Planner with the current set of layers after a composition strategy is
    // determined.
    void reportFinalPlan(
            compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers);

    void dump(const Vector<String16>& args, std::string&);

private:
    void dumpUsage(std::string&) const;

    std::unordered_map<LayerId, LayerState> mPreviousLayers;

    std::vector<const LayerState*> mCurrentLayers;

    Predictor mPredictor;

    std::optional<Predictor::PredictedPlan> mPredictedPlan;
};

} // namespace compositionengine::impl::planner
} // namespace android
