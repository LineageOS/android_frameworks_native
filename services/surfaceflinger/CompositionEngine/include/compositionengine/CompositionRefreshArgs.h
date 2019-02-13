/*
 * Copyright 2019 The Android Open Source Project
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

#include <compositionengine/Display.h>
#include <compositionengine/Layer.h>

namespace android::compositionengine {

using Layers = std::vector<std::shared_ptr<compositionengine::Layer>>;
using Outputs = std::vector<std::shared_ptr<compositionengine::Output>>;

/**
 * A parameter object for refreshing a set of outputs
 */
struct CompositionRefreshArgs {
    // All the outputs being refreshed
    Outputs outputs;

    // All the layers that are potentially visible in the outputs. The order of
    // the layers is important, and should be in traversal order from back to
    // front.
    Layers layers;
};

} // namespace android::compositionengine
