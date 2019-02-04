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

#include <utils/StrongPointer.h>

namespace android::compositionengine {

class Output;
class Layer;
class LayerFE;

/**
 * An output layer contains the output-dependent composition state for a layer
 */
class OutputLayer {
public:
    virtual ~OutputLayer();

    // Gets the output which owns this output layer
    virtual const Output& getOutput() const = 0;

    // Gets the display-independent layer which this output layer represents
    virtual Layer& getLayer() const = 0;

    // Gets the front-end layer interface this output layer represents
    virtual LayerFE& getLayerFE() const = 0;
};

} // namespace android::compositionengine
