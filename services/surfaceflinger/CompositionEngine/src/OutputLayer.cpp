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

#include <compositionengine/Layer.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/Output.h>
#include <compositionengine/impl/OutputLayer.h>

namespace android::compositionengine {

OutputLayer::~OutputLayer() = default;

namespace impl {

std::unique_ptr<compositionengine::OutputLayer> createOutputLayer(
        const compositionengine::Output& display, std::shared_ptr<compositionengine::Layer> layer,
        sp<compositionengine::LayerFE> layerFE) {
    return std::make_unique<OutputLayer>(display, layer, layerFE);
}

OutputLayer::OutputLayer(const Output& output, std::shared_ptr<Layer> layer, sp<LayerFE> layerFE)
      : mOutput(output), mLayer(layer), mLayerFE(layerFE) {}

OutputLayer::~OutputLayer() = default;

const compositionengine::Output& OutputLayer::getOutput() const {
    return mOutput;
}

compositionengine::Layer& OutputLayer::getLayer() const {
    return *mLayer;
}

compositionengine::LayerFE& OutputLayer::getLayerFE() const {
    return *mLayerFE;
}

} // namespace impl
} // namespace android::compositionengine
