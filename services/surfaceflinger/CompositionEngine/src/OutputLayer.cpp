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

#include <android-base/stringprintf.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/Layer.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/Output.h>
#include <compositionengine/impl/OutputLayer.h>

#include "DisplayHardware/HWComposer.h"

namespace android::compositionengine {

OutputLayer::~OutputLayer() = default;

namespace impl {

std::unique_ptr<compositionengine::OutputLayer> createOutputLayer(
        const CompositionEngine& compositionEngine, std::optional<DisplayId> displayId,
        const compositionengine::Output& output, std::shared_ptr<compositionengine::Layer> layer,
        sp<compositionengine::LayerFE> layerFE) {
    auto result = std::make_unique<OutputLayer>(output, layer, layerFE);
    result->initialize(compositionEngine, displayId);
    return result;
}

OutputLayer::OutputLayer(const Output& output, std::shared_ptr<Layer> layer, sp<LayerFE> layerFE)
      : mOutput(output), mLayer(layer), mLayerFE(layerFE) {}

OutputLayer::~OutputLayer() = default;

void OutputLayer::initialize(const CompositionEngine& compositionEngine,
                             std::optional<DisplayId> displayId) {
    if (!displayId) {
        return;
    }

    auto& hwc = compositionEngine.getHwComposer();

    mState.hwc.emplace(std::shared_ptr<HWC2::Layer>(hwc.createLayer(*displayId),
                                                    [&hwc, displayId](HWC2::Layer* layer) {
                                                        hwc.destroyLayer(*displayId, layer);
                                                    }));
}

const compositionengine::Output& OutputLayer::getOutput() const {
    return mOutput;
}

compositionengine::Layer& OutputLayer::getLayer() const {
    return *mLayer;
}

compositionengine::LayerFE& OutputLayer::getLayerFE() const {
    return *mLayerFE;
}

const OutputLayerCompositionState& OutputLayer::getState() const {
    return mState;
}

OutputLayerCompositionState& OutputLayer::editState() {
    return mState;
}

void OutputLayer::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "     Output Layer %p\n", this);
    mState.dump(out);
}

} // namespace impl
} // namespace android::compositionengine
