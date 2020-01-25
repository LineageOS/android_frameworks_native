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
#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/impl/Layer.h>

namespace android::compositionengine {

Layer::~Layer() = default;

namespace impl {

std::shared_ptr<Layer> createLayer(const LayerCreationArgs& args) {
    return compositionengine::impl::createLayerTemplated<Layer>(args);
}

Layer::~Layer() = default;

void Layer::dump(std::string& out) const {
    auto layerFE = getLayerFE();
    android::base::StringAppendF(&out, "* compositionengine::Layer %p (%s)\n", this,
                                 layerFE ? layerFE->getDebugName() : "<unknown>");
    out.append("    frontend:\n");
    dumpFEState(out);
}

} // namespace impl
} // namespace android::compositionengine
