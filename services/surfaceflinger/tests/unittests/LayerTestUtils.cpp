/*
 * Copyright 2022 The Android Open Source Project
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

#include "LayerTestUtils.h"

namespace android {

sp<Layer> BufferStateLayerFactory::createLayer(TestableSurfaceFlinger& flinger) {
    sp<Client> client;
    LayerCreationArgs args(flinger.flinger(), client, "buffer-state-layer", LAYER_FLAGS,
                           LayerMetadata());
    return sp<Layer>::make(args);
}

sp<Layer> EffectLayerFactory::createLayer(TestableSurfaceFlinger& flinger) {
    sp<Client> client;
    LayerCreationArgs args(flinger.flinger(), client, "color-layer", LAYER_FLAGS, LayerMetadata());
    return sp<Layer>::make(args);
}

std::string PrintToStringParamName(
        const ::testing::TestParamInfo<std::shared_ptr<LayerFactory>>& info) {
    return info.param->name();
}

BaseLayerTest::BaseLayerTest() {
    mFlinger.setupMockScheduler();
}

} // namespace android
