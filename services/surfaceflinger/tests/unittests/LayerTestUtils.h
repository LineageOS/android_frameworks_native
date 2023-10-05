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

#pragma once

#include <memory>

#include <gtest/gtest.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include "Layer.h"
// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include "TestableSurfaceFlinger.h"

namespace android {

class LayerFactory {
public:
    virtual ~LayerFactory() = default;

    virtual std::string name() = 0;
    virtual sp<Layer> createLayer(TestableSurfaceFlinger& flinger) = 0;

protected:
    static constexpr uint32_t WIDTH = 100;
    static constexpr uint32_t HEIGHT = 100;
    static constexpr uint32_t LAYER_FLAGS = 0;
};

class BufferStateLayerFactory : public LayerFactory {
public:
    std::string name() override { return "BufferStateLayer"; }
    sp<Layer> createLayer(TestableSurfaceFlinger& flinger) override;
};

class EffectLayerFactory : public LayerFactory {
public:
    std::string name() override { return "EffectLayer"; }
    sp<Layer> createLayer(TestableSurfaceFlinger& flinger) override;
};

std::string PrintToStringParamName(
        const ::testing::TestParamInfo<std::shared_ptr<LayerFactory>>& info);

class BaseLayerTest : public ::testing::TestWithParam<std::shared_ptr<LayerFactory>> {
protected:
    BaseLayerTest();

    TestableSurfaceFlinger mFlinger;
};

} // namespace android
