/*
 * Copyright (C) 2022 The Android Open Source Project
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
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <EffectLayer.h>
#include <gtest/gtest.h>
#include <ui/FloatRect.h>
#include <ui/Transform.h>
#include <limits>

#include "LayerTestUtils.h"
#include "TestableSurfaceFlinger.h"

namespace android {
namespace {

class LayerTest : public BaseLayerTest {
protected:
    static constexpr const float MIN_FLOAT = std::numeric_limits<float>::min();
    static constexpr const float MAX_FLOAT = std::numeric_limits<float>::max();
    static constexpr const FloatRect LARGE_FLOAT_RECT{MIN_FLOAT, MIN_FLOAT, MAX_FLOAT, MAX_FLOAT};
};

INSTANTIATE_TEST_SUITE_P(PerLayerType, LayerTest,
                         testing::Values(std::make_shared<BufferStateLayerFactory>(),
                                         std::make_shared<EffectLayerFactory>()),
                         PrintToStringParamName);

TEST_P(LayerTest, layerVisibleByDefault) {
    sp<Layer> layer = GetParam()->createLayer(mFlinger);
    layer->updateGeometry();
    layer->computeBounds(LARGE_FLOAT_RECT, ui::Transform(), 0.f);
    ASSERT_FALSE(layer->isHiddenByPolicy());
}

TEST_P(LayerTest, hideLayerWithZeroMatrix) {
    sp<Layer> layer = GetParam()->createLayer(mFlinger);

    layer_state_t::matrix22_t matrix{0, 0, 0, 0};
    layer->setMatrix(matrix);
    layer->updateGeometry();
    layer->computeBounds(LARGE_FLOAT_RECT, ui::Transform(), 0.f);

    ASSERT_TRUE(layer->isHiddenByPolicy());
}

TEST_P(LayerTest, hideLayerWithInfMatrix) {
    sp<Layer> layer = GetParam()->createLayer(mFlinger);

    constexpr const float INF = std::numeric_limits<float>::infinity();
    layer_state_t::matrix22_t matrix{INF, 0, 0, INF};
    layer->setMatrix(matrix);
    layer->updateGeometry();
    layer->computeBounds(LARGE_FLOAT_RECT, ui::Transform(), 0.f);

    ASSERT_TRUE(layer->isHiddenByPolicy());
}

TEST_P(LayerTest, hideLayerWithNanMatrix) {
    sp<Layer> layer = GetParam()->createLayer(mFlinger);

    constexpr const float QUIET_NAN = std::numeric_limits<float>::quiet_NaN();
    layer_state_t::matrix22_t matrix{QUIET_NAN, 0, 0, QUIET_NAN};
    layer->setMatrix(matrix);
    layer->updateGeometry();
    layer->computeBounds(LARGE_FLOAT_RECT, ui::Transform(), 0.f);

    ASSERT_TRUE(layer->isHiddenByPolicy());
}

} // namespace
} // namespace android
