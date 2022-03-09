/*
 * Copyright (C) 2019 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <gui/BufferItemConsumer.h>
#include "TransactionTestHarnesses.h"

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

class LayerTypeAndRenderTypeTransactionTest
      : public LayerTypeTransactionHarness,
        public ::testing::WithParamInterface<std::tuple<uint32_t, RenderPath>> {
public:
    LayerTypeAndRenderTypeTransactionTest()
          : LayerTypeTransactionHarness(std::get<0>(GetParam())),
            mRenderPathHarness(LayerRenderPathTestHarness(this, std::get<1>(GetParam()))) {}

    std::unique_ptr<ScreenCapture> getScreenCapture() {
        return mRenderPathHarness.getScreenCapture();
    }

protected:
    LayerRenderPathTestHarness mRenderPathHarness;

    static constexpr int64_t kUsageFlags = BufferUsage::CPU_READ_OFTEN |
            BufferUsage::CPU_WRITE_OFTEN | BufferUsage::COMPOSER_OVERLAY | BufferUsage::GPU_TEXTURE;
};

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

INSTANTIATE_TEST_CASE_P(
        LayerTypeAndRenderTypeTransactionTests, LayerTypeAndRenderTypeTransactionTest,
        ::testing::Combine(
                ::testing::Values(
                        static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferState)),
                ::testing::Values(RenderPath::VIRTUAL_DISPLAY, RenderPath::SCREENSHOT)));

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetZBasic) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction().setLayer(layerR, mLayerZBase + 1).apply();
    {
        SCOPED_TRACE("layerR");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setLayer(layerG, mLayerZBase + 2).apply();
    {
        SCOPED_TRACE("layerG");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::GREEN);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetRelativeZBug64572777) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;

    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction().setPosition(layerG, 16, 16).setRelativeLayer(layerG, layerR, 1).apply();

    Transaction().reparent(layerG, nullptr).apply();

    // layerG should have been removed
    getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetFlagsHidden) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    Transaction().setFlags(layer, layer_state_t::eLayerHidden, layer_state_t::eLayerHidden).apply();
    {
        SCOPED_TRACE("layer hidden");
        getScreenCapture()->expectColor(mDisplayRect, Color::BLACK);
    }

    Transaction().setFlags(layer, 0, layer_state_t::eLayerHidden).apply();
    {
        SCOPED_TRACE("layer shown");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetFlagsOpaque) {
    const Color translucentRed = {100, 0, 0, 100};
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, translucentRed, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction()
            .setLayer(layerR, mLayerZBase + 1)
            .setFlags(layerR, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque)
            .apply();
    {
        SCOPED_TRACE("layerR opaque");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), {100, 0, 0, 255});
    }

    Transaction().setFlags(layerR, 0, layer_state_t::eLayerOpaque).apply();
    {
        SCOPED_TRACE("layerR translucent");
        const uint8_t g = uint8_t(255 - translucentRed.a);
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), {100, g, 0, 255});
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetZNegative) {
    sp<SurfaceControl> parent =
            LayerTransactionTest::createLayer("Parent", 0 /* buffer width */, 0 /* buffer height */,
                                              ISurfaceComposerClient::eFXSurfaceContainer);
    Transaction().setCrop(parent, Rect(0, 0, mDisplayWidth, mDisplayHeight)).apply();
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction().reparent(layerR, parent).reparent(layerG, parent).apply();
    Transaction().setLayer(layerR, -1).setLayer(layerG, -2).apply();
    {
        SCOPED_TRACE("layerR");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setLayer(layerR, -3).apply();
    {
        SCOPED_TRACE("layerG");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::GREEN);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetAlphaClamped) {
    const Color color = {64, 0, 0, 255};
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, color, 32, 32));

    Transaction().setAlpha(layer, 2.0f).apply();
    {
        SCOPED_TRACE("clamped to 1.0f");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), color);
    }

    Transaction().setAlpha(layer, -1.0f).apply();
    {
        SCOPED_TRACE("clamped to 0.0f");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadius) {
    sp<SurfaceControl> layer;
    const uint8_t size = 64;
    const uint8_t testArea = 4;
    const float cornerRadius = 20.0f;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, size, size));

    Transaction().setCornerRadius(layer, cornerRadius).apply();
    {
        const uint8_t bottom = size - 1;
        const uint8_t right = size - 1;
        auto shot = getScreenCapture();
        // Transparent corners
        shot->expectColor(Rect(0, 0, testArea, testArea), Color::BLACK);
        shot->expectColor(Rect(size - testArea, 0, right, testArea), Color::BLACK);
        shot->expectColor(Rect(0, bottom - testArea, testArea, bottom), Color::BLACK);
        shot->expectColor(Rect(size - testArea, bottom - testArea, right, bottom), Color::BLACK);
        // Solid center
        shot->expectColor(Rect(size / 2 - testArea / 2, size / 2 - testArea / 2,
                               size / 2 + testArea / 2, size / 2 + testArea / 2),
                          Color::RED);
    }
}

// b/200781179 - don't round a layer without a valid crop
// This behaviour should be fixed since we treat buffer layers differently than
// effect or container layers.
TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadiusInvalidCrop) {
    sp<SurfaceControl> parent;
    sp<SurfaceControl> child;
    const uint8_t size = 64;
    const uint8_t testArea = 4;
    const float cornerRadius = 20.0f;
    ASSERT_NO_FATAL_FAILURE(parent = createLayer("parent", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(parent, Color::GREEN, size, size));
    ASSERT_NO_FATAL_FAILURE(child = createColorLayer("child", Color::RED));

    Transaction().setCornerRadius(child, cornerRadius).reparent(child, parent).show(child).apply();
    {
        const uint8_t bottom = size - 1;
        const uint8_t right = size - 1;
        auto shot = getScreenCapture();
        std::this_thread::sleep_for(std::chrono::seconds(5));
        // Solid corners since we don't round a layer without a valid crop
        shot->expectColor(Rect(0, 0, testArea, testArea), Color::RED);
        shot->expectColor(Rect(size - testArea, 0, right, testArea), Color::RED);
        shot->expectColor(Rect(0, bottom - testArea, testArea, bottom), Color::RED);
        shot->expectColor(Rect(size - testArea, bottom - testArea, right, bottom), Color::RED);
        // Solid center
        shot->expectColor(Rect(size / 2 - testArea / 2, size / 2 - testArea / 2,
                               size / 2 + testArea / 2, size / 2 + testArea / 2),
                          Color::RED);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadiusRotated) {
    sp<SurfaceControl> parent;
    sp<SurfaceControl> child;
    const uint8_t size = 64;
    const uint8_t testArea = 4;
    const float cornerRadius = 20.0f;
    ASSERT_NO_FATAL_FAILURE(parent = createLayer("parent", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(parent, Color::RED, size, size));
    ASSERT_NO_FATAL_FAILURE(child = createLayer("child", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(child, Color::GREEN, size, size));

    Transaction()
            .setCornerRadius(parent, cornerRadius)
            .reparent(child, parent)
            .setPosition(child, 0, size)
            // Rotate by half PI
            .setMatrix(child, 0.0f, -1.0f, 1.0f, 0.0f)
            .apply();

    {
        const uint8_t bottom = size - 1;
        const uint8_t right = size - 1;
        auto shot = getScreenCapture();
        // Edges are transparent
        shot->expectColor(Rect(0, 0, testArea, testArea), Color::BLACK);
        shot->expectColor(Rect(size - testArea, 0, right, testArea), Color::BLACK);
        shot->expectColor(Rect(0, bottom - testArea, testArea, bottom - testArea), Color::BLACK);
        shot->expectColor(Rect(right - testArea, bottom - testArea, right, bottom), Color::BLACK);
        // Solid center
        shot->expectColor(Rect(size / 2 - testArea / 2, size / 2 - testArea / 2,
                               size / 2 + testArea / 2, size / 2 + testArea / 2),
                          Color::GREEN);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadiusChildCrop) {
    sp<SurfaceControl> parent;
    sp<SurfaceControl> child;
    const uint8_t size = 64;
    const uint8_t testArea = 4;
    const float cornerRadius = 20.0f;
    ASSERT_NO_FATAL_FAILURE(parent = createLayer("parent", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(parent, Color::RED, size, size));
    ASSERT_NO_FATAL_FAILURE(child = createLayer("child", size, size / 2));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(child, Color::GREEN, size, size / 2));

    Transaction()
            .setCornerRadius(parent, cornerRadius)
            .reparent(child, parent)
            .setPosition(child, 0, size / 2)
            .apply();

    {
        const uint8_t bottom = size - 1;
        const uint8_t right = size - 1;
        auto shot = getScreenCapture();
        // Top edge of child should not have rounded corners because it's translated in the parent
        shot->expectColor(Rect(0, size / 2, right, static_cast<int>(bottom - cornerRadius)),
                          Color::GREEN);
        // But bottom edges should have been clipped according to parent bounds
        shot->expectColor(Rect(0, bottom - testArea, testArea, bottom), Color::BLACK);
        shot->expectColor(Rect(right - testArea, bottom - testArea, right, bottom), Color::BLACK);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadiusBufferRotationTransform) {
    sp<SurfaceControl> layer;
    sp<SurfaceControl> parent;
    ASSERT_NO_FATAL_FAILURE(
            parent = LayerTransactionTest::createLayer("parent", 0, 0,
                                                       ISurfaceComposerClient::eFXSurfaceEffect));

    const uint32_t bufferWidth = 1500;
    const uint32_t bufferHeight = 300;

    const uint32_t layerWidth = 300;
    const uint32_t layerHeight = 1500;

    const uint32_t testArea = 4;
    const float cornerRadius = 120.0f;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", bufferWidth, bufferHeight));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, bufferWidth, bufferHeight));

    Transaction()
            .reparent(layer, parent)
            .setColor(parent, half3(0, 1, 0))
            .setCrop(parent, Rect(0, 0, layerWidth, layerHeight))
            .setCornerRadius(parent, cornerRadius)

            .setTransform(layer, ui::Transform::ROT_90)
            .setDestinationFrame(layer, Rect(0, 0, layerWidth, layerHeight))
            .apply();
    {
        auto shot = getScreenCapture();
        // Corners are transparent
        // top-left
        shot->expectColor(Rect(0, 0, testArea, testArea), Color::BLACK);
        // top-right
        shot->expectColor(Rect(layerWidth - testArea, 0, layerWidth, testArea), Color::BLACK);
        // bottom-left
        shot->expectColor(Rect(0, layerHeight - testArea, testArea, layerHeight), Color::BLACK);
        // bottom-right
        shot->expectColor(Rect(layerWidth - testArea, layerHeight - testArea, layerWidth,
                               layerHeight),
                          Color::BLACK);

        // Area after corner radius is solid
        // top-left to top-right under the corner
        shot->expectColor(Rect(0, cornerRadius, layerWidth, cornerRadius + testArea), Color::RED);
        // bottom-left to bottom-right above the corner
        shot->expectColor(Rect(0, layerHeight - cornerRadius - testArea, layerWidth,
                               layerHeight - cornerRadius),
                          Color::RED);
        // left side after the corner
        shot->expectColor(Rect(cornerRadius, 0, cornerRadius + testArea, layerHeight), Color::RED);
        // right side before the corner
        shot->expectColor(Rect(layerWidth - cornerRadius - testArea, 0, layerWidth - cornerRadius,
                               layerHeight),
                          Color::RED);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadiusBufferCropTransform) {
    sp<SurfaceControl> layer;
    sp<SurfaceControl> parent;
    ASSERT_NO_FATAL_FAILURE(
            parent = LayerTransactionTest::createLayer("parent", 0, 0,
                                                       ISurfaceComposerClient::eFXSurfaceEffect));

    const uint32_t bufferWidth = 150 * 2;
    const uint32_t bufferHeight = 750 * 2;

    const Rect bufferCrop(0, 0, 150, 750);

    const uint32_t layerWidth = 300;
    const uint32_t layerHeight = 1500;

    const uint32_t testArea = 4;
    const float cornerRadius = 120.0f;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", bufferWidth, bufferHeight));
    ASSERT_NO_FATAL_FAILURE(fillLayerQuadrant(layer, bufferWidth, bufferHeight, Color::RED,
                                              Color::BLACK, Color::GREEN, Color::BLUE));

    Transaction()
            .reparent(layer, parent)
            .setColor(parent, half3(0, 1, 0))
            .setCrop(parent, Rect(0, 0, layerWidth, layerHeight))
            .setCornerRadius(parent, cornerRadius)

            .setBufferCrop(layer, bufferCrop)
            .setDestinationFrame(layer, Rect(0, 0, layerWidth, layerHeight))
            .apply();
    {
        auto shot = getScreenCapture();
        // Corners are transparent
        // top-left
        shot->expectColor(Rect(0, 0, testArea, testArea), Color::BLACK);
        // top-right
        shot->expectColor(Rect(layerWidth - testArea, 0, layerWidth, testArea), Color::BLACK);
        // bottom-left
        shot->expectColor(Rect(0, layerHeight - testArea, testArea, layerHeight), Color::BLACK);
        // bottom-right
        shot->expectColor(Rect(layerWidth - testArea, layerHeight - testArea, layerWidth,
                               layerHeight),
                          Color::BLACK);

        // Area after corner radius is solid
        // since the buffer is scaled, there will blending so adjust some of the bounds when
        // checking.
        float adjustedCornerRadius = cornerRadius + 15;
        float adjustedLayerHeight = layerHeight - 15;
        float adjustedLayerWidth = layerWidth - 15;

        // top-left to top-right under the corner
        shot->expectColor(Rect(15, adjustedCornerRadius, adjustedLayerWidth,
                               adjustedCornerRadius + testArea),
                          Color::RED);
        // bottom-left to bottom-right above the corner
        shot->expectColor(Rect(15, adjustedLayerHeight - adjustedCornerRadius - testArea,
                               adjustedLayerWidth, adjustedLayerHeight - adjustedCornerRadius),
                          Color::RED);
        // left side after the corner
        shot->expectColor(Rect(adjustedCornerRadius, 15, adjustedCornerRadius + testArea,
                               adjustedLayerHeight),
                          Color::RED);
        // right side before the corner
        shot->expectColor(Rect(adjustedLayerWidth - adjustedCornerRadius - testArea, 15,
                               adjustedLayerWidth - adjustedCornerRadius, adjustedLayerHeight),
                          Color::RED);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetCornerRadiusChildBufferRotationTransform) {
    sp<SurfaceControl> layer;
    sp<SurfaceControl> parent;
    ASSERT_NO_FATAL_FAILURE(
            parent = LayerTransactionTest::createLayer("parent", 0, 0,
                                                       ISurfaceComposerClient::eFXSurfaceEffect));

    const uint32_t bufferWidth = 1500;
    const uint32_t bufferHeight = 300;

    const uint32_t layerWidth = 300;
    const uint32_t layerHeight = 1500;

    const uint32_t testArea = 4;
    const float cornerRadius = 120.0f;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", bufferWidth, bufferHeight));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::BLUE, bufferWidth, bufferHeight));

    sp<SurfaceControl> child;
    ASSERT_NO_FATAL_FAILURE(child = createLayer("child", bufferWidth, bufferHeight));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(child, Color::RED, bufferWidth, bufferHeight));

    Transaction()
            .reparent(layer, parent)
            .reparent(child, layer)
            .setColor(parent, half3(0, 1, 0))
            .setCrop(parent, Rect(0, 0, layerWidth, layerHeight))
            .setCornerRadius(parent, cornerRadius) /* */

            .setTransform(layer, ui::Transform::ROT_90)
            .setDestinationFrame(layer, Rect(0, 0, layerWidth, layerHeight))

            .setTransform(child, ui::Transform::ROT_90)
            .setDestinationFrame(child, Rect(0, 0, layerWidth, layerHeight))
            .apply();
    {
        auto shot = getScreenCapture();
        // Corners are transparent
        // top-left
        shot->expectColor(Rect(0, 0, testArea, testArea), Color::BLACK);
        // top-right
        shot->expectColor(Rect(layerWidth - testArea, 0, layerWidth, testArea), Color::BLACK);
        // bottom-left
        shot->expectColor(Rect(0, layerHeight - testArea, testArea, layerHeight), Color::BLACK);
        // bottom-right
        shot->expectColor(Rect(layerWidth - testArea, layerHeight - testArea, layerWidth,
                               layerHeight),
                          Color::BLACK);

        // Area after corner radius is solid
        // top-left to top-right under the corner
        shot->expectColor(Rect(0, cornerRadius, layerWidth, cornerRadius + testArea), Color::RED);
        // bottom-left to bottom-right above the corner
        shot->expectColor(Rect(0, layerHeight - cornerRadius - testArea, layerWidth,
                               layerHeight - cornerRadius),
                          Color::RED);
        // left side after the corner
        shot->expectColor(Rect(cornerRadius, 0, cornerRadius + testArea, layerHeight), Color::RED);
        // right side before the corner
        shot->expectColor(Rect(layerWidth - cornerRadius - testArea, 0, layerWidth - cornerRadius,
                               layerHeight),
                          Color::RED);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, ChildCornerRadiusTakesPrecedence) {
    sp<SurfaceControl> parent;
    sp<SurfaceControl> child;
    const uint32_t size = 64;
    const uint32_t parentSize = size * 3;
    const uint32_t testLength = 4;
    const float cornerRadius = 20.0f;
    ASSERT_NO_FATAL_FAILURE(parent = createLayer("parent", parentSize, parentSize));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(parent, Color::RED, parentSize, parentSize));
    ASSERT_NO_FATAL_FAILURE(child = createLayer("child", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(child, Color::GREEN, size, size));

    Transaction()
            .setCornerRadius(parent, cornerRadius)
            .setCornerRadius(child, cornerRadius)
            .reparent(child, parent)
            .setPosition(child, size, size)
            .apply();

    {
        const uint32_t top = size - 1;
        const uint32_t left = size - 1;
        const uint32_t bottom = size * 2 - 1;
        const uint32_t right = size * 2 - 1;
        auto shot = getScreenCapture();
        // Edges are transparent
        // TL
        shot->expectColor(Rect(left, top, testLength, testLength), Color::RED);
        // TR
        shot->expectColor(Rect(right - testLength, top, right, testLength), Color::RED);
        // BL
        shot->expectColor(Rect(left, bottom - testLength, testLength, bottom - testLength),
                          Color::RED);
        // BR
        shot->expectColor(Rect(right - testLength, bottom - testLength, right, bottom), Color::RED);
        // Solid center
        shot->expectColor(Rect(parentSize / 2 - testLength / 2, parentSize / 2 - testLength / 2,
                               parentSize / 2 + testLength / 2, parentSize / 2 + testLength / 2),
                          Color::GREEN);
    }
}

// Test if ParentCornerRadiusTakesPrecedence if the parent corner radius crop is fully contained by
// the child corner radius crop.
TEST_P(LayerTypeAndRenderTypeTransactionTest, ParentCornerRadiusTakesPrecedence) {
    sp<SurfaceControl> parent;
    sp<SurfaceControl> child;
    const uint32_t size = 64;
    const uint32_t parentSize = size * 3;
    const Rect parentCrop(size + 1, size + 1, size * 2 - 1, size * 2 - 1);
    const uint32_t testLength = 4;
    const float cornerRadius = 20.0f;
    ASSERT_NO_FATAL_FAILURE(parent = createLayer("parent", parentSize, parentSize));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(parent, Color::RED, parentSize, parentSize));
    ASSERT_NO_FATAL_FAILURE(child = createLayer("child", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(child, Color::GREEN, size, size));

    Transaction()
            .setCornerRadius(parent, cornerRadius)
            .setCrop(parent, parentCrop)
            .setCornerRadius(child, cornerRadius)
            .reparent(child, parent)
            .setPosition(child, size, size)
            .apply();

    {
        const uint32_t top = size - 1;
        const uint32_t left = size - 1;
        const uint32_t bottom = size * 2 - 1;
        const uint32_t right = size * 2 - 1;
        auto shot = getScreenCapture();
        // Edges are transparent
        // TL
        shot->expectColor(Rect(left, top, testLength, testLength), Color::BLACK);
        // TR
        shot->expectColor(Rect(right - testLength, top, right, testLength), Color::BLACK);
        // BL
        shot->expectColor(Rect(left, bottom - testLength, testLength, bottom - testLength),
                          Color::BLACK);
        // BR
        shot->expectColor(Rect(right - testLength, bottom - testLength, right, bottom),
                          Color::BLACK);
        // Solid center
        shot->expectColor(Rect(parentSize / 2 - testLength / 2, parentSize / 2 - testLength / 2,
                               parentSize / 2 + testLength / 2, parentSize / 2 + testLength / 2),
                          Color::GREEN);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetBackgroundBlurRadiusSimple) {
    if (!deviceSupportsBlurs()) GTEST_SKIP();
    if (!deviceUsesSkiaRenderEngine()) GTEST_SKIP();

    const auto canvasSize = 256;

    sp<SurfaceControl> leftLayer;
    sp<SurfaceControl> rightLayer;
    sp<SurfaceControl> greenLayer;
    sp<SurfaceControl> blurLayer;
    const auto leftRect = Rect(0, 0, canvasSize / 2, canvasSize);
    const auto rightRect = Rect(canvasSize / 2, 0, canvasSize, canvasSize);
    const auto blurRect = Rect(0, 0, canvasSize, canvasSize);

    ASSERT_NO_FATAL_FAILURE(leftLayer =
                                    createLayer("Left", leftRect.getWidth(), leftRect.getHeight()));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerColor(leftLayer, Color::BLUE, leftRect.getWidth(), leftRect.getHeight()));
    ASSERT_NO_FATAL_FAILURE(greenLayer = createLayer("Green", canvasSize * 2, canvasSize * 2));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerColor(greenLayer, Color::GREEN, canvasSize * 2, canvasSize * 2));
    ASSERT_NO_FATAL_FAILURE(
            rightLayer = createLayer("Right", rightRect.getWidth(), rightRect.getHeight()));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerColor(rightLayer, Color::RED, rightRect.getWidth(), rightRect.getHeight()));

    Transaction()
            .setLayer(greenLayer, mLayerZBase)
            .setLayer(leftLayer, mLayerZBase + 1)
            .setLayer(rightLayer, mLayerZBase + 2)
            .setPosition(rightLayer, rightRect.left, rightRect.top)
            .apply();

    {
        auto shot = getScreenCapture();
        shot->expectColor(leftRect, Color::BLUE);
        shot->expectColor(rightRect, Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(blurLayer = createColorLayer("BackgroundBlur", Color::TRANSPARENT));

    const auto blurRadius = canvasSize / 2;
    Transaction()
            .setLayer(blurLayer, mLayerZBase + 3)
            .setBackgroundBlurRadius(blurLayer, blurRadius)
            .setCrop(blurLayer, blurRect)
            .setAlpha(blurLayer, 0.0f)
            .apply();

    {
        auto shot = getScreenCapture();

        const auto stepSize = 1;
        const auto blurAreaOffset = blurRadius * 0.7f;
        const auto blurAreaStartX = canvasSize / 2 - blurRadius + blurAreaOffset;
        const auto blurAreaEndX = canvasSize / 2 + blurRadius - blurAreaOffset;
        Color previousColor;
        Color currentColor;
        for (int y = 0; y < canvasSize; y++) {
            shot->checkPixel(0, y, /* r = */ 0, /* g = */ 0, /* b = */ 255);
            previousColor = shot->getPixelColor(0, y);
            for (int x = blurAreaStartX; x < blurAreaEndX; x += stepSize) {
                currentColor = shot->getPixelColor(x, y);
                ASSERT_GT(currentColor.r, previousColor.r);
                ASSERT_LT(currentColor.b, previousColor.b);
                ASSERT_EQ(0, currentColor.g);
            }
            shot->checkPixel(canvasSize - 1, y, 255, 0, 0);
        }
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetBackgroundBlurRadiusOnMultipleLayers) {
    if (!deviceSupportsBlurs()) GTEST_SKIP();
    if (!deviceUsesSkiaRenderEngine()) GTEST_SKIP();

    auto size = 256;
    auto center = size / 2;
    auto blurRadius = 50;

    sp<SurfaceControl> backgroundLayer;
    ASSERT_NO_FATAL_FAILURE(backgroundLayer = createLayer("background", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(backgroundLayer, Color::GREEN, size, size));

    sp<SurfaceControl> leftLayer;
    ASSERT_NO_FATAL_FAILURE(leftLayer = createLayer("left", size / 2, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(leftLayer, Color::RED, size / 2, size));

    sp<SurfaceControl> blurLayer1;
    auto centralSquareSize = size / 2;
    ASSERT_NO_FATAL_FAILURE(blurLayer1 =
                                    createLayer("blur1", centralSquareSize, centralSquareSize));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerColor(blurLayer1, Color::BLUE, centralSquareSize, centralSquareSize));

    sp<SurfaceControl> blurLayer2;
    ASSERT_NO_FATAL_FAILURE(blurLayer2 = createLayer("blur2", size, size));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerColor(blurLayer2, Color::TRANSPARENT, centralSquareSize, centralSquareSize));

    Transaction()
            .setBackgroundBlurRadius(blurLayer1, blurRadius)
            .setBackgroundBlurRadius(blurLayer2, blurRadius)
            .apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(center - 5, center - 5, center, center), Color{100, 100, 100, 255},
                      40 /* tolerance */);
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetBackgroundBlurAffectedByParentAlpha) {
    if (!deviceSupportsBlurs()) GTEST_SKIP();
    if (!deviceUsesSkiaRenderEngine()) GTEST_SKIP();

    sp<SurfaceControl> left;
    sp<SurfaceControl> right;
    sp<SurfaceControl> blur;
    sp<SurfaceControl> blurParent;

    const auto size = 256;
    ASSERT_NO_FATAL_FAILURE(left = createLayer("Left", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(left, Color::BLUE, size, size));
    ASSERT_NO_FATAL_FAILURE(right = createLayer("Right", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(right, Color::RED, size, size));

    Transaction()
            .setLayer(left, mLayerZBase + 1)
            .setLayer(right, mLayerZBase + 2)
            .setPosition(right, size, 0)
            .apply();

    {
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, size, size), Color::BLUE);
        shot->expectColor(Rect(size, 0, size * 2, size), Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(blur = createLayer("BackgroundBlur", size * 2, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(blur, Color::TRANSPARENT, size * 2, size));
    ASSERT_NO_FATAL_FAILURE(blurParent = createLayer("BackgroundBlurParent", size * 2, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(blurParent, Color::TRANSPARENT, size * 2, size));

    Transaction()
            .setLayer(blurParent, mLayerZBase + 3)
            .setAlpha(blurParent, 0.5)
            .setLayer(blur, mLayerZBase + 4)
            .setBackgroundBlurRadius(blur, size) // set the blur radius to the size of one rect
            .reparent(blur, blurParent)
            .apply();

    {
        auto shot = getScreenCapture();
        // assert that outer sides of the red and blue rects are not blended with the other color;
        // if the blur didn't take into account parent alpha, the outer sides would have traces of
        // the other color
        shot->expectColor(Rect(0, 0, size / 2, size), Color::BLUE);
        shot->expectColor(Rect(size + size / 2, 0, size * 2, size), Color::RED);
        // assert that middle line has blended red and blur color; adding a tolerance of 10 to
        // account for future blur algorithm changes
        shot->expectColor(Rect(size, 0, size + 1, size), {136, 0, 119, 255}, 10);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetColorWithBuffer) {
    sp<SurfaceControl> bufferLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(bufferLayer, Color::RED, 32, 32));

    // color is ignored
    Transaction().setColor(bufferLayer, half3(0.0f, 1.0f, 0.0f)).apply();
    getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetLayerStackBasic) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    Transaction().setLayerStack(layer, mDisplayLayerStack + 1).apply();
    {
        SCOPED_TRACE("non-existing layer stack");
        getScreenCapture()->expectColor(mDisplayRect, Color::BLACK);
    }

    Transaction().setLayerStack(layer, mDisplayLayerStack).apply();
    {
        SCOPED_TRACE("original layer stack");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetBufferFormat) {
    int32_t width = 100;
    int32_t height = 100;
    Rect crop = Rect(0, 0, width, height);

    sp<SurfaceControl> behindLayer = createColorLayer("Behind layer", Color::RED);
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", width, height, 0, nullptr, nullptr,
                                                PIXEL_FORMAT_RGBX_8888));

    Transaction()
            .setLayer(layer, INT32_MAX - 1)
            .show(layer)
            .setLayerStack(behindLayer, mDisplayLayerStack)
            .setCrop(behindLayer, crop)
            .setLayer(behindLayer, INT32_MAX - 2)
            .show(behindLayer)
            .apply();

    sp<Surface> surface = layer->getSurface();

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(width, height, PIXEL_FORMAT_RGBX_8888, 1, kUsageFlags, "test");
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillGraphicBufferColor(buffer, crop, Color::TRANSPARENT));

    if (mLayerType == ISurfaceComposerClient::eFXSurfaceBufferQueue) {
        Surface::attachAndQueueBufferWithDataspace(surface.get(), buffer, ui::Dataspace::V0_SRGB);
    } else {
        Transaction().setBuffer(layer, buffer).apply();
    }

    {
        SCOPED_TRACE("Buffer Opaque Format");
        auto shot = screenshot();
        shot->expectColor(crop, Color::BLACK);
    }

    buffer = new GraphicBuffer(width, height, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillGraphicBufferColor(buffer, crop, Color::TRANSPARENT));

    if (mLayerType == ISurfaceComposerClient::eFXSurfaceBufferQueue) {
        Surface::attachAndQueueBufferWithDataspace(surface.get(), buffer, ui::Dataspace::V0_SRGB);
    } else {
        Transaction().setBuffer(layer, buffer).apply();
    }

    {
        SCOPED_TRACE("Buffer Transparent Format");
        auto shot = screenshot();
        shot->expectColor(crop, Color::RED);
    }
}
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
