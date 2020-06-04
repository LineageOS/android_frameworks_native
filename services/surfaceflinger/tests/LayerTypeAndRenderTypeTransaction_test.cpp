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

#include <cutils/properties.h>
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
};

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

INSTANTIATE_TEST_CASE_P(
        LayerTypeAndRenderTypeTransactionTests, LayerTypeAndRenderTypeTransactionTest,
        ::testing::Combine(
                ::testing::Values(
                        static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferQueue),
                        static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferState)),
                ::testing::Values(RenderPath::VIRTUAL_DISPLAY, RenderPath::SCREENSHOT)));

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetSizeInvalid) {
    // cannot test robustness against invalid sizes (zero or really huge)
}

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

    Transaction()
            .setPosition(layerG, 16, 16)
            .setRelativeLayer(layerG, layerR->getHandle(), 1)
            .apply();

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
    Transaction().setCrop_legacy(parent, Rect(0, 0, mDisplayWidth, mDisplayHeight)).apply();
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction()
            .reparent(layerR, parent->getHandle())
            .reparent(layerG, parent->getHandle())
            .apply();
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

    if (mLayerType == ISurfaceComposerClient::eFXSurfaceBufferQueue) {
        Transaction()
                .setCornerRadius(layer, cornerRadius)
                .setCrop_legacy(layer, Rect(0, 0, size, size))
                .apply();
    } else {
        Transaction()
                .setCornerRadius(layer, cornerRadius)
                .setFrame(layer, Rect(0, 0, size, size))
                .apply();
    }
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

    auto transaction = Transaction()
                               .setCornerRadius(parent, cornerRadius)
                               .setCrop_legacy(parent, Rect(0, 0, size, size))
                               .reparent(child, parent->getHandle())
                               .setPosition(child, 0, size)
                               // Rotate by half PI
                               .setMatrix(child, 0.0f, -1.0f, 1.0f, 0.0f);
    if (mLayerType == ISurfaceComposerClient::eFXSurfaceBufferQueue) {
        transaction.setCrop_legacy(parent, Rect(0, 0, size, size));
    } else {
        transaction.setFrame(parent, Rect(0, 0, size, size));
    }
    transaction.apply();

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

    if (mLayerType == ISurfaceComposerClient::eFXSurfaceBufferQueue) {
        Transaction()
                .setCornerRadius(parent, cornerRadius)
                .setCrop_legacy(parent, Rect(0, 0, size, size))
                .reparent(child, parent->getHandle())
                .setPosition(child, 0, size / 2)
                .apply();
    } else {
        Transaction()
                .setCornerRadius(parent, cornerRadius)
                .setFrame(parent, Rect(0, 0, size, size))
                .reparent(child, parent->getHandle())
                .setFrame(child, Rect(0, size / 2, size, size))
                .apply();
    }
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

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetBackgroundBlurRadius) {
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    if (!atoi(value)) {
        // This device doesn't support blurs, no-op.
        return;
    }

    auto size = 256;
    auto center = size / 2;
    auto blurRadius = 50;

    sp<SurfaceControl> backgroundLayer;
    ASSERT_NO_FATAL_FAILURE(backgroundLayer = createLayer("background", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(backgroundLayer, Color::GREEN, size, size));

    sp<SurfaceControl> leftLayer;
    ASSERT_NO_FATAL_FAILURE(leftLayer = createLayer("left", size / 2, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(leftLayer, Color::RED, size / 2, size));

    sp<SurfaceControl> blurLayer;
    ASSERT_NO_FATAL_FAILURE(blurLayer = createLayer("blur", size, size));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(blurLayer, Color::TRANSPARENT, size, size));

    Transaction().setBackgroundBlurRadius(blurLayer, blurRadius).apply();

    auto shot = getScreenCapture();
    // Edges are mixed
    shot->expectColor(Rect(center - 1, center - 5, center, center + 5), Color{150, 150, 0, 255},
                      50 /* tolerance */);
    shot->expectColor(Rect(center, center - 5, center + 1, center + 5), Color{150, 150, 0, 255},
                      50 /* tolerance */);
}

TEST_P(LayerTypeAndRenderTypeTransactionTest, SetBackgroundBlurRadiusOnMultipleLayers) {
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    if (!atoi(value)) {
        // This device doesn't support blurs, no-op.
        return;
    }

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
            .setCrop_legacy(behindLayer, crop)
            .setLayer(behindLayer, INT32_MAX - 2)
            .show(behindLayer)
            .apply();

    sp<Surface> surface = layer->getSurface();

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(width, height, PIXEL_FORMAT_RGBX_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");
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

    buffer = new GraphicBuffer(width, height, PIXEL_FORMAT_RGBA_8888, 1,
                               BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                       BufferUsage::COMPOSER_OVERLAY,
                               "test");
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
