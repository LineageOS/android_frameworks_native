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
#include <ui/Transform.h>
#include <thread>
#include "TransactionTestHarnesses.h"
namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

class LayerRenderTypeTransactionTest : public LayerTransactionTest,
                                       public ::testing::WithParamInterface<RenderPath> {
public:
    LayerRenderTypeTransactionTest() : mHarness(LayerRenderPathTestHarness(this, GetParam())) {}

    std::unique_ptr<ScreenCapture> getScreenCapture() { return mHarness.getScreenCapture(); }
    void setRelativeZBasicHelper(uint32_t layerType);
    void setRelativeZGroupHelper(uint32_t layerType);
    void setAlphaBasicHelper(uint32_t layerType);
    void setBackgroundColorHelper(uint32_t layerType, bool priorColor, bool bufferFill, float alpha,
                                  Color finalColor);

protected:
    LayerRenderPathTestHarness mHarness;

    static constexpr int64_t kUsageFlags = BufferUsage::CPU_READ_OFTEN |
            BufferUsage::CPU_WRITE_OFTEN | BufferUsage::COMPOSER_OVERLAY | BufferUsage::GPU_TEXTURE;
};

INSTANTIATE_TEST_CASE_P(LayerRenderTypeTransactionTests, LayerRenderTypeTransactionTest,
                        ::testing::Values(RenderPath::VIRTUAL_DISPLAY, RenderPath::SCREENSHOT));

TEST_P(LayerRenderTypeTransactionTest, SetPositionBasic_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("default position");
        const Rect rect(0, 0, 32, 32);
        auto shot = getScreenCapture();
        shot->expectColor(rect, Color::RED);
        shot->expectBorder(rect, Color::BLACK);
    }

    Transaction().setPosition(layer, 5, 10).apply();
    {
        SCOPED_TRACE("new position");
        const Rect rect(5, 10, 37, 42);
        auto shot = getScreenCapture();
        shot->expectColor(rect, Color::RED);
        shot->expectBorder(rect, Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetPositionRounding_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // GPU composition requires only 4 bits of subpixel precision during rasterization
    // XXX GPU composition does not match HWC composition due to precision
    // loss (b/69315223)
    const float epsilon = 1.0f / 16.0f;
    Transaction().setPosition(layer, 0.5f - epsilon, 0.5f - epsilon).apply();
    {
        SCOPED_TRACE("rounding down");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setPosition(layer, 0.5f + epsilon, 0.5f + epsilon).apply();
    {
        SCOPED_TRACE("rounding up");
        getScreenCapture()->expectColor(Rect(1, 1, 33, 33), Color::RED);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetPositionOutOfBounds_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    Transaction().setPosition(layer, -32, -32).apply();
    {
        SCOPED_TRACE("negative coordinates");
        getScreenCapture()->expectColor(mDisplayRect, Color::BLACK);
    }

    Transaction().setPosition(layer, mDisplayWidth, mDisplayHeight).apply();
    {
        SCOPED_TRACE("positive coordinates");
        getScreenCapture()->expectColor(mDisplayRect, Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetPositionPartiallyOutOfBounds_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // partially out of bounds
    Transaction().setPosition(layer, -30, -30).apply();
    {
        SCOPED_TRACE("negative coordinates");
        getScreenCapture()->expectColor(Rect(0, 0, 2, 2), Color::RED);
    }

    Transaction().setPosition(layer, mDisplayWidth - 2, mDisplayHeight - 2).apply();
    {
        SCOPED_TRACE("positive coordinates");
        getScreenCapture()->expectColor(Rect(mDisplayWidth - 2, mDisplayHeight - 2, mDisplayWidth,
                                             mDisplayHeight),
                                        Color::RED);
    }
}

TEST_P(LayerRenderTypeTransactionTest, CreateLayer_BufferState) {
    uint32_t transformHint = ui::Transform::ROT_INVALID;
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32,
                                                ISurfaceComposerClient::eFXSurfaceBufferState,
                                                /*parent*/ nullptr, &transformHint));
    ASSERT_NE(ui::Transform::ROT_INVALID, transformHint);
}

void LayerRenderTypeTransactionTest::setRelativeZBasicHelper(uint32_t layerType) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layerG, Color::GREEN, 32, 32));

    switch (layerType) {
        case ISurfaceComposerClient::eFXSurfaceBufferQueue:
            Transaction().setPosition(layerG, 16, 16).setRelativeLayer(layerG, layerR, 1).apply();
            break;
        case ISurfaceComposerClient::eFXSurfaceBufferState:
            Transaction().setPosition(layerG, 16, 16).setRelativeLayer(layerG, layerR, 1).apply();
            break;
        default:
            ASSERT_FALSE(true) << "Unsupported layer type";
    }
    {
        SCOPED_TRACE("layerG above");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 16, 16), Color::RED);
        shot->expectColor(Rect(16, 16, 48, 48), Color::GREEN);
    }

    Transaction().setRelativeLayer(layerG, layerR, -1).apply();
    {
        SCOPED_TRACE("layerG below");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectColor(Rect(32, 32, 48, 48), Color::GREEN);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetRelativeZBasic_BufferQueue) {
    ASSERT_NO_FATAL_FAILURE(setRelativeZBasicHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue));
}

TEST_P(LayerRenderTypeTransactionTest, SetRelativeZBasic_BufferState) {
    ASSERT_NO_FATAL_FAILURE(setRelativeZBasicHelper(ISurfaceComposerClient::eFXSurfaceBufferState));
}

void LayerRenderTypeTransactionTest::setRelativeZGroupHelper(uint32_t layerType) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    sp<SurfaceControl> layerB;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layerG, Color::GREEN, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerB = createLayer("test", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layerB, Color::BLUE, 32, 32));

    // layerR = 0, layerG = layerR + 3, layerB = 2
    switch (layerType) {
        case ISurfaceComposerClient::eFXSurfaceBufferQueue:
            Transaction()
                    .setPosition(layerG, 8, 8)
                    .setRelativeLayer(layerG, layerR, 3)
                    .setPosition(layerB, 16, 16)
                    .setLayer(layerB, mLayerZBase + 2)
                    .apply();
            break;
        case ISurfaceComposerClient::eFXSurfaceBufferState:
            Transaction()
                    .setPosition(layerG, 8, 8)
                    .setRelativeLayer(layerG, layerR, 3)
                    .setPosition(layerB, 16, 16)
                    .setLayer(layerB, mLayerZBase + 2)
                    .apply();
            break;
        default:
            ASSERT_FALSE(true) << "Unsupported layer type";
    }

    {
        SCOPED_TRACE("(layerR < layerG) < layerB");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 8, 8), Color::RED);
        shot->expectColor(Rect(8, 8, 16, 16), Color::GREEN);
        shot->expectColor(Rect(16, 16, 48, 48), Color::BLUE);
    }

    // layerR = 4, layerG = layerR + 3, layerB = 2
    Transaction().setLayer(layerR, mLayerZBase + 4).apply();
    {
        SCOPED_TRACE("layerB < (layerR < layerG)");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 8, 8), Color::RED);
        shot->expectColor(Rect(8, 8, 40, 40), Color::GREEN);
        shot->expectColor(Rect(40, 40, 48, 48), Color::BLUE);
    }

    // layerR = 4, layerG = layerR - 3, layerB = 2
    Transaction().setRelativeLayer(layerG, layerR, -3).apply();
    {
        SCOPED_TRACE("layerB < (layerG < layerR)");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectColor(Rect(32, 32, 40, 40), Color::GREEN);
        shot->expectColor(Rect(40, 40, 48, 48), Color::BLUE);
    }

    // restore to absolute z
    // layerR = 4, layerG = 0, layerB = 2
    Transaction().setLayer(layerG, mLayerZBase).apply();
    {
        SCOPED_TRACE("layerG < layerB < layerR");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectColor(Rect(32, 32, 48, 48), Color::BLUE);
    }

    // layerR should not affect layerG anymore
    // layerR = 1, layerG = 0, layerB = 2
    Transaction().setLayer(layerR, mLayerZBase + 1).apply();
    {
        SCOPED_TRACE("layerG < layerR < layerB");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 16, 16), Color::RED);
        shot->expectColor(Rect(16, 16, 48, 48), Color::BLUE);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetRelativeZGroup_BufferQueue) {
    ASSERT_NO_FATAL_FAILURE(setRelativeZGroupHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue));
}

TEST_P(LayerRenderTypeTransactionTest, SetRelativeZGroup_BufferState) {
    ASSERT_NO_FATAL_FAILURE(setRelativeZGroupHelper(ISurfaceComposerClient::eFXSurfaceBufferState));
}

TEST_P(LayerRenderTypeTransactionTest, SetTransparentRegionHintBasic_BufferQueue) {
    const Rect top(0, 0, 32, 16);
    const Rect bottom(0, 16, 32, 32);
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));

    ANativeWindow_Buffer buffer;
    ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillANativeWindowBufferColor(buffer, top, Color::TRANSPARENT));
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillANativeWindowBufferColor(buffer, bottom, Color::RED));
    // setTransparentRegionHint always applies to the following buffer
    Transaction().setTransparentRegionHint(layer, Region(top)).apply();
    ASSERT_NO_FATAL_FAILURE(postBufferQueueLayerBuffer(layer));
    {
        SCOPED_TRACE("top transparent");
        auto shot = getScreenCapture();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::RED);
    }

    Transaction().setTransparentRegionHint(layer, Region(bottom)).apply();
    {
        SCOPED_TRACE("transparent region hint pending");
        auto shot = getScreenCapture();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillANativeWindowBufferColor(buffer, top, Color::RED));
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillANativeWindowBufferColor(buffer, bottom, Color::TRANSPARENT));
    ASSERT_NO_FATAL_FAILURE(postBufferQueueLayerBuffer(layer));
    {
        SCOPED_TRACE("bottom transparent");
        auto shot = getScreenCapture();
        shot->expectColor(top, Color::RED);
        shot->expectColor(bottom, Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetTransparentRegionHintBasic_BufferState) {
    const Rect top(0, 0, 32, 16);
    const Rect bottom(0, 16, 32, 32);
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");

    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillGraphicBufferColor(buffer, top, Color::TRANSPARENT));
    ASSERT_NO_FATAL_FAILURE(TransactionUtils::fillGraphicBufferColor(buffer, bottom, Color::RED));
    Transaction()
            .setTransparentRegionHint(layer, Region(top))
            .setBuffer(layer, buffer)
            .apply();
    {
        SCOPED_TRACE("top transparent");
        auto shot = getScreenCapture();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::RED);
    }

    Transaction().setTransparentRegionHint(layer, Region(bottom)).apply();
    {
        SCOPED_TRACE("transparent region hint intermediate");
        auto shot = getScreenCapture();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::BLACK);
    }

    buffer = new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");

    ASSERT_NO_FATAL_FAILURE(TransactionUtils::fillGraphicBufferColor(buffer, top, Color::RED));
    ASSERT_NO_FATAL_FAILURE(
            TransactionUtils::fillGraphicBufferColor(buffer, bottom, Color::TRANSPARENT));
    Transaction().setBuffer(layer, buffer).apply();
    {
        SCOPED_TRACE("bottom transparent");
        auto shot = getScreenCapture();
        shot->expectColor(top, Color::RED);
        shot->expectColor(bottom, Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetTransparentRegionHintOutOfBounds_BufferQueue) {
    sp<SurfaceControl> layerTransparent;
    sp<SurfaceControl> layerR;
    ASSERT_NO_FATAL_FAILURE(layerTransparent = createLayer("test transparent", 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));

    // check that transparent region hint is bound by the layer size
    Transaction()
            .setTransparentRegionHint(layerTransparent, Region(mDisplayRect))
            .setPosition(layerR, 16, 16)
            .setLayer(layerR, mLayerZBase + 1)
            .apply();
    ASSERT_NO_FATAL_FAILURE(
            fillBufferQueueLayerColor(layerTransparent, Color::TRANSPARENT, 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layerR, Color::RED, 32, 32));
    getScreenCapture()->expectColor(Rect(16, 16, 48, 48), Color::RED);
}

TEST_P(LayerRenderTypeTransactionTest, SetTransparentRegionHintOutOfBounds_BufferState) {
    sp<SurfaceControl> layerTransparent;
    sp<SurfaceControl> layerR;
    ASSERT_NO_FATAL_FAILURE(layerTransparent = createLayer("test transparent", 32, 32));
    ASSERT_NO_FATAL_FAILURE(
            layerR = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    // check that transparent region hint is bound by the layer size
    Transaction()
            .setTransparentRegionHint(layerTransparent, Region(mDisplayRect))
            .setPosition(layerR, 16, 16)
            .setLayer(layerR, mLayerZBase + 1)
            .apply();
    ASSERT_NO_FATAL_FAILURE(
            fillBufferQueueLayerColor(layerTransparent, Color::TRANSPARENT, 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layerR, Color::RED, 32, 32));
    getScreenCapture()->expectColor(Rect(16, 16, 48, 48), Color::RED);
}

void LayerRenderTypeTransactionTest::setAlphaBasicHelper(uint32_t layerType) {
    sp<SurfaceControl> layer1;
    sp<SurfaceControl> layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer("test 1", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer("test 2", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer1, {64, 0, 0, 255}, 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer2, {0, 64, 0, 255}, 32, 32));

    switch (layerType) {
        case ISurfaceComposerClient::eFXSurfaceBufferQueue:
            Transaction()
                    .setAlpha(layer1, 0.25f)
                    .setAlpha(layer2, 0.75f)
                    .setPosition(layer2, 16, 0)
                    .setLayer(layer2, mLayerZBase + 1)
                    .apply();
            break;
        case ISurfaceComposerClient::eFXSurfaceBufferState:
            Transaction()
                    .setAlpha(layer1, 0.25f)
                    .setAlpha(layer2, 0.75f)
                    .setPosition(layer2, 16, 0)
                    .setLayer(layer2, mLayerZBase + 1)
                    .apply();
            break;
        default:
            ASSERT_FALSE(true) << "Unsupported layer type";
    }
    {
        auto shot = getScreenCapture();
        uint8_t r = 16; // 64 * 0.25f
        uint8_t g = 48; // 64 * 0.75f
        shot->expectColor(Rect(0, 0, 16, 32), {r, 0, 0, 255});
        shot->expectColor(Rect(32, 0, 48, 32), {0, g, 0, 255});

        r /= 4; // r * (1.0f - 0.75f)
        shot->expectColor(Rect(16, 0, 32, 32), {r, g, 0, 255});
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetAlphaBasic_BufferQueue) {
    ASSERT_NO_FATAL_FAILURE(setAlphaBasicHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue));
}

TEST_P(LayerRenderTypeTransactionTest, SetAlphaBasic_BufferState) {
    ASSERT_NO_FATAL_FAILURE(setAlphaBasicHelper(ISurfaceComposerClient::eFXSurfaceBufferState));
}

TEST_P(LayerRenderTypeTransactionTest, SetColorBasic) {
    sp<SurfaceControl> bufferLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test bg", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(colorLayer =
                                    createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                                ISurfaceComposerClient::eFXSurfaceEffect));

    Transaction()
            .setCrop(colorLayer, Rect(0, 0, 32, 32))
            .setLayer(colorLayer, mLayerZBase + 1)
            .apply();

    {
        SCOPED_TRACE("default color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    const half3 color(15.0f / 255.0f, 51.0f / 255.0f, 85.0f / 255.0f);
    const Color expected = {15, 51, 85, 255};
    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;
    Transaction().setColor(colorLayer, color).apply();
    {
        SCOPED_TRACE("new color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), expected, tolerance);
    }
}

// RED: Color layer base color and BufferQueueLayer/BufferStateLayer fill
// BLUE: prior background color
// GREEN: final background color
// BLACK: no color or fill
void LayerRenderTypeTransactionTest::setBackgroundColorHelper(uint32_t layerType, bool priorColor,
                                                              bool bufferFill, float alpha,
                                                              Color finalColor) {
    sp<SurfaceControl> layer;
    int32_t width = 500;
    int32_t height = 500;

    Color fillColor = Color::RED;
    Color priorBgColor = Color::BLUE;
    Color expectedColor = Color::BLACK;
    switch (layerType) {
        case ISurfaceComposerClient::eFXSurfaceEffect:
            ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 0, 0, layerType));
            Transaction()
                    .setCrop(layer, Rect(0, 0, width, height))
                    .setColor(layer, half3(1.0f, 0, 0))
                    .apply();
            expectedColor = fillColor;
            break;
        case ISurfaceComposerClient::eFXSurfaceBufferQueue:
            ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", width, height));
            if (bufferFill) {
                ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, fillColor, width, height));
                expectedColor = fillColor;
            }
            Transaction().setCrop(layer, Rect(0, 0, width, height)).apply();
            break;
        case ISurfaceComposerClient::eFXSurfaceBufferState:
            ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", width, height, layerType));
            if (bufferFill) {
                ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, fillColor, width, height));
                expectedColor = fillColor;
            }
            Transaction().setCrop(layer, Rect(0, 0, width, height)).apply();
            break;
        default:
            GTEST_FAIL() << "Unknown layer type in setBackgroundColorHelper";
            return;
    }

    if (priorColor && layerType != ISurfaceComposerClient::eFXSurfaceEffect) {
        Transaction()
                .setBackgroundColor(layer, half3(0, 0, 1.0f), 1.0f, ui::Dataspace::UNKNOWN)
                .apply();
        if (!bufferFill) {
            expectedColor = priorBgColor;
        }
    }

    {
        SCOPED_TRACE("default before setting background color layer");
        screenshot()->expectColor(Rect(0, 0, width, height), expectedColor);
    }
    Transaction()
            .setBackgroundColor(layer, half3(0, 1.0f, 0), alpha, ui::Dataspace::UNKNOWN)
            .apply();

    {
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, width, height), finalColor);
        shot->expectBorder(Rect(0, 0, width, height), Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetBackgroundColor_Color_NoEffect) {
    bool priorColor = false;
    bool bufferFill = false;
    float alpha = 1.0f;
    Color finalColor = Color::RED;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceEffect,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferQueue_NoPriorColor_ZeroAlpha_NoEffect) {
    bool priorColor = false;
    bool bufferFill = false;
    float alpha = 0;
    Color finalColor = Color::BLACK;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferQueue_PriorColor_ZeroAlpha_DeleteBackground) {
    bool priorColor = true;
    bool bufferFill = false;
    float alpha = 0;
    Color finalColor = Color::BLACK;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferState_BufferFill_NoPriorColor_Basic) {
    bool priorColor = false;
    bool bufferFill = true;
    float alpha = 1.0f;
    Color finalColor = Color::RED;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferState,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferState_NoBufferFill_NoPriorColor_Basic) {
    bool priorColor = false;
    bool bufferFill = false;
    float alpha = 1.0f;
    Color finalColor = Color::GREEN;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferState,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferState_NoBufferFill_PriorColor_Basic) {
    bool priorColor = true;
    bool bufferFill = false;
    float alpha = 1.0f;
    Color finalColor = Color::GREEN;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferState,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferState_NoPriorColor_ZeroAlpha_NoEffect) {
    bool priorColor = false;
    bool bufferFill = false;
    float alpha = 0;
    Color finalColor = Color::BLACK;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferState,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest,
       SetBackgroundColor_BufferState_PriorColor_ZeroAlpha_DeleteBackground) {
    bool priorColor = true;
    bool bufferFill = false;
    float alpha = 0;
    Color finalColor = Color::BLACK;
    ASSERT_NO_FATAL_FAILURE(setBackgroundColorHelper(ISurfaceComposerClient::eFXSurfaceBufferState,
                                                     priorColor, bufferFill, alpha, finalColor));
}

TEST_P(LayerRenderTypeTransactionTest, SetColorClamped) {
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(colorLayer =
                                    createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                                ISurfaceComposerClient::eFXSurfaceEffect));
    Transaction()
            .setCrop(colorLayer, Rect(0, 0, 32, 32))
            .setColor(colorLayer, half3(2.0f, 0.0f, 0.0f))
            .apply();

    getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
}

// An invalid color will not render a color and the layer will not be visible.
TEST_P(LayerRenderTypeTransactionTest, SetInvalidColor) {
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(colorLayer =
                                    createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                                ISurfaceComposerClient::eFXSurfaceEffect));
    Transaction()
            .setCrop(colorLayer, Rect(0, 0, 32, 32))
            .setColor(colorLayer, half3(1.0f, -1.0f, 0.5f))
            .apply();

    getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetColorWithAlpha) {
    sp<SurfaceControl> bufferLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test bg", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(colorLayer =
                                    createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                                ISurfaceComposerClient::eFXSurfaceEffect));
    Transaction().setCrop(colorLayer, Rect(0, 0, 32, 32)).apply();

    const half3 color(15.0f / 255.0f, 51.0f / 255.0f, 85.0f / 255.0f);
    const float alpha = 0.25f;
    const ubyte3 expected((vec3(color) * alpha + vec3(1.0f, 0.0f, 0.0f) * (1.0f - alpha)) * 255.0f);
    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;
    Transaction()
            .setColor(colorLayer, color)
            .setAlpha(colorLayer, alpha)
            .setLayer(colorLayer, mLayerZBase + 1)
            .apply();
    getScreenCapture()->expectColor(Rect(0, 0, 32, 32), {expected.r, expected.g, expected.b, 255},
                                    tolerance);
}

TEST_P(LayerRenderTypeTransactionTest, SetColorWithParentAlpha_Bug74220420) {
    sp<SurfaceControl> bufferLayer;
    sp<SurfaceControl> parentLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test bg", 32, 32));
    ASSERT_NO_FATAL_FAILURE(parentLayer = createLayer("parentWithAlpha", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(colorLayer = createLayer("childWithColor", 0 /* buffer width */,
                                                     0 /* buffer height */,
                                                     ISurfaceComposerClient::eFXSurfaceEffect));
    Transaction().setCrop(colorLayer, Rect(0, 0, 32, 32)).apply();
    const half3 color(15.0f / 255.0f, 51.0f / 255.0f, 85.0f / 255.0f);
    const float alpha = 0.25f;
    const ubyte3 expected((vec3(color) * alpha + vec3(1.0f, 0.0f, 0.0f) * (1.0f - alpha)) * 255.0f);
    // this is handwavy, but the precision loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;
    Transaction()
            .reparent(colorLayer, parentLayer)
            .setColor(colorLayer, color)
            .setAlpha(parentLayer, alpha)
            .setLayer(parentLayer, mLayerZBase + 1)
            .apply();
    getScreenCapture()->expectColor(Rect(0, 0, 32, 32), {expected.r, expected.g, expected.b, 255},
                                    tolerance);
}

TEST_P(LayerRenderTypeTransactionTest, SetMatrixBasic_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction().setMatrix(layer, 1.0f, 0.0f, 0.0f, 1.0f).setPosition(layer, 0, 0).apply();
    {
        SCOPED_TRACE("IDENTITY");
        getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::RED, Color::GREEN,
                                           Color::BLUE, Color::WHITE);
    }

    Transaction().setMatrix(layer, -1.0f, 0.0f, 0.0f, 1.0f).setPosition(layer, 32, 0).apply();
    {
        SCOPED_TRACE("FLIP_H");
        getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::GREEN, Color::RED,
                                           Color::WHITE, Color::BLUE);
    }

    Transaction().setMatrix(layer, 1.0f, 0.0f, 0.0f, -1.0f).setPosition(layer, 0, 32).apply();
    {
        SCOPED_TRACE("FLIP_V");
        getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::WHITE,
                                           Color::RED, Color::GREEN);
    }

    Transaction().setMatrix(layer, 0.0f, 1.0f, -1.0f, 0.0f).setPosition(layer, 32, 0).apply();
    {
        SCOPED_TRACE("ROT_90");
        getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::RED,
                                           Color::WHITE, Color::GREEN);
    }

    Transaction().setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f).setPosition(layer, 0, 0).apply();
    {
        SCOPED_TRACE("SCALE");
        getScreenCapture()->expectQuadrant(Rect(0, 0, 64, 64), Color::RED, Color::GREEN,
                                           Color::BLUE, Color::WHITE, true /* filtered */);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetMatrixBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction().setPosition(layer, 32, 32).setMatrix(layer, 1.0f, 0.0f, 0.0f, 1.0f).apply();
    {
        SCOPED_TRACE("IDENTITY");
        getScreenCapture()->expectQuadrant(Rect(32, 32, 64, 64), Color::RED, Color::GREEN,
                                           Color::BLUE, Color::WHITE);
    }

    Transaction().setMatrix(layer, -1.0f, 0.0f, 0.0f, 1.0f).apply();
    {
        SCOPED_TRACE("FLIP_H");
        getScreenCapture()->expectQuadrant(Rect(0, 32, 32, 64), Color::GREEN, Color::RED,
                                           Color::WHITE, Color::BLUE);
    }

    Transaction().setMatrix(layer, 1.0f, 0.0f, 0.0f, -1.0f).apply();
    {
        SCOPED_TRACE("FLIP_V");
        getScreenCapture()->expectQuadrant(Rect(32, 0, 64, 32), Color::BLUE, Color::WHITE,
                                           Color::RED, Color::GREEN);
    }

    Transaction().setMatrix(layer, 0.0f, 1.0f, -1.0f, 0.0f).apply();
    {
        SCOPED_TRACE("ROT_90");
        getScreenCapture()->expectQuadrant(Rect(0, 32, 32, 64), Color::BLUE, Color::RED,
                                           Color::WHITE, Color::GREEN);
    }

    Transaction().setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f).apply();
    {
        SCOPED_TRACE("SCALE");
        getScreenCapture()->expectQuadrant(Rect(32, 32, 96, 96), Color::RED, Color::GREEN,
                                           Color::BLUE, Color::WHITE, 1 /* tolerance */);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetMatrixRot45_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    const float rot = M_SQRT1_2; // 45 degrees
    const float trans = M_SQRT2 * 16.0f;
    Transaction().setMatrix(layer, rot, rot, -rot, rot).setPosition(layer, trans, 0).apply();

    auto shot = getScreenCapture();
    // check a 8x8 region inside each color
    auto get8x8Rect = [](int32_t centerX, int32_t centerY) {
        const int32_t halfL = 4;
        return Rect(centerX - halfL, centerY - halfL, centerX + halfL, centerY + halfL);
    };
    const int32_t unit = int32_t(trans / 2);
    shot->expectColor(get8x8Rect(2 * unit, 1 * unit), Color::RED);
    shot->expectColor(get8x8Rect(3 * unit, 2 * unit), Color::GREEN);
    shot->expectColor(get8x8Rect(1 * unit, 2 * unit), Color::BLUE);
    shot->expectColor(get8x8Rect(2 * unit, 3 * unit), Color::WHITE);
}

TEST_P(LayerRenderTypeTransactionTest, SetCropBasic_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));
    const Rect crop(8, 8, 24, 24);

    Transaction().setCrop(layer, crop).apply();
    auto shot = getScreenCapture();
    shot->expectColor(crop, Color::RED);
    shot->expectBorder(crop, Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetCropBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));
    const Rect crop(8, 8, 24, 24);

    Transaction().setCrop(layer, crop).apply();
    auto shot = getScreenCapture();
    shot->expectColor(crop, Color::RED);
    shot->expectBorder(crop, Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetCropEmpty_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("empty rect");
        Transaction().setCrop(layer, Rect(8, 8, 8, 8)).apply();
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    {
        SCOPED_TRACE("negative rect");
        Transaction().setCrop(layer, Rect(8, 8, 0, 0)).apply();
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetCropEmpty_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("empty rect");
        Transaction().setCrop(layer, Rect(8, 8, 8, 8)).apply();
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    {
        SCOPED_TRACE("negative rect");
        Transaction().setCrop(layer, Rect(8, 8, 0, 0)).apply();
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetCropOutOfBounds_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    Transaction().setCrop(layer, Rect(-128, -64, 128, 64)).apply();
    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetCropOutOfBounds_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 64, ISurfaceComposerClient::eFXSurfaceBufferState));
    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 64, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 16), Color::BLUE);
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 16, 32, 64), Color::RED);

    Transaction().setBuffer(layer, buffer).apply();

    // Partially out of bounds in the negative (upper left) direction
    Transaction().setCrop(layer, Rect(-128, -128, 32, 16)).apply();
    {
        SCOPED_TRACE("out of bounds, negative (upper left) direction");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 16), Color::BLUE);
        shot->expectBorder(Rect(0, 0, 32, 16), Color::BLACK);
    }

    // Partially out of bounds in the positive (lower right) direction
    Transaction().setCrop(layer, Rect(0, 16, 128, 128)).apply();
    {
        SCOPED_TRACE("out of bounds, positive (lower right) direction");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 16, 32, 64), Color::RED);
        shot->expectBorder(Rect(0, 16, 32, 64), Color::BLACK);
    }

    // Fully out of buffer space bounds
    Transaction().setCrop(layer, Rect(-128, -128, -1, -1)).apply();
    {
        SCOPED_TRACE("Fully out of bounds");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 64, 64), Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetCropWithTranslation_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    const Point position(32, 32);
    const Rect crop(8, 8, 24, 24);
    Transaction().setPosition(layer, position.x, position.y).setCrop(layer, crop).apply();
    auto shot = getScreenCapture();
    shot->expectColor(crop + position, Color::RED);
    shot->expectBorder(crop + position, Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetCropWithTranslation_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    const Rect crop(8, 8, 24, 24);
    Transaction().setPosition(layer, 32, 32).setCrop(layer, crop).apply();
    auto shot = getScreenCapture();
    shot->expectColor(Rect(40, 40, 56, 56), Color::RED);
    shot->expectBorder(Rect(40, 40, 56, 56), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetCropWithScale_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // crop is affected by matrix
    Transaction()
            .setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f)
            .setCrop(layer, Rect(8, 8, 24, 24))
            .apply();
    auto shot = getScreenCapture();
    shot->expectColor(Rect(16, 16, 48, 48), Color::RED);
    shot->expectBorder(Rect(16, 16, 48, 48), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));
    const Rect frame(8, 8, 24, 24);

    Transaction t;
    TransactionUtils::setFrame(t, layer, Rect(0, 0, 32, 32), frame);
    t.apply();

    auto shot = getScreenCapture();
    shot->expectColor(frame, Color::RED);
    shot->expectBorder(frame, Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameEmpty_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    Transaction t;
    {
        SCOPED_TRACE("empty rect");
        TransactionUtils::setFrame(t, layer, Rect(0, 0, 32, 32), Rect(8, 8, 8, 8));
        t.apply();

        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    {
        SCOPED_TRACE("negative rect");
        TransactionUtils::setFrame(t, layer, Rect(0, 0, 32, 32), Rect(8, 8, 0, 0));
        t.apply();

        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 8, 8), Color::RED);
        shot->expectBorder(Rect(0, 0, 8, 8), Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameDefaultParentless_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 10, 10));

    // A layer with a buffer will have a computed size that matches the buffer size.
    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 10, 10), Color::RED);
    shot->expectBorder(Rect(0, 0, 10, 10), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameDefaultBSParent_BufferState) {
    sp<SurfaceControl> parent, child;
    ASSERT_NO_FATAL_FAILURE(
            parent = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(parent, Color::RED, 32, 32));

    ASSERT_NO_FATAL_FAILURE(
            child = createLayer("test", 10, 10, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(child, Color::BLUE, 10, 10));

    Transaction().reparent(child, parent).apply();

    // A layer with a buffer will have a computed size that matches the buffer size.
    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 10, 10), Color::BLUE);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameDefaultBQParent_BufferState) {
    sp<SurfaceControl> parent, child;
    ASSERT_NO_FATAL_FAILURE(parent = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(parent, Color::RED, 32, 32));

    ASSERT_NO_FATAL_FAILURE(
            child = createLayer("test", 10, 10, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(child, Color::BLUE, 10, 10));

    Transaction().reparent(child, parent).apply();

    // A layer with a buffer will have a computed size that matches the buffer size.
    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 10, 10), Color::BLUE);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameUpdate_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    std::this_thread::sleep_for(500ms);

    Transaction().setPosition(layer, 16, 16).apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(16, 16, 48, 48), Color::RED);
    shot->expectBorder(Rect(16, 16, 48, 48), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFrameOutsideBounds_BufferState) {
    sp<SurfaceControl> parent, child;
    ASSERT_NO_FATAL_FAILURE(
            parent = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(
            child = createLayer("test", 10, 10, ISurfaceComposerClient::eFXSurfaceBufferState));
    Transaction().reparent(child, parent).apply();

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(parent, Color::RED, 32, 32));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(child, Color::BLUE, 10, 10));
    Rect childDst(0, 16, 32, 32);
    Transaction t;
    TransactionUtils::setFrame(t, child, Rect(0, 0, 10, 10), childDst);
    t.apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 16), Color::RED);
    shot->expectColor(childDst, Color::BLUE);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetBufferBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetBufferMultipleBuffers_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("set buffer 1");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::BLUE, 32, 32));

    {
        SCOPED_TRACE("set buffer 2");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("set buffer 3");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetBufferMultipleLayers_BufferState) {
    sp<SurfaceControl> layer1;
    ASSERT_NO_FATAL_FAILURE(
            layer1 = createLayer("test", 64, 64, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<SurfaceControl> layer2;
    ASSERT_NO_FATAL_FAILURE(
            layer2 = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer1, Color::RED, 64, 64));

    {
        SCOPED_TRACE("set layer 1 buffer red");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 64, 64), Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer2, Color::BLUE, 32, 32));

    {
        SCOPED_TRACE("set layer 2 buffer blue");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
        shot->expectColor(Rect(0, 32, 64, 64), Color::RED);
        shot->expectColor(Rect(0, 32, 32, 64), Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer1, Color::GREEN, 64, 64));
    {
        SCOPED_TRACE("set layer 1 buffer green");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
        shot->expectColor(Rect(0, 32, 64, 64), Color::GREEN);
        shot->expectColor(Rect(0, 32, 32, 64), Color::GREEN);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer2, Color::WHITE, 32, 32));

    {
        SCOPED_TRACE("set layer 2 buffer white");
        auto shot = getScreenCapture();
        shot->expectColor(Rect(0, 0, 32, 32), Color::WHITE);
        shot->expectColor(Rect(0, 32, 64, 64), Color::GREEN);
        shot->expectColor(Rect(0, 32, 32, 64), Color::GREEN);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetBufferCaching_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    std::array<Color, 4> colors = {Color::RED, Color::BLUE, Color::WHITE, Color::GREEN};

    std::array<sp<GraphicBuffer>, 10> buffers;

    size_t idx = 0;
    for (auto& buffer : buffers) {
        buffer = new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
        Color color = colors[idx % colors.size()];
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), color);
        idx++;
    }

    // Set each buffer twice. The first time adds it to the cache, the second time tests that the
    // cache is working.
    idx = 0;
    for (auto& buffer : buffers) {
        for (int i = 0; i < 2; i++) {
            Transaction().setBuffer(layer, buffer).apply();

            Color color = colors[idx % colors.size()];
            auto shot = screenshot();
            shot->expectColor(Rect(0, 0, 32, 32), color);
            shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
        }
        idx++;
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetBufferCaching_LeastRecentlyUsed_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    std::array<Color, 4> colors = {Color::RED, Color::BLUE, Color::WHITE, Color::GREEN};

    std::array<sp<GraphicBuffer>, 70> buffers;

    size_t idx = 0;
    for (auto& buffer : buffers) {
        buffer = new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
        Color color = colors[idx % colors.size()];
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), color);
        idx++;
    }

    // Set each buffer twice. The first time adds it to the cache, the second time tests that the
    // cache is working.
    idx = 0;
    for (auto& buffer : buffers) {
        for (int i = 0; i < 2; i++) {
            Transaction().setBuffer(layer, buffer).apply();

            Color color = colors[idx % colors.size()];
            auto shot = screenshot();
            shot->expectColor(Rect(0, 0, 32, 32), color);
            shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
        }
        idx++;
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetBufferCaching_DestroyedBuffer_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    std::array<Color, 4> colors = {Color::RED, Color::BLUE, Color::WHITE, Color::GREEN};

    std::array<sp<GraphicBuffer>, 65> buffers;

    size_t idx = 0;
    for (auto& buffer : buffers) {
        buffer = new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
        Color color = colors[idx % colors.size()];
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), color);
        idx++;
    }

    // Set each buffer twice. The first time adds it to the cache, the second time tests that the
    // cache is working.
    idx = 0;
    for (auto& buffer : buffers) {
        for (int i = 0; i < 2; i++) {
            Transaction().setBuffer(layer, buffer).apply();

            Color color = colors[idx % colors.size()];
            auto shot = screenshot();
            shot->expectColor(Rect(0, 0, 32, 32), color);
            shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
        }
        if (idx == 0) {
            buffers[0].clear();
        }
        idx++;
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetTransformRotate90_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction()
            .setTransform(layer, NATIVE_WINDOW_TRANSFORM_ROT_90)
            .apply();

    getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::RED, Color::WHITE,
                                       Color::GREEN, true /* filtered */);
}

TEST_P(LayerRenderTypeTransactionTest, SetTransformFlipH_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction()
            .setTransform(layer, NATIVE_WINDOW_TRANSFORM_FLIP_H)
            .apply();

    getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::GREEN, Color::RED, Color::WHITE,
                                       Color::BLUE, true /* filtered */);
}

TEST_P(LayerRenderTypeTransactionTest, SetTransformFlipV_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction()
            .setTransform(layer, NATIVE_WINDOW_TRANSFORM_FLIP_V)
            .apply();

    getScreenCapture()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::WHITE, Color::RED,
                                       Color::GREEN, true /* filtered */);
}

// TODO (b/186543004): Fix & re-enable
TEST_P(LayerRenderTypeTransactionTest, DISABLED_SetFenceBasic_BufferState) {
    sp<SurfaceControl> layer;
    Transaction transaction;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    sp<Fence> fence;
    if (getBuffer(nullptr, &fence) != NO_ERROR) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    Transaction().setBuffer(layer, buffer).setAcquireFence(layer, fence).apply();

    status_t status = fence->wait(1000);
    ASSERT_NE(static_cast<status_t>(Fence::Status::Unsignaled), status);
    std::this_thread::sleep_for(200ms);

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::RED);
    shot->expectBorder(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetFenceNull_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    sp<Fence> fence = Fence::NO_FENCE;

    Transaction().setBuffer(layer, buffer).setAcquireFence(layer, fence).apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetDataspaceBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    Transaction().setBuffer(layer, buffer).setDataspace(layer, ui::Dataspace::UNKNOWN).apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetHdrMetadataBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    HdrMetadata hdrMetadata;
    hdrMetadata.validTypes = 0;
    Transaction().setBuffer(layer, buffer).setHdrMetadata(layer, hdrMetadata).apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetSurfaceDamageRegionBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    Region region;
    region.set(32, 32);
    Transaction().setBuffer(layer, buffer).setSurfaceDamageRegion(layer, region).apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetApiBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1, kUsageFlags, "test");
    TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    Transaction().setBuffer(layer, buffer).setApi(layer, NATIVE_WINDOW_API_CPU).apply();

    auto shot = getScreenCapture();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_P(LayerRenderTypeTransactionTest, SetColorTransformBasic) {
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(colorLayer =
                                    createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                                ISurfaceComposerClient::eFXSurfaceEffect));
    Transaction()
            .setCrop(colorLayer, Rect(0, 0, 32, 32))
            .setLayer(colorLayer, mLayerZBase + 1)
            .apply();
    {
        SCOPED_TRACE("default color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    const half3 color(50.0f / 255.0f, 100.0f / 255.0f, 150.0f / 255.0f);
    half3 expected = color;
    mat3 matrix;
    matrix[0][0] = 0.3;
    matrix[1][0] = 0.59;
    matrix[2][0] = 0.11;
    matrix[0][1] = 0.3;
    matrix[1][1] = 0.59;
    matrix[2][1] = 0.11;
    matrix[0][2] = 0.3;
    matrix[1][2] = 0.59;
    matrix[2][2] = 0.11;

    // degamma before applying the matrix
    if (mColorManagementUsed) {
        ColorTransformHelper::DegammaColor(expected);
    }

    ColorTransformHelper::applyMatrix(expected, matrix);

    if (mColorManagementUsed) {
        ColorTransformHelper::GammaColor(expected);
    }

    const Color expectedColor = {uint8_t(expected.r * 255), uint8_t(expected.g * 255),
                                 uint8_t(expected.b * 255), 255};

    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;

    Transaction().setColor(colorLayer, color).setColorTransform(colorLayer, matrix, vec3()).apply();
    {
        SCOPED_TRACE("new color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), expectedColor, tolerance);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetColorTransformOnParent) {
    sp<SurfaceControl> parentLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(parentLayer = createLayer("parent", 0 /* buffer width */,
                                                      0 /* buffer height */,
                                                      ISurfaceComposerClient::eFXSurfaceContainer));
    ASSERT_NO_FATAL_FAILURE(
            colorLayer = createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                     ISurfaceComposerClient::eFXSurfaceEffect, parentLayer.get()));

    Transaction()
            .setCrop(parentLayer, Rect(0, 0, 100, 100))
            .setCrop(colorLayer, Rect(0, 0, 32, 32))
            .setLayer(parentLayer, mLayerZBase + 1)
            .apply();
    {
        SCOPED_TRACE("default color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    const half3 color(50.0f / 255.0f, 100.0f / 255.0f, 150.0f / 255.0f);
    half3 expected = color;
    mat3 matrix;
    matrix[0][0] = 0.3;
    matrix[1][0] = 0.59;
    matrix[2][0] = 0.11;
    matrix[0][1] = 0.3;
    matrix[1][1] = 0.59;
    matrix[2][1] = 0.11;
    matrix[0][2] = 0.3;
    matrix[1][2] = 0.59;
    matrix[2][2] = 0.11;

    // degamma before applying the matrix
    if (mColorManagementUsed) {
        ColorTransformHelper::DegammaColor(expected);
    }

    ColorTransformHelper::applyMatrix(expected, matrix);

    if (mColorManagementUsed) {
        ColorTransformHelper::GammaColor(expected);
    }

    const Color expectedColor = {uint8_t(expected.r * 255), uint8_t(expected.g * 255),
                                 uint8_t(expected.b * 255), 255};

    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;

    Transaction()
            .setColor(colorLayer, color)
            .setColorTransform(parentLayer, matrix, vec3())
            .apply();
    {
        SCOPED_TRACE("new color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), expectedColor, tolerance);
    }
}

TEST_P(LayerRenderTypeTransactionTest, SetColorTransformOnChildAndParent) {
    sp<SurfaceControl> parentLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(parentLayer = createLayer("parent", 0 /* buffer width */,
                                                      0 /* buffer height */,
                                                      ISurfaceComposerClient::eFXSurfaceContainer));
    ASSERT_NO_FATAL_FAILURE(
            colorLayer = createLayer("test", 0 /* buffer width */, 0 /* buffer height */,
                                     ISurfaceComposerClient::eFXSurfaceEffect, parentLayer.get()));

    Transaction()
            .setCrop(parentLayer, Rect(0, 0, 100, 100))
            .setCrop(colorLayer, Rect(0, 0, 32, 32))
            .setLayer(parentLayer, mLayerZBase + 1)
            .apply();
    {
        SCOPED_TRACE("default color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    const half3 color(50.0f / 255.0f, 100.0f / 255.0f, 150.0f / 255.0f);
    half3 expected = color;
    mat3 matrixChild;
    matrixChild[0][0] = 0.3;
    matrixChild[1][0] = 0.59;
    matrixChild[2][0] = 0.11;
    matrixChild[0][1] = 0.3;
    matrixChild[1][1] = 0.59;
    matrixChild[2][1] = 0.11;
    matrixChild[0][2] = 0.3;
    matrixChild[1][2] = 0.59;
    matrixChild[2][2] = 0.11;
    mat3 matrixParent;
    matrixParent[0][0] = 0.2;
    matrixParent[1][0] = 0.4;
    matrixParent[2][0] = 0.10;
    matrixParent[0][1] = 0.2;
    matrixParent[1][1] = 0.4;
    matrixParent[2][1] = 0.10;
    matrixParent[0][2] = 0.2;
    matrixParent[1][2] = 0.4;
    matrixParent[2][2] = 0.10;

    // degamma before applying the matrix
    if (mColorManagementUsed) {
        ColorTransformHelper::DegammaColor(expected);
    }

    ColorTransformHelper::applyMatrix(expected, matrixChild);
    ColorTransformHelper::applyMatrix(expected, matrixParent);

    if (mColorManagementUsed) {
        ColorTransformHelper::GammaColor(expected);
    }

    const Color expectedColor = {uint8_t(expected.r * 255), uint8_t(expected.g * 255),
                                 uint8_t(expected.b * 255), 255};

    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;

    Transaction()
            .setColor(colorLayer, color)
            .setColorTransform(parentLayer, matrixParent, vec3())
            .setColorTransform(colorLayer, matrixChild, vec3())
            .apply();
    {
        SCOPED_TRACE("new color");
        getScreenCapture()->expectColor(Rect(0, 0, 32, 32), expectedColor, tolerance);
    }
}
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
