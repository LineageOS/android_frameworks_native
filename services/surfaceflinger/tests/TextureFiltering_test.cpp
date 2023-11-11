/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android/gui/ISurfaceComposerClient.h>
#include <gtest/gtest.h>
#include <gui/DisplayCaptureArgs.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>

#include "LayerTransactionTest.h"

namespace android {

bool operator==(const Color& left, const Color& right) {
    return left.a == right.a && left.r == right.r && left.g == right.g && left.b == right.b;
}

class TextureFilteringTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();

        mParent = createLayer("test-parent", 100, 100,
                              gui::ISurfaceComposerClient::eFXSurfaceContainer);
        mLayer = createLayer("test-child", 100, 100,
                             gui::ISurfaceComposerClient::eFXSurfaceBufferState, mParent.get());
        sp<GraphicBuffer> buffer =
                sp<GraphicBuffer>::make(static_cast<uint32_t>(100), static_cast<uint32_t>(100),
                                        PIXEL_FORMAT_RGBA_8888, 1u,
                                        BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                                BufferUsage::COMPOSER_OVERLAY |
                                                BufferUsage::GPU_TEXTURE,
                                        "test");
        TransactionUtils::fillGraphicBufferColor(buffer, Rect{0, 0, 50, 100}, Color::RED);
        TransactionUtils::fillGraphicBufferColor(buffer, Rect{50, 0, 100, 100}, Color::BLUE);
        Transaction()
                .setBuffer(mLayer, buffer)
                .setDataspace(mLayer, ui::Dataspace::V0_SRGB)
                .setLayer(mLayer, INT32_MAX)
                .apply();
    }

    virtual void TearDown() { LayerTransactionTest::TearDown(); }

    void expectFiltered(Rect redRect, Rect blueRect) {
        // Check that at least some of the pixels in the red rectangle aren't solid red
        int redPixels = 0;
        for (int x = redRect.left; x < redRect.right; x++) {
            for (int y = redRect.top; y < redRect.bottom; y++) {
                redPixels += mCapture->getPixelColor(static_cast<uint32_t>(x),
                                                     static_cast<uint32_t>(y)) == Color::RED;
            }
        }
        ASSERT_LT(redPixels, redRect.getWidth() * redRect.getHeight());

        // Check that at least some of the pixels in the blue rectangle aren't solid blue
        int bluePixels = 0;
        for (int x = blueRect.left; x < blueRect.right; x++) {
            for (int y = blueRect.top; y < blueRect.bottom; y++) {
                bluePixels += mCapture->getPixelColor(static_cast<uint32_t>(x),
                                                      static_cast<uint32_t>(y)) == Color::BLUE;
            }
        }
        ASSERT_LT(bluePixels, blueRect.getWidth() * blueRect.getHeight());
    }

    sp<SurfaceControl> mParent;
    sp<SurfaceControl> mLayer;
    std::unique_ptr<ScreenCapture> mCapture;
    gui::LayerCaptureArgs captureArgs;
};

TEST_F(TextureFilteringTest, NoFiltering) {
    captureArgs.sourceCrop = Rect{0, 0, 100, 100};
    captureArgs.layerHandle = mParent->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{0, 0, 50, 100}, Color::RED);
    mCapture->expectColor(Rect{50, 0, 100, 100}, Color::BLUE);
}

TEST_F(TextureFilteringTest, BufferCropNoFiltering) {
    captureArgs.sourceCrop = Rect{0, 0, 100, 100};
    captureArgs.layerHandle = mParent->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{0, 0, 50, 100}, Color::RED);
    mCapture->expectColor(Rect{50, 0, 100, 100}, Color::BLUE);
}

// Expect filtering because the buffer is stretched to the layer's bounds.
TEST_F(TextureFilteringTest, BufferCropIsFiltered) {
    Transaction().setBufferCrop(mLayer, Rect{25, 25, 75, 75}).apply();

    captureArgs.sourceCrop = Rect{0, 0, 100, 100};
    captureArgs.layerHandle = mParent->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    expectFiltered({0, 0, 50, 100}, {50, 0, 100, 100});
}

// Expect filtering because the output source crop is stretched to the output buffer's size.
TEST_F(TextureFilteringTest, OutputSourceCropIsFiltered) {
    captureArgs.frameScaleX = 2;
    captureArgs.frameScaleY = 2;
    captureArgs.sourceCrop = Rect{25, 25, 75, 75};
    captureArgs.layerHandle = mParent->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    expectFiltered({0, 0, 50, 100}, {50, 0, 100, 100});
}

// Expect filtering because the layer crop and output source crop are stretched to the output
// buffer's size.
TEST_F(TextureFilteringTest, LayerCropOutputSourceCropIsFiltered) {
    Transaction().setCrop(mLayer, Rect{25, 25, 75, 75}).apply();
    captureArgs.frameScaleX = 2;
    captureArgs.frameScaleY = 2;
    captureArgs.sourceCrop = Rect{25, 25, 75, 75};
    captureArgs.layerHandle = mParent->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    expectFiltered({0, 0, 50, 100}, {50, 0, 100, 100});
}

// Expect filtering because the layer is scaled up.
TEST_F(TextureFilteringTest, LayerCaptureWithScalingIsFiltered) {
    captureArgs.layerHandle = mLayer->getHandle();
    captureArgs.frameScaleX = 2;
    captureArgs.frameScaleY = 2;
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    expectFiltered({0, 0, 100, 200}, {100, 0, 200, 200});
}

// Expect no filtering because the output buffer's size matches the source crop.
TEST_F(TextureFilteringTest, LayerCaptureOutputSourceCropNoFiltering) {
    captureArgs.layerHandle = mLayer->getHandle();
    captureArgs.sourceCrop = Rect{25, 25, 75, 75};
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{0, 0, 25, 50}, Color::RED);
    mCapture->expectColor(Rect{25, 0, 50, 50}, Color::BLUE);
}

// Expect no filtering because the output buffer's size matches the source crop (with a cropped
// layer).
TEST_F(TextureFilteringTest, LayerCaptureWithCropNoFiltering) {
    Transaction().setCrop(mLayer, Rect{10, 10, 90, 90}).apply();

    captureArgs.layerHandle = mLayer->getHandle();
    captureArgs.sourceCrop = Rect{25, 25, 75, 75};
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{0, 0, 25, 50}, Color::RED);
    mCapture->expectColor(Rect{25, 0, 50, 50}, Color::BLUE);
}

// Expect no filtering because the output source crop and output buffer are the same size.
TEST_F(TextureFilteringTest, OutputSourceCropDisplayFrameMatchNoFiltering) {
    captureArgs.layerHandle = mLayer->getHandle();
    captureArgs.sourceCrop = Rect{25, 25, 75, 75};
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{0, 0, 25, 50}, Color::RED);
    mCapture->expectColor(Rect{25, 0, 50, 50}, Color::BLUE);
}

// Expect no filtering because the layer crop shouldn't scale the layer.
TEST_F(TextureFilteringTest, LayerCropDisplayFrameMatchNoFiltering) {
    Transaction().setCrop(mLayer, Rect{25, 25, 75, 75}).apply();

    captureArgs.layerHandle = mLayer->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{25, 25, 50, 75}, Color::RED);
    mCapture->expectColor(Rect{50, 25, 75, 75}, Color::BLUE);
}

// Expect no filtering because the parent layer crop shouldn't scale the layer.
TEST_F(TextureFilteringTest, ParentCropNoFiltering) {
    Transaction().setCrop(mParent, Rect{25, 25, 75, 75}).apply();

    captureArgs.layerHandle = mLayer->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{25, 25, 50, 75}, Color::RED);
    mCapture->expectColor(Rect{50, 25, 75, 75}, Color::BLUE);
}

// Expect no filtering because parent's position transform shouldn't scale the layer.
TEST_F(TextureFilteringTest, ParentHasTransformNoFiltering) {
    Transaction().setPosition(mParent, 100, 100).apply();

    captureArgs.layerHandle = mParent->getHandle();
    captureArgs.sourceCrop = Rect{0, 0, 100, 100};
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect{0, 0, 50, 100}, Color::RED);
    mCapture->expectColor(Rect{50, 0, 100, 100}, Color::BLUE);
}

} // namespace android
