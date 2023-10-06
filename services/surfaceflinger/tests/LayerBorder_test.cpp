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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
// TODO: Amend all tests when screenshots become fully reworked for borders
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <chrono> // std::chrono::seconds
#include <thread> // std::this_thread::sleep_for
#include "LayerTransactionTest.h"

namespace android {

class LayerBorderTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        toHalf3 = ColorTransformHelper::toHalf3;
        toHalf4 = ColorTransformHelper::toHalf4;

        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        ASSERT_FALSE(ids.empty());
        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
        ASSERT_FALSE(display == nullptr);
        mColorOrange = toHalf4({255, 140, 0, 255});
        mParentLayer = createColorLayer("Parent layer", Color::RED);

        mContainerLayer = mClient->createSurface(String8("Container Layer"), 0 /* width */,
                                                 0 /* height */, PIXEL_FORMAT_RGBA_8888,
                                                 ISurfaceComposerClient::eFXSurfaceContainer |
                                                         ISurfaceComposerClient::eNoColorFill,
                                                 mParentLayer->getHandle());
        EXPECT_NE(nullptr, mContainerLayer.get()) << "failed to create container layer";

        mEffectLayer1 = mClient->createSurface(String8("Effect Layer"), 0 /* width */,
                                               0 /* height */, PIXEL_FORMAT_RGBA_8888,
                                               ISurfaceComposerClient::eFXSurfaceEffect |
                                                       ISurfaceComposerClient::eNoColorFill,
                                               mContainerLayer->getHandle());
        EXPECT_NE(nullptr, mEffectLayer1.get()) << "failed to create effect layer 1";

        mEffectLayer2 = mClient->createSurface(String8("Effect Layer"), 0 /* width */,
                                               0 /* height */, PIXEL_FORMAT_RGBA_8888,
                                               ISurfaceComposerClient::eFXSurfaceEffect |
                                                       ISurfaceComposerClient::eNoColorFill,
                                               mContainerLayer->getHandle());

        EXPECT_NE(nullptr, mEffectLayer2.get()) << "failed to create effect layer 2";

        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, ui::DEFAULT_LAYER_STACK);
            t.setLayer(mParentLayer, INT32_MAX - 20).show(mParentLayer);
            t.setFlags(mParentLayer, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque);

            t.setColor(mEffectLayer1, toHalf3(Color::BLUE));

            t.setColor(mEffectLayer2, toHalf3(Color::GREEN));
        });
    }

    virtual void TearDown() {
        // Uncomment the line right below when running any of the tests
        // std::this_thread::sleep_for (std::chrono::seconds(30));
        LayerTransactionTest::TearDown();
        mParentLayer = 0;
    }

    std::function<half3(Color)> toHalf3;
    std::function<half4(Color)> toHalf4;
    sp<SurfaceControl> mParentLayer, mContainerLayer, mEffectLayer1, mEffectLayer2;
    half4 mColorOrange;
};

TEST_F(LayerBorderTest, OverlappingVisibleRegions) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));

        t.enableBorder(mContainerLayer, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, PartiallyCoveredVisibleRegion) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));

        t.enableBorder(mEffectLayer1, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, NonOverlappingVisibleRegion) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 200, 200));
        t.setCrop(mEffectLayer2, Rect(400, 400, 600, 600));

        t.enableBorder(mContainerLayer, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, EmptyVisibleRegion) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(200, 200, 400, 400));
        t.setCrop(mEffectLayer2, Rect(0, 0, 600, 600));

        t.enableBorder(mEffectLayer1, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, ZOrderAdjustment) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));
        t.setLayer(mParentLayer, 10);
        t.setLayer(mEffectLayer1, 30);
        t.setLayer(mEffectLayer2, 20);

        t.enableBorder(mEffectLayer1, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, GrandChildHierarchy) {
    sp<SurfaceControl> containerLayer2 =
            mClient->createSurface(String8("Container Layer"), 0 /* width */, 0 /* height */,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceContainer |
                                           ISurfaceComposerClient::eNoColorFill,
                                   mContainerLayer->getHandle());
    EXPECT_NE(nullptr, containerLayer2.get()) << "failed to create container layer 2";

    sp<SurfaceControl> effectLayer3 =
            mClient->createSurface(String8("Effect Layer"), 0 /* width */, 0 /* height */,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceEffect |
                                           ISurfaceComposerClient::eNoColorFill,
                                   containerLayer2->getHandle());

    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));
        t.setCrop(effectLayer3, Rect(400, 400, 800, 800));
        t.setColor(effectLayer3, toHalf3(Color::BLUE));

        t.enableBorder(mContainerLayer, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(effectLayer3);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, TransparentAlpha) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));
        t.setAlpha(mEffectLayer1, 0.0f);

        t.enableBorder(mContainerLayer, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, SemiTransparentAlpha) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));
        t.setAlpha(mEffectLayer2, 0.5f);

        t.enableBorder(mEffectLayer2, true, 20, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, InvisibleLayers) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));

        t.enableBorder(mContainerLayer, true, 20, mColorOrange);
        t.hide(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, LayerWithBuffer) {
    asTransaction([&](Transaction& t) {
        t.hide(mEffectLayer1);
        t.hide(mEffectLayer2);
        t.show(mContainerLayer);

        sp<SurfaceControl> layer =
                mClient->createSurface(String8("BufferState"), 0 /* width */, 0 /* height */,
                                       PIXEL_FORMAT_RGBA_8888,
                                       ISurfaceComposerClient::eFXSurfaceBufferState,
                                       mContainerLayer->getHandle());

        sp<GraphicBuffer> buffer =
                sp<GraphicBuffer>::make(400u, 400u, PIXEL_FORMAT_RGBA_8888, 1u,
                                        BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                                BufferUsage::COMPOSER_OVERLAY |
                                                BufferUsage::GPU_TEXTURE,
                                        "test");
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, 200, 200), Color::GREEN);
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(200, 200, 400, 400), Color::BLUE);

        t.setBuffer(layer, buffer);
        t.setPosition(layer, 100, 100);
        t.show(layer);
        t.enableBorder(mContainerLayer, true, 20, mColorOrange);
    });
}

TEST_F(LayerBorderTest, CustomWidth) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));

        t.enableBorder(mContainerLayer, true, 50, mColorOrange);
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, CustomColor) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 400, 400));
        t.setCrop(mEffectLayer2, Rect(200, 200, 600, 600));

        t.enableBorder(mContainerLayer, true, 20, toHalf4({255, 0, 255, 255}));
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

TEST_F(LayerBorderTest, CustomWidthAndColorAndOpacity) {
    asTransaction([&](Transaction& t) {
        t.setCrop(mEffectLayer1, Rect(0, 0, 200, 200));
        t.setCrop(mEffectLayer2, Rect(400, 400, 600, 600));

        t.enableBorder(mContainerLayer, true, 40, toHalf4({255, 255, 0, 128}));
        t.show(mEffectLayer1);
        t.show(mEffectLayer2);
        t.show(mContainerLayer);
    });
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
