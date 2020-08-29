/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "LayerTransactionTest.h"

namespace android {

class EffectLayerTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        const auto display = SurfaceComposerClient::getInternalDisplayToken();
        ASSERT_FALSE(display == nullptr);

        mParentLayer = createColorLayer("Parent layer", Color::RED);
        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, 0);
            t.setLayer(mParentLayer, INT32_MAX - 2).show(mParentLayer);
            t.setFlags(mParentLayer, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque);
        });
    }

    virtual void TearDown() {
        LayerTransactionTest::TearDown();
        mParentLayer = 0;
    }

    sp<SurfaceControl> mParentLayer;
};

TEST_F(EffectLayerTest, DefaultEffectLayerHasSolidBlackFill) {
    sp<SurfaceControl> effectLayer =
            mClient->createSurface(String8("Effect Layer"), 0 /* width */, 0 /* height */,
                                   PIXEL_FORMAT_RGBA_8888, ISurfaceComposerClient::eFXSurfaceEffect,
                                   mParentLayer.get());

    EXPECT_NE(nullptr, effectLayer.get()) << "failed to create SurfaceControl";
    asTransaction([&](Transaction& t) {
        t.setCrop_legacy(effectLayer, Rect(0, 0, 400, 400));
        t.show(effectLayer);
    });

    {
        SCOPED_TRACE("Default effect Layer has solid black fill");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 400, 400), Color::BLACK);
    }
}

TEST_F(EffectLayerTest, EffectLayerWithNoFill) {
    sp<SurfaceControl> effectLayer =
            mClient->createSurface(String8("Effect Layer"), 0 /* width */, 0 /* height */,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceEffect |
                                           ISurfaceComposerClient::eNoColorFill,
                                   mParentLayer.get());

    EXPECT_NE(nullptr, effectLayer.get()) << "failed to create SurfaceControl";
    asTransaction([&](Transaction& t) {
        t.setCrop_legacy(effectLayer, Rect(0, 0, 400, 400));
        t.show(effectLayer);
    });

    {
        SCOPED_TRACE("Effect layer with nofill option is transparent");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 400, 400), Color::RED);
    }
}

TEST_F(EffectLayerTest, EffectLayerCanSetColor) {
    sp<SurfaceControl> effectLayer =
            mClient->createSurface(String8("Effect Layer"), 0 /* width */, 0 /* height */,
                                   PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceEffect |
                                           ISurfaceComposerClient::eNoColorFill,
                                   mParentLayer.get());

    EXPECT_NE(nullptr, effectLayer.get()) << "failed to create SurfaceControl";
    asTransaction([&](Transaction& t) {
        t.setCrop_legacy(effectLayer, Rect(0, 0, 400, 400));
        t.setColor(effectLayer,
                   half3{Color::GREEN.r / 255.0f, Color::GREEN.g / 255.0f,
                         Color::GREEN.b / 255.0f});
        t.show(effectLayer);
    });

    {
        SCOPED_TRACE("Effect Layer can set color");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 400, 400), Color::GREEN);
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
