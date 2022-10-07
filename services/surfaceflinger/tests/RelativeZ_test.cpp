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

#include "LayerTransactionTest.h"

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

class RelativeZTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        ASSERT_FALSE(ids.empty());
        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
        ASSERT_FALSE(display == nullptr);

        // Back layer
        mBackgroundLayer = createColorLayer("Background layer", Color::RED);

        // Front layer
        mForegroundLayer = createColorLayer("Foreground layer", Color::GREEN);

        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, ui::DEFAULT_LAYER_STACK);
            t.setLayer(mBackgroundLayer, INT32_MAX - 2).show(mBackgroundLayer);
            t.setLayer(mForegroundLayer, INT32_MAX - 1).show(mForegroundLayer);
        });
    }

    virtual void TearDown() {
        LayerTransactionTest::TearDown();
        mBackgroundLayer = 0;
        mForegroundLayer = 0;
    }

    sp<SurfaceControl> mBackgroundLayer;
    sp<SurfaceControl> mForegroundLayer;
};

// When a layer is reparented offscreen, remove relative z order if the relative parent
// is still onscreen so that the layer is not drawn.
TEST_F(RelativeZTest, LayerRemoved) {
    std::unique_ptr<ScreenCapture> sc;

    // Background layer (RED)
    //   Child layer (WHITE) (relative to foregroud layer)
    // Foregroud layer (GREEN)
    sp<SurfaceControl> childLayer =
            createColorLayer("Child layer", Color::BLUE, mBackgroundLayer.get());

    Transaction{}.setRelativeLayer(childLayer, mForegroundLayer, 1).show(childLayer).apply();

    {
        // The childLayer should be in front of the FG control.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::BLUE.r, Color::BLUE.g, Color::BLUE.b);
    }

    // Background layer (RED)
    // Foregroud layer (GREEN)
    Transaction{}.reparent(childLayer, nullptr).apply();

    // Background layer (RED)
    //   Child layer (WHITE)
    // Foregroud layer (GREEN)
    Transaction{}.reparent(childLayer, mBackgroundLayer).apply();

    {
        // The relative z info for child layer should be reset, leaving FG control on top.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::GREEN.r, Color::GREEN.g, Color::GREEN.b);
    }
}

// When a layer is reparented offscreen, preseve relative z order if the relative parent
// is also offscreen. Regression test b/132613412
TEST_F(RelativeZTest, LayerRemovedOffscreenRelativeParent) {
    std::unique_ptr<ScreenCapture> sc;

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   child level 1 (WHITE)
    //     child level 2a (BLUE)
    //       child level 3 (GREEN) (relative to child level 2b)
    //     child level 2b (BLACK)
    sp<SurfaceControl> childLevel1 =
            createColorLayer("child level 1", Color::WHITE, mForegroundLayer.get());
    sp<SurfaceControl> childLevel2a =
            createColorLayer("child level 2a", Color::BLUE, childLevel1.get());
    sp<SurfaceControl> childLevel2b =
            createColorLayer("child level 2b", Color::BLACK, childLevel1.get());
    sp<SurfaceControl> childLevel3 =
            createColorLayer("child level 3", Color::GREEN, childLevel2a.get());

    Transaction{}
            .setRelativeLayer(childLevel3, childLevel2b, 1)
            .show(childLevel2a)
            .show(childLevel2b)
            .show(childLevel3)
            .apply();

    {
        // The childLevel3 should be in front of childLevel2b.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::GREEN.r, Color::GREEN.g, Color::GREEN.b);
    }

    // Background layer (RED)
    // Foregroud layer (GREEN)
    Transaction{}.reparent(childLevel1, nullptr).apply();

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   child level 1 (WHITE)
    //     child level 2 back (BLUE)
    //       child level 3 (GREEN) (relative to child level 2b)
    //     child level 2 front (BLACK)
    Transaction{}.reparent(childLevel1, mForegroundLayer).apply();

    {
        // Nothing should change at this point since relative z info was preserved.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::GREEN.r, Color::GREEN.g, Color::GREEN.b);
    }
}

TEST_F(RelativeZTest, LayerAndRelativeRemoved) {
    std::unique_ptr<ScreenCapture> sc;

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   Child layer (BLUE) (relative to relativeToLayer layer)
    //   Relative layer (WHITE)
    sp<SurfaceControl> childLayer =
            createColorLayer("Child layer", Color::BLUE, mForegroundLayer.get());
    sp<SurfaceControl> relativeToLayer =
            createColorLayer("Relative layer", Color::WHITE, mForegroundLayer.get());

    Transaction{}
            .setRelativeLayer(childLayer, relativeToLayer, 1)
            .show(childLayer)
            .show(relativeToLayer)
            .apply();

    {
        // The childLayer should be in front of relativeToLayer.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::BLUE.r, Color::BLUE.g, Color::BLUE.b);
    }

    // Remove layer that childLayer is relative to
    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   Child layer (BLUE) (relative to relativeToLayer layer)
    Transaction{}.reparent(relativeToLayer, nullptr).apply();
    relativeToLayer = 0;

    {
        // The child layer is relative to an deleted layer so it won't be drawn.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::GREEN.r, Color::GREEN.g, Color::GREEN.b);
    }

    // Background layer (RED)
    // Foregroud layer (GREEN)
    Transaction{}.reparent(childLayer, nullptr).apply();

    {
        // The child layer is offscreen, so it won't be drawn.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::GREEN.r, Color::GREEN.g, Color::GREEN.b);
    }

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   Child layer (BLUE)
    Transaction{}.reparent(childLayer, mForegroundLayer).apply();

    {
        // The relative z info for child layer should be reset, leaving the child layer on top.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(1, 1, Color::BLUE.r, Color::BLUE.g, Color::BLUE.b);
    }
}

// Preserve the relative z order when a layer is reparented to a layer that's already offscreen
TEST_F(RelativeZTest, LayerWithRelativeReparentedToOffscreen) {
    std::unique_ptr<ScreenCapture> sc;

    Color testLayerColor = {255, 100, 0, 255};

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   child level 1a (testLayerColor) (relative to child level 2b)
    //   child level 1b (WHITE)
    //     child level 2a (BLUE)
    //     child level 2b (BLACK)
    sp<SurfaceControl> childLevel1a =
            createColorLayer("child level 1a", testLayerColor, mForegroundLayer.get());
    sp<SurfaceControl> childLevel1b =
            createColorLayer("child level 1b", Color::WHITE, mForegroundLayer.get());
    sp<SurfaceControl> childLevel2a =
            createColorLayer("child level 2a", Color::BLUE, childLevel1b.get());
    sp<SurfaceControl> childLevel2b =
            createColorLayer("child level 2b", Color::BLACK, childLevel1b.get());

    Transaction{}
            .setRelativeLayer(childLevel1a, childLevel2b, 1)
            .show(childLevel1a)
            .show(childLevel1b)
            .show(childLevel2a)
            .show(childLevel2b)
            .apply();

    {
        // The childLevel1a should be in front of childLevel2b.
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), testLayerColor);
    }

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   child level 1a (testLayerColor) (relative to child level 2b)
    Transaction{}.reparent(childLevel1b, nullptr).apply();

    // // Background layer (RED)
    // // Foregroud layer (GREEN)
    Transaction{}.reparent(childLevel1a, childLevel2a).apply();

    {
        // The childLevel1a and childLevel1b are no longer on screen
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::GREEN);
    }

    // Background layer (RED)
    // Foregroud layer (GREEN)
    //   child level 1b (WHITE)
    //     child level 2a (BLUE)
    //       child level 1a (testLayerColor) (relative to child level 2b)
    //     child level 2b (BLACK)
    Transaction{}.reparent(childLevel1b, mForegroundLayer).apply();

    {
        // Nothing should change at this point since relative z info was preserved.
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), testLayerColor);
    }
}
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
