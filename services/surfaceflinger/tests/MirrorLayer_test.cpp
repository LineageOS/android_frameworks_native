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

#include <private/android_filesystem_config.h>
#include "LayerTransactionTest.h"
#include "utils/TransactionUtils.h"

namespace android {

class MirrorLayerTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        const auto display = SurfaceComposerClient::getInternalDisplayToken();
        ASSERT_FALSE(display == nullptr);

        mParentLayer = createColorLayer("Parent layer", Color::RED);
        mChildLayer = createColorLayer("Child layer", Color::GREEN, mParentLayer.get());
        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, ui::DEFAULT_LAYER_STACK);
            t.setLayer(mParentLayer, INT32_MAX - 2).show(mParentLayer);
            t.setCrop(mChildLayer, Rect(0, 0, 400, 400)).show(mChildLayer);
            t.setPosition(mChildLayer, 50, 50);
            t.setFlags(mParentLayer, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque);
            t.setFlags(mChildLayer, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque);
        });
    }

    virtual void TearDown() {
        LayerTransactionTest::TearDown();
        mParentLayer = 0;
        mChildLayer = 0;
    }

    sp<SurfaceControl> mParentLayer;
    sp<SurfaceControl> mChildLayer;
};

TEST_F(MirrorLayerTest, MirrorColorLayer) {
    sp<SurfaceControl> grandchild =
            createColorLayer("Grandchild layer", Color::BLUE, mChildLayer.get());
    Transaction()
            .setFlags(grandchild, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque)
            .setCrop(grandchild, Rect(0, 0, 200, 200))
            .show(grandchild)
            .apply();

    // Mirror mChildLayer
    sp<SurfaceControl> mirrorLayer = mClient->mirrorSurface(mChildLayer.get());
    ASSERT_NE(mirrorLayer, nullptr);

    // Add mirrorLayer as child of mParentLayer so it's shown on the display
    Transaction()
            .reparent(mirrorLayer, mParentLayer)
            .setPosition(mirrorLayer, 500, 500)
            .show(mirrorLayer)
            .apply();

    {
        SCOPED_TRACE("Initial Mirror");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::BLUE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    // Set color to white on grandchild layer.
    Transaction().setColor(grandchild, half3{1, 1, 1}).apply();
    {
        SCOPED_TRACE("Updated Grandchild Layer Color");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::WHITE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    // Set color to black on child layer.
    Transaction().setColor(mChildLayer, half3{0, 0, 0}).apply();
    {
        SCOPED_TRACE("Updated Child Layer Color");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::WHITE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::BLACK);
    }

    // Remove grandchild layer
    Transaction().reparent(grandchild, nullptr).apply();
    {
        SCOPED_TRACE("Removed Grandchild Layer");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::BLACK);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::BLACK);
    }

    // Remove child layer
    Transaction().reparent(mChildLayer, nullptr).apply();
    {
        SCOPED_TRACE("Removed Child Layer");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::RED);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::RED);
    }

    // Add grandchild layer to offscreen layer
    Transaction().reparent(grandchild, mChildLayer).apply();
    {
        SCOPED_TRACE("Added Grandchild Layer");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::RED);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::RED);
    }

    // Add child layer
    Transaction().reparent(mChildLayer, mParentLayer).apply();
    {
        SCOPED_TRACE("Added Child Layer");
        auto shot = screenshot();
        // Grandchild mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::WHITE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::BLACK);
    }
}

TEST_F(MirrorLayerTest, MirrorBufferLayer) {
    sp<SurfaceControl> bufferQueueLayer =
            createLayer("BufferQueueLayer", 200, 200, 0, mChildLayer.get());
    fillBufferQueueLayerColor(bufferQueueLayer, Color::BLUE, 200, 200);
    Transaction().show(bufferQueueLayer).apply();

    sp<SurfaceControl> mirrorLayer = mClient->mirrorSurface(mChildLayer.get());
    Transaction()
            .reparent(mirrorLayer, mParentLayer)
            .setPosition(mirrorLayer, 500, 500)
            .show(mirrorLayer)
            .apply();

    {
        SCOPED_TRACE("Initial Mirror BufferQueueLayer");
        auto shot = screenshot();
        // Buffer mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::BLUE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    fillBufferQueueLayerColor(bufferQueueLayer, Color::WHITE, 200, 200);
    {
        SCOPED_TRACE("Update BufferQueueLayer");
        auto shot = screenshot();
        // Buffer mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::WHITE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    Transaction().reparent(bufferQueueLayer, nullptr).apply();
    {
        SCOPED_TRACE("Removed BufferQueueLayer");
        auto shot = screenshot();
        // Buffer mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::GREEN);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    sp<SurfaceControl> bufferStateLayer =
            createLayer("BufferStateLayer", 200, 200, ISurfaceComposerClient::eFXSurfaceBufferState,
                        mChildLayer.get());
    fillBufferStateLayerColor(bufferStateLayer, Color::BLUE, 200, 200);
    Transaction().show(bufferStateLayer).apply();

    {
        SCOPED_TRACE("Initial Mirror BufferStateLayer");
        auto shot = screenshot();
        // Buffer mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::BLUE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    fillBufferStateLayerColor(bufferStateLayer, Color::WHITE, 200, 200);
    {
        SCOPED_TRACE("Update BufferStateLayer");
        auto shot = screenshot();
        // Buffer mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::WHITE);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }

    Transaction().reparent(bufferStateLayer, nullptr).apply();
    {
        SCOPED_TRACE("Removed BufferStateLayer");
        auto shot = screenshot();
        // Buffer mirror
        shot->expectColor(Rect(550, 550, 750, 750), Color::GREEN);
        // Child mirror
        shot->expectColor(Rect(750, 750, 950, 950), Color::GREEN);
    }
}

// Test that the mirror layer is initially offscreen.
TEST_F(MirrorLayerTest, InitialMirrorState) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    ui::DisplayMode mode;
    SurfaceComposerClient::getActiveDisplayMode(display, &mode);
    const ui::Size& size = mode.resolution;

    sp<SurfaceControl> mirrorLayer = nullptr;
    {
        // Run as system to get the ACCESS_SURFACE_FLINGER permission when mirroring
        UIDFaker f(AID_SYSTEM);
        // Mirror mChildLayer
        mirrorLayer = mClient->mirrorSurface(mChildLayer.get());
        ASSERT_NE(mirrorLayer, nullptr);
    }

    // Show the mirror layer, but don't reparent to a layer on screen.
    Transaction()
            .setPosition(mirrorLayer, 500, 500)
            .show(mirrorLayer)
            .setLayer(mirrorLayer, INT32_MAX - 1)
            .apply();

    {
        SCOPED_TRACE("Offscreen Mirror");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, size.getWidth(), 50), Color::RED);
        shot->expectColor(Rect(0, 0, 50, size.getHeight()), Color::RED);
        shot->expectColor(Rect(450, 0, size.getWidth(), size.getHeight()), Color::RED);
        shot->expectColor(Rect(0, 450, size.getWidth(), size.getHeight()), Color::RED);
        shot->expectColor(Rect(50, 50, 450, 450), Color::GREEN);
    }

    // Add mirrorLayer as child of mParentLayer so it's shown on the display
    Transaction().reparent(mirrorLayer, mParentLayer).apply();

    {
        SCOPED_TRACE("On Screen Mirror");
        auto shot = screenshot();
        // Child mirror
        shot->expectColor(Rect(550, 550, 950, 950), Color::GREEN);
    }
}

// Test that a mirror layer can be screenshot when offscreen
TEST_F(MirrorLayerTest, OffscreenMirrorScreenshot) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    ui::DisplayMode mode;
    SurfaceComposerClient::getActiveDisplayMode(display, &mode);
    const ui::Size& size = mode.resolution;

    sp<SurfaceControl> grandchild =
            createLayer("Grandchild layer", 50, 50, ISurfaceComposerClient::eFXSurfaceBufferState,
                        mChildLayer.get());
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(grandchild, Color::BLUE, 50, 50));
    Rect childBounds = Rect(50, 50, 450, 450);

    asTransaction([&](Transaction& t) {
        t.setCrop(grandchild, Rect(0, 0, 50, 50)).show(grandchild);
        t.setFlags(grandchild, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque);
    });

    sp<SurfaceControl> mirrorLayer = nullptr;
    {
        // Run as system to get the ACCESS_SURFACE_FLINGER permission when mirroring
        UIDFaker f(AID_SYSTEM);
        // Mirror mChildLayer
        mirrorLayer = mClient->mirrorSurface(mChildLayer.get());
        ASSERT_NE(mirrorLayer, nullptr);
    }

    // Show the mirror layer, but don't reparent to a layer on screen.
    Transaction().show(mirrorLayer).apply();

    {
        SCOPED_TRACE("Offscreen Mirror");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, size.getWidth(), 50), Color::RED);
        shot->expectColor(Rect(0, 0, 50, size.getHeight()), Color::RED);
        shot->expectColor(Rect(450, 0, size.getWidth(), size.getHeight()), Color::RED);
        shot->expectColor(Rect(0, 450, size.getWidth(), size.getHeight()), Color::RED);
        shot->expectColor(Rect(100, 100, 450, 450), Color::GREEN);
        shot->expectColor(Rect(50, 50, 100, 100), Color::BLUE);
    }

    {
        SCOPED_TRACE("Capture Mirror");
        // Capture just the mirror layer and child.
        LayerCaptureArgs captureArgs;
        captureArgs.layerHandle = mirrorLayer->getHandle();
        captureArgs.sourceCrop = childBounds;
        std::unique_ptr<ScreenCapture> shot;
        ScreenCapture::captureLayers(&shot, captureArgs);
        shot->expectSize(childBounds.width(), childBounds.height());
        shot->expectColor(Rect(0, 0, 50, 50), Color::BLUE);
        shot->expectColor(Rect(50, 50, 400, 400), Color::GREEN);
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
