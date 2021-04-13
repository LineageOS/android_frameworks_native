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
            t.setDisplayLayerStack(display, 0);
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

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
