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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "LayerTransactionTest.h"

namespace android {

class DetachChildren : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();

        mMainSurface = createLayer(String8("Main Test Surface"), mMainSurfaceBounds.width(),
                                   mMainSurfaceBounds.height(), 0, mBlackBgSurface.get());

        ASSERT_TRUE(mMainSurface != nullptr);
        ASSERT_TRUE(mMainSurface->isValid());

        TransactionUtils::fillSurfaceRGBA8(mMainSurface, mMainSurfaceColor);

        asTransaction([&](Transaction& t) {
            t.setLayer(mMainSurface, INT32_MAX - 1)
                    .setPosition(mMainSurface, mMainSurfaceBounds.left, mMainSurfaceBounds.top)
                    .show(mMainSurface);
        });
    }

    virtual void TearDown() {
        LayerTransactionTest::TearDown();
        mMainSurface = 0;
    }

    sp<SurfaceControl> mMainSurface;
    Color mMainSurfaceColor = {195, 63, 63, 255};
    Rect mMainSurfaceBounds = Rect(64, 64, 128, 128);
    std::unique_ptr<ScreenCapture> mCapture;
};

TEST_F(DetachChildren, RelativesAreNotDetached) {
    Color relativeColor = {10, 10, 10, 255};
    Rect relBounds = Rect(64, 64, 74, 74);

    sp<SurfaceControl> relative =
            createLayer(String8("relativeTestSurface"), relBounds.width(), relBounds.height(), 0);
    TransactionUtils::fillSurfaceRGBA8(relative, relativeColor);

    Transaction{}
            .setRelativeLayer(relative, mMainSurface, 1)
            .setPosition(relative, relBounds.left, relBounds.top)
            .apply();

    {
        // The relative should be on top of the FG control.
        mCapture = screenshot();
        mCapture->expectColor(relBounds, relativeColor);
    }
    Transaction{}.detachChildren(mMainSurface).apply();

    {
        // Nothing should change at this point.
        mCapture = screenshot();
        mCapture->expectColor(relBounds, relativeColor);
    }

    Transaction{}.hide(relative).apply();

    {
        // Ensure that the relative was actually hidden, rather than
        // being left in the detached but visible state.
        mCapture = screenshot();
        mCapture->expectColor(mMainSurfaceBounds, mMainSurfaceColor);
    }
}

TEST_F(DetachChildren, DetachChildrenSameClient) {
    Color childColor = {200, 200, 200, 255};
    Rect childBounds = Rect(74, 74, 84, 84);
    sp<SurfaceControl> child = createLayer(String8("Child surface"), childBounds.width(),
                                           childBounds.height(), 0, mMainSurface.get());
    ASSERT_TRUE(child->isValid());

    TransactionUtils::fillSurfaceRGBA8(child, childColor);

    asTransaction([&](Transaction& t) {
        t.show(child);
        t.setPosition(child, childBounds.left - mMainSurfaceBounds.left,
                      childBounds.top - mMainSurfaceBounds.top);
    });

    {
        mCapture = screenshot();
        // Expect main color around the child surface
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }

    asTransaction([&](Transaction& t) { t.detachChildren(mMainSurface); });

    asTransaction([&](Transaction& t) { t.hide(child); });

    // Since the child has the same client as the parent, it will not get
    // detached and will be hidden.
    {
        mCapture = screenshot();
        mCapture->expectColor(mMainSurfaceBounds, mMainSurfaceColor);
    }
}

TEST_F(DetachChildren, DetachChildrenDifferentClient) {
    Color childColor = {200, 200, 200, 255};
    Rect childBounds = Rect(74, 74, 84, 84);

    sp<SurfaceComposerClient> newComposerClient = new SurfaceComposerClient;
    sp<SurfaceControl> childNewClient =
            createSurface(newComposerClient, "New Child Test Surface", childBounds.width(),
                          childBounds.height(), PIXEL_FORMAT_RGBA_8888, 0, mMainSurface.get());
    ASSERT_TRUE(childNewClient->isValid());

    TransactionUtils::fillSurfaceRGBA8(childNewClient, childColor);

    asTransaction([&](Transaction& t) {
        t.show(childNewClient);
        t.setPosition(childNewClient, childBounds.left - mMainSurfaceBounds.left,
                      childBounds.top - mMainSurfaceBounds.top);
    });

    {
        mCapture = screenshot();
        // Expect main color around the child surface
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }

    asTransaction([&](Transaction& t) { t.detachChildren(mMainSurface); });

    asTransaction([&](Transaction& t) { t.hide(childNewClient); });

    // Nothing should have changed.
    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }
}

TEST_F(DetachChildren, DetachChildrenThenAttach) {
    Color childColor = {200, 200, 200, 255};
    Rect childBounds = Rect(74, 74, 84, 84);

    sp<SurfaceComposerClient> newComposerClient = new SurfaceComposerClient;
    sp<SurfaceControl> childNewClient =
            createSurface(newComposerClient, "New Child Test Surface", childBounds.width(),
                          childBounds.height(), PIXEL_FORMAT_RGBA_8888, 0, mMainSurface.get());
    ASSERT_TRUE(childNewClient->isValid());

    TransactionUtils::fillSurfaceRGBA8(childNewClient, childColor);

    Transaction()
            .show(childNewClient)
            .setPosition(childNewClient, childBounds.left - mMainSurfaceBounds.left,
                         childBounds.top - mMainSurfaceBounds.top)
            .apply();

    {
        mCapture = screenshot();
        // Expect main color around the child surface
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }

    Transaction().detachChildren(mMainSurface).apply();
    Transaction().hide(childNewClient).apply();

    // Nothing should have changed.
    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }

    Color newParentColor = Color::RED;
    Rect newParentBounds = Rect(20, 20, 52, 52);
    sp<SurfaceControl> newParentSurface =
            createLayer(String8("New Parent Surface"), newParentBounds.width(),
                        newParentBounds.height(), 0);
    TransactionUtils::fillSurfaceRGBA8(newParentSurface, newParentColor);
    Transaction()
            .setLayer(newParentSurface, INT32_MAX - 1)
            .show(newParentSurface)
            .setPosition(newParentSurface, newParentBounds.left, newParentBounds.top)
            .reparent(childNewClient, newParentSurface)
            .apply();
    {
        mCapture = screenshot();
        // Child is now hidden.
        mCapture->expectColor(newParentBounds, newParentColor);
    }
}

TEST_F(DetachChildren, DetachChildrenWithDeferredTransaction) {
    Color childColor = {200, 200, 200, 255};
    Rect childBounds = Rect(74, 74, 84, 84);

    sp<SurfaceComposerClient> newComposerClient = new SurfaceComposerClient;
    sp<SurfaceControl> childNewClient =
            createSurface(newComposerClient, "New Child Test Surface", childBounds.width(),
                          childBounds.height(), PIXEL_FORMAT_RGBA_8888, 0, mMainSurface.get());
    ASSERT_TRUE(childNewClient->isValid());

    TransactionUtils::fillSurfaceRGBA8(childNewClient, childColor);

    Transaction()
            .show(childNewClient)
            .setPosition(childNewClient, childBounds.left - mMainSurfaceBounds.left,
                         childBounds.top - mMainSurfaceBounds.top)
            .apply();

    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }

    Transaction()
            .deferTransactionUntil_legacy(childNewClient, mMainSurface,
                                          mMainSurface->getSurface()->getNextFrameNumber())
            .apply();
    Transaction().detachChildren(mMainSurface).apply();
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(mMainSurface, Color::RED,
                                                      mMainSurfaceBounds.width(),
                                                      mMainSurfaceBounds.height()));

    // BufferLayer can still dequeue buffers even though there's a detached layer with a
    // deferred transaction.
    {
        SCOPED_TRACE("new buffer");
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, Color::RED);
        mCapture->expectColor(childBounds, childColor);
    }
}

/**
 * Tests that a deferring transaction on an already detached layer will be dropped gracefully and
 * allow the barrier layer to dequeue buffers.
 *
 * Fixes b/150924737 - buffer cannot be latched because it waits for a detached layer
 * to commit its pending states.
 */
TEST_F(DetachChildren, DeferredTransactionOnDetachedChildren) {
    Color childColor = {200, 200, 200, 255};
    Rect childBounds = Rect(74, 74, 84, 84);

    sp<SurfaceComposerClient> newComposerClient = new SurfaceComposerClient;
    sp<SurfaceControl> childNewClient =
            createSurface(newComposerClient, "New Child Test Surface", childBounds.width(),
                          childBounds.height(), PIXEL_FORMAT_RGBA_8888, 0, mMainSurface.get());
    ASSERT_TRUE(childNewClient->isValid());

    TransactionUtils::fillSurfaceRGBA8(childNewClient, childColor);

    Transaction()
            .show(childNewClient)
            .setPosition(childNewClient, childBounds.left - mMainSurfaceBounds.left,
                         childBounds.top - mMainSurfaceBounds.top)
            .apply();

    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectColor(childBounds, childColor);
    }

    Transaction().detachChildren(mMainSurface).apply();
    Transaction()
            .setCrop_legacy(childNewClient, {0, 0, childBounds.width(), childBounds.height()})
            .deferTransactionUntil_legacy(childNewClient, mMainSurface,
                                          mMainSurface->getSurface()->getNextFrameNumber())
            .apply();

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(mMainSurface, Color::RED,
                                                      mMainSurfaceBounds.width(),
                                                      mMainSurfaceBounds.height()));

    // BufferLayer can still dequeue buffers even though there's a detached layer with a
    // deferred transaction.
    {
        SCOPED_TRACE("new buffer");
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, Color::RED);
        mCapture->expectColor(childBounds, childColor);
    }
}

TEST_F(DetachChildren, ReparentParentLayerOfDetachedChildren) {
    Color childColor = {200, 200, 200, 255};
    Rect childBounds = Rect(74, 74, 94, 94);
    Color grandchildColor = Color::RED;
    Rect grandchildBounds = Rect(80, 80, 90, 90);

    sp<SurfaceComposerClient> newClient1 = new SurfaceComposerClient;
    sp<SurfaceComposerClient> newClient2 = new SurfaceComposerClient;

    sp<SurfaceControl> childSurface =
            createSurface(newClient1, "Child surface", childBounds.width(), childBounds.height(),
                          PIXEL_FORMAT_RGBA_8888, 0, mMainSurface.get());
    sp<SurfaceControl> grandchildSurface =
            createSurface(newClient2, "Grandchild Surface", grandchildBounds.width(),
                          grandchildBounds.height(), PIXEL_FORMAT_RGBA_8888, 0, childSurface.get());

    TransactionUtils::fillSurfaceRGBA8(childSurface, childColor);
    TransactionUtils::fillSurfaceRGBA8(grandchildSurface, grandchildColor);

    Transaction()
            .show(childSurface)
            .show(grandchildSurface)
            .setPosition(childSurface, childBounds.left - mMainSurfaceBounds.left,
                         childBounds.top - mMainSurfaceBounds.top)
            .setPosition(grandchildSurface, grandchildBounds.left - childBounds.left,
                         grandchildBounds.top - childBounds.top)
            .apply();

    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectBorder(grandchildBounds, childColor);
        mCapture->expectColor(grandchildBounds, grandchildColor);
    }

    Transaction().detachChildren(childSurface).apply();

    // Remove main surface offscreen
    Transaction().reparent(mMainSurface, nullptr).apply();
    {
        mCapture = screenshot();
        mCapture->expectColor(mMainSurfaceBounds, Color::BLACK);
    }

    Transaction().reparent(mMainSurface, mBlackBgSurface).apply();
    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectBorder(grandchildBounds, childColor);
        mCapture->expectColor(grandchildBounds, grandchildColor);
    }

    Transaction().hide(grandchildSurface).apply();

    // grandchild is still detached so it will not hide
    {
        mCapture = screenshot();
        mCapture->expectBorder(childBounds, mMainSurfaceColor);
        mCapture->expectBorder(grandchildBounds, childColor);
        mCapture->expectColor(grandchildBounds, grandchildColor);
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"