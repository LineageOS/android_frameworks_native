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

#include <private/android_filesystem_config.h>

#include "LayerTransactionTest.h"

namespace android {

class ScreenCaptureTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        const auto display = SurfaceComposerClient::getInternalDisplayToken();
        ASSERT_FALSE(display == nullptr);

        ui::DisplayMode mode;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayMode(display, &mode));
        const ui::Size& resolution = mode.resolution;

        // Background surface
        mBGSurfaceControl = createLayer(String8("BG Test Surface"), resolution.getWidth(),
                                        resolution.getHeight(), 0);
        ASSERT_TRUE(mBGSurfaceControl != nullptr);
        ASSERT_TRUE(mBGSurfaceControl->isValid());
        TransactionUtils::fillSurfaceRGBA8(mBGSurfaceControl, 63, 63, 195);

        // Foreground surface
        mFGSurfaceControl = createLayer(String8("FG Test Surface"), 64, 64, 0);

        ASSERT_TRUE(mFGSurfaceControl != nullptr);
        ASSERT_TRUE(mFGSurfaceControl->isValid());

        TransactionUtils::fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);

        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, 0);

            t.setLayer(mBGSurfaceControl, INT32_MAX - 2).show(mBGSurfaceControl);

            t.setLayer(mFGSurfaceControl, INT32_MAX - 1)
                    .setPosition(mFGSurfaceControl, 64, 64)
                    .show(mFGSurfaceControl);
        });
    }

    virtual void TearDown() {
        LayerTransactionTest::TearDown();
        mBGSurfaceControl = 0;
        mFGSurfaceControl = 0;
    }

    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mFGSurfaceControl;
    std::unique_ptr<ScreenCapture> mCapture;
};

TEST_F(ScreenCaptureTest, SetFlagsSecureEUidSystem) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32,
                                ISurfaceComposerClient::eSecure |
                                        ISurfaceComposerClient::eFXSurfaceBufferQueue));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    Transaction().show(layer).setLayer(layer, INT32_MAX).apply(true);

    ASSERT_EQ(PERMISSION_DENIED, ScreenCapture::captureDisplay(mCaptureArgs, mCaptureResults));

    UIDFaker f(AID_SYSTEM);

    // By default the system can capture screenshots with secure layers but they
    // will be blacked out
    ASSERT_EQ(NO_ERROR, ScreenCapture::captureDisplay(mCaptureArgs, mCaptureResults));

    {
        SCOPED_TRACE("as system");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    // Here we pass captureSecureLayers = true and since we are AID_SYSTEM we should be able
    // to receive them...we are expected to take care with the results.
    DisplayCaptureArgs args;
    args.displayToken = mDisplay;
    args.captureSecureLayers = true;
    ASSERT_EQ(NO_ERROR, ScreenCapture::captureDisplay(args, mCaptureResults));
    ASSERT_TRUE(mCaptureResults.capturedSecureLayers);
    ScreenCapture sc(mCaptureResults.buffer);
    sc.expectColor(Rect(0, 0, 32, 32), Color::RED);
}

TEST_F(ScreenCaptureTest, CaptureChildSetParentFlagsSecureEUidSystem) {
    sp<SurfaceControl> parentLayer;
    ASSERT_NO_FATAL_FAILURE(
            parentLayer = createLayer("parent-test", 32, 32,
                                      ISurfaceComposerClient::eSecure |
                                              ISurfaceComposerClient::eFXSurfaceBufferQueue));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(parentLayer, Color::RED, 32, 32));

    sp<SurfaceControl> childLayer;
    ASSERT_NO_FATAL_FAILURE(childLayer = createLayer("child-test", 10, 10,
                                                     ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                     parentLayer.get()));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(childLayer, Color::BLUE, 10, 10));

    Transaction().show(parentLayer).setLayer(parentLayer, INT32_MAX).show(childLayer).apply(true);

    UIDFaker f(AID_SYSTEM);

    {
        SCOPED_TRACE("as system");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 10, 10), Color::BLACK);
    }

    // Here we pass captureSecureLayers = true and since we are AID_SYSTEM we should be able
    // to receive them...we are expected to take care with the results.
    DisplayCaptureArgs args;
    args.displayToken = mDisplay;
    args.captureSecureLayers = true;
    ASSERT_EQ(NO_ERROR, ScreenCapture::captureDisplay(args, mCaptureResults));
    ASSERT_TRUE(mCaptureResults.capturedSecureLayers);
    ScreenCapture sc(mCaptureResults.buffer);
    sc.expectColor(Rect(0, 0, 10, 10), Color::BLUE);
}

TEST_F(ScreenCaptureTest, CaptureSingleLayer) {
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = mBGSurfaceControl->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectBGColor(0, 0);
    // Doesn't capture FG layer which is at 64, 64
    mCapture->expectBGColor(64, 64);
}

TEST_F(ScreenCaptureTest, CaptureLayerWithChild) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().show(child).apply(true);

    // Captures mFGSurfaceControl layer and its child.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = mFGSurfaceControl->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureLayerChildOnly) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().show(child).apply(true);

    // Captures mFGSurfaceControl's child
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = fgHandle;
    captureArgs.childrenOnly = true;
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->checkPixel(10, 10, 0, 0, 0);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureLayerExclude) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);
    sp<SurfaceControl> child2 = createSurface(mClient, "Child surface", 10, 10,
                                              PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child2, 200, 0, 200);

    SurfaceComposerClient::Transaction()
            .show(child)
            .show(child2)
            .setLayer(child, 1)
            .setLayer(child2, 2)
            .apply(true);

    // Child2 would be visible but its excluded, so we should see child1 color instead.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = fgHandle;
    captureArgs.childrenOnly = true;
    captureArgs.excludeHandles = {child2->getHandle()};
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->checkPixel(10, 10, 0, 0, 0);
    mCapture->checkPixel(0, 0, 200, 200, 200);
}

// Like the last test but verifies that children are also exclude.
TEST_F(ScreenCaptureTest, CaptureLayerExcludeTree) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);
    sp<SurfaceControl> child2 = createSurface(mClient, "Child surface", 10, 10,
                                              PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child2, 200, 0, 200);
    sp<SurfaceControl> child3 = createSurface(mClient, "Child surface", 10, 10,
                                              PIXEL_FORMAT_RGBA_8888, 0, child2.get());
    TransactionUtils::fillSurfaceRGBA8(child2, 200, 0, 200);

    SurfaceComposerClient::Transaction()
            .show(child)
            .show(child2)
            .show(child3)
            .setLayer(child, 1)
            .setLayer(child2, 2)
            .apply(true);

    // Child2 would be visible but its excluded, so we should see child1 color instead.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = fgHandle;
    captureArgs.childrenOnly = true;
    captureArgs.excludeHandles = {child2->getHandle()};
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->checkPixel(10, 10, 0, 0, 0);
    mCapture->checkPixel(0, 0, 200, 200, 200);
}

TEST_F(ScreenCaptureTest, CaptureTransparent) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());

    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().show(child).apply(true);

    // Captures child
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = child->getHandle();
    captureArgs.sourceCrop = {0, 0, 10, 20};
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 9, 9), {200, 200, 200, 255});
    // Area outside of child's bounds is transparent.
    mCapture->expectColor(Rect(0, 10, 9, 19), {0, 0, 0, 0});
}

TEST_F(ScreenCaptureTest, DontCaptureRelativeOutsideTree) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    ASSERT_NE(nullptr, child.get()) << "failed to create surface";
    sp<SurfaceControl> relative = createLayer(String8("Relative surface"), 10, 10, 0);
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);
    TransactionUtils::fillSurfaceRGBA8(relative, 100, 100, 100);

    SurfaceComposerClient::Transaction()
            .show(child)
            // Set relative layer above fg layer so should be shown above when computing all layers.
            .setRelativeLayer(relative, mFGSurfaceControl, 1)
            .show(relative)
            .apply(true);

    // Captures mFGSurfaceControl layer and its child. Relative layer shouldn't be captured.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = mFGSurfaceControl->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureRelativeInTree) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    sp<SurfaceControl> relative = createSurface(mClient, "Relative surface", 10, 10,
                                                PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);
    TransactionUtils::fillSurfaceRGBA8(relative, 100, 100, 100);

    SurfaceComposerClient::Transaction()
            .show(child)
            // Set relative layer below fg layer but relative to child layer so it should be shown
            // above child layer.
            .setLayer(relative, -1)
            .setRelativeLayer(relative, child, 1)
            .show(relative)
            .apply(true);

    // Captures mFGSurfaceControl layer and its children. Relative layer is a child of fg so its
    // relative value should be taken into account, placing it above child layer.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = mFGSurfaceControl->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectFGColor(10, 10);
    // Relative layer is showing on top of child layer
    mCapture->expectColor(Rect(0, 0, 9, 9), {100, 100, 100, 255});
}

TEST_F(ScreenCaptureTest, CaptureBoundlessLayerWithSourceCrop) {
    sp<SurfaceControl> child = createColorLayer("Child layer", Color::RED, mFGSurfaceControl.get());
    SurfaceComposerClient::Transaction().show(child).apply(true);

    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = child->getHandle();
    captureArgs.sourceCrop = {0, 0, 10, 10};
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect(0, 0, 9, 9), Color::RED);
}

TEST_F(ScreenCaptureTest, CaptureBoundedLayerWithoutSourceCrop) {
    sp<SurfaceControl> child = createColorLayer("Child layer", Color::RED, mFGSurfaceControl.get());
    Rect layerCrop(0, 0, 10, 10);
    SurfaceComposerClient::Transaction().setCrop(child, layerCrop).show(child).apply(true);

    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = child->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    mCapture->expectColor(Rect(0, 0, 9, 9), Color::RED);
}

TEST_F(ScreenCaptureTest, CaptureBoundlessLayerWithoutSourceCropFails) {
    sp<SurfaceControl> child = createColorLayer("Child layer", Color::RED, mFGSurfaceControl.get());
    SurfaceComposerClient::Transaction().show(child).apply(true);

    LayerCaptureArgs args;
    args.layerHandle = child->getHandle();

    ScreenCaptureResults captureResults;
    ASSERT_EQ(BAD_VALUE, ScreenCapture::captureLayers(args, captureResults));
}

TEST_F(ScreenCaptureTest, CaptureBufferLayerWithoutBufferFails) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    SurfaceComposerClient::Transaction().show(child).apply(true);
    sp<GraphicBuffer> outBuffer;

    LayerCaptureArgs args;
    args.layerHandle = child->getHandle();
    args.childrenOnly = false;

    ScreenCaptureResults captureResults;
    ASSERT_EQ(BAD_VALUE, ScreenCapture::captureLayers(args, captureResults));

    TransactionUtils::fillSurfaceRGBA8(child, Color::RED);
    SurfaceComposerClient::Transaction().apply(true);
    ASSERT_EQ(NO_ERROR, ScreenCapture::captureLayers(args, captureResults));
    ScreenCapture sc(captureResults.buffer);
    sc.expectColor(Rect(0, 0, 9, 9), Color::RED);
}

TEST_F(ScreenCaptureTest, CaptureLayerWithGrandchild) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);

    sp<SurfaceControl> grandchild = createSurface(mClient, "Grandchild surface", 5, 5,
                                                  PIXEL_FORMAT_RGBA_8888, 0, child.get());

    TransactionUtils::fillSurfaceRGBA8(grandchild, 50, 50, 50);
    SurfaceComposerClient::Transaction()
            .show(child)
            .setPosition(grandchild, 5, 5)
            .show(grandchild)
            .apply(true);

    // Captures mFGSurfaceControl, its child, and the grandchild.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = mFGSurfaceControl->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
    mCapture->checkPixel(5, 5, 50, 50, 50);
}

TEST_F(ScreenCaptureTest, CaptureChildOnly) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().setPosition(child, 5, 5).show(child).apply(true);

    // Captures only the child layer, and not the parent.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = child->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectChildColor(0, 0);
    mCapture->expectChildColor(9, 9);
}

TEST_F(ScreenCaptureTest, CaptureGrandchildOnly) {
    sp<SurfaceControl> child = createSurface(mClient, "Child surface", 10, 10,
                                             PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    TransactionUtils::fillSurfaceRGBA8(child, 200, 200, 200);
    auto childHandle = child->getHandle();

    sp<SurfaceControl> grandchild = createSurface(mClient, "Grandchild surface", 5, 5,
                                                  PIXEL_FORMAT_RGBA_8888, 0, child.get());
    TransactionUtils::fillSurfaceRGBA8(grandchild, 50, 50, 50);

    SurfaceComposerClient::Transaction()
            .show(child)
            .setPosition(grandchild, 5, 5)
            .show(grandchild)
            .apply(true);

    // Captures only the grandchild.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = grandchild->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->checkPixel(0, 0, 50, 50, 50);
    mCapture->checkPixel(4, 4, 50, 50, 50);
}

TEST_F(ScreenCaptureTest, CaptureCrop) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);
    sp<SurfaceControl> blueLayer = createSurface(mClient, "Blue surface", 30, 30,
                                                 PIXEL_FORMAT_RGBA_8888, 0, redLayer.get());

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(blueLayer, Color::BLUE, 30, 30));

    SurfaceComposerClient::Transaction()
            .setLayer(redLayer, INT32_MAX - 1)
            .show(redLayer)
            .show(blueLayer)
            .apply(true);

    // Capturing full screen should have both red and blue are visible.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = redLayer->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 29, 29), Color::BLUE);
    // red area below the blue area
    mCapture->expectColor(Rect(0, 30, 59, 59), Color::RED);
    // red area to the right of the blue area
    mCapture->expectColor(Rect(30, 0, 59, 59), Color::RED);

    captureArgs.sourceCrop = {0, 0, 30, 30};
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    // Capturing the cropped screen, cropping out the shown red area, should leave only the blue
    // area visible.
    mCapture->expectColor(Rect(0, 0, 29, 29), Color::BLUE);
    mCapture->checkPixel(30, 30, 0, 0, 0);
}

TEST_F(ScreenCaptureTest, CaptureSize) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);
    sp<SurfaceControl> blueLayer = createSurface(mClient, "Blue surface", 30, 30,
                                                 PIXEL_FORMAT_RGBA_8888, 0, redLayer.get());

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(blueLayer, Color::BLUE, 30, 30));

    SurfaceComposerClient::Transaction()
            .setLayer(redLayer, INT32_MAX - 1)
            .show(redLayer)
            .show(blueLayer)
            .apply(true);

    // Capturing full screen should have both red and blue are visible.
    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = redLayer->getHandle();
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 29, 29), Color::BLUE);
    // red area below the blue area
    mCapture->expectColor(Rect(0, 30, 59, 59), Color::RED);
    // red area to the right of the blue area
    mCapture->expectColor(Rect(30, 0, 59, 59), Color::RED);

    captureArgs.frameScaleX = 0.5f;
    captureArgs.frameScaleY = 0.5f;

    ScreenCapture::captureLayers(&mCapture, captureArgs);
    // Capturing the downsized area (30x30) should leave both red and blue but in a smaller area.
    mCapture->expectColor(Rect(0, 0, 14, 14), Color::BLUE);
    // red area below the blue area
    mCapture->expectColor(Rect(0, 15, 29, 29), Color::RED);
    // red area to the right of the blue area
    mCapture->expectColor(Rect(15, 0, 29, 29), Color::RED);
    mCapture->checkPixel(30, 30, 0, 0, 0);
}

TEST_F(ScreenCaptureTest, CaptureInvalidLayer) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));

    auto redLayerHandle = redLayer->getHandle();
    Transaction().reparent(redLayer, nullptr).apply();
    redLayer.clear();
    SurfaceComposerClient::Transaction().apply(true);

    LayerCaptureArgs args;
    args.layerHandle = redLayerHandle;

    ScreenCaptureResults captureResults;
    // Layer was deleted so captureLayers should fail with NAME_NOT_FOUND
    ASSERT_EQ(NAME_NOT_FOUND, ScreenCapture::captureLayers(args, captureResults));
}

TEST_F(ScreenCaptureTest, CaputureSecureLayer) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);
    sp<SurfaceControl> secureLayer =
            createLayer(String8("Secure surface"), 30, 30,
                        ISurfaceComposerClient::eSecure |
                                ISurfaceComposerClient::eFXSurfaceBufferQueue,
                        redLayer.get());
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(secureLayer, Color::BLUE, 30, 30));

    auto redLayerHandle = redLayer->getHandle();
    Transaction()
            .show(redLayer)
            .show(secureLayer)
            .setLayerStack(redLayer, 0)
            .setLayer(redLayer, INT32_MAX)
            .apply();

    LayerCaptureArgs args;
    args.layerHandle = redLayerHandle;
    args.childrenOnly = false;
    ScreenCaptureResults captureResults;

    // Call from outside system with secure layers will result in permission denied
    ASSERT_EQ(PERMISSION_DENIED, ScreenCapture::captureLayers(args, captureResults));

    UIDFaker f(AID_SYSTEM);

    // From system request, only red layer will be screenshot since the blue layer is secure.
    // Black will be present where the secure layer is.
    ScreenCapture::captureLayers(&mCapture, args);
    mCapture->expectColor(Rect(0, 0, 30, 30), Color::BLACK);
    mCapture->expectColor(Rect(30, 30, 60, 60), Color::RED);

    // Passing flag secure so the blue layer should be screenshot too.
    args.captureSecureLayers = true;
    ScreenCapture::captureLayers(&mCapture, args);
    mCapture->expectColor(Rect(0, 0, 30, 30), Color::BLUE);
    mCapture->expectColor(Rect(30, 30, 60, 60), Color::RED);
}

TEST_F(ScreenCaptureTest, CaptureDisplayWithUid) {
    uid_t fakeUid = 12345;

    DisplayCaptureArgs captureArgs;
    captureArgs.displayToken = mDisplay;

    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test layer", 32, 32,
                                                ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                mBGSurfaceControl.get()));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    Transaction().show(layer).setLayer(layer, INT32_MAX).apply();

    // Make sure red layer with the background layer is screenshot.
    ScreenCapture::captureDisplay(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 32, 32), Color::RED);
    mCapture->expectBorder(Rect(0, 0, 32, 32), {63, 63, 195, 255});

    // From non system uid, can't request screenshot without a specified uid.
    UIDFaker f(fakeUid);
    ASSERT_EQ(PERMISSION_DENIED, ScreenCapture::captureDisplay(captureArgs, mCaptureResults));

    // Make screenshot request with current uid set. No layers were created with the current
    // uid so screenshot will be black.
    captureArgs.uid = fakeUid;
    ScreenCapture::captureDisplay(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    mCapture->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);

    sp<SurfaceControl> layerWithFakeUid;
    // Create a new layer with the current uid
    ASSERT_NO_FATAL_FAILURE(layerWithFakeUid =
                                    createLayer("new test layer", 32, 32,
                                                ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                mBGSurfaceControl.get()));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layerWithFakeUid, Color::GREEN, 32, 32));
    Transaction()
            .show(layerWithFakeUid)
            .setLayer(layerWithFakeUid, INT32_MAX)
            .setPosition(layerWithFakeUid, 128, 128)
            .apply();

    // Screenshot from the fakeUid caller with the uid requested allows the layer
    // with that uid to be screenshotted. Everything else is black
    ScreenCapture::captureDisplay(&mCapture, captureArgs);
    mCapture->expectColor(Rect(128, 128, 160, 160), Color::GREEN);
    mCapture->expectBorder(Rect(128, 128, 160, 160), Color::BLACK);
}

TEST_F(ScreenCaptureTest, CaptureDisplayPrimaryDisplayOnly) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test layer", 0, 0, ISurfaceComposerClient::eFXSurfaceEffect));

    const Color layerColor = Color::RED;
    const Rect bounds = Rect(10, 10, 40, 40);

    Transaction()
            .show(layer)
            .hide(mFGSurfaceControl)
            .setLayerStack(layer, 0)
            .setLayer(layer, INT32_MAX)
            .setColor(layer, {layerColor.r / 255, layerColor.g / 255, layerColor.b / 255})
            .setCrop(layer, bounds)
            .apply();

    DisplayCaptureArgs captureArgs;
    captureArgs.displayToken = mDisplay;

    {
        ScreenCapture::captureDisplay(&mCapture, captureArgs);
        mCapture->expectColor(bounds, layerColor);
        mCapture->expectBorder(bounds, {63, 63, 195, 255});
    }

    Transaction()
            .setFlags(layer, layer_state_t::eLayerSkipScreenshot,
                      layer_state_t::eLayerSkipScreenshot)
            .apply();

    {
        // Can't screenshot test layer since it now has flag
        // eLayerSkipScreenshot
        ScreenCapture::captureDisplay(&mCapture, captureArgs);
        mCapture->expectColor(bounds, {63, 63, 195, 255});
        mCapture->expectBorder(bounds, {63, 63, 195, 255});
    }
}

TEST_F(ScreenCaptureTest, CaptureDisplayChildPrimaryDisplayOnly) {
    sp<SurfaceControl> layer;
    sp<SurfaceControl> childLayer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test layer", 0, 0, ISurfaceComposerClient::eFXSurfaceEffect));
    ASSERT_NO_FATAL_FAILURE(childLayer = createLayer("test layer", 0, 0,
                                                     ISurfaceComposerClient::eFXSurfaceEffect,
                                                     layer.get()));

    const Color layerColor = Color::RED;
    const Color childColor = Color::BLUE;
    const Rect bounds = Rect(10, 10, 40, 40);
    const Rect childBounds = Rect(20, 20, 30, 30);

    Transaction()
            .show(layer)
            .show(childLayer)
            .hide(mFGSurfaceControl)
            .setLayerStack(layer, 0)
            .setLayer(layer, INT32_MAX)
            .setColor(layer, {layerColor.r / 255, layerColor.g / 255, layerColor.b / 255})
            .setColor(childLayer, {childColor.r / 255, childColor.g / 255, childColor.b / 255})
            .setCrop(layer, bounds)
            .setCrop(childLayer, childBounds)
            .apply();

    DisplayCaptureArgs captureArgs;
    captureArgs.displayToken = mDisplay;

    {
        ScreenCapture::captureDisplay(&mCapture, captureArgs);
        mCapture->expectColor(childBounds, childColor);
        mCapture->expectBorder(childBounds, layerColor);
        mCapture->expectBorder(bounds, {63, 63, 195, 255});
    }

    Transaction()
            .setFlags(layer, layer_state_t::eLayerSkipScreenshot,
                      layer_state_t::eLayerSkipScreenshot)
            .apply();

    {
        // Can't screenshot child layer since the parent has the flag
        // eLayerSkipScreenshot
        ScreenCapture::captureDisplay(&mCapture, captureArgs);
        mCapture->expectColor(childBounds, {63, 63, 195, 255});
        mCapture->expectBorder(childBounds, {63, 63, 195, 255});
        mCapture->expectBorder(bounds, {63, 63, 195, 255});
    }
}

TEST_F(ScreenCaptureTest, CaptureLayerWithUid) {
    uid_t fakeUid = 12345;

    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test layer", 32, 32,
                                                ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                mBGSurfaceControl.get()));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    Transaction().show(layer).setLayer(layer, INT32_MAX).apply();

    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = mBGSurfaceControl->getHandle();
    captureArgs.childrenOnly = false;

    // Make sure red layer with the background layer is screenshot.
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 32, 32), Color::RED);
    mCapture->expectBorder(Rect(0, 0, 32, 32), {63, 63, 195, 255});

    // From non system uid, can't request screenshot without a specified uid.
    std::unique_ptr<UIDFaker> uidFaker = std::make_unique<UIDFaker>(fakeUid);

    ASSERT_EQ(PERMISSION_DENIED, ScreenCapture::captureLayers(captureArgs, mCaptureResults));

    // Make screenshot request with current uid set. No layers were created with the current
    // uid so screenshot will be black.
    captureArgs.uid = fakeUid;
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 32, 32), Color::TRANSPARENT);
    mCapture->expectBorder(Rect(0, 0, 32, 32), Color::TRANSPARENT);

    sp<SurfaceControl> layerWithFakeUid;
    // Create a new layer with the current uid
    ASSERT_NO_FATAL_FAILURE(layerWithFakeUid =
                                    createLayer("new test layer", 32, 32,
                                                ISurfaceComposerClient::eFXSurfaceBufferQueue,
                                                mBGSurfaceControl.get()));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layerWithFakeUid, Color::GREEN, 32, 32));
    Transaction()
            .show(layerWithFakeUid)
            .setLayer(layerWithFakeUid, INT32_MAX)
            .setPosition(layerWithFakeUid, 128, 128)
            // reparent a layer that was created with a different uid to the new layer.
            .reparent(layer, layerWithFakeUid)
            .apply();

    // Screenshot from the fakeUid caller with the uid requested allows the layer
    // with that uid to be screenshotted. The child layer is skipped since it was created
    // from a different uid.
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(128, 128, 160, 160), Color::GREEN);
    mCapture->expectBorder(Rect(128, 128, 160, 160), Color::TRANSPARENT);

    // Clear fake calling uid so it's back to system.
    uidFaker = nullptr;
    // Screenshot from the test caller with the uid requested allows the layer
    // with that uid to be screenshotted. The child layer is skipped since it was created
    // from a different uid.
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(128, 128, 160, 160), Color::GREEN);
    mCapture->expectBorder(Rect(128, 128, 160, 160), Color::TRANSPARENT);

    // Screenshot from the fakeUid caller with no uid requested allows everything to be screenshot.
    captureArgs.uid = -1;
    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(128, 128, 160, 160), Color::RED);
    mCapture->expectBorder(Rect(128, 128, 160, 160), {63, 63, 195, 255});
}

TEST_F(ScreenCaptureTest, CaptureWithGrayscale) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test layer", 32, 32,
                                                ISurfaceComposerClient::eFXSurfaceBufferState,
                                                mBGSurfaceControl.get()));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));
    Transaction().show(layer).setLayer(layer, INT32_MAX).apply();

    LayerCaptureArgs captureArgs;
    captureArgs.layerHandle = layer->getHandle();

    ScreenCapture::captureLayers(&mCapture, captureArgs);
    mCapture->expectColor(Rect(0, 0, 32, 32), Color::RED);

    captureArgs.grayscale = true;

    const uint8_t tolerance = 1;

    // Values based on SurfaceFlinger::calculateColorMatrix
    float3 luminance{0.213f, 0.715f, 0.072f};

    ScreenCapture::captureLayers(&mCapture, captureArgs);

    uint8_t expectedColor = luminance.r * 255;
    mCapture->expectColor(Rect(0, 0, 32, 32),
                          Color{expectedColor, expectedColor, expectedColor, 255}, tolerance);

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::BLUE, 32, 32));
    ScreenCapture::captureLayers(&mCapture, captureArgs);

    expectedColor = luminance.b * 255;
    mCapture->expectColor(Rect(0, 0, 32, 32),
                          Color{expectedColor, expectedColor, expectedColor, 255}, tolerance);
}

// In the following tests we verify successful skipping of a parent layer,
// so we use the same verification logic and only change how we mutate
// the parent layer to verify that various properties are ignored.
class ScreenCaptureChildOnlyTest : public ScreenCaptureTest {
public:
    void SetUp() override {
        ScreenCaptureTest::SetUp();

        mChild = createSurface(mClient, "Child surface", 10, 10, PIXEL_FORMAT_RGBA_8888, 0,
                               mFGSurfaceControl.get());
        TransactionUtils::fillSurfaceRGBA8(mChild, 200, 200, 200);

        SurfaceComposerClient::Transaction().show(mChild).apply(true);
    }

    void verify(std::function<void()> verifyStartingState) {
        // Verify starting state before a screenshot is taken.
        verifyStartingState();

        // Verify child layer does not inherit any of the properties of its
        // parent when its screenshot is captured.
        LayerCaptureArgs captureArgs;
        captureArgs.layerHandle = mFGSurfaceControl->getHandle();
        captureArgs.childrenOnly = true;
        ScreenCapture::captureLayers(&mCapture, captureArgs);
        mCapture->checkPixel(10, 10, 0, 0, 0);
        mCapture->expectChildColor(0, 0);

        // Verify all assumptions are still true after the screenshot is taken.
        verifyStartingState();
    }

    std::unique_ptr<ScreenCapture> mCapture;
    sp<SurfaceControl> mChild;
};

// Regression test b/76099859
TEST_F(ScreenCaptureChildOnlyTest, CaptureLayerIgnoresParentVisibility) {
    SurfaceComposerClient::Transaction().hide(mFGSurfaceControl).apply(true);

    // Even though the parent is hidden we should still capture the child.

    // Before and after reparenting, verify child is properly hidden
    // when rendering full-screen.
    verify([&] { screenshot()->expectBGColor(64, 64); });
}

TEST_F(ScreenCaptureChildOnlyTest, CaptureLayerIgnoresParentCrop) {
    SurfaceComposerClient::Transaction().setCrop(mFGSurfaceControl, Rect(0, 0, 1, 1)).apply(true);

    // Even though the parent is cropped out we should still capture the child.

    // Before and after reparenting, verify child is cropped by parent.
    verify([&] { screenshot()->expectBGColor(65, 65); });
}

// Regression test b/124372894
TEST_F(ScreenCaptureChildOnlyTest, CaptureLayerIgnoresTransform) {
    SurfaceComposerClient::Transaction().setMatrix(mFGSurfaceControl, 2, 0, 0, 2).apply(true);

    // We should not inherit the parent scaling.

    // Before and after reparenting, verify child is properly scaled.
    verify([&] { screenshot()->expectChildColor(80, 80); });
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"