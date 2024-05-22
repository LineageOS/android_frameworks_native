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

#include <common/FlagManager.h>
#include <ui/DisplayState.h>

#include "LayerTransactionTest.h"
#include "gui/SurfaceComposerClient.h"
#include "ui/DisplayId.h"

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

class MultiDisplayLayerBoundsTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        ASSERT_FALSE(ids.empty());
        mMainDisplayId = ids.front();
        mMainDisplay = SurfaceComposerClient::getPhysicalDisplayToken(mMainDisplayId);
        SurfaceComposerClient::getDisplayState(mMainDisplay, &mMainDisplayState);
        SurfaceComposerClient::getActiveDisplayMode(mMainDisplay, &mMainDisplayMode);

        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&mProducer, &consumer);
        consumer->setConsumerName(String8("Virtual disp consumer"));
        consumer->setDefaultBufferSize(mMainDisplayMode.resolution.getWidth(),
                                       mMainDisplayMode.resolution.getHeight());
    }

    virtual void TearDown() {
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::destroyVirtualDisplay(mVirtualDisplay));
        LayerTransactionTest::TearDown();
        mColorLayer = 0;
    }

    void createDisplay(const ui::Size& layerStackSize, ui::LayerStack layerStack) {
        static const std::string kDisplayName("VirtualDisplay");
        mVirtualDisplay =
                SurfaceComposerClient::createVirtualDisplay(kDisplayName, false /*isSecure*/);
        asTransaction([&](Transaction& t) {
            t.setDisplaySurface(mVirtualDisplay, mProducer);
            t.setDisplayLayerStack(mVirtualDisplay, layerStack);
            t.setDisplayProjection(mVirtualDisplay, mMainDisplayState.orientation,
                                   Rect(layerStackSize), Rect(mMainDisplayMode.resolution));
        });
    }

    void createColorLayer(ui::LayerStack layerStack) {
        mColorLayer =
                createSurface(mClient, "ColorLayer", 0 /* buffer width */, 0 /* buffer height */,
                              PIXEL_FORMAT_RGBA_8888, ISurfaceComposerClient::eFXSurfaceEffect);
        ASSERT_TRUE(mColorLayer != nullptr);
        ASSERT_TRUE(mColorLayer->isValid());
        asTransaction([&](Transaction& t) {
            t.setLayerStack(mColorLayer, layerStack);
            t.setCrop(mColorLayer, Rect(0, 0, 30, 40));
            t.setLayer(mColorLayer, INT32_MAX - 2);
            t.setColor(mColorLayer,
                       half3{mExpectedColor.r / 255.0f, mExpectedColor.g / 255.0f,
                             mExpectedColor.b / 255.0f});
            t.show(mColorLayer);
        });
    }

    ui::DisplayState mMainDisplayState;
    ui::DisplayMode mMainDisplayMode;
    sp<IBinder> mMainDisplay;
    PhysicalDisplayId mMainDisplayId;
    sp<IBinder> mVirtualDisplay;
    sp<IGraphicBufferProducer> mProducer;
    sp<SurfaceControl> mColorLayer;
    Color mExpectedColor = {63, 63, 195, 255};
};

TEST_F(MultiDisplayLayerBoundsTest, RenderLayerInVirtualDisplay) {
    constexpr ui::LayerStack kLayerStack{1u};
    createDisplay(mMainDisplayState.layerStackSpaceRect, kLayerStack);
    createColorLayer(kLayerStack);

    asTransaction([&](Transaction& t) { t.setPosition(mColorLayer, 10, 10); });

    // Verify color layer does not render on main display.
    std::unique_ptr<ScreenCapture> sc;
    ScreenCapture::captureScreen(&sc, mMainDisplay);
    sc->expectColor(Rect(10, 10, 40, 50), {0, 0, 0, 255});
    sc->expectColor(Rect(0, 0, 9, 9), {0, 0, 0, 255});

    // Verify color layer renders correctly on virtual display.
    ScreenCapture::captureScreen(&sc, mVirtualDisplay);
    sc->expectColor(Rect(10, 10, 40, 50), mExpectedColor);
    sc->expectColor(Rect(1, 1, 9, 9), {0, 0, 0, 255});
}

TEST_F(MultiDisplayLayerBoundsTest, RenderLayerInMirroredVirtualDisplay) {
    // Create a display and set its layer stack to the main display's layer stack so
    // the contents of the main display are mirrored on to the virtual display.

    // Assumption here is that the new mirrored display has the same layer stack rect as the
    // primary display that it is mirroring.
    createDisplay(mMainDisplayState.layerStackSpaceRect, ui::DEFAULT_LAYER_STACK);
    createColorLayer(ui::DEFAULT_LAYER_STACK);

    sp<SurfaceControl> mirrorSc =
            SurfaceComposerClient::getDefault()->mirrorDisplay(mMainDisplayId);

    asTransaction([&](Transaction& t) { t.setPosition(mColorLayer, 10, 10); });

    // Verify color layer renders correctly on main display and it is mirrored on the
    // virtual display.
    std::unique_ptr<ScreenCapture> sc;
    ScreenCapture::captureScreen(&sc, mMainDisplay);
    sc->expectColor(Rect(10, 10, 40, 50), mExpectedColor);
    sc->expectColor(Rect(0, 0, 9, 9), {0, 0, 0, 255});

    ScreenCapture::captureScreen(&sc, mVirtualDisplay);
    sc->expectColor(Rect(10, 10, 40, 50), mExpectedColor);
    sc->expectColor(Rect(0, 0, 9, 9), {0, 0, 0, 255});
}

TEST_F(MultiDisplayLayerBoundsTest, RenderLayerWithPromisedFenceInMirroredVirtualDisplay) {
    // Create a display and use a unique layerstack ID for mirrorDisplay() so
    // the contents of the main display are mirrored on to the virtual display.

    // A unique layerstack ID must be used because sharing the same layerFE
    // with more than one display is unsupported. A unique layerstack ensures
    // that a different layerFE is used between displays.
    constexpr ui::LayerStack layerStack{77687666}; // ASCII for MDLB (MultiDisplayLayerBounds)
    createDisplay(mMainDisplayState.layerStackSpaceRect, layerStack);
    createColorLayer(ui::DEFAULT_LAYER_STACK);

    sp<SurfaceControl> mirrorSc =
            SurfaceComposerClient::getDefault()->mirrorDisplay(mMainDisplayId);

    asTransaction([&](Transaction& t) {
        t.setPosition(mColorLayer, 10, 10);
        t.setLayerStack(mirrorSc, layerStack);
    });

    // Verify color layer renders correctly on main display and it is mirrored on the
    // virtual display.
    std::unique_ptr<ScreenCapture> sc;
    ScreenCapture::captureScreen(&sc, mMainDisplay);
    sc->expectColor(Rect(10, 10, 40, 50), mExpectedColor);
    sc->expectColor(Rect(0, 0, 9, 9), {0, 0, 0, 255});

    ScreenCapture::captureScreen(&sc, mVirtualDisplay);
    sc->expectColor(Rect(10, 10, 40, 50), mExpectedColor);
    sc->expectColor(Rect(0, 0, 9, 9), {0, 0, 0, 255});
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
