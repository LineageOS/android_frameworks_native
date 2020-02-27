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
#include "TransactionTestHarnesses.h"

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

class LayerTypeTransactionTest : public LayerTypeTransactionHarness,
                                 public ::testing::WithParamInterface<uint32_t> {
public:
    LayerTypeTransactionTest() : LayerTypeTransactionHarness(GetParam()) {}
};

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

INSTANTIATE_TEST_CASE_P(
        LayerTypeTransactionTests, LayerTypeTransactionTest,
        ::testing::Values(static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferQueue),
                          static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferState)));

TEST_P(LayerTypeTransactionTest, SetRelativeZNegative) {
    sp<SurfaceControl> parent =
            LayerTransactionTest::createLayer("Parent", 0 /* buffer width */, 0 /* buffer height */,
                                              ISurfaceComposerClient::eFXSurfaceContainer);
    Transaction().setCrop_legacy(parent, Rect(0, 0, mDisplayWidth, mDisplayHeight)).apply();
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    sp<SurfaceControl> layerB;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerB = createLayer("test B", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerB, Color::BLUE, 32, 32));

    Transaction().reparent(layerB, parent->getHandle()).apply();

    // layerR = mLayerZBase, layerG = layerR - 1, layerB = -2
    Transaction().setRelativeLayer(layerG, layerR->getHandle(), -1).setLayer(layerB, -2).apply();

    std::unique_ptr<ScreenCapture> screenshot;
    // only layerB is in this range
    sp<IBinder> parentHandle = parent->getHandle();
    ScreenCapture::captureLayers(&screenshot, parentHandle, Rect(0, 0, 32, 32));
    screenshot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
}

TEST_P(LayerTypeTransactionTest, SetLayerAndRelative) {
    sp<SurfaceControl> parent =
            LayerTransactionTest::createLayer("Parent", 0 /* buffer width */, 0 /* buffer height */,
                                              ISurfaceComposerClient::eFXSurfaceEffect);

    sp<SurfaceControl> childLayer;
    ASSERT_NO_FATAL_FAILURE(
            childLayer = LayerTransactionTest::createLayer("childLayer", 0 /* buffer width */,
                                                           0 /* buffer height */,
                                                           ISurfaceComposerClient::eFXSurfaceEffect,
                                                           parent.get()));
    Transaction()
            .setColor(childLayer, half3{1.0f, 0.0f, 0.0f})
            .setColor(parent, half3{0.0f, 0.0f, 0.0f})
            .show(childLayer)
            .show(parent)
            .setCrop_legacy(parent, Rect(0, 0, mDisplayWidth, mDisplayHeight))
            .setCrop_legacy(childLayer, Rect(0, 0, 20, 30))
            .apply();

    Transaction()
            .setRelativeLayer(childLayer, parent->getHandle(), -1)
            .setLayer(childLayer, 1)
            .apply();

    {
        SCOPED_TRACE("setLayer above");
        // Set layer should get applied and place the child above.
        std::unique_ptr<ScreenCapture> screenshot;
        ScreenCapture::captureScreen(&screenshot);
        screenshot->expectColor(Rect(0, 0, 20, 30), Color::RED);
    }

    Transaction()
            .setLayer(childLayer, 1)
            .setRelativeLayer(childLayer, parent->getHandle(), -1)
            .apply();

    {
        SCOPED_TRACE("setRelative below");
        // Set relative layer should get applied and place the child below.
        std::unique_ptr<ScreenCapture> screenshot;
        ScreenCapture::captureScreen(&screenshot);
        screenshot->expectColor(Rect(0, 0, 20, 30), Color::BLACK);
    }
}

TEST_P(LayerTypeTransactionTest, HideRelativeParentHidesLayer) {
    sp<SurfaceControl> parent =
            LayerTransactionTest::createLayer("Parent", 0 /* buffer width */, 0 /* buffer height */,
                                              ISurfaceComposerClient::eFXSurfaceEffect);
    sp<SurfaceControl> relativeParent =
            LayerTransactionTest::createLayer("RelativeParent", 0 /* buffer width */,
                                              0 /* buffer height */,
                                              ISurfaceComposerClient::eFXSurfaceEffect);

    sp<SurfaceControl> childLayer;
    ASSERT_NO_FATAL_FAILURE(
            childLayer = LayerTransactionTest::createLayer("childLayer", 0 /* buffer width */,
                                                           0 /* buffer height */,
                                                           ISurfaceComposerClient::eFXSurfaceEffect,
                                                           parent.get()));
    Transaction()
            .setColor(childLayer, half3{1.0f, 0.0f, 0.0f})
            .setColor(parent, half3{0.0f, 0.0f, 0.0f})
            .setColor(relativeParent, half3{0.0f, 1.0f, 0.0f})
            .show(childLayer)
            .show(parent)
            .show(relativeParent)
            .setLayer(parent, mLayerZBase - 1)
            .setLayer(relativeParent, mLayerZBase)
            .apply();

    Transaction().setRelativeLayer(childLayer, relativeParent->getHandle(), 1).apply();

    {
        SCOPED_TRACE("setLayer above");
        // Set layer should get applied and place the child above.
        std::unique_ptr<ScreenCapture> screenshot;
        ScreenCapture::captureScreen(&screenshot);
        screenshot->expectColor(Rect(0, 0, 20, 30), Color::RED);
    }

    Transaction().hide(relativeParent).apply();

    {
        SCOPED_TRACE("hide relative parent");
        // The relative should no longer be visible.
        std::unique_ptr<ScreenCapture> screenshot;
        ScreenCapture::captureScreen(&screenshot);
        screenshot->expectColor(Rect(0, 0, 20, 30), Color::BLACK);
    }
}

TEST_P(LayerTypeTransactionTest, SetFlagsSecure) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    sp<ISurfaceComposer> composer = ComposerService::getComposerService();
    sp<GraphicBuffer> outBuffer;
    Transaction()
            .setFlags(layer, layer_state_t::eLayerSecure, layer_state_t::eLayerSecure)
            .apply(true);
    ASSERT_EQ(PERMISSION_DENIED,
              composer->captureScreen(mDisplay, &outBuffer, Rect(), 0, 0, false));

    Transaction().setFlags(layer, 0, layer_state_t::eLayerSecure).apply(true);
    ASSERT_EQ(NO_ERROR, composer->captureScreen(mDisplay, &outBuffer, Rect(), 0, 0, false));
}
TEST_P(LayerTypeTransactionTest, RefreshRateIsInitialized) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));

    sp<IBinder> handle = layer->getHandle();
    ASSERT_TRUE(handle != nullptr);

    FrameStats frameStats;
    mClient->getLayerFrameStats(handle, &frameStats);

    ASSERT_GT(frameStats.refreshPeriodNano, static_cast<nsecs_t>(0));
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
