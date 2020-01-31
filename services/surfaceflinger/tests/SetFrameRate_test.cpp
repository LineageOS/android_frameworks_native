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

#include <system/window.h>

#include <thread>

#include "LayerTransactionTest.h"

namespace android {

class SetFrameRateTest : public LayerTransactionTest {
protected:
    void TearDown() {
        mLayer = nullptr;
        LayerTransactionTest::TearDown();
    }

    void CreateLayer(uint32_t layerType) {
        ASSERT_EQ(nullptr, mLayer.get());
        mLayerType = layerType;
        ASSERT_NO_FATAL_FAILURE(mLayer = createLayer("TestLayer", mLayerWidth, mLayerHeight,
                                                     /*flags=*/mLayerType));
        ASSERT_NE(nullptr, mLayer.get());
    }

    void PostBuffers(const Color& color) {
        auto startTime = systemTime();
        while (systemTime() - startTime < s2ns(1)) {
            ASSERT_NO_FATAL_FAILURE(
                    fillLayerColor(mLayerType, mLayer, color, mLayerWidth, mLayerHeight));
            std::this_thread::sleep_for(100ms);
        }
    }

    const int mLayerWidth = 32;
    const int mLayerHeight = 32;
    sp<SurfaceControl> mLayer;
    uint32_t mLayerType;
};

TEST_F(SetFrameRateTest, BufferQueueLayerSetFrameRate) {
    CreateLayer(ISurfaceComposerClient::eFXSurfaceBufferQueue);
    native_window_set_frame_rate(mLayer->getSurface().get(), 100.f,
                                 ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT);
    ASSERT_NO_FATAL_FAILURE(PostBuffers(Color::RED));
    Transaction()
            .setFrameRate(mLayer, 200.f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT)
            .apply();
    ASSERT_NO_FATAL_FAILURE(PostBuffers(Color::RED));
    native_window_set_frame_rate(mLayer->getSurface().get(), 300.f,
                                 ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT);
    ASSERT_NO_FATAL_FAILURE(PostBuffers(Color::RED));
}

TEST_F(SetFrameRateTest, BufferStateLayerSetFrameRate) {
    CreateLayer(ISurfaceComposerClient::eFXSurfaceBufferState);
    Transaction()
            .setFrameRate(mLayer, 400.f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT)
            .apply();
    ASSERT_NO_FATAL_FAILURE(PostBuffers(Color::GREEN));
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"