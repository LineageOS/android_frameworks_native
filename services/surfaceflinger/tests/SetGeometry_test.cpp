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

class SetGeometryTest : public LayerTransactionTest {
protected:
    void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        mLayer = createLayer("Layer", mLayerWidth, mLayerHeight);
        fillBufferQueueLayerColor(mLayer, Color::RED, mLayerWidth, mLayerHeight);
        asTransaction([&](Transaction& t) { t.setLayer(mLayer, INT32_MAX - 1).show(mLayer); });

        {
            SCOPED_TRACE("init");
            ScreenCapture::captureScreen(&sc);
            sc->expectColor(Rect(0, 0, mLayerWidth, mLayerHeight), Color::RED);
            sc->expectBorder(Rect(0, 0, mLayerWidth, mLayerHeight), Color::BLACK);
        }
    }

    void TearDown() {
        LayerTransactionTest::TearDown();
        sc = 0;
        mLayer = 0;
    }

    std::unique_ptr<ScreenCapture> sc;
    sp<SurfaceControl> mLayer;
    const int mLayerWidth = 100;
    const int mLayerHeight = 200;
};

TEST_F(SetGeometryTest, SourceAtZeroNoScale) {
    Rect source = Rect(0, 0, 30, 30);
    Rect dest = Rect(60, 60, 90, 90);
    Transaction{}.setGeometry(mLayer, source, dest, 0).apply();

    {
        SCOPED_TRACE("geometry applied");
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(dest, Color::RED);
        sc->expectBorder(dest, Color::BLACK);
    }
}

TEST_F(SetGeometryTest, SourceNotAtZero) {
    Rect source = Rect(40, 40, 70, 70);
    Rect dest = Rect(60, 60, 90, 90);
    Transaction{}.setGeometry(mLayer, source, dest, 0).apply();

    {
        SCOPED_TRACE("geometry applied");
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(dest, Color::RED);
        sc->expectBorder(dest, Color::BLACK);
    }
}

TEST_F(SetGeometryTest, Scale) {
    Rect source = Rect(0, 0, 100, 200);
    Rect dest = Rect(0, 0, 200, 400);
    Transaction{}.setGeometry(mLayer, source, dest, 0).apply();

    {
        SCOPED_TRACE("Scaled by 2");
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(dest, Color::RED);
        sc->expectBorder(dest, Color::BLACK);
    }

    dest = Rect(0, 0, 50, 100);
    Transaction{}.setGeometry(mLayer, source, dest, 0).apply();
    {
        SCOPED_TRACE("Scaled by .5");
        ScreenCapture::captureScreen(&sc);
        sc->expectColor(dest, Color::RED);
        sc->expectBorder(dest, Color::BLACK);
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
