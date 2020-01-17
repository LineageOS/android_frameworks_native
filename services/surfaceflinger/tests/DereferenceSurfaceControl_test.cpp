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

class DereferenceSurfaceControlTest : public LayerTransactionTest {
protected:
    void SetUp() override {
        LayerTransactionTest::SetUp();
        bgLayer = createLayer("BG layer", 20, 20);
        fillBufferQueueLayerColor(bgLayer, Color::RED, 20, 20);
        fgLayer = createLayer("FG layer", 20, 20);
        fillBufferQueueLayerColor(fgLayer, Color::BLUE, 20, 20);
        Transaction().setLayer(fgLayer, mLayerZBase + 1).apply();
        {
            SCOPED_TRACE("before anything");
            auto shot = screenshot();
            shot->expectColor(Rect(0, 0, 20, 20), Color::BLUE);
        }
    }
    void TearDown() override {
        LayerTransactionTest::TearDown();
        bgLayer = 0;
        fgLayer = 0;
    }

    sp<SurfaceControl> bgLayer;
    sp<SurfaceControl> fgLayer;
};

TEST_F(DereferenceSurfaceControlTest, LayerNotInTransaction) {
    fgLayer = nullptr;
    {
        SCOPED_TRACE("after setting null");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 20, 20), Color::RED);
    }
}

TEST_F(DereferenceSurfaceControlTest, LayerInTransaction) {
    auto transaction = Transaction().show(fgLayer);
    fgLayer = nullptr;
    {
        SCOPED_TRACE("after setting null");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 20, 20), Color::BLUE);
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
