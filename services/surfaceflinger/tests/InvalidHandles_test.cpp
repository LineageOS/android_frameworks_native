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

#include <binder/Binder.h>

#include <gtest/gtest.h>

#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <ui/Rect.h>
#include "utils/ScreenshotUtils.h"

namespace android {
namespace {

class NotALayer : public BBinder {};

/**
 * For all of these tests we make a SurfaceControl with an invalid layer handle
 * and verify we aren't able to trick SurfaceFlinger.
 */
class InvalidHandleTest : public ::testing::Test {
protected:
    sp<SurfaceComposerClient> mScc;
    sp<SurfaceControl> mNotSc;
    void SetUp() override {
        mScc = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mScc->initCheck());
        mNotSc = makeNotSurfaceControl();
    }

    sp<SurfaceControl> makeNotSurfaceControl() {
        return new SurfaceControl(mScc, new NotALayer(), nullptr, true);
    }
};

TEST_F(InvalidHandleTest, createSurfaceInvalidParentHandle) {
    // The createSurface is scheduled now, we could still get a created surface from createSurface.
    // Should verify if it actually added into current state by checking the screenshot.
    auto notSc = mScc->createSurface(String8("lolcats"), 19, 47, PIXEL_FORMAT_RGBA_8888, 0,
                                     mNotSc->getHandle());
    LayerCaptureArgs args;
    args.layerHandle = notSc->getHandle();
    ScreenCaptureResults captureResults;
    ASSERT_EQ(NAME_NOT_FOUND, ScreenCapture::captureLayers(args, captureResults));
}

TEST_F(InvalidHandleTest, captureLayersInvalidHandle) {
    LayerCaptureArgs args;
    args.layerHandle = mNotSc->getHandle();

    ScreenCaptureResults captureResults;
    ASSERT_EQ(NAME_NOT_FOUND, ScreenCapture::captureLayers(args, captureResults));
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"