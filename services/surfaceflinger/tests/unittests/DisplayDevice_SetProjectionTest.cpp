/*
 * Copyright 2020 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ui/Rotation.h>

namespace android {
namespace {

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

class DisplayDeviceSetProjectionTest : public DisplayTransactionTest {
public:
    static constexpr int32_t DEFAULT_DISPLAY_WIDTH = 1080;  // arbitrary
    static constexpr int32_t DEFAULT_DISPLAY_HEIGHT = 1920; // arbitrary

    static constexpr int32_t TRANSFORM_FLAGS_ROT_0 = 0;
    static constexpr int32_t TRANSFORM_FLAGS_ROT_90 = HAL_TRANSFORM_ROT_90;
    static constexpr int32_t TRANSFORM_FLAGS_ROT_180 = HAL_TRANSFORM_FLIP_H | HAL_TRANSFORM_FLIP_V;
    static constexpr int32_t TRANSFORM_FLAGS_ROT_270 =
            HAL_TRANSFORM_FLIP_H | HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_ROT_90;

    DisplayDeviceSetProjectionTest(ui::Size flingerDisplaySize, ui::Size hardwareDisplaySize,
                                   ui::Rotation physicalOrientation)
          : mFlingerDisplaySize(flingerDisplaySize),
            mHardwareDisplaySize(hardwareDisplaySize),
            mPhysicalOrientation(physicalOrientation),
            mDisplayDevice(createDisplayDevice()) {}

    sp<DisplayDevice> createDisplayDevice() {
        return injectDefaultInternalDisplay([this](FakeDisplayDeviceInjector& injector) {
            injector.setPhysicalOrientation(mPhysicalOrientation);
        });
    }

    ui::Size swapWH(const ui::Size size) const { return ui::Size(size.height, size.width); }

    void setDefaultProjection() {
        // INVALID_RECT pulls from the physical display dimensions.
        mDisplayDevice->setProjection(ui::ROTATION_0, Rect::INVALID_RECT, Rect::INVALID_RECT);
    }

    void setProjectionForRotation0() {
        // A logical rotation of 0 uses the SurfaceFlinger display size
        mDisplayDevice->setProjection(ui::ROTATION_0, Rect(mFlingerDisplaySize),
                                      Rect(mFlingerDisplaySize));
    }

    void setProjectionForRotation90() {
        // A logical rotation of 90 uses the SurfaceFlinger display size with
        // the width/height swapped.
        mDisplayDevice->setProjection(ui::ROTATION_90, Rect(swapWH(mFlingerDisplaySize)),
                                      Rect(swapWH(mFlingerDisplaySize)));
    }

    void setProjectionForRotation180() {
        // A logical rotation of 180 uses the SurfaceFlinger display size
        mDisplayDevice->setProjection(ui::ROTATION_180, Rect(mFlingerDisplaySize),
                                      Rect(mFlingerDisplaySize));
    }

    void setProjectionForRotation270() {
        // A logical rotation of 270 uses the SurfaceFlinger display size with
        // the width/height swapped.
        mDisplayDevice->setProjection(ui::ROTATION_270, Rect(swapWH(mFlingerDisplaySize)),
                                      Rect(swapWH(mFlingerDisplaySize)));
    }

    void expectDefaultState() {
        const auto& compositionState = mDisplayDevice->getCompositionDisplay()->getState();
        EXPECT_EQ(ui::Transform(ui::Transform::toRotationFlags(mPhysicalOrientation),
                                mHardwareDisplaySize.width, mHardwareDisplaySize.height),
                  compositionState.transform);
        EXPECT_EQ(mPhysicalOrientation, compositionState.displaySpace.getOrientation());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.displaySpace.getContent());
        EXPECT_EQ(mHardwareDisplaySize, compositionState.displaySpace.getBounds());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.framebufferSpace.getContent());
        EXPECT_EQ(mHardwareDisplaySize, compositionState.framebufferSpace.getBounds());

        const ui::Size expectedLogicalSize = (mPhysicalOrientation == ui::ROTATION_270 ||
                                              mPhysicalOrientation == ui::ROTATION_90)
                ? swapWH(mHardwareDisplaySize)
                : mHardwareDisplaySize;

        EXPECT_EQ(Rect(expectedLogicalSize), compositionState.orientedDisplaySpace.getContent());
        EXPECT_EQ(expectedLogicalSize, compositionState.orientedDisplaySpace.getBounds());
        EXPECT_EQ(Rect(expectedLogicalSize), compositionState.layerStackSpace.getContent());
        EXPECT_EQ(expectedLogicalSize, compositionState.layerStackSpace.getBounds());

        EXPECT_EQ(false, compositionState.needsFiltering);
    }

    void expectStateForHardwareTransform0() {
        const auto& compositionState = mDisplayDevice->getCompositionDisplay()->getState();
        EXPECT_EQ(ui::Transform(TRANSFORM_FLAGS_ROT_0, mHardwareDisplaySize.width,
                                mHardwareDisplaySize.height),
                  compositionState.transform);
        EXPECT_EQ(ui::ROTATION_0, compositionState.displaySpace.getOrientation());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.displaySpace.getContent());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.orientedDisplaySpace.getContent());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.layerStackSpace.getContent());
        EXPECT_EQ(false, compositionState.needsFiltering);
    }

    void expectStateForHardwareTransform90() {
        const auto& compositionState = mDisplayDevice->getCompositionDisplay()->getState();
        EXPECT_EQ(ui::Transform(TRANSFORM_FLAGS_ROT_90, mHardwareDisplaySize.width,
                                mHardwareDisplaySize.height),
                  compositionState.transform);
        EXPECT_EQ(ui::ROTATION_90, compositionState.displaySpace.getOrientation());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.displaySpace.getContent());
        // For 90, the orientedDisplaySpaceRect and layerStackSpaceRect have the hardware display
        // size width and height swapped
        EXPECT_EQ(Rect(swapWH(mHardwareDisplaySize)),
                  compositionState.orientedDisplaySpace.getContent());
        EXPECT_EQ(Rect(swapWH(mHardwareDisplaySize)),
                  compositionState.layerStackSpace.getContent());
        EXPECT_EQ(false, compositionState.needsFiltering);
    }

    void expectStateForHardwareTransform180() {
        const auto& compositionState = mDisplayDevice->getCompositionDisplay()->getState();
        EXPECT_EQ(ui::Transform(TRANSFORM_FLAGS_ROT_180, mHardwareDisplaySize.width,
                                mHardwareDisplaySize.height),
                  compositionState.transform);
        EXPECT_EQ(ui::ROTATION_180, compositionState.displaySpace.getOrientation());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.orientedDisplaySpace.getContent());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.layerStackSpace.getContent());
        EXPECT_EQ(false, compositionState.needsFiltering);
    }

    void expectStateForHardwareTransform270() {
        const auto& compositionState = mDisplayDevice->getCompositionDisplay()->getState();
        EXPECT_EQ(ui::Transform(TRANSFORM_FLAGS_ROT_270, mHardwareDisplaySize.width,
                                mHardwareDisplaySize.height),
                  compositionState.transform);
        EXPECT_EQ(ui::ROTATION_270, compositionState.displaySpace.getOrientation());
        EXPECT_EQ(Rect(mHardwareDisplaySize), compositionState.displaySpace.getContent());
        // For 270, the orientedDisplaySpaceRect and layerStackSpaceRect have the hardware display
        // size width and height swapped
        EXPECT_EQ(Rect(swapWH(mHardwareDisplaySize)),
                  compositionState.orientedDisplaySpace.getContent());
        EXPECT_EQ(Rect(swapWH(mHardwareDisplaySize)),
                  compositionState.layerStackSpace.getContent());
        EXPECT_EQ(false, compositionState.needsFiltering);
    }

    const ui::Size mFlingerDisplaySize;
    const ui::Size mHardwareDisplaySize;
    const ui::Rotation mPhysicalOrientation;
    const sp<DisplayDevice> mDisplayDevice;
};

struct DisplayDeviceSetProjectionTest_Installed0 : public DisplayDeviceSetProjectionTest {
    DisplayDeviceSetProjectionTest_Installed0()
          : DisplayDeviceSetProjectionTest(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                                           ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                                           ui::ROTATION_0) {}
};

TEST_F(DisplayDeviceSetProjectionTest_Installed0, checkDefaultProjection) {
    setDefaultProjection();
    expectDefaultState();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed0, checkWith0OutputRotation) {
    setProjectionForRotation0();
    expectStateForHardwareTransform0();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed0, checkWith90OutputRotation) {
    setProjectionForRotation90();
    expectStateForHardwareTransform90();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed0, checkWith180OutputRotation) {
    setProjectionForRotation180();
    expectStateForHardwareTransform180();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed0, checkWith270OutputRotation) {
    setProjectionForRotation270();
    expectStateForHardwareTransform270();
}

struct DisplayDeviceSetProjectionTest_Installed90 : public DisplayDeviceSetProjectionTest {
    DisplayDeviceSetProjectionTest_Installed90()
          : DisplayDeviceSetProjectionTest(ui::Size(DEFAULT_DISPLAY_HEIGHT, DEFAULT_DISPLAY_WIDTH),
                                           ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                                           ui::ROTATION_90) {}
};

TEST_F(DisplayDeviceSetProjectionTest_Installed90, checkDefaultProjection) {
    setDefaultProjection();
    expectDefaultState();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed90, checkWith0OutputRotation) {
    setProjectionForRotation0();
    expectStateForHardwareTransform90();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed90, checkWith90OutputRotation) {
    setProjectionForRotation90();
    expectStateForHardwareTransform180();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed90, checkWith180OutputRotation) {
    setProjectionForRotation180();
    expectStateForHardwareTransform270();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed90, checkWith270OutputRotation) {
    setProjectionForRotation270();
    expectStateForHardwareTransform0();
}

struct DisplayDeviceSetProjectionTest_Installed180 : public DisplayDeviceSetProjectionTest {
    DisplayDeviceSetProjectionTest_Installed180()
          : DisplayDeviceSetProjectionTest(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                                           ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                                           ui::ROTATION_180) {}
};

TEST_F(DisplayDeviceSetProjectionTest_Installed180, checkDefaultProjection) {
    setDefaultProjection();
    expectDefaultState();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed180, checkWith0OutputRotation) {
    setProjectionForRotation0();
    expectStateForHardwareTransform180();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed180, checkWith90OutputRotation) {
    setProjectionForRotation90();
    expectStateForHardwareTransform270();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed180, checkWith180OutputRotation) {
    setProjectionForRotation180();
    expectStateForHardwareTransform0();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed180, checkWith270OutputRotation) {
    setProjectionForRotation270();
    expectStateForHardwareTransform90();
}

struct DisplayDeviceSetProjectionTest_Installed270 : public DisplayDeviceSetProjectionTest {
    DisplayDeviceSetProjectionTest_Installed270()
          : DisplayDeviceSetProjectionTest(ui::Size(DEFAULT_DISPLAY_HEIGHT, DEFAULT_DISPLAY_WIDTH),
                                           ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                                           ui::ROTATION_270) {}
};

TEST_F(DisplayDeviceSetProjectionTest_Installed270, checkDefaultProjection) {
    setDefaultProjection();
    expectDefaultState();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed270, checkWith0OutputRotation) {
    setProjectionForRotation0();
    expectStateForHardwareTransform270();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed270, checkWith90OutputRotation) {
    setProjectionForRotation90();
    expectStateForHardwareTransform0();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed270, checkWith180OutputRotation) {
    setProjectionForRotation180();
    expectStateForHardwareTransform90();
}

TEST_F(DisplayDeviceSetProjectionTest_Installed270, checkWith270OutputRotation) {
    setProjectionForRotation270();
    expectStateForHardwareTransform180();
}

} // namespace
} // namespace android
