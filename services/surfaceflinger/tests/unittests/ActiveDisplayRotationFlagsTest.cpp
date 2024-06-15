/*
 * Copyright 2023 The Android Open Source Project
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

#include "DualDisplayTransactionTest.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

struct ActiveDisplayRotationFlagsTest
      : DualDisplayTransactionTest<hal::PowerMode::ON, hal::PowerMode::OFF> {
    void SetUp() override {
        DualDisplayTransactionTest::SetUp();

        // The flags are a static variable, so by modifying them in the test, we
        // are modifying the real ones used by SurfaceFlinger. Save the original
        // flags so we can restore them on teardown. This isn't perfect - the
        // phone may have been rotated during the test, so we're restoring the
        // wrong flags. But if the phone is rotated, this may also fail the test.
        mOldRotationFlags = mFlinger.mutableActiveDisplayRotationFlags();

        // Reset to the expected default state.
        mFlinger.mutableActiveDisplayRotationFlags() = ui::Transform::ROT_0;
    }

    void TearDown() override { mFlinger.mutableActiveDisplayRotationFlags() = mOldRotationFlags; }

    ui::Transform::RotationFlags mOldRotationFlags;
};

TEST_F(ActiveDisplayRotationFlagsTest, defaultRotation) {
    ASSERT_EQ(ui::Transform::ROT_0, SurfaceFlinger::getActiveDisplayRotationFlags());
}

TEST_F(ActiveDisplayRotationFlagsTest, rotate90) {
    auto displayToken = mInnerDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_90;

    mFlinger.commitTransactionsLocked(eDisplayTransactionNeeded);
    ASSERT_EQ(ui::Transform::ROT_90, SurfaceFlinger::getActiveDisplayRotationFlags());
}

TEST_F(ActiveDisplayRotationFlagsTest, rotate90inactive) {
    auto displayToken = mOuterDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_90;

    mFlinger.commitTransactionsLocked(eDisplayTransactionNeeded);
    ASSERT_EQ(ui::Transform::ROT_0, SurfaceFlinger::getActiveDisplayRotationFlags());
}

TEST_F(ActiveDisplayRotationFlagsTest, rotateBothInnerActive) {
    auto displayToken = mInnerDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_180;

    displayToken = mOuterDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_270;

    mFlinger.commitTransactionsLocked(eDisplayTransactionNeeded);
    ASSERT_EQ(ui::Transform::ROT_180, SurfaceFlinger::getActiveDisplayRotationFlags());
}

TEST_F(ActiveDisplayRotationFlagsTest, rotateBothOuterActive) {
    mFlinger.mutableActiveDisplayId() = kOuterDisplayId;
    auto displayToken = mInnerDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_180;

    displayToken = mOuterDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_270;

    mFlinger.commitTransactionsLocked(eDisplayTransactionNeeded);
    ASSERT_EQ(ui::Transform::ROT_270, SurfaceFlinger::getActiveDisplayRotationFlags());
}

TEST_F(ActiveDisplayRotationFlagsTest, onActiveDisplayChanged) {
    auto displayToken = mInnerDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_180;

    displayToken = mOuterDisplay->getDisplayToken().promote();
    mFlinger.mutableDrawingState().displays.editValueFor(displayToken).orientation = ui::ROTATION_0;
    mFlinger.mutableCurrentState().displays.editValueFor(displayToken).orientation =
            ui::ROTATION_270;

    mFlinger.commitTransactionsLocked(eDisplayTransactionNeeded);
    ASSERT_EQ(ui::Transform::ROT_180, SurfaceFlinger::getActiveDisplayRotationFlags());

    mFlinger.onActiveDisplayChanged(mInnerDisplay.get(), *mOuterDisplay);
    ASSERT_EQ(ui::Transform::ROT_270, SurfaceFlinger::getActiveDisplayRotationFlags());
}

} // namespace
} // namespace android
