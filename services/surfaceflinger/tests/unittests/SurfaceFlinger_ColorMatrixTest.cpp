/*
 * Copyright 2024 The Android Open Source Project
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

#include "CommitAndCompositeTest.h"

#define EXPECT_COLOR_MATRIX_CHANGED(current, drawing)               \
    EXPECT_EQ(current, mFlinger.currentState().colorMatrixChanged); \
    EXPECT_EQ(drawing, mFlinger.drawingState().colorMatrixChanged);

namespace android {

class ColorMatrixTest : public CommitAndCompositeTest {};

TEST_F(ColorMatrixTest, colorMatrixChanged) {
    EXPECT_COLOR_MATRIX_CHANGED(true, true);
    mFlinger.mutableTransactionFlags() |= eTransactionNeeded;

    mFlinger.commitAndComposite();
    EXPECT_COLOR_MATRIX_CHANGED(false, false);

    mFlinger.setDaltonizerType(ColorBlindnessType::Deuteranomaly);
    EXPECT_COLOR_MATRIX_CHANGED(true, false);

    mFlinger.commit();
    EXPECT_COLOR_MATRIX_CHANGED(false, true);

    mFlinger.commitAndComposite();
    EXPECT_COLOR_MATRIX_CHANGED(false, false);
}

TEST_F(ColorMatrixTest, colorMatrixChangedAfterDisplayTransaction) {
    EXPECT_COLOR_MATRIX_CHANGED(true, true);
    mFlinger.mutableTransactionFlags() |= eTransactionNeeded;

    mFlinger.commitAndComposite();
    EXPECT_COLOR_MATRIX_CHANGED(false, false);

    mFlinger.createDisplay(String8("Test Display"), false);

    mFlinger.commit();
    EXPECT_COLOR_MATRIX_CHANGED(false, true);

    mFlinger.commitAndComposite();
    EXPECT_COLOR_MATRIX_CHANGED(false, false);
}

} // namespace android
