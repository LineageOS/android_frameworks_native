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

namespace android {
namespace {

class DestroyDisplayTest : public DisplayTransactionTest {};

TEST_F(DestroyDisplayTest, destroyDisplayClearsCurrentStateForDisplay) {
    using Case = NonHwcVirtualDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A virtual display exists
    auto existing = Case::Display::makeFakeExistingDisplayInjector(this);
    existing.inject();

    // --------------------------------------------------------------------
    // Call Expectations

    // The call should notify the interceptor that a display was created.
    EXPECT_CALL(*mSurfaceInterceptor, saveDisplayDeletion(_)).Times(1);

    // Destroying the display commits a display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.destroyDisplay(existing.token());

    // --------------------------------------------------------------------
    // Postconditions

    // The display should have been removed from the current state
    EXPECT_FALSE(hasCurrentDisplayState(existing.token()));

    // Ths display should still exist in the drawing state
    EXPECT_TRUE(hasDrawingDisplayState(existing.token()));

    // The display transaction needed flasg should be set
    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));
}

TEST_F(DestroyDisplayTest, destroyDisplayHandlesUnknownDisplay) {
    // --------------------------------------------------------------------
    // Preconditions

    sp<BBinder> displayToken = new BBinder();

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.destroyDisplay(displayToken);
}

} // namespace
} // namespace android
