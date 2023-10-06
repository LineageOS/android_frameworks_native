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

class InitializeDisplaysTest : public DisplayTransactionTest {};

TEST_F(InitializeDisplaysTest, commitsPrimaryDisplay) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A primary display is set up
    Case::Display::injectHwcDisplay(this);
    auto primaryDisplay = Case::Display::makeFakeExistingDisplayInjector(this);
    primaryDisplay.inject();

    // --------------------------------------------------------------------
    // Call Expectations

    // We expect a call to get the active display config.
    Case::Display::setupHwcGetActiveConfigCallExpectations(this);

    // We expect a scheduled commit for the display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    EXPECT_CALL(static_cast<mock::VSyncTracker&>(
                        mFlinger.scheduler()->getVsyncSchedule()->getTracker()),
                nextAnticipatedVSyncTimeFrom(_))
            .WillRepeatedly(Return(0));

    // --------------------------------------------------------------------
    // Invocation

    FTL_FAKE_GUARD(kMainThreadContext, mFlinger.initializeDisplays());

    // --------------------------------------------------------------------
    // Postconditions

    // The primary display should have a current state
    ASSERT_TRUE(hasCurrentDisplayState(primaryDisplay.token()));
    const auto& primaryDisplayState = getCurrentDisplayState(primaryDisplay.token());

    // The primary display state should be reset
    EXPECT_EQ(ui::DEFAULT_LAYER_STACK, primaryDisplayState.layerStack);
    EXPECT_EQ(ui::ROTATION_0, primaryDisplayState.orientation);
    EXPECT_EQ(Rect::INVALID_RECT, primaryDisplayState.orientedDisplaySpaceRect);
    EXPECT_EQ(Rect::INVALID_RECT, primaryDisplayState.layerStackSpaceRect);

    // The width and height should both be zero
    EXPECT_EQ(0u, primaryDisplayState.width);
    EXPECT_EQ(0u, primaryDisplayState.height);

    // The display should be set to PowerMode::ON
    ASSERT_TRUE(hasDisplayDevice(primaryDisplay.token()));
    auto displayDevice = primaryDisplay.mutableDisplayDevice();
    EXPECT_EQ(PowerMode::ON, displayDevice->getPowerMode());

    // The display transaction needed flag should be set.
    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));
}

} // namespace
} // namespace android
