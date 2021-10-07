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

class OnInitializeDisplaysTest : public DisplayTransactionTest {};

TEST_F(OnInitializeDisplaysTest, onInitializeDisplaysSetsUpPrimaryDisplay) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A primary display is set up
    Case::Display::injectHwcDisplay(this);
    auto primaryDisplay = Case::Display::makeFakeExistingDisplayInjector(this);
    primaryDisplay.inject();

    // --------------------------------------------------------------------
    // Call Expectations

    // We expect the surface interceptor to possibly be used, but we treat it as
    // disabled since it is called as a side effect rather than directly by this
    // function.
    EXPECT_CALL(*mSurfaceInterceptor, isEnabled()).WillOnce(Return(false));

    // We expect a call to get the active display config.
    Case::Display::setupHwcGetActiveConfigCallExpectations(this);

    // We expect invalidate() to be invoked once to trigger display transaction
    // processing.
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    EXPECT_CALL(*mVSyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.onInitializeDisplays();

    // --------------------------------------------------------------------
    // Postconditions

    // The primary display should have a current state
    ASSERT_TRUE(hasCurrentDisplayState(primaryDisplay.token()));
    const auto& primaryDisplayState = getCurrentDisplayState(primaryDisplay.token());
    // The layer stack state should be set to zero
    EXPECT_EQ(0u, primaryDisplayState.layerStack);
    // The orientation state should be set to zero
    EXPECT_EQ(ui::ROTATION_0, primaryDisplayState.orientation);

    // The orientedDisplaySpaceRect state should be set to INVALID
    EXPECT_EQ(Rect::INVALID_RECT, primaryDisplayState.orientedDisplaySpaceRect);

    // The layerStackSpaceRect state should be set to INVALID
    EXPECT_EQ(Rect::INVALID_RECT, primaryDisplayState.layerStackSpaceRect);

    // The width and height should both be zero
    EXPECT_EQ(0u, primaryDisplayState.width);
    EXPECT_EQ(0u, primaryDisplayState.height);

    // The display should be set to PowerMode::ON
    ASSERT_TRUE(hasDisplayDevice(primaryDisplay.token()));
    auto displayDevice = primaryDisplay.mutableDisplayDevice();
    EXPECT_EQ(PowerMode::ON, displayDevice->getPowerMode());

    // The display refresh period should be set in the orientedDisplaySpaceRect tracker.
    FrameStats stats;
    mFlinger.getAnimFrameTracker().getStats(&stats);
    EXPECT_EQ(DEFAULT_VSYNC_PERIOD, stats.refreshPeriodNano);

    // The display transaction needed flag should be set.
    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));

    // The compositor timing should be set to default values
    const auto& compositorTiming = mFlinger.getCompositorTiming();
    EXPECT_EQ(-DEFAULT_VSYNC_PERIOD, compositorTiming.deadline);
    EXPECT_EQ(DEFAULT_VSYNC_PERIOD, compositorTiming.interval);
    EXPECT_EQ(DEFAULT_VSYNC_PERIOD, compositorTiming.presentLatency);
}

} // namespace
} // namespace android