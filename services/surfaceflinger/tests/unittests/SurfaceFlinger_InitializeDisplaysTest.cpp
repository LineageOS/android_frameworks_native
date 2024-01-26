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

#include "DualDisplayTransactionTest.h"

namespace android {
namespace {

constexpr bool kExpectSetPowerModeOnce = false;
struct InitializeDisplaysTest : DualDisplayTransactionTest<hal::PowerMode::OFF, hal::PowerMode::OFF,
                                                           kExpectSetPowerModeOnce> {};

TEST_F(InitializeDisplaysTest, initializesDisplays) {
    // Scheduled by the display transaction, and by powering on each display.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(3);

    EXPECT_CALL(static_cast<mock::VSyncTracker&>(
                        mFlinger.scheduler()->getVsyncSchedule()->getTracker()),
                nextAnticipatedVSyncTimeFrom(_, _))
            .WillRepeatedly(Return(0));

    FTL_FAKE_GUARD(kMainThreadContext, mFlinger.initializeDisplays());

    for (const auto& display : {mInnerDisplay, mOuterDisplay}) {
        const auto token = display->getDisplayToken().promote();
        ASSERT_TRUE(token);

        ASSERT_TRUE(hasCurrentDisplayState(token));
        const auto& state = getCurrentDisplayState(token);

        const ui::LayerStack expectedLayerStack = display == mInnerDisplay
                ? ui::DEFAULT_LAYER_STACK
                : ui::LayerStack::fromValue(ui::DEFAULT_LAYER_STACK.id + 1);

        EXPECT_EQ(expectedLayerStack, state.layerStack);
        EXPECT_EQ(ui::ROTATION_0, state.orientation);
        EXPECT_EQ(Rect::INVALID_RECT, state.orientedDisplaySpaceRect);
        EXPECT_EQ(Rect::INVALID_RECT, state.layerStackSpaceRect);

        EXPECT_EQ(0u, state.width);
        EXPECT_EQ(0u, state.height);

        ASSERT_TRUE(hasDisplayDevice(token));
        EXPECT_EQ(PowerMode::ON, getDisplayDevice(token).getPowerMode());
    }

    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));
}

} // namespace
} // namespace android
