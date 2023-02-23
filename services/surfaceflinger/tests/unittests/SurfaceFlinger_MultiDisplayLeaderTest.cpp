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

#include "DisplayTransactionTestHelpers.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

struct MultiDisplayLeaderTest : DisplayTransactionTest {
    static constexpr bool kWithMockScheduler = false;
    MultiDisplayLeaderTest() : DisplayTransactionTest(kWithMockScheduler) {}
};

TEST_F(MultiDisplayLeaderTest, foldable) {
    injectMockScheduler(InnerDisplayVariant::DISPLAY_ID::get());

    // Inject inner and outer displays with uninitialized power modes.
    sp<DisplayDevice> innerDisplay, outerDisplay;
    constexpr bool kInitPowerMode = false;
    {
        InnerDisplayVariant::injectHwcDisplay<kInitPowerMode>(this);
        auto injector = InnerDisplayVariant::makeFakeExistingDisplayInjector(this);
        injector.setPowerMode(std::nullopt);
        injector.setRefreshRateSelector(mFlinger.scheduler()->refreshRateSelector());
        innerDisplay = injector.inject();
    }
    {
        OuterDisplayVariant::injectHwcDisplay<kInitPowerMode>(this);
        auto injector = OuterDisplayVariant::makeFakeExistingDisplayInjector(this);
        injector.setPowerMode(std::nullopt);
        outerDisplay = injector.inject();
    }

    // When the device boots, the inner display should be the leader.
    ASSERT_EQ(mFlinger.scheduler()->leaderDisplayId(), innerDisplay->getPhysicalId());

    // ...and should still be after powering on.
    mFlinger.setPowerModeInternal(innerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->leaderDisplayId(), innerDisplay->getPhysicalId());

    // The outer display should become the leader after folding.
    mFlinger.setPowerModeInternal(innerDisplay, PowerMode::OFF);
    mFlinger.setPowerModeInternal(outerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->leaderDisplayId(), outerDisplay->getPhysicalId());

    // The inner display should become the leader after unfolding.
    mFlinger.setPowerModeInternal(outerDisplay, PowerMode::OFF);
    mFlinger.setPowerModeInternal(innerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->leaderDisplayId(), innerDisplay->getPhysicalId());

    // The inner display should stay the leader if both are powered on.
    // TODO(b/256196556): The leader should depend on the displays' VSYNC phases.
    mFlinger.setPowerModeInternal(outerDisplay, PowerMode::ON);
    ASSERT_EQ(mFlinger.scheduler()->leaderDisplayId(), innerDisplay->getPhysicalId());

    // The outer display should become the leader if designated.
    mFlinger.scheduler()->setLeaderDisplay(outerDisplay->getPhysicalId());
    ASSERT_EQ(mFlinger.scheduler()->leaderDisplayId(), outerDisplay->getPhysicalId());
}

} // namespace
} // namespace android
