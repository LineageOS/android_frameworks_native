/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "SurfaceFlingerPowerHintTest"

#include <chrono>

#include "CommitAndCompositeTest.h"

using namespace std::chrono_literals;
using testing::_;
using testing::Return;

namespace android {
namespace {

class SurfaceFlingerPowerHintTest : public CommitAndCompositeTest {};

TEST_F(SurfaceFlingerPowerHintTest, sendDurationsIncludingHwcWaitTime) {
    ON_CALL(*mPowerAdvisor, usePowerHintSession()).WillByDefault(Return(true));

    EXPECT_CALL(*mPowerAdvisor, updateTargetWorkDuration(_)).Times(1);
    EXPECT_CALL(*mDisplaySurface,
                prepareFrame(compositionengine::DisplaySurface::CompositionType::Hwc))
            .Times(1);
    EXPECT_CALL(*mComposer, presentOrValidateDisplay(HWC_DISPLAY, _, _, _, _, _, _)).WillOnce([] {
        constexpr Duration kMockHwcRunTime = 20ms;
        std::this_thread::sleep_for(kMockHwcRunTime);
        return hardware::graphics::composer::V2_1::Error::NONE;
    });
    EXPECT_CALL(*mPowerAdvisor, reportActualWorkDuration()).Times(1);

    const TimePoint frameTime = scheduler::SchedulerClock::now();
    constexpr Period kMockVsyncPeriod = 15ms;
    mFlinger.commitAndComposite(frameTime, VsyncId{123}, frameTime + kMockVsyncPeriod);
}

TEST_F(SurfaceFlingerPowerHintTest, inactiveOnDisplayDoze) {
    ON_CALL(*mPowerAdvisor, usePowerHintSession()).WillByDefault(Return(true));

    mDisplay->setPowerMode(hal::PowerMode::DOZE);

    EXPECT_CALL(*mPowerAdvisor, updateTargetWorkDuration(_)).Times(0);
    EXPECT_CALL(*mDisplaySurface,
                prepareFrame(compositionengine::DisplaySurface::CompositionType::Hwc))
            .Times(1);
    EXPECT_CALL(*mComposer, presentOrValidateDisplay(HWC_DISPLAY, _, _, _, _, _, _)).WillOnce([] {
        constexpr Duration kMockHwcRunTime = 20ms;
        std::this_thread::sleep_for(kMockHwcRunTime);
        return hardware::graphics::composer::V2_1::Error::NONE;
    });
    EXPECT_CALL(*mPowerAdvisor, reportActualWorkDuration()).Times(0);

    const TimePoint frameTime = scheduler::SchedulerClock::now();
    constexpr Period kMockVsyncPeriod = 15ms;
    mFlinger.commitAndComposite(frameTime, VsyncId{123}, frameTime + kMockVsyncPeriod);
}

} // namespace
} // namespace android
