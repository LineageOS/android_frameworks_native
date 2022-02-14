/*
 * Copyright 2021 The Android Open Source Project
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

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

class InitiateModeChangeTest : public DisplayTransactionTest {
public:
    using Event = scheduler::RefreshRateConfigEvent;

    void SetUp() override {
        injectFakeBufferQueueFactory();
        injectFakeNativeWindowSurfaceFactory();

        PrimaryDisplayVariant::setupHwcHotplugCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferConsumerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferProducerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupNativeWindowSurfaceCreationCallExpectations(this);
        PrimaryDisplayVariant::setupHwcGetActiveConfigCallExpectations(this);

        mFlinger.onComposerHalHotplug(PrimaryDisplayVariant::HWC_DISPLAY_ID, Connection::CONNECTED);

        mDisplay = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this)
                           .setSupportedModes({kDisplayMode60, kDisplayMode90, kDisplayMode120})
                           .setActiveMode(kDisplayModeId60)
                           .inject();
    }

protected:
    sp<DisplayDevice> mDisplay;

    const DisplayModeId kDisplayModeId60 = DisplayModeId(0);
    const DisplayModePtr kDisplayMode60 =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId60.value()))
                    .setId(kDisplayModeId60)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod(int32_t(16'666'667))
                    .setGroup(0)
                    .setHeight(1000)
                    .setWidth(1000)
                    .build();

    const DisplayModeId kDisplayModeId90 = DisplayModeId(1);
    const DisplayModePtr kDisplayMode90 =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId90.value()))
                    .setId(kDisplayModeId90)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod(int32_t(11'111'111))
                    .setGroup(0)
                    .setHeight(1000)
                    .setWidth(1000)
                    .build();

    const DisplayModeId kDisplayModeId120 = DisplayModeId(2);
    const DisplayModePtr kDisplayMode120 =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId120.value()))
                    .setId(kDisplayModeId120)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod(int32_t(8'333'333))
                    .setGroup(0)
                    .setHeight(1000)
                    .setWidth(1000)
                    .build();
};

TEST_F(InitiateModeChangeTest, setDesiredActiveMode_setCurrentMode) {
    EXPECT_FALSE(mDisplay->setDesiredActiveMode({kDisplayMode60, Event::None}));
    EXPECT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, setDesiredActiveMode_setNewMode) {
    EXPECT_TRUE(mDisplay->setDesiredActiveMode({kDisplayMode90, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_EQ(kDisplayMode90, mDisplay->getDesiredActiveMode()->mode);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    // Setting another mode should be cached but return false
    EXPECT_FALSE(mDisplay->setDesiredActiveMode({kDisplayMode120, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_EQ(kDisplayMode120, mDisplay->getDesiredActiveMode()->mode);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);
}

TEST_F(InitiateModeChangeTest, clearDesiredActiveModeState) {
    EXPECT_TRUE(mDisplay->setDesiredActiveMode({kDisplayMode90, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());

    mDisplay->clearDesiredActiveModeState();
    ASSERT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, initiateModeChange) NO_THREAD_SAFETY_ANALYSIS {
    EXPECT_TRUE(mDisplay->setDesiredActiveMode({kDisplayMode90, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_EQ(kDisplayMode90, mDisplay->getDesiredActiveMode()->mode);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    hal::VsyncPeriodChangeConstraints constraints{
            .desiredTimeNanos = systemTime(),
            .seamlessRequired = false,
    };
    hal::VsyncPeriodChangeTimeline timeline;
    EXPECT_EQ(OK,
              mDisplay->initiateModeChange(*mDisplay->getDesiredActiveMode(), constraints,
                                           &timeline));
    EXPECT_EQ(kDisplayMode90, mDisplay->getUpcomingActiveMode().mode);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    mDisplay->clearDesiredActiveModeState();
    ASSERT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, getUpcomingActiveMode_desiredActiveModeChanged)
NO_THREAD_SAFETY_ANALYSIS {
    EXPECT_TRUE(mDisplay->setDesiredActiveMode({kDisplayMode90, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_EQ(kDisplayMode90, mDisplay->getDesiredActiveMode()->mode);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    hal::VsyncPeriodChangeConstraints constraints{
            .desiredTimeNanos = systemTime(),
            .seamlessRequired = false,
    };
    hal::VsyncPeriodChangeTimeline timeline;
    EXPECT_EQ(OK,
              mDisplay->initiateModeChange(*mDisplay->getDesiredActiveMode(), constraints,
                                           &timeline));
    EXPECT_EQ(kDisplayMode90, mDisplay->getUpcomingActiveMode().mode);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    EXPECT_FALSE(mDisplay->setDesiredActiveMode({kDisplayMode120, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_EQ(kDisplayMode120, mDisplay->getDesiredActiveMode()->mode);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    EXPECT_EQ(kDisplayMode90, mDisplay->getUpcomingActiveMode().mode);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    EXPECT_EQ(OK,
              mDisplay->initiateModeChange(*mDisplay->getDesiredActiveMode(), constraints,
                                           &timeline));
    EXPECT_EQ(kDisplayMode120, mDisplay->getUpcomingActiveMode().mode);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    mDisplay->clearDesiredActiveModeState();
    ASSERT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

} // namespace
} // namespace android
