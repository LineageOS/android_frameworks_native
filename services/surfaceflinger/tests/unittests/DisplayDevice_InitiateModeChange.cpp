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
#include "mock/MockFrameRateMode.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

class InitiateModeChangeTest : public DisplayTransactionTest {
public:
    using Action = DisplayDevice::DesiredActiveModeAction;
    using Event = scheduler::DisplayModeEvent;

    void SetUp() override {
        injectFakeBufferQueueFactory();
        injectFakeNativeWindowSurfaceFactory();

        PrimaryDisplayVariant::setupHwcHotplugCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferConsumerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferProducerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupNativeWindowSurfaceCreationCallExpectations(this);
        PrimaryDisplayVariant::setupHwcGetActiveConfigCallExpectations(this);

        mFlinger.onComposerHalHotplug(PrimaryDisplayVariant::HWC_DISPLAY_ID, Connection::CONNECTED);
        mFlinger.configureAndCommit();

        mDisplay = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this)
                           .setDisplayModes(makeModes(kMode60, kMode90, kMode120), kModeId60)
                           .inject();
    }

protected:
    sp<DisplayDevice> mDisplay;

    static constexpr DisplayModeId kModeId60{0};
    static constexpr DisplayModeId kModeId90{1};
    static constexpr DisplayModeId kModeId120{2};

    static inline const ftl::NonNull<DisplayModePtr> kMode60 =
            ftl::as_non_null(createDisplayMode(kModeId60, 60_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode90 =
            ftl::as_non_null(createDisplayMode(kModeId90, 90_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode120 =
            ftl::as_non_null(createDisplayMode(kModeId120, 120_Hz));
};

TEST_F(InitiateModeChangeTest, setDesiredActiveMode_setCurrentMode) {
    EXPECT_EQ(Action::None,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{60_Hz, kMode60}, Event::None}));
    EXPECT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, setDesiredActiveMode_setNewMode) {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getDesiredActiveMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    // Setting another mode should be cached but return None
    EXPECT_EQ(Action::None,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{120_Hz, kMode120}, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, *mDisplay->getDesiredActiveMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);
}

TEST_F(InitiateModeChangeTest, clearDesiredActiveModeState) {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());

    mDisplay->clearDesiredActiveModeState();
    ASSERT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, initiateModeChange) NO_THREAD_SAFETY_ANALYSIS {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getDesiredActiveMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    hal::VsyncPeriodChangeConstraints constraints{
            .desiredTimeNanos = systemTime(),
            .seamlessRequired = false,
    };
    hal::VsyncPeriodChangeTimeline timeline;
    EXPECT_EQ(OK,
              mDisplay->initiateModeChange(*mDisplay->getDesiredActiveMode(), constraints,
                                           &timeline));
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getUpcomingActiveMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    mDisplay->clearDesiredActiveModeState();
    ASSERT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, initiateRenderRateChange) {
    EXPECT_EQ(Action::InitiateRenderRateSwitch,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{30_Hz, kMode60}, Event::None}));
    EXPECT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

TEST_F(InitiateModeChangeTest, getUpcomingActiveMode_desiredActiveModeChanged)
NO_THREAD_SAFETY_ANALYSIS {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getDesiredActiveMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    hal::VsyncPeriodChangeConstraints constraints{
            .desiredTimeNanos = systemTime(),
            .seamlessRequired = false,
    };
    hal::VsyncPeriodChangeTimeline timeline;
    EXPECT_EQ(OK,
              mDisplay->initiateModeChange(*mDisplay->getDesiredActiveMode(), constraints,
                                           &timeline));
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getUpcomingActiveMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    EXPECT_EQ(Action::None,
              mDisplay->setDesiredActiveMode(
                      {scheduler::FrameRateMode{120_Hz, kMode120}, Event::None}));
    ASSERT_NE(std::nullopt, mDisplay->getDesiredActiveMode());
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, *mDisplay->getDesiredActiveMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredActiveMode()->event);

    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getUpcomingActiveMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    EXPECT_EQ(OK,
              mDisplay->initiateModeChange(*mDisplay->getDesiredActiveMode(), constraints,
                                           &timeline));
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, *mDisplay->getUpcomingActiveMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getUpcomingActiveMode().event);

    mDisplay->clearDesiredActiveModeState();
    ASSERT_EQ(std::nullopt, mDisplay->getDesiredActiveMode());
}

} // namespace
} // namespace android
