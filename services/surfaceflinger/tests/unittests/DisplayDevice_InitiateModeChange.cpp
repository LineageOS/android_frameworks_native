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
    using Action = DisplayDevice::DesiredModeAction;
    using Event = scheduler::DisplayModeEvent;

    void SetUp() override {
        injectFakeBufferQueueFactory();
        injectFakeNativeWindowSurfaceFactory();

        PrimaryDisplayVariant::setupHwcHotplugCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferConsumerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferProducerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupNativeWindowSurfaceCreationCallExpectations(this);
        PrimaryDisplayVariant::setupHwcGetActiveConfigCallExpectations(this);

        mFlinger.onComposerHalHotplugEvent(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                           DisplayHotplugEvent::CONNECTED);
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

TEST_F(InitiateModeChangeTest, setDesiredModeToActiveMode) {
    EXPECT_EQ(Action::None,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{60_Hz, kMode60}, Event::None}));
    EXPECT_FALSE(mDisplay->getDesiredMode());
}

TEST_F(InitiateModeChangeTest, setDesiredMode) {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getDesiredMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredMode()->event);

    // Setting another mode should be cached but return None.
    EXPECT_EQ(Action::None,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{120_Hz, kMode120}, Event::None}));
    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, *mDisplay->getDesiredMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredMode()->event);
}

TEST_F(InitiateModeChangeTest, clearDesiredMode) {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    EXPECT_TRUE(mDisplay->getDesiredMode());

    mDisplay->clearDesiredMode();
    EXPECT_FALSE(mDisplay->getDesiredMode());
}

TEST_F(InitiateModeChangeTest, initiateModeChange) REQUIRES(kMainThreadContext) {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getDesiredMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredMode()->event);

    const hal::VsyncPeriodChangeConstraints constraints{
            .desiredTimeNanos = systemTime(),
            .seamlessRequired = false,
    };
    hal::VsyncPeriodChangeTimeline timeline;
    EXPECT_TRUE(mDisplay->initiateModeChange(*mDisplay->getDesiredMode(), constraints, timeline));
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getPendingMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getPendingMode().event);

    mDisplay->clearDesiredMode();
    EXPECT_FALSE(mDisplay->getDesiredMode());
}

TEST_F(InitiateModeChangeTest, initiateRenderRateSwitch) {
    EXPECT_EQ(Action::InitiateRenderRateSwitch,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{30_Hz, kMode60}, Event::None}));
    EXPECT_FALSE(mDisplay->getDesiredMode());
}

TEST_F(InitiateModeChangeTest, initiateDisplayModeSwitch) FTL_FAKE_GUARD(kMainThreadContext) {
    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{90_Hz, kMode90}, Event::None}));
    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getDesiredMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredMode()->event);

    const hal::VsyncPeriodChangeConstraints constraints{
            .desiredTimeNanos = systemTime(),
            .seamlessRequired = false,
    };
    hal::VsyncPeriodChangeTimeline timeline;
    EXPECT_TRUE(mDisplay->initiateModeChange(*mDisplay->getDesiredMode(), constraints, timeline));
    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getPendingMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getPendingMode().event);

    EXPECT_EQ(Action::None,
              mDisplay->setDesiredMode({scheduler::FrameRateMode{120_Hz, kMode120}, Event::None}));
    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, *mDisplay->getDesiredMode()->modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getDesiredMode()->event);

    EXPECT_FRAME_RATE_MODE(kMode90, 90_Hz, *mDisplay->getPendingMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getPendingMode().event);

    EXPECT_TRUE(mDisplay->initiateModeChange(*mDisplay->getDesiredMode(), constraints, timeline));
    EXPECT_FRAME_RATE_MODE(kMode120, 120_Hz, *mDisplay->getPendingMode().modeOpt);
    EXPECT_EQ(Event::None, mDisplay->getPendingMode().event);

    mDisplay->clearDesiredMode();
    EXPECT_FALSE(mDisplay->getDesiredMode());
}

} // namespace
} // namespace android
