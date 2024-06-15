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
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockDisplayModeSpecs.h"

#include <com_android_graphics_surfaceflinger_flags.h>
#include <common/test/FlagUtils.h>
#include <ftl/fake_guard.h>
#include <scheduler/Fps.h>

using namespace com::android::graphics::surfaceflinger;

#define EXPECT_SET_ACTIVE_CONFIG(displayId, modeId)                                 \
    EXPECT_CALL(*mComposer,                                                         \
                setActiveConfigWithConstraints(displayId,                           \
                                               static_cast<hal::HWConfigId>(        \
                                                       ftl::to_underlying(modeId)), \
                                               _, _))                               \
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)))

namespace android {
namespace {

using android::hardware::graphics::composer::V2_4::Error;
using android::hardware::graphics::composer::V2_4::VsyncPeriodChangeTimeline;

class DisplayModeSwitchingTest : public DisplayTransactionTest {
public:
    void SetUp() override {
        injectFakeBufferQueueFactory();
        injectFakeNativeWindowSurfaceFactory();

        PrimaryDisplayVariant::setupHwcHotplugCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferConsumerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupFramebufferProducerBufferQueueCallExpectations(this);
        PrimaryDisplayVariant::setupNativeWindowSurfaceCreationCallExpectations(this);
        PrimaryDisplayVariant::setupHwcGetActiveConfigCallExpectations(this);

        auto selectorPtr = std::make_shared<scheduler::RefreshRateSelector>(kModes, kModeId60);

        setupScheduler(selectorPtr);

        mFlinger.onComposerHalHotplugEvent(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                           DisplayHotplugEvent::CONNECTED);
        mFlinger.configureAndCommit();

        auto vsyncController = std::make_unique<mock::VsyncController>();
        auto vsyncTracker = std::make_shared<mock::VSyncTracker>();

        EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(*vsyncTracker, currentPeriod())
                .WillRepeatedly(Return(
                        TestableSurfaceFlinger::FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));
        EXPECT_CALL(*vsyncTracker, minFramePeriod())
                .WillRepeatedly(Return(Period::fromNs(
                        TestableSurfaceFlinger::FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD)));

        mDisplay = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this)
                           .setRefreshRateSelector(std::move(selectorPtr))
                           .inject(std::move(vsyncController), std::move(vsyncTracker));

        // isVsyncPeriodSwitchSupported should return true, otherwise the SF's HWC proxy
        // will call setActiveConfig instead of setActiveConfigWithConstraints.
        ON_CALL(*mComposer, isSupported(Hwc2::Composer::OptionalFeature::RefreshRateSwitching))
                .WillByDefault(Return(true));
    }

    static constexpr HWDisplayId kInnerDisplayHwcId = PrimaryDisplayVariant::HWC_DISPLAY_ID;
    static constexpr HWDisplayId kOuterDisplayHwcId = kInnerDisplayHwcId + 1;

    auto injectOuterDisplay() {
        constexpr PhysicalDisplayId kOuterDisplayId = PhysicalDisplayId::fromPort(254u);

        constexpr bool kIsPrimary = false;
        TestableSurfaceFlinger::FakeHwcDisplayInjector(kOuterDisplayId, hal::DisplayType::PHYSICAL,
                                                       kIsPrimary)
                .setHwcDisplayId(kOuterDisplayHwcId)
                .setPowerMode(hal::PowerMode::OFF)
                .inject(&mFlinger, mComposer);

        mOuterDisplay = mFakeDisplayInjector.injectInternalDisplay(
                [&](FakeDisplayDeviceInjector& injector) {
                    injector.setPowerMode(hal::PowerMode::OFF);
                    injector.setDisplayModes(mock::cloneForDisplay(kOuterDisplayId, kModes),
                                             kModeId120);
                },
                {.displayId = kOuterDisplayId,
                 .hwcDisplayId = kOuterDisplayHwcId,
                 .isPrimary = kIsPrimary});

        return std::forward_as_tuple(mDisplay, mOuterDisplay);
    }

protected:
    void setupScheduler(std::shared_ptr<scheduler::RefreshRateSelector>);

    sp<DisplayDevice> mDisplay, mOuterDisplay;
    mock::EventThread* mAppEventThread;

    static constexpr DisplayModeId kModeId60{0};
    static constexpr DisplayModeId kModeId90{1};
    static constexpr DisplayModeId kModeId120{2};
    static constexpr DisplayModeId kModeId90_4K{3};

    static inline const DisplayModePtr kMode60 = createDisplayMode(kModeId60, 60_Hz, 0);
    static inline const DisplayModePtr kMode90 = createDisplayMode(kModeId90, 90_Hz, 1);
    static inline const DisplayModePtr kMode120 = createDisplayMode(kModeId120, 120_Hz, 2);

    static constexpr ui::Size kResolution4K{3840, 2160};
    static inline const DisplayModePtr kMode90_4K =
            createDisplayMode(kModeId90_4K, 90_Hz, 3, kResolution4K);

    static inline const DisplayModes kModes = makeModes(kMode60, kMode90, kMode120, kMode90_4K);
};

void DisplayModeSwitchingTest::setupScheduler(
        std::shared_ptr<scheduler::RefreshRateSelector> selectorPtr) {
    auto eventThread = std::make_unique<mock::EventThread>();
    mAppEventThread = eventThread.get();
    auto sfEventThread = std::make_unique<mock::EventThread>();

    EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*eventThread, createEventConnection(_, _))
            .WillOnce(Return(sp<EventThreadConnection>::make(eventThread.get(),
                                                             mock::EventThread::kCallingUid)));

    EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
            .WillOnce(Return(sp<EventThreadConnection>::make(sfEventThread.get(),
                                                             mock::EventThread::kCallingUid)));

    auto vsyncController = std::make_unique<mock::VsyncController>();
    auto vsyncTracker = std::make_shared<mock::VSyncTracker>();

    EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*vsyncTracker, currentPeriod())
            .WillRepeatedly(
                    Return(TestableSurfaceFlinger::FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));
    EXPECT_CALL(*vsyncTracker, minFramePeriod())
            .WillRepeatedly(Return(Period::fromNs(
                    TestableSurfaceFlinger::FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD)));
    EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_, _)).WillRepeatedly(Return(0));
    mFlinger.setupScheduler(std::move(vsyncController), std::move(vsyncTracker),
                            std::move(eventThread), std::move(sfEventThread),
                            std::move(selectorPtr),
                            TestableSurfaceFlinger::SchedulerCallbackImpl::kNoOp);
}

TEST_F(DisplayModeSwitchingTest, changeRefreshRateOnActiveDisplayWithRefreshRequired) {
    ftl::FakeGuard guard(kMainThreadContext);

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    mFlinger.onActiveDisplayChanged(nullptr, *mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        mock::createDisplayModeSpecs(kModeId90, false, 0, 120));

    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getDesiredMode()->mode.modePtr->getId(), kModeId90);
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_SET_ACTIVE_CONFIG(PrimaryDisplayVariant::HWC_DISPLAY_ID, kModeId90);

    mFlinger.commit();

    Mock::VerifyAndClearExpectations(mComposer);

    EXPECT_TRUE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    // Verify that the next commit will complete the mode change and send
    // a onModeChanged event to the framework.

    EXPECT_CALL(*mAppEventThread,
                onModeChanged(scheduler::FrameRateMode{90_Hz, ftl::as_non_null(kMode90)}));
    mFlinger.commit();
    Mock::VerifyAndClearExpectations(mAppEventThread);

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId90);
}

TEST_F(DisplayModeSwitchingTest, changeRefreshRateOnActiveDisplayWithoutRefreshRequired) {
    ftl::FakeGuard guard(kMainThreadContext);

    EXPECT_FALSE(mDisplay->getDesiredMode());

    mFlinger.onActiveDisplayChanged(nullptr, *mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        mock::createDisplayModeSpecs(kModeId90, true, 0, 120));

    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getDesiredMode()->mode.modePtr->getId(), kModeId90);
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    // and complete the mode change.
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = false};
    EXPECT_SET_ACTIVE_CONFIG(PrimaryDisplayVariant::HWC_DISPLAY_ID, kModeId90);

    EXPECT_CALL(*mAppEventThread,
                onModeChanged(scheduler::FrameRateMode{90_Hz, ftl::as_non_null(kMode90)}));

    mFlinger.commit();

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId90);
}

TEST_F(DisplayModeSwitchingTest, twoConsecutiveSetDesiredDisplayModeSpecs) {
    ftl::FakeGuard guard(kMainThreadContext);

    // Test that if we call setDesiredDisplayModeSpecs while a previous mode change
    // is still being processed the later call will be respected.

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    mFlinger.onActiveDisplayChanged(nullptr, *mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        mock::createDisplayModeSpecs(kModeId90, false, 0, 120));

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_SET_ACTIVE_CONFIG(PrimaryDisplayVariant::HWC_DISPLAY_ID, kModeId90);

    mFlinger.commit();

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        mock::createDisplayModeSpecs(kModeId120, false, 0, 180));

    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getDesiredMode()->mode.modePtr->getId(), kModeId120);

    EXPECT_SET_ACTIVE_CONFIG(PrimaryDisplayVariant::HWC_DISPLAY_ID, kModeId120);

    mFlinger.commit();

    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getDesiredMode()->mode.modePtr->getId(), kModeId120);

    mFlinger.commit();

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId120);
}

TEST_F(DisplayModeSwitchingTest, changeResolutionOnActiveDisplayWithoutRefreshRequired) {
    ftl::FakeGuard guard(kMainThreadContext);

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    mFlinger.onActiveDisplayChanged(nullptr, *mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        mock::createDisplayModeSpecs(kModeId90_4K, false, 0, 120));

    ASSERT_TRUE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getDesiredMode()->mode.modePtr->getId(), kModeId90_4K);
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    // and complete the mode change.
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = false};
    EXPECT_SET_ACTIVE_CONFIG(PrimaryDisplayVariant::HWC_DISPLAY_ID, kModeId90_4K);

    EXPECT_CALL(*mAppEventThread, onHotplugReceived(mDisplay->getPhysicalId(), true));

    // Misc expecations. We don't need to enforce these method calls, but since the helper methods
    // already set expectations we should add new ones here, otherwise the test will fail.
    EXPECT_CALL(*mConsumer,
                setDefaultBufferSize(static_cast<uint32_t>(kResolution4K.getWidth()),
                                     static_cast<uint32_t>(kResolution4K.getHeight())))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mConsumer, consumerConnect(_, false)).WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mComposer, setClientTargetSlotCount(_)).WillOnce(Return(hal::Error::NONE));

    // Create a new native surface to be used by the recreated display.
    mNativeWindowSurface = nullptr;
    injectFakeNativeWindowSurfaceFactory();
    PrimaryDisplayVariant::setupNativeWindowSurfaceCreationCallExpectations(this);

    const auto displayToken = mDisplay->getDisplayToken().promote();

    mFlinger.commit();

    // The DisplayDevice will be destroyed and recreated,
    // so we need to update with the new instance.
    mDisplay = mFlinger.getDisplay(displayToken);

    EXPECT_FALSE(mDisplay->getDesiredMode());
    EXPECT_EQ(mDisplay->getActiveMode().modePtr->getId(), kModeId90_4K);
}

MATCHER_P2(ModeSwitchingTo, flinger, modeId, "") {
    if (!arg->getDesiredMode()) {
        *result_listener << "No desired mode";
        return false;
    }

    if (arg->getDesiredMode()->mode.modePtr->getId() != modeId) {
        *result_listener << "Unexpected desired mode " << ftl::to_underlying(modeId);
        return false;
    }

    if (!flinger->scheduler()->vsyncModulator().isVsyncConfigEarly()) {
        *result_listener << "VsyncModulator did not shift to early phase";
        return false;
    }

    return true;
}

MATCHER_P(ModeSettledTo, modeId, "") {
    if (const auto desiredOpt = arg->getDesiredMode()) {
        *result_listener << "Unsettled desired mode "
                         << ftl::to_underlying(desiredOpt->mode.modePtr->getId());
        return false;
    }

    ftl::FakeGuard guard(kMainThreadContext);

    if (arg->getActiveMode().modePtr->getId() != modeId) {
        *result_listener << "Settled to unexpected active mode " << ftl::to_underlying(modeId);
        return false;
    }

    return true;
}

TEST_F(DisplayModeSwitchingTest, innerXorOuterDisplay) {
    SET_FLAG_FOR_TEST(flags::connected_display, true);

    // For the inner display, this is handled by setupHwcHotplugCallExpectations.
    EXPECT_CALL(*mComposer, getDisplayConnectionType(kOuterDisplayHwcId, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayConnectionType::INTERNAL),
                            Return(hal::V2_4::Error::NONE)));

    const auto [innerDisplay, outerDisplay] = injectOuterDisplay();

    EXPECT_TRUE(innerDisplay->isPoweredOn());
    EXPECT_FALSE(outerDisplay->isPoweredOn());

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId60));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    // Only the inner display is powered on.
    mFlinger.onActiveDisplayChanged(nullptr, *innerDisplay);

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId60));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(innerDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId90, false,
                                                                               0.f, 120.f)));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(outerDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId60, false,
                                                                               0.f, 120.f)));

    EXPECT_THAT(innerDisplay, ModeSwitchingTo(&mFlinger, kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_SET_ACTIVE_CONFIG(kInnerDisplayHwcId, kModeId90);

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSwitchingTo(&mFlinger, kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    innerDisplay->setPowerMode(hal::PowerMode::OFF);
    outerDisplay->setPowerMode(hal::PowerMode::ON);

    // Only the outer display is powered on.
    mFlinger.onActiveDisplayChanged(innerDisplay.get(), *outerDisplay);

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSwitchingTo(&mFlinger, kModeId60));

    EXPECT_SET_ACTIVE_CONFIG(kOuterDisplayHwcId, kModeId60);

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSwitchingTo(&mFlinger, kModeId60));

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId60));
}

TEST_F(DisplayModeSwitchingTest, innerAndOuterDisplay) {
    SET_FLAG_FOR_TEST(flags::connected_display, true);

    // For the inner display, this is handled by setupHwcHotplugCallExpectations.
    EXPECT_CALL(*mComposer, getDisplayConnectionType(kOuterDisplayHwcId, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayConnectionType::INTERNAL),
                            Return(hal::V2_4::Error::NONE)));
    const auto [innerDisplay, outerDisplay] = injectOuterDisplay();

    EXPECT_TRUE(innerDisplay->isPoweredOn());
    EXPECT_FALSE(outerDisplay->isPoweredOn());

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId60));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    outerDisplay->setPowerMode(hal::PowerMode::ON);

    // Both displays are powered on.
    mFlinger.onActiveDisplayChanged(nullptr, *innerDisplay);

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId60));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(innerDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId90, false,
                                                                               0.f, 120.f)));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(outerDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId60, false,
                                                                               0.f, 120.f)));

    EXPECT_THAT(innerDisplay, ModeSwitchingTo(&mFlinger, kModeId90));
    EXPECT_THAT(outerDisplay, ModeSwitchingTo(&mFlinger, kModeId60));

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_SET_ACTIVE_CONFIG(kInnerDisplayHwcId, kModeId90);
    EXPECT_SET_ACTIVE_CONFIG(kOuterDisplayHwcId, kModeId60);

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSwitchingTo(&mFlinger, kModeId90));
    EXPECT_THAT(outerDisplay, ModeSwitchingTo(&mFlinger, kModeId60));

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId60));
}

TEST_F(DisplayModeSwitchingTest, powerOffDuringModeSet) {
    EXPECT_TRUE(mDisplay->isPoweredOn());
    EXPECT_THAT(mDisplay, ModeSettledTo(kModeId60));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId90, false,
                                                                               0.f, 120.f)));

    EXPECT_THAT(mDisplay, ModeSwitchingTo(&mFlinger, kModeId90));

    // Power off the display before the mode has been set.
    mDisplay->setPowerMode(hal::PowerMode::OFF);

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_SET_ACTIVE_CONFIG(kInnerDisplayHwcId, kModeId90);

    mFlinger.commit();

    // Powering off should not abort the mode set.
    EXPECT_FALSE(mDisplay->isPoweredOn());
    EXPECT_THAT(mDisplay, ModeSwitchingTo(&mFlinger, kModeId90));

    mFlinger.commit();

    EXPECT_THAT(mDisplay, ModeSettledTo(kModeId90));
}

TEST_F(DisplayModeSwitchingTest, powerOffDuringConcurrentModeSet) {
    SET_FLAG_FOR_TEST(flags::connected_display, true);

    // For the inner display, this is handled by setupHwcHotplugCallExpectations.
    EXPECT_CALL(*mComposer, getDisplayConnectionType(kOuterDisplayHwcId, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayConnectionType::INTERNAL),
                            Return(hal::V2_4::Error::NONE)));

    const auto [innerDisplay, outerDisplay] = injectOuterDisplay();

    EXPECT_TRUE(innerDisplay->isPoweredOn());
    EXPECT_FALSE(outerDisplay->isPoweredOn());

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId60));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    outerDisplay->setPowerMode(hal::PowerMode::ON);

    // Both displays are powered on.
    mFlinger.onActiveDisplayChanged(nullptr, *innerDisplay);

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId60));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(innerDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId90, false,
                                                                               0.f, 120.f)));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(outerDisplay->getDisplayToken().promote(),
                                                  mock::createDisplayModeSpecs(kModeId60, false,
                                                                               0.f, 120.f)));

    EXPECT_THAT(innerDisplay, ModeSwitchingTo(&mFlinger, kModeId90));
    EXPECT_THAT(outerDisplay, ModeSwitchingTo(&mFlinger, kModeId60));

    // Power off the outer display before the mode has been set.
    outerDisplay->setPowerMode(hal::PowerMode::OFF);

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_SET_ACTIVE_CONFIG(kInnerDisplayHwcId, kModeId90);

    mFlinger.commit();

    // Powering off the inactive display should abort the mode set.
    EXPECT_THAT(innerDisplay, ModeSwitchingTo(&mFlinger, kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId120));

    innerDisplay->setPowerMode(hal::PowerMode::OFF);
    outerDisplay->setPowerMode(hal::PowerMode::ON);

    // Only the outer display is powered on.
    mFlinger.onActiveDisplayChanged(innerDisplay.get(), *outerDisplay);

    EXPECT_SET_ACTIVE_CONFIG(kOuterDisplayHwcId, kModeId60);

    mFlinger.commit();

    // The mode set should resume once the display becomes active.
    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSwitchingTo(&mFlinger, kModeId60));

    mFlinger.commit();

    EXPECT_THAT(innerDisplay, ModeSettledTo(kModeId90));
    EXPECT_THAT(outerDisplay, ModeSettledTo(kModeId60));
}

} // namespace
} // namespace android
