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

#include <scheduler/Fps.h>

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

        mFlinger.onComposerHalHotplug(PrimaryDisplayVariant::HWC_DISPLAY_ID, Connection::CONNECTED);

        mDisplay = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this)
                           .setDisplayModes(kModes, kModeId60)
                           .inject();

        setupScheduler(mDisplay->holdRefreshRateConfigs());

        // isVsyncPeriodSwitchSupported should return true, otherwise the SF's HWC proxy
        // will call setActiveConfig instead of setActiveConfigWithConstraints.
        ON_CALL(*mComposer, isSupported(Hwc2::Composer::OptionalFeature::RefreshRateSwitching))
                .WillByDefault(Return(true));
    }

protected:
    void setupScheduler(std::shared_ptr<scheduler::RefreshRateConfigs>);

    sp<DisplayDevice> mDisplay;
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
        std::shared_ptr<scheduler::RefreshRateConfigs> configs) {
    auto eventThread = std::make_unique<mock::EventThread>();
    mAppEventThread = eventThread.get();
    auto sfEventThread = std::make_unique<mock::EventThread>();

    EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*eventThread, createEventConnection(_, _))
            .WillOnce(Return(new EventThreadConnection(eventThread.get(), /*callingUid=*/0,
                                                       ResyncCallback())));

    EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
            .WillOnce(Return(new EventThreadConnection(sfEventThread.get(), /*callingUid=*/0,
                                                       ResyncCallback())));

    auto vsyncController = std::make_unique<mock::VsyncController>();
    auto vsyncTracker = std::make_unique<mock::VSyncTracker>();

    EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*vsyncTracker, currentPeriod())
            .WillRepeatedly(
                    Return(TestableSurfaceFlinger::FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));
    EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
    mFlinger.setupScheduler(std::move(vsyncController), std::move(vsyncTracker),
                            std::move(eventThread), std::move(sfEventThread),
                            TestableSurfaceFlinger::SchedulerCallbackImpl::kNoOp,
                            std::move(configs));
}

TEST_F(DisplayModeSwitchingTest, changeRefreshRate_OnActiveDisplay_WithRefreshRequired) {
    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(), kModeId90.value(),
                                        false, 0.f, 120.f, 0.f, 120.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kModeId90);
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    Mock::VerifyAndClearExpectations(mComposer);
    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    // Verify that the next commit will complete the mode change and send
    // a onModeChanged event to the framework.

    EXPECT_CALL(*mAppEventThread, onModeChanged(kMode90));
    mFlinger.commit();
    Mock::VerifyAndClearExpectations(mAppEventThread);

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId90);
}

TEST_F(DisplayModeSwitchingTest, changeRefreshRate_OnActiveDisplay_WithoutRefreshRequired) {
    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(), kModeId90.value(),
                                        true, 0.f, 120.f, 0.f, 120.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kModeId90);
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    // and complete the mode change.
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = false};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    EXPECT_CALL(*mAppEventThread, onModeChanged(kMode90));

    mFlinger.commit();

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId90);
}

TEST_F(DisplayModeSwitchingTest, twoConsecutiveSetDesiredDisplayModeSpecs) {
    // Test that if we call setDesiredDisplayModeSpecs while a previous mode change
    // is still being processed the later call will be respected.

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(), kModeId90.value(),
                                        false, 0.f, 120.f, 0.f, 120.f);

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(), kModeId120.value(),
                                        false, 0.f, 180.f, 0.f, 180.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kModeId120);

    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kModeId120.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kModeId120);

    mFlinger.commit();

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId120);
}

TEST_F(DisplayModeSwitchingTest, changeResolution_OnActiveDisplay_WithoutRefreshRequired) {
    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(), kModeId90_4K.value(),
                                        false, 0.f, 120.f, 0.f, 120.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kModeId90_4K);
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    // and complete the mode change.
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = false};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kModeId90_4K.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

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

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kModeId90_4K);
}

TEST_F(DisplayModeSwitchingTest, multiDisplay) {
    constexpr HWDisplayId kInnerDisplayHwcId = PrimaryDisplayVariant::HWC_DISPLAY_ID;
    constexpr HWDisplayId kOuterDisplayHwcId = kInnerDisplayHwcId + 1;

    constexpr PhysicalDisplayId kOuterDisplayId = PhysicalDisplayId::fromPort(254u);

    constexpr bool kIsPrimary = false;
    TestableSurfaceFlinger::FakeHwcDisplayInjector(kOuterDisplayId, hal::DisplayType::PHYSICAL,
                                                   kIsPrimary)
            .setHwcDisplayId(kOuterDisplayHwcId)
            .inject(&mFlinger, mComposer);

    const auto outerDisplay = mFakeDisplayInjector.injectInternalDisplay(
            [&](FakeDisplayDeviceInjector& injector) {
                injector.setDisplayModes(mock::cloneForDisplay(kOuterDisplayId, kModes),
                                         kModeId120);
            },
            {.displayId = kOuterDisplayId,
             .hwcDisplayId = kOuterDisplayHwcId,
             .isPrimary = kIsPrimary});

    const auto& innerDisplay = mDisplay;

    EXPECT_FALSE(innerDisplay->getDesiredActiveMode());
    EXPECT_FALSE(outerDisplay->getDesiredActiveMode());

    EXPECT_EQ(innerDisplay->getActiveMode()->getId(), kModeId60);
    EXPECT_EQ(outerDisplay->getActiveMode()->getId(), kModeId120);

    mFlinger.onActiveDisplayChanged(innerDisplay);

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(innerDisplay->getDisplayToken().promote(),
                                                  kModeId90.value(), false, 0.f, 120.f, 0.f,
                                                  120.f));

    EXPECT_EQ(NO_ERROR,
              mFlinger.setDesiredDisplayModeSpecs(outerDisplay->getDisplayToken().promote(),
                                                  kModeId60.value(), false, 0.f, 120.f, 0.f,
                                                  120.f));

    // Transition on the inner display.
    ASSERT_TRUE(innerDisplay->getDesiredActiveMode());
    EXPECT_EQ(innerDisplay->getDesiredActiveMode()->mode->getId(), kModeId90);

    // No transition on the outer display.
    EXPECT_FALSE(outerDisplay->getDesiredActiveMode());

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(kInnerDisplayHwcId,
                                               hal::HWConfigId(kModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    // Transition on the inner display.
    ASSERT_TRUE(innerDisplay->getDesiredActiveMode());
    EXPECT_EQ(innerDisplay->getDesiredActiveMode()->mode->getId(), kModeId90);

    // No transition on the outer display.
    EXPECT_FALSE(outerDisplay->getDesiredActiveMode());

    mFlinger.commit();

    // Transition on the inner display.
    EXPECT_FALSE(innerDisplay->getDesiredActiveMode());
    EXPECT_EQ(innerDisplay->getActiveMode()->getId(), kModeId90);

    // No transition on the outer display.
    EXPECT_FALSE(outerDisplay->getDesiredActiveMode());
    EXPECT_EQ(outerDisplay->getActiveMode()->getId(), kModeId120);

    mFlinger.onActiveDisplayChanged(outerDisplay);

    // No transition on the inner display.
    EXPECT_FALSE(innerDisplay->getDesiredActiveMode());

    // Transition on the outer display.
    ASSERT_TRUE(outerDisplay->getDesiredActiveMode());
    EXPECT_EQ(outerDisplay->getDesiredActiveMode()->mode->getId(), kModeId60);

    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(kOuterDisplayHwcId,
                                               hal::HWConfigId(kModeId60.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    // No transition on the inner display.
    EXPECT_FALSE(innerDisplay->getDesiredActiveMode());

    // Transition on the outer display.
    ASSERT_TRUE(outerDisplay->getDesiredActiveMode());
    EXPECT_EQ(outerDisplay->getDesiredActiveMode()->mode->getId(), kModeId60);

    mFlinger.commit();

    // No transition on the inner display.
    EXPECT_FALSE(innerDisplay->getDesiredActiveMode());
    EXPECT_EQ(innerDisplay->getActiveMode()->getId(), kModeId90);

    // Transition on the outer display.
    EXPECT_FALSE(outerDisplay->getDesiredActiveMode());
    EXPECT_EQ(outerDisplay->getActiveMode()->getId(), kModeId60);
}

} // namespace
} // namespace android
