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

#include "mock/MockEventThread.h"
#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

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
                           .setSupportedModes({kDisplayMode60, kDisplayMode90, kDisplayMode120,
                                               kDisplayMode90DifferentResolution})
                           .setActiveMode(kDisplayModeId60)
                           .inject();

        setupScheduler();

        // isVsyncPeriodSwitchSupported should return true, otherwise the SF's HWC proxy
        // will call setActiveConfig instead of setActiveConfigWithConstraints.
        ON_CALL(*mComposer, isSupported(Hwc2::Composer::OptionalFeature::RefreshRateSwitching))
                .WillByDefault(Return(true));
    }

protected:
    void setupScheduler();
    void testChangeRefreshRate(bool isDisplayActive, bool isRefreshRequired);

    sp<DisplayDevice> mDisplay;
    mock::EventThread* mAppEventThread;

    const DisplayModeId kDisplayModeId60 = DisplayModeId(0);
    const DisplayModePtr kDisplayMode60 =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId60.value()))
                    .setId(kDisplayModeId60)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod((60_Hz).getPeriodNsecs())
                    .setGroup(0)
                    .setHeight(1000)
                    .setWidth(1000)
                    .build();

    const DisplayModeId kDisplayModeId90 = DisplayModeId(1);
    const DisplayModePtr kDisplayMode90 =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId90.value()))
                    .setId(kDisplayModeId90)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod((90_Hz).getPeriodNsecs())
                    .setGroup(1)
                    .setHeight(1000)
                    .setWidth(1000)
                    .build();

    const DisplayModeId kDisplayModeId120 = DisplayModeId(2);
    const DisplayModePtr kDisplayMode120 =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId120.value()))
                    .setId(kDisplayModeId120)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod((120_Hz).getPeriodNsecs())
                    .setGroup(2)
                    .setHeight(1000)
                    .setWidth(1000)
                    .build();

    const DisplayModeId kDisplayModeId90DifferentResolution = DisplayModeId(3);
    const DisplayModePtr kDisplayMode90DifferentResolution =
            DisplayMode::Builder(hal::HWConfigId(kDisplayModeId90DifferentResolution.value()))
                    .setId(kDisplayModeId90DifferentResolution)
                    .setPhysicalDisplayId(PrimaryDisplayVariant::DISPLAY_ID::get())
                    .setVsyncPeriod((90_Hz).getPeriodNsecs())
                    .setGroup(3)
                    .setHeight(2000)
                    .setWidth(2000)
                    .build();
};

void DisplayModeSwitchingTest::setupScheduler() {
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
                            std::move(eventThread), std::move(sfEventThread), /*callback*/ nullptr,
                            /*hasMultipleModes*/ true);
}

TEST_F(DisplayModeSwitchingTest, changeRefreshRate_OnActiveDisplay_WithRefreshRequired) {
    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        kDisplayModeId90.value(), false, 0.f, 120.f, 0.f, 120.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kDisplayModeId90);
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kDisplayModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    Mock::VerifyAndClearExpectations(mComposer);
    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    // Verify that the next commit will complete the mode change and send
    // a onModeChanged event to the framework.

    EXPECT_CALL(*mAppEventThread, onModeChanged(kDisplayMode90));
    mFlinger.commit();
    Mock::VerifyAndClearExpectations(mAppEventThread);

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId90);
}

TEST_F(DisplayModeSwitchingTest, changeRefreshRate_OnActiveDisplay_WithoutRefreshRequired) {
    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        kDisplayModeId90.value(), true, 0.f, 120.f, 0.f, 120.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kDisplayModeId90);
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    // and complete the mode change.
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = false};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kDisplayModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    EXPECT_CALL(*mAppEventThread, onModeChanged(kDisplayMode90));

    mFlinger.commit();

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId90);
}

TEST_F(DisplayModeSwitchingTest, twoConsecutiveSetDesiredDisplayModeSpecs) {
    // Test that if we call setDesiredDisplayModeSpecs while a previous mode change
    // is still being processed the later call will be respected.

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        kDisplayModeId90.value(), false, 0.f, 120.f, 0.f, 120.f);

    const VsyncPeriodChangeTimeline timeline{.refreshRequired = true};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kDisplayModeId90.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        kDisplayModeId120.value(), false, 0.f, 180.f, 0.f, 180.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kDisplayModeId120);

    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(kDisplayModeId120.value()), _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    mFlinger.commit();

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kDisplayModeId120);

    mFlinger.commit();

    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId120);
}

TEST_F(DisplayModeSwitchingTest, changeResolution_OnActiveDisplay_WithoutRefreshRequired) {
    ASSERT_FALSE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    mFlinger.onActiveDisplayChanged(mDisplay);

    mFlinger.setDesiredDisplayModeSpecs(mDisplay->getDisplayToken().promote(),
                                        kDisplayModeId90DifferentResolution.value(), false, 0.f,
                                        120.f, 0.f, 120.f);

    ASSERT_TRUE(mDisplay->getDesiredActiveMode().has_value());
    ASSERT_EQ(mDisplay->getDesiredActiveMode()->mode->getId(), kDisplayModeId90DifferentResolution);
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId60);

    // Verify that next commit will call setActiveConfigWithConstraints in HWC
    // and complete the mode change.
    const VsyncPeriodChangeTimeline timeline{.refreshRequired = false};
    EXPECT_CALL(*mComposer,
                setActiveConfigWithConstraints(PrimaryDisplayVariant::HWC_DISPLAY_ID,
                                               hal::HWConfigId(
                                                       kDisplayModeId90DifferentResolution.value()),
                                               _, _))
            .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(Error::NONE)));

    EXPECT_CALL(*mAppEventThread, onHotplugReceived(mDisplay->getPhysicalId(), true));

    // Misc expecations. We don't need to enforce these method calls, but since the helper methods
    // already set expectations we should add new ones here, otherwise the test will fail.
    EXPECT_CALL(*mConsumer, setDefaultBufferSize(2000, 2000)).WillOnce(Return(NO_ERROR));
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
    ASSERT_EQ(mDisplay->getActiveMode()->getId(), kDisplayModeId90DifferentResolution);
}

} // namespace
} // namespace android
