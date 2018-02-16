/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <log/log.h>

#include "MockComposer.h"
#include "MockEventThread.h"
#include "MockRenderEngine.h"
#include "TestableSurfaceFlinger.h"

namespace android {
namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

using android::hardware::graphics::common::V1_0::Hdr;
using android::Hwc2::Error;
using android::Hwc2::IComposer;
using android::Hwc2::IComposerClient;

constexpr int32_t DEFAULT_REFRESH_RATE = 1666666666;
constexpr int32_t DEFAULT_DPI = 320;

class DisplayTransactionTest : public testing::Test {
protected:
    DisplayTransactionTest();
    ~DisplayTransactionTest() override;

    void setupComposer(int virtualDisplayCount);
    void setupPrimaryDisplay(int width, int height);

    TestableSurfaceFlinger mFlinger;
    mock::EventThread* mEventThread = new mock::EventThread();

    // These mocks are created by the test, but are destroyed by SurfaceFlinger
    // by virtue of being stored into a std::unique_ptr. However we still need
    // to keep a reference to them for use in setting up call expectations.
    RE::mock::RenderEngine* mRenderEngine = new RE::mock::RenderEngine();
    Hwc2::mock::Composer* mComposer = new Hwc2::mock::Composer();
};

DisplayTransactionTest::DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    mFlinger.mutableEventThread().reset(mEventThread);
    mFlinger.setupRenderEngine(std::unique_ptr<RE::RenderEngine>(mRenderEngine));

    setupComposer(0);
}

DisplayTransactionTest::~DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

void DisplayTransactionTest::setupComposer(int virtualDisplayCount) {
    EXPECT_CALL(*mComposer, getCapabilities())
            .WillOnce(Return(std::vector<IComposer::Capability>()));
    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    Mock::VerifyAndClear(mComposer);
}

void DisplayTransactionTest::setupPrimaryDisplay(int width, int height) {
    EXPECT_CALL(*mComposer, getDisplayType(DisplayDevice::DISPLAY_PRIMARY, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayType::PHYSICAL),
                            Return(Error::NONE)));
    EXPECT_CALL(*mComposer, setClientTargetSlotCount(_)).WillOnce(Return(Error::NONE));
    EXPECT_CALL(*mComposer, getDisplayConfigs(_, _))
            .WillOnce(DoAll(SetArgPointee<1>(std::vector<unsigned>{0}), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(DisplayDevice::DISPLAY_PRIMARY, 0,
                                    IComposerClient::Attribute::WIDTH, _))
            .WillOnce(DoAll(SetArgPointee<3>(width), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(DisplayDevice::DISPLAY_PRIMARY, 0,
                                    IComposerClient::Attribute::HEIGHT, _))
            .WillOnce(DoAll(SetArgPointee<3>(height), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(DisplayDevice::DISPLAY_PRIMARY, 0,
                                    IComposerClient::Attribute::VSYNC_PERIOD, _))
            .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_REFRESH_RATE), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(DisplayDevice::DISPLAY_PRIMARY, 0,
                                    IComposerClient::Attribute::DPI_X, _))
            .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_DPI), Return(Error::NONE)));
    EXPECT_CALL(*mComposer,
                getDisplayAttribute(DisplayDevice::DISPLAY_PRIMARY, 0,
                                    IComposerClient::Attribute::DPI_Y, _))
            .WillOnce(DoAll(SetArgPointee<3>(DEFAULT_DPI), Return(Error::NONE)));

    mFlinger.setupPrimaryDisplay();

    Mock::VerifyAndClear(mComposer);
}

TEST_F(DisplayTransactionTest, processDisplayChangesLockedProcessesPrimaryDisplayConnected) {
    using android::hardware::graphics::common::V1_0::ColorMode;

    setupPrimaryDisplay(1920, 1080);

    sp<BBinder> token = new BBinder();
    mFlinger.mutableCurrentState().displays.add(token, {DisplayDevice::DISPLAY_PRIMARY, true});

    EXPECT_CALL(*mComposer, getActiveConfig(DisplayDevice::DISPLAY_PRIMARY, _))
            .WillOnce(DoAll(SetArgPointee<1>(0), Return(Error::NONE)));
    EXPECT_CALL(*mComposer, getColorModes(DisplayDevice::DISPLAY_PRIMARY, _))
            .WillOnce(DoAll(SetArgPointee<1>(std::vector<ColorMode>({ColorMode::NATIVE})),
                            Return(Error::NONE)));

    EXPECT_CALL(*mComposer, getHdrCapabilities(DisplayDevice::DISPLAY_PRIMARY, _, _, _, _))
            .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hdr>()), Return(Error::NONE)));

    auto reSurface = new RE::mock::Surface();
    EXPECT_CALL(*mRenderEngine, createSurface())
            .WillOnce(Return(ByMove(std::unique_ptr<RE::Surface>(reSurface))));
    EXPECT_CALL(*reSurface, setAsync(false)).Times(1);
    EXPECT_CALL(*reSurface, setCritical(true)).Times(1);
    EXPECT_CALL(*reSurface, setNativeWindow(_)).Times(1);
    EXPECT_CALL(*reSurface, queryWidth()).WillOnce(Return(1920));
    EXPECT_CALL(*reSurface, queryHeight()).WillOnce(Return(1080));

    EXPECT_CALL(*mEventThread, onHotplugReceived(DisplayDevice::DISPLAY_PRIMARY, true)).Times(1);

    mFlinger.processDisplayChangesLocked();

    ASSERT_TRUE(mFlinger.mutableDisplays().indexOfKey(token) >= 0);

    const auto& device = mFlinger.mutableDisplays().valueFor(token);
    ASSERT_TRUE(device.get());
    EXPECT_TRUE(device->isSecure());
    EXPECT_TRUE(device->isPrimary());

    ssize_t i = mFlinger.mutableDrawingState().displays.indexOfKey(token);
    ASSERT_GE(0, i);
    const auto& draw = mFlinger.mutableDrawingState().displays[i];
    EXPECT_EQ(DisplayDevice::DISPLAY_PRIMARY, draw.type);

    EXPECT_CALL(*mComposer, setVsyncEnabled(0, IComposerClient::Vsync::DISABLE))
            .WillOnce(Return(Error::NONE));
}

} // namespace
} // namespace android
