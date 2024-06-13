/*
 * Copyright 2024 The Android Open Source Project
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

#include "Display/DisplayModeController.h"
#include "Display/DisplaySnapshot.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayIdentificationTestHelpers.h"
#include "FpsOps.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockFrameRateMode.h"

#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define EXPECT_DISPLAY_MODE_REQUEST(expected, requestOpt)                               \
    ASSERT_TRUE(requestOpt);                                                            \
    EXPECT_FRAME_RATE_MODE(expected.mode.modePtr, expected.mode.fps, requestOpt->mode); \
    EXPECT_EQ(expected.emitEvent, requestOpt->emitEvent)

namespace android::display {
namespace {

namespace hal = android::hardware::graphics::composer::hal;

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

class DisplayModeControllerTest : public testing::Test {
public:
    using Action = DisplayModeController::DesiredModeAction;

    void SetUp() override {
        mDmc.setHwComposer(mComposer.get());
        mDmc.setActiveModeListener(
                [this](PhysicalDisplayId displayId, Fps vsyncRate, Fps renderFps) {
                    mActiveModeListener.Call(displayId, vsyncRate, renderFps);
                });

        constexpr uint8_t kPort = 111;
        EXPECT_CALL(*mComposerHal, getDisplayIdentificationData(kHwcDisplayId, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(kPort), SetArgPointee<2>(getInternalEdid()),
                                Return(hal::Error::NONE)));

        EXPECT_CALL(*mComposerHal, setClientTargetSlotCount(kHwcDisplayId));
        EXPECT_CALL(*mComposerHal,
                    setVsyncEnabled(kHwcDisplayId, hal::IComposerClient::Vsync::DISABLE));
        EXPECT_CALL(*mComposerHal, onHotplugConnect(kHwcDisplayId));

        const auto infoOpt = mComposer->onHotplug(kHwcDisplayId, hal::Connection::CONNECTED);
        ASSERT_TRUE(infoOpt);

        mDisplayId = infoOpt->id;
        mDisplaySnapshotOpt.emplace(mDisplayId, ui::DisplayConnectionType::Internal,
                                    makeModes(kMode60, kMode90, kMode120), ui::ColorModes{},
                                    std::nullopt);

        ftl::FakeGuard guard(kMainThreadContext);
        mDmc.registerDisplay(*mDisplaySnapshotOpt, kModeId60,
                             scheduler::RefreshRateSelector::Config{});
    }

protected:
    hal::VsyncPeriodChangeConstraints expectModeSet(const DisplayModeRequest& request,
                                                    hal::VsyncPeriodChangeTimeline& timeline,
                                                    bool subsequent = false) {
        EXPECT_CALL(*mComposerHal,
                    isSupported(Hwc2::Composer::OptionalFeature::RefreshRateSwitching))
                .WillOnce(Return(true));

        if (!subsequent) {
            EXPECT_CALL(*mComposerHal, getDisplayConnectionType(kHwcDisplayId, _))
                    .WillOnce(DoAll(SetArgPointee<1>(
                                            hal::IComposerClient::DisplayConnectionType::INTERNAL),
                                    Return(hal::V2_4::Error::NONE)));
        }

        const hal::VsyncPeriodChangeConstraints constraints{
                .desiredTimeNanos = systemTime(),
                .seamlessRequired = false,
        };

        const hal::HWConfigId hwcModeId = request.mode.modePtr->getHwcId();

        EXPECT_CALL(*mComposerHal,
                    setActiveConfigWithConstraints(kHwcDisplayId, hwcModeId, constraints, _))
                .WillOnce(DoAll(SetArgPointee<3>(timeline), Return(hal::V2_4::Error::NONE)));

        return constraints;
    }

    static constexpr hal::HWDisplayId kHwcDisplayId = 1234;

    Hwc2::mock::Composer* mComposerHal = new testing::StrictMock<Hwc2::mock::Composer>();
    const std::unique_ptr<HWComposer> mComposer{
            std::make_unique<impl::HWComposer>(std::unique_ptr<Hwc2::Composer>(mComposerHal))};

    testing::MockFunction<void(PhysicalDisplayId, Fps, Fps)> mActiveModeListener;

    DisplayModeController mDmc;

    PhysicalDisplayId mDisplayId;
    std::optional<DisplaySnapshot> mDisplaySnapshotOpt;

    static constexpr DisplayModeId kModeId60{0};
    static constexpr DisplayModeId kModeId90{1};
    static constexpr DisplayModeId kModeId120{2};

    static inline const ftl::NonNull<DisplayModePtr> kMode60 =
            ftl::as_non_null(mock::createDisplayMode(kModeId60, 60_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode90 =
            ftl::as_non_null(mock::createDisplayMode(kModeId90, 90_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kMode120 =
            ftl::as_non_null(mock::createDisplayMode(kModeId120, 120_Hz));

    static inline const DisplayModeRequest kDesiredMode30{{30_Hz, kMode60}, .emitEvent = false};
    static inline const DisplayModeRequest kDesiredMode60{{60_Hz, kMode60}, .emitEvent = true};
    static inline const DisplayModeRequest kDesiredMode90{{90_Hz, kMode90}, .emitEvent = false};
    static inline const DisplayModeRequest kDesiredMode120{{120_Hz, kMode120}, .emitEvent = true};
};

TEST_F(DisplayModeControllerTest, setDesiredModeToActiveMode) {
    EXPECT_CALL(mActiveModeListener, Call(_, _, _)).Times(0);

    EXPECT_EQ(Action::None, mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode60)));
    EXPECT_FALSE(mDmc.getDesiredMode(mDisplayId));
}

TEST_F(DisplayModeControllerTest, setDesiredMode) {
    // Called because setDesiredMode resets the render rate to the active refresh rate.
    EXPECT_CALL(mActiveModeListener, Call(mDisplayId, 60_Hz, 60_Hz)).Times(1);

    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode90)));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode90, mDmc.getDesiredMode(mDisplayId));

    // No action since a mode switch has already been initiated.
    EXPECT_EQ(Action::None, mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode120)));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode120, mDmc.getDesiredMode(mDisplayId));
}

TEST_F(DisplayModeControllerTest, clearDesiredMode) {
    // Called because setDesiredMode resets the render rate to the active refresh rate.
    EXPECT_CALL(mActiveModeListener, Call(mDisplayId, 60_Hz, 60_Hz)).Times(1);

    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode90)));
    EXPECT_TRUE(mDmc.getDesiredMode(mDisplayId));

    mDmc.clearDesiredMode(mDisplayId);
    EXPECT_FALSE(mDmc.getDesiredMode(mDisplayId));
}

TEST_F(DisplayModeControllerTest, initiateModeChange) REQUIRES(kMainThreadContext) {
    // Called because setDesiredMode resets the render rate to the active refresh rate.
    EXPECT_CALL(mActiveModeListener, Call(mDisplayId, 60_Hz, 60_Hz)).Times(1);

    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode90)));

    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode90, mDmc.getDesiredMode(mDisplayId));
    auto modeRequest = kDesiredMode90;

    hal::VsyncPeriodChangeTimeline timeline;
    const auto constraints = expectModeSet(modeRequest, timeline);

    EXPECT_TRUE(mDmc.initiateModeChange(mDisplayId, std::move(modeRequest), constraints, timeline));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode90, mDmc.getPendingMode(mDisplayId));

    mDmc.clearDesiredMode(mDisplayId);
    EXPECT_FALSE(mDmc.getDesiredMode(mDisplayId));
}

TEST_F(DisplayModeControllerTest, initiateRenderRateSwitch) {
    EXPECT_CALL(mActiveModeListener, Call(mDisplayId, 60_Hz, 30_Hz)).Times(1);

    EXPECT_EQ(Action::InitiateRenderRateSwitch,
              mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode30)));
    EXPECT_FALSE(mDmc.getDesiredMode(mDisplayId));
}

TEST_F(DisplayModeControllerTest, initiateDisplayModeSwitch) FTL_FAKE_GUARD(kMainThreadContext) {
    // Called because setDesiredMode resets the render rate to the active refresh rate.
    EXPECT_CALL(mActiveModeListener, Call(mDisplayId, 60_Hz, 60_Hz)).Times(1);

    EXPECT_EQ(Action::InitiateDisplayModeSwitch,
              mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode90)));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode90, mDmc.getDesiredMode(mDisplayId));
    auto modeRequest = kDesiredMode90;

    hal::VsyncPeriodChangeTimeline timeline;
    auto constraints = expectModeSet(modeRequest, timeline);

    EXPECT_TRUE(mDmc.initiateModeChange(mDisplayId, std::move(modeRequest), constraints, timeline));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode90, mDmc.getPendingMode(mDisplayId));

    // No action since a mode switch has already been initiated.
    EXPECT_EQ(Action::None, mDmc.setDesiredMode(mDisplayId, DisplayModeRequest(kDesiredMode120)));

    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode90, mDmc.getPendingMode(mDisplayId));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode120, mDmc.getDesiredMode(mDisplayId));
    modeRequest = kDesiredMode120;

    constexpr bool kSubsequent = true;
    constraints = expectModeSet(modeRequest, timeline, kSubsequent);

    EXPECT_TRUE(mDmc.initiateModeChange(mDisplayId, std::move(modeRequest), constraints, timeline));
    EXPECT_DISPLAY_MODE_REQUEST(kDesiredMode120, mDmc.getPendingMode(mDisplayId));

    mDmc.clearDesiredMode(mDisplayId);
    EXPECT_FALSE(mDmc.getDesiredMode(mDisplayId));
}

} // namespace
} // namespace android::display
