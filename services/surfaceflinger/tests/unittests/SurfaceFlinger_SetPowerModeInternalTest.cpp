/*
 * Copyright 2020 The Android Open Source Project
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

// Used when we simulate a display that supports doze.
template <typename Display>
struct DozeIsSupportedVariant {
    static constexpr bool DOZE_SUPPORTED = true;
    static constexpr IComposerClient::PowerMode ACTUAL_POWER_MODE_FOR_DOZE =
            IComposerClient::PowerMode::DOZE;
    static constexpr IComposerClient::PowerMode ACTUAL_POWER_MODE_FOR_DOZE_SUSPEND =
            IComposerClient::PowerMode::DOZE_SUSPEND;

    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getDisplayCapabilities(Display::HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(
                                        std::vector<DisplayCapability>({DisplayCapability::DOZE})),
                                Return(Error::NONE)));
    }
};

template <typename Display>
// Used when we simulate a display that does not support doze.
struct DozeNotSupportedVariant {
    static constexpr bool DOZE_SUPPORTED = false;
    static constexpr IComposerClient::PowerMode ACTUAL_POWER_MODE_FOR_DOZE =
            IComposerClient::PowerMode::ON;
    static constexpr IComposerClient::PowerMode ACTUAL_POWER_MODE_FOR_DOZE_SUSPEND =
            IComposerClient::PowerMode::ON;

    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getDisplayCapabilities(Display::HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<DisplayCapability>({})),
                                Return(Error::NONE)));
    }
};

struct EventThreadBaseSupportedVariant {
    static void setupVsyncAndEventThreadNoCallExpectations(DisplayTransactionTest* test) {
        // The callback should not be notified to toggle VSYNC.
        EXPECT_CALL(test->mSchedulerCallback, setVsyncEnabled(_)).Times(0);

        // The event thread should not be notified.
        EXPECT_CALL(*test->mEventThread, onScreenReleased()).Times(0);
        EXPECT_CALL(*test->mEventThread, onScreenAcquired()).Times(0);
    }
};

struct EventThreadNotSupportedVariant : public EventThreadBaseSupportedVariant {
    static void setupAcquireAndEnableVsyncCallExpectations(DisplayTransactionTest* test) {
        // These calls are only expected for the primary display.

        // Instead expect no calls.
        setupVsyncAndEventThreadNoCallExpectations(test);
    }

    static void setupReleaseAndDisableVsyncCallExpectations(DisplayTransactionTest* test) {
        // These calls are only expected for the primary display.

        // Instead expect no calls.
        setupVsyncAndEventThreadNoCallExpectations(test);
    }
};

struct EventThreadIsSupportedVariant : public EventThreadBaseSupportedVariant {
    static void setupAcquireAndEnableVsyncCallExpectations(DisplayTransactionTest* test) {
        // The callback should be notified to enable VSYNC.
        EXPECT_CALL(test->mSchedulerCallback, setVsyncEnabled(true)).Times(1);

        // The event thread should be notified that the screen was acquired.
        EXPECT_CALL(*test->mEventThread, onScreenAcquired()).Times(1);
    }

    static void setupReleaseAndDisableVsyncCallExpectations(DisplayTransactionTest* test) {
        // The callback should be notified to disable VSYNC.
        EXPECT_CALL(test->mSchedulerCallback, setVsyncEnabled(false)).Times(1);

        // The event thread should not be notified that the screen was released.
        EXPECT_CALL(*test->mEventThread, onScreenReleased()).Times(1);
    }
};

struct DispSyncIsSupportedVariant {
    static void setupResetModelCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mVsyncController, startPeriodTransition(DEFAULT_VSYNC_PERIOD)).Times(1);
        EXPECT_CALL(*test->mVSyncTracker, resetModel()).Times(1);
    }
};

struct DispSyncNotSupportedVariant {
    static void setupResetModelCallExpectations(DisplayTransactionTest* /* test */) {}
};

// --------------------------------------------------------------------
// Note:
//
// There are a large number of transitions we could test, however we only test a
// selected subset which provides complete test coverage of the implementation.
// --------------------------------------------------------------------

template <PowerMode initialPowerMode, PowerMode targetPowerMode>
struct TransitionVariantCommon {
    static constexpr auto INITIAL_POWER_MODE = initialPowerMode;
    static constexpr auto TARGET_POWER_MODE = targetPowerMode;

    static void verifyPostconditions(DisplayTransactionTest*) {}
};

struct TransitionOffToOnVariant : public TransitionVariantCommon<PowerMode::OFF, PowerMode::ON> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::setupComposerCallExpectations(test, IComposerClient::PowerMode::ON);
        Case::EventThread::setupAcquireAndEnableVsyncCallExpectations(test);
        Case::DispSync::setupResetModelCallExpectations(test);
        Case::setupRepaintEverythingCallExpectations(test);
    }

    static void verifyPostconditions(DisplayTransactionTest* test) {
        EXPECT_TRUE(test->mFlinger.getVisibleRegionsDirty());
        EXPECT_TRUE(test->mFlinger.getHasPoweredOff());
    }
};

struct TransitionOffToDozeSuspendVariant
      : public TransitionVariantCommon<PowerMode::OFF, PowerMode::DOZE_SUSPEND> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::setupComposerCallExpectations(test, Case::Doze::ACTUAL_POWER_MODE_FOR_DOZE_SUSPEND);
        Case::EventThread::setupVsyncAndEventThreadNoCallExpectations(test);
        Case::setupRepaintEverythingCallExpectations(test);
    }

    static void verifyPostconditions(DisplayTransactionTest* test) {
        EXPECT_TRUE(test->mFlinger.getVisibleRegionsDirty());
        EXPECT_TRUE(test->mFlinger.getHasPoweredOff());
    }
};

struct TransitionOnToOffVariant : public TransitionVariantCommon<PowerMode::ON, PowerMode::OFF> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupReleaseAndDisableVsyncCallExpectations(test);
        Case::setupComposerCallExpectations(test, IComposerClient::PowerMode::OFF);
    }

    static void verifyPostconditions(DisplayTransactionTest* test) {
        EXPECT_TRUE(test->mFlinger.getVisibleRegionsDirty());
    }
};

struct TransitionDozeSuspendToOffVariant
      : public TransitionVariantCommon<PowerMode::DOZE_SUSPEND, PowerMode::OFF> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupVsyncAndEventThreadNoCallExpectations(test);
        Case::setupComposerCallExpectations(test, IComposerClient::PowerMode::OFF);
    }

    static void verifyPostconditions(DisplayTransactionTest* test) {
        EXPECT_TRUE(test->mFlinger.getVisibleRegionsDirty());
    }
};

struct TransitionOnToDozeVariant : public TransitionVariantCommon<PowerMode::ON, PowerMode::DOZE> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupVsyncAndEventThreadNoCallExpectations(test);
        Case::setupComposerCallExpectations(test, Case::Doze::ACTUAL_POWER_MODE_FOR_DOZE);
    }
};

struct TransitionDozeSuspendToDozeVariant
      : public TransitionVariantCommon<PowerMode::DOZE_SUSPEND, PowerMode::DOZE> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupAcquireAndEnableVsyncCallExpectations(test);
        Case::DispSync::setupResetModelCallExpectations(test);
        Case::setupComposerCallExpectations(test, Case::Doze::ACTUAL_POWER_MODE_FOR_DOZE);
    }
};

struct TransitionDozeToOnVariant : public TransitionVariantCommon<PowerMode::DOZE, PowerMode::ON> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupVsyncAndEventThreadNoCallExpectations(test);
        Case::setupComposerCallExpectations(test, IComposerClient::PowerMode::ON);
    }
};

struct TransitionDozeSuspendToOnVariant
      : public TransitionVariantCommon<PowerMode::DOZE_SUSPEND, PowerMode::ON> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupAcquireAndEnableVsyncCallExpectations(test);
        Case::DispSync::setupResetModelCallExpectations(test);
        Case::setupComposerCallExpectations(test, IComposerClient::PowerMode::ON);
    }
};

struct TransitionOnToDozeSuspendVariant
      : public TransitionVariantCommon<PowerMode::ON, PowerMode::DOZE_SUSPEND> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupReleaseAndDisableVsyncCallExpectations(test);
        Case::setupComposerCallExpectations(test, Case::Doze::ACTUAL_POWER_MODE_FOR_DOZE_SUSPEND);
    }
};

struct TransitionOnToUnknownVariant
      : public TransitionVariantCommon<PowerMode::ON, static_cast<PowerMode>(POWER_MODE_LEET)> {
    template <typename Case>
    static void setupCallExpectations(DisplayTransactionTest* test) {
        Case::EventThread::setupVsyncAndEventThreadNoCallExpectations(test);
        Case::setupNoComposerPowerModeCallExpectations(test);
    }
};

// --------------------------------------------------------------------
// Note:
//
// Rather than testing the cartesian product of
// DozeIsSupported/DozeNotSupported with all other options, we use one for one
// display type, and the other for another display type.
// --------------------------------------------------------------------

template <typename DisplayVariant, typename DozeVariant, typename EventThreadVariant,
          typename DispSyncVariant, typename TransitionVariant>
struct DisplayPowerCase {
    using Display = DisplayVariant;
    using Doze = DozeVariant;
    using EventThread = EventThreadVariant;
    using DispSync = DispSyncVariant;
    using Transition = TransitionVariant;

    static auto injectDisplayWithInitialPowerMode(DisplayTransactionTest* test, PowerMode mode) {
        Display::injectHwcDisplayWithNoDefaultCapabilities(test);
        auto display = Display::makeFakeExistingDisplayInjector(test);
        display.inject();
        display.mutableDisplayDevice()->setPowerMode(mode);
        return display;
    }

    static void setInitialPrimaryHWVsyncEnabled(DisplayTransactionTest* test, bool enabled) {
        test->mFlinger.scheduler()->mutablePrimaryHWVsyncEnabled() = enabled;
    }

    static void setupRepaintEverythingCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mMessageQueue, invalidate()).Times(1);
    }

    static void setupSurfaceInterceptorCallExpectations(DisplayTransactionTest* test,
                                                        PowerMode mode) {
        EXPECT_CALL(*test->mSurfaceInterceptor, isEnabled()).WillOnce(Return(true));
        EXPECT_CALL(*test->mSurfaceInterceptor, savePowerModeUpdate(_, static_cast<int32_t>(mode)))
                .Times(1);
    }

    static void setupComposerCallExpectations(DisplayTransactionTest* test, PowerMode mode) {
        // Any calls to get the active config will return a default value.
        EXPECT_CALL(*test->mComposer, getActiveConfig(Display::HWC_DISPLAY_ID, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(Display::HWC_ACTIVE_CONFIG_ID),
                                      Return(Error::NONE)));

        // Any calls to get whether the display supports dozing will return the value set by the
        // policy variant.
        EXPECT_CALL(*test->mComposer, getDozeSupport(Display::HWC_DISPLAY_ID, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(Doze::DOZE_SUPPORTED), Return(Error::NONE)));

        EXPECT_CALL(*test->mComposer, setPowerMode(Display::HWC_DISPLAY_ID, mode)).Times(1);
    }

    static void setupNoComposerPowerModeCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, setPowerMode(Display::HWC_DISPLAY_ID, _)).Times(0);
    }
};

// A sample configuration for the primary display.
// In addition to having event thread support, we emulate doze support.
template <typename TransitionVariant>
using PrimaryDisplayPowerCase =
        DisplayPowerCase<PrimaryDisplayVariant, DozeIsSupportedVariant<PrimaryDisplayVariant>,
                         EventThreadIsSupportedVariant, DispSyncIsSupportedVariant,
                         TransitionVariant>;

// A sample configuration for the external display.
// In addition to not having event thread support, we emulate not having doze
// support.
template <typename TransitionVariant>
using ExternalDisplayPowerCase =
        DisplayPowerCase<ExternalDisplayVariant, DozeNotSupportedVariant<ExternalDisplayVariant>,
                         EventThreadNotSupportedVariant, DispSyncNotSupportedVariant,
                         TransitionVariant>;

class SetPowerModeInternalTest : public DisplayTransactionTest {
public:
    template <typename Case>
    void transitionDisplayCommon();
};

template <PowerMode PowerMode>
struct PowerModeInitialVSyncEnabled : public std::false_type {};

template <>
struct PowerModeInitialVSyncEnabled<PowerMode::ON> : public std::true_type {};

template <>
struct PowerModeInitialVSyncEnabled<PowerMode::DOZE> : public std::true_type {};

template <typename Case>
void SetPowerModeInternalTest::transitionDisplayCommon() {
    // --------------------------------------------------------------------
    // Preconditions

    Case::Doze::setupComposerCallExpectations(this);
    auto display =
            Case::injectDisplayWithInitialPowerMode(this, Case::Transition::INITIAL_POWER_MODE);
    Case::setInitialPrimaryHWVsyncEnabled(this,
                                          PowerModeInitialVSyncEnabled<
                                                  Case::Transition::INITIAL_POWER_MODE>::value);

    // --------------------------------------------------------------------
    // Call Expectations

    Case::setupSurfaceInterceptorCallExpectations(this, Case::Transition::TARGET_POWER_MODE);
    Case::Transition::template setupCallExpectations<Case>(this);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.setPowerModeInternal(display.mutableDisplayDevice(),
                                  Case::Transition::TARGET_POWER_MODE);

    // --------------------------------------------------------------------
    // Postconditions

    Case::Transition::verifyPostconditions(this);
}

TEST_F(SetPowerModeInternalTest, setPowerModeInternalDoesNothingIfNoChange) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A primary display device is set up
    Case::Display::injectHwcDisplay(this);
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display is already set to PowerMode::ON
    display.mutableDisplayDevice()->setPowerMode(PowerMode::ON);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.setPowerModeInternal(display.mutableDisplayDevice(), PowerMode::ON);

    // --------------------------------------------------------------------
    // Postconditions

    EXPECT_EQ(PowerMode::ON, display.mutableDisplayDevice()->getPowerMode());
}

TEST_F(SetPowerModeInternalTest, setPowerModeInternalDoesNothingIfVirtualDisplay) {
    using Case = HwcVirtualDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // Insert display data so that the HWC thinks it created the virtual display.
    const auto displayId = Case::Display::DISPLAY_ID::get();
    ASSERT_TRUE(HalVirtualDisplayId::tryCast(displayId));
    mFlinger.mutableHwcDisplayData().try_emplace(displayId);

    // A virtual display device is set up
    Case::Display::injectHwcDisplay(this);
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display is set to PowerMode::ON
    getDisplayDevice(display.token())->setPowerMode(PowerMode::ON);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.setPowerModeInternal(display.mutableDisplayDevice(), PowerMode::OFF);

    // --------------------------------------------------------------------
    // Postconditions

    EXPECT_EQ(PowerMode::ON, display.mutableDisplayDevice()->getPowerMode());
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOffToOnPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionOffToOnVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOffToDozeSuspendPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionOffToDozeSuspendVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToOffPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionOnToOffVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeSuspendToOffPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionDozeSuspendToOffVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToDozePrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionOnToDozeVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeSuspendToDozePrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionDozeSuspendToDozeVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeToOnPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionDozeToOnVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeSuspendToOnPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionDozeSuspendToOnVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToDozeSuspendPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionOnToDozeSuspendVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToUnknownPrimaryDisplay) {
    transitionDisplayCommon<PrimaryDisplayPowerCase<TransitionOnToUnknownVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOffToOnExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionOffToOnVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOffToDozeSuspendExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionOffToDozeSuspendVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToOffExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionOnToOffVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeSuspendToOffExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionDozeSuspendToOffVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToDozeExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionOnToDozeVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeSuspendToDozeExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionDozeSuspendToDozeVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeToOnExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionDozeToOnVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromDozeSuspendToOnExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionDozeSuspendToOnVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToDozeSuspendExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionOnToDozeSuspendVariant>>();
}

TEST_F(SetPowerModeInternalTest, transitionsDisplayFromOnToUnknownExternalDisplay) {
    transitionDisplayCommon<ExternalDisplayPowerCase<TransitionOnToUnknownVariant>>();
}

} // namespace
} // namespace android
