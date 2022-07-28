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

namespace android {

class HotplugTest : public DisplayTransactionTest {};

TEST_F(HotplugTest, schedulesConfigureToProcessHotplugEvents) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleConfigure()).Times(2);

    constexpr HWDisplayId hwcDisplayId1 = 456;
    mFlinger.onComposerHalHotplug(hwcDisplayId1, Connection::CONNECTED);

    constexpr HWDisplayId hwcDisplayId2 = 654;
    mFlinger.onComposerHalHotplug(hwcDisplayId2, Connection::DISCONNECTED);

    const auto& pendingEvents = mFlinger.mutablePendingHotplugEvents();
    ASSERT_EQ(2u, pendingEvents.size());
    EXPECT_EQ(hwcDisplayId1, pendingEvents[0].hwcDisplayId);
    EXPECT_EQ(Connection::CONNECTED, pendingEvents[0].connection);
    EXPECT_EQ(hwcDisplayId2, pendingEvents[1].hwcDisplayId);
    EXPECT_EQ(Connection::DISCONNECTED, pendingEvents[1].connection);
}

TEST_F(HotplugTest, schedulesFrameToCommitDisplayTransaction) {
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    constexpr HWDisplayId displayId1 = 456;
    mFlinger.onComposerHalHotplug(displayId1, Connection::DISCONNECTED);
    mFlinger.configure();

    // The configure stage should consume the hotplug queue and produce a display transaction.
    EXPECT_TRUE(mFlinger.mutablePendingHotplugEvents().empty());
    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));
}

TEST_F(HotplugTest, rejectsHotplugIfFailedToLoadDisplayModes) {
    // Inject a primary display.
    PrimaryDisplayVariant::injectHwcDisplay(this);

    using ExternalDisplay = ExternalDisplayVariant;
    constexpr bool kFailedHotplug = true;
    ExternalDisplay::setupHwcHotplugCallExpectations<kFailedHotplug>(this);

    // Simulate a connect event that fails to load display modes due to HWC already having
    // disconnected the display but SF yet having to process the queued disconnect event.
    EXPECT_CALL(*mComposer, getActiveConfig(ExternalDisplay::HWC_DISPLAY_ID, _))
            .WillRepeatedly(Return(Error::BAD_DISPLAY));

    // TODO(b/241286146): Remove this unnecessary call.
    EXPECT_CALL(*mComposer,
                setVsyncEnabled(ExternalDisplay::HWC_DISPLAY_ID, IComposerClient::Vsync::DISABLE))
            .WillOnce(Return(Error::NONE));

    ExternalDisplay::injectPendingHotplugEvent(this, Connection::CONNECTED);
    mFlinger.configure();

    // The hotplug should be rejected, so no HWComposer::DisplayData should be created.
    EXPECT_FALSE(hasPhysicalHwcDisplay(ExternalDisplay::HWC_DISPLAY_ID));

    // Disconnecting a display that does not exist should be a no-op.
    ExternalDisplay::injectPendingHotplugEvent(this, Connection::DISCONNECTED);
    mFlinger.configure();

    EXPECT_FALSE(hasPhysicalHwcDisplay(ExternalDisplay::HWC_DISPLAY_ID));
}

} // namespace android
