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
namespace {

class CreateDisplayTest : public DisplayTransactionTest {};

TEST_F(CreateDisplayTest, createDisplaySetsCurrentStateForNonsecureDisplay) {
    const String8 name("virtual.test");

    // --------------------------------------------------------------------
    // Call Expectations

    // The call should notify the interceptor that a display was created.
    EXPECT_CALL(*mSurfaceInterceptor, saveDisplayCreation(_)).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    sp<IBinder> displayToken = mFlinger.createDisplay(name, false);

    // --------------------------------------------------------------------
    // Postconditions

    // The display should have been added to the current state
    ASSERT_TRUE(hasCurrentDisplayState(displayToken));
    const auto& display = getCurrentDisplayState(displayToken);
    EXPECT_TRUE(display.isVirtual());
    EXPECT_FALSE(display.isSecure);
    EXPECT_EQ(name.string(), display.displayName);

    // --------------------------------------------------------------------
    // Cleanup conditions

    // Creating the display commits a display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);
}

TEST_F(CreateDisplayTest, createDisplaySetsCurrentStateForSecureDisplay) {
    const String8 name("virtual.test");

    // --------------------------------------------------------------------
    // Call Expectations

    // The call should notify the interceptor that a display was created.
    EXPECT_CALL(*mSurfaceInterceptor, saveDisplayCreation(_)).Times(1);

    // --------------------------------------------------------------------
    // Invocation
    int64_t oldId = IPCThreadState::self()->clearCallingIdentity();
    // Set the calling identity to graphics so captureDisplay with secure is allowed.
    IPCThreadState::self()->restoreCallingIdentity(static_cast<int64_t>(AID_GRAPHICS) << 32 |
                                                   AID_GRAPHICS);
    sp<IBinder> displayToken = mFlinger.createDisplay(name, true);
    IPCThreadState::self()->restoreCallingIdentity(oldId);

    // --------------------------------------------------------------------
    // Postconditions

    // The display should have been added to the current state
    ASSERT_TRUE(hasCurrentDisplayState(displayToken));
    const auto& display = getCurrentDisplayState(displayToken);
    EXPECT_TRUE(display.isVirtual());
    EXPECT_TRUE(display.isSecure);
    EXPECT_EQ(name.string(), display.displayName);

    // --------------------------------------------------------------------
    // Cleanup conditions

    // Creating the display commits a display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);
}

} // namespace
} // namespace android
