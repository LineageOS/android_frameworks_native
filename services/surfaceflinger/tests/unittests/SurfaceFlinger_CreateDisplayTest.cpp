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

#include <scheduler/Fps.h>

#include "DisplayTransactionTestHelpers.h"
#include "FpsOps.h"

namespace android {
namespace {

class CreateDisplayTest : public DisplayTransactionTest {
public:
    void createDisplayWithRequestedRefreshRate(const String8& name, uint64_t displayId,
                                               float pacesetterDisplayRefreshRate,
                                               float requestedRefreshRate,
                                               float expectedAdjustedRefreshRate) {
        // --------------------------------------------------------------------
        // Call Expectations

        // --------------------------------------------------------------------
        // Invocation

        sp<IBinder> displayToken = mFlinger.createDisplay(name, false, requestedRefreshRate);

        // --------------------------------------------------------------------
        // Postconditions

        // The display should have been added to the current state
        ASSERT_TRUE(hasCurrentDisplayState(displayToken));
        const auto& display = getCurrentDisplayState(displayToken);
        EXPECT_TRUE(display.isVirtual());
        EXPECT_EQ(display.requestedRefreshRate, Fps::fromValue(requestedRefreshRate));
        EXPECT_EQ(name.c_str(), display.displayName);

        std::optional<VirtualDisplayId> vid =
                DisplayId::fromValue<VirtualDisplayId>(displayId | DisplayId::FLAG_VIRTUAL);
        ASSERT_TRUE(vid.has_value());

        sp<DisplayDevice> device =
                mFlinger.createVirtualDisplayDevice(displayToken, *vid, requestedRefreshRate);
        EXPECT_TRUE(device->isVirtual());
        device->adjustRefreshRate(Fps::fromValue(pacesetterDisplayRefreshRate));
        // verifying desired value
        EXPECT_EQ(device->getAdjustedRefreshRate(), Fps::fromValue(expectedAdjustedRefreshRate));
        // verifying rounding up
        if (requestedRefreshRate < pacesetterDisplayRefreshRate) {
            EXPECT_GE(device->getAdjustedRefreshRate(), Fps::fromValue(requestedRefreshRate));
        } else {
            EXPECT_EQ(device->getAdjustedRefreshRate(),
                      Fps::fromValue(pacesetterDisplayRefreshRate));
        }

        // --------------------------------------------------------------------
        // Cleanup conditions
    }
};

TEST_F(CreateDisplayTest, createDisplaySetsCurrentStateForNonsecureDisplay) {
    const String8 name("virtual.test");

    // --------------------------------------------------------------------
    // Call Expectations

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
    EXPECT_EQ(name.c_str(), display.displayName);

    // --------------------------------------------------------------------
    // Cleanup conditions

    // Creating the display commits a display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);
}

TEST_F(CreateDisplayTest, createDisplaySetsCurrentStateForSecureDisplay) {
    const String8 name("virtual.test");

    // --------------------------------------------------------------------
    // Call Expectations

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
    EXPECT_EQ(name.c_str(), display.displayName);

    // --------------------------------------------------------------------
    // Cleanup conditions

    // Creating the display commits a display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);
}

// Requesting 0 tells SF not to do anything, i.e., default to refresh as physical displays
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRate0) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 60.f;
    const float kRequestedRefreshRate = 0.f;
    const float kExpectedAdjustedRefreshRate = 0.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

// Requesting negative refresh rate, will be ignored, same as requesting 0
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRateNegative) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 60.f;
    const float kRequestedRefreshRate = -60.f;
    const float kExpectedAdjustedRefreshRate = 0.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

// Requesting a higher refresh rate than the pacesetter
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRateHigh) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 60.f;
    const float kRequestedRefreshRate = 90.f;
    const float kExpectedAdjustedRefreshRate = 60.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

// Requesting the same refresh rate as the pacesetter
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRateSame) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 60.f;
    const float kRequestedRefreshRate = 60.f;
    const float kExpectedAdjustedRefreshRate = 60.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

// Requesting a divisor (30) of the pacesetter (60) should be honored
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRateDivisor) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 60.f;
    const float kRequestedRefreshRate = 30.f;
    const float kExpectedAdjustedRefreshRate = 30.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

// Requesting a non divisor (45) of the pacesetter (120) should round up to a divisor (60)
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRateNoneDivisor) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 120.f;
    const float kRequestedRefreshRate = 45.f;
    const float kExpectedAdjustedRefreshRate = 60.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

// Requesting a non divisor (75) of the pacesetter (120) should round up to pacesetter (120)
TEST_F(CreateDisplayTest, createDisplayWithRequestedRefreshRateNoneDivisorMax) {
    const String8 displayName("virtual.test");
    const uint64_t displayId = 123ull;
    const float kPacesetterDisplayRefreshRate = 120.f;
    const float kRequestedRefreshRate = 75.f;
    const float kExpectedAdjustedRefreshRate = 120.f;
    createDisplayWithRequestedRefreshRate(displayName, displayId, kPacesetterDisplayRefreshRate,
                                          kRequestedRefreshRate, kExpectedAdjustedRefreshRate);
}

} // namespace
} // namespace android
