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

#include <chrono>
#include <thread>

#include "DisplayTransactionTestHelpers.h"
#include "FakeDisplayInjector.h"

#include <aidl/android/hardware/power/Boost.h>

namespace android {
namespace {

using aidl::android::hardware::power::Boost;

TEST_F(DisplayTransactionTest, notifyPowerBoostNotifiesTouchEvent) {
    using namespace std::chrono_literals;

    std::mutex timerMutex;
    std::condition_variable cv;

    injectDefaultInternalDisplay([](FakeDisplayDeviceInjector&) {});

    std::unique_lock lock(timerMutex);
    bool didReset = false; // keeps track of what the most recent call was

    auto waitForTimerReset = [&] { cv.wait_for(lock, 100ms, [&] { return didReset; }); };
    auto waitForTimerExpired = [&] { cv.wait_for(lock, 100ms, [&] { return !didReset; }); };

    // Add extra logic to unblock the test when the timer callbacks get called
    mFlinger.scheduler()->replaceTouchTimer(10, [&](bool isReset) {
        {
            std::unique_lock lock(timerMutex); // guarantee we're waiting on the cv
            didReset = isReset;
        }
        cv.notify_one();                   // wake the cv
        std::unique_lock lock(timerMutex); // guarantee we finished the cv logic
    });

    waitForTimerReset();
    EXPECT_TRUE(mFlinger.scheduler()->isTouchActive()); // Starting timer activates touch

    waitForTimerExpired();
    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive()); // Stopping timer deactivates touch

    EXPECT_EQ(NO_ERROR, mFlinger.notifyPowerBoost(static_cast<int32_t>(Boost::CAMERA_SHOT)));

    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive());
    // Wait for the timer to start just in case
    waitForTimerReset();
    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive());
    // Wait for the timer to stop, again just in case
    waitForTimerExpired();
    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive());

    EXPECT_EQ(NO_ERROR, mFlinger.notifyPowerBoost(static_cast<int32_t>(Boost::INTERACTION)));
    waitForTimerReset();
    EXPECT_TRUE(mFlinger.scheduler()->isTouchActive());
}

} // namespace
} // namespace android
