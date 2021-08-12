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

#include <android/hardware/power/Boost.h>

namespace android {
namespace {

using android::hardware::power::Boost;

TEST_F(DisplayTransactionTest, notifyPowerBoostNotifiesTouchEvent) {
    using namespace std::chrono_literals;

    mFlinger.scheduler()->replaceTouchTimer(100);
    std::this_thread::sleep_for(10ms);                  // wait for callback to be triggered
    EXPECT_TRUE(mFlinger.scheduler()->isTouchActive()); // Starting timer activates touch

    std::this_thread::sleep_for(110ms); // wait for reset touch timer to expire and trigger callback
    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive());

    EXPECT_EQ(NO_ERROR, mFlinger.notifyPowerBoost(static_cast<int32_t>(Boost::CAMERA_SHOT)));
    std::this_thread::sleep_for(10ms); // wait for callback to maybe be triggered
    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive());

    std::this_thread::sleep_for(110ms); // wait for reset touch timer to expire and trigger callback
    EXPECT_FALSE(mFlinger.scheduler()->isTouchActive());

    EXPECT_EQ(NO_ERROR, mFlinger.notifyPowerBoost(static_cast<int32_t>(Boost::INTERACTION)));
    std::this_thread::sleep_for(10ms); // wait for callback to be triggered.
    EXPECT_TRUE(mFlinger.scheduler()->isTouchActive());
}

} // namespace
} // namespace android
