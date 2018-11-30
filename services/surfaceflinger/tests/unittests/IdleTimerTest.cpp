/*
 * Copyright 2018 The Android Open Source Project
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
#define LOG_TAG "SchedulerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <utils/Log.h>

#include "AsyncCallRecorder.h"
#include "Scheduler/IdleTimer.h"

using namespace std::chrono_literals;

namespace android {
namespace scheduler {

class IdleTimerTest : public testing::Test {
protected:
    IdleTimerTest() = default;
    ~IdleTimerTest() override = default;

    AsyncCallRecorder<void (*)()> mExpiredTimerCallback;

    std::unique_ptr<IdleTimer> mIdleTimer;
};

namespace {
TEST_F(IdleTimerTest, createAndDestroyTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(30ms, [] {});
}

TEST_F(IdleTimerTest, startStopTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(30ms, mExpiredTimerCallback.getInvocable());
    mIdleTimer->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    // The timer expires after 30 ms, so the call to the callback should not happen.
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall().has_value());
    mIdleTimer->stop();
}

TEST_F(IdleTimerTest, resetTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(20ms, mExpiredTimerCallback.getInvocable());
    mIdleTimer->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    // The timer expires after 30 ms, so the call to the callback should not happen.
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall(1us).has_value());
    mIdleTimer->reset();
    // The timer was reset, so the call to the callback should not happen.
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall(1us).has_value());
    mIdleTimer->stop();
}

TEST_F(IdleTimerTest, startNotCalledTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(3ms, mExpiredTimerCallback.getInvocable());
    std::this_thread::sleep_for(6ms);
    // The start hasn't happened, so the callback does not happen.
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall(1us).has_value());
    mIdleTimer->stop();
}

TEST_F(IdleTimerTest, idleTimerIdlesTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(3ms, mExpiredTimerCallback.getInvocable());
    mIdleTimer->start();
    std::this_thread::sleep_for(6ms);
    // The timer expires after 3 ms, so the call to the callback happens.
    EXPECT_TRUE(mExpiredTimerCallback.waitForCall(1us).has_value());
    std::this_thread::sleep_for(6ms);
    // Timer can be idle.
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall(1us).has_value());
    // Timer can be reset.
    mIdleTimer->reset();
    std::this_thread::sleep_for(6ms);
    // Timer fires again.
    EXPECT_TRUE(mExpiredTimerCallback.waitForCall(1us).has_value());
    mIdleTimer->stop();
}

TEST_F(IdleTimerTest, timeoutCallbackExecutionTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(3ms, mExpiredTimerCallback.getInvocable());

    mIdleTimer->start();
    std::this_thread::sleep_for(6ms);
    // The timer expires after 3 ms, so the call to the callback should happen.
    EXPECT_TRUE(mExpiredTimerCallback.waitForCall(1us).has_value());
    mIdleTimer->stop();
}

TEST_F(IdleTimerTest, noCallbacksAfterStopAndResetTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(3ms, mExpiredTimerCallback.getInvocable());
    mIdleTimer->start();
    std::this_thread::sleep_for(6ms);
    EXPECT_TRUE(mExpiredTimerCallback.waitForCall().has_value());
    mIdleTimer->stop();
    mIdleTimer->reset();
    std::this_thread::sleep_for(6ms);
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall().has_value());
}

TEST_F(IdleTimerTest, noCallbacksAfterStopTest) {
    mIdleTimer = std::make_unique<scheduler::IdleTimer>(3ms, mExpiredTimerCallback.getInvocable());
    mIdleTimer->start();
    std::this_thread::sleep_for(1ms);
    mIdleTimer->stop();
    std::this_thread::sleep_for(3ms);
    EXPECT_FALSE(mExpiredTimerCallback.waitForCall(1us).has_value());
}

} // namespace
} // namespace scheduler
} // namespace android