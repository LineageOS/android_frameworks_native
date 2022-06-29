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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <scheduler/TimeKeeper.h>
#include <scheduler/Timer.h>

#include "AsyncCallRecorder.h"

namespace android::scheduler {

struct TestableTimer : public Timer {
public:
    void makeEpollError() {
        // close the epoll file descriptor to cause an epoll error
        close(mEpollFd);
    }
};

struct TimerTest : testing::Test {
    static constexpr int kIterations = 20;

    AsyncCallRecorder<void (*)()> mCallbackRecorder;
    TestableTimer mTimer;

    void timerCallback() { mCallbackRecorder.recordCall(); }
};

TEST_F(TimerTest, callsCallbackIfScheduledInPast) {
    for (int i = 0; i < kIterations; i++) {
        mTimer.alarmAt(std::bind(&TimerTest::timerCallback, this), systemTime() - 1'000'000);
        EXPECT_TRUE(mCallbackRecorder.waitForCall().has_value());
        EXPECT_FALSE(mCallbackRecorder.waitForUnexpectedCall().has_value());
    }
}

TEST_F(TimerTest, recoversAfterEpollError) {
    for (int i = 0; i < kIterations; i++) {
        mTimer.makeEpollError();
        mTimer.alarmAt(std::bind(&TimerTest::timerCallback, this), systemTime() - 1'000'000);
        EXPECT_TRUE(mCallbackRecorder.waitForCall().has_value());
        EXPECT_FALSE(mCallbackRecorder.waitForUnexpectedCall().has_value());
    }
}

} // namespace android::scheduler
