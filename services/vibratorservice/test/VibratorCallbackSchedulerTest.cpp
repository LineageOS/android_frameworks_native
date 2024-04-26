/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <vibratorservice/VibratorCallbackScheduler.h>

#include "test_utils.h"

using std::chrono::milliseconds;
using std::chrono::steady_clock;
using std::chrono::time_point;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

// Delay allowed for the scheduler to process callbacks during this test.
static const auto TEST_TIMEOUT = 100ms;

class VibratorCallbackSchedulerTest : public Test {
public:
    void SetUp() override { mScheduler = std::make_unique<vibrator::CallbackScheduler>(); }

protected:
    std::mutex mMutex;
    std::unique_ptr<vibrator::CallbackScheduler> mScheduler = nullptr;
    vibrator::TestCounter mCallbackCounter;
    std::vector<int32_t> mExpiredCallbacks GUARDED_BY(mMutex);

    std::function<void()> createCallback(int32_t id) {
        return [this, id]() {
            {
                std::lock_guard<std::mutex> lock(mMutex);
                mExpiredCallbacks.push_back(id);
            }
            mCallbackCounter.increment();
        };
    }

    std::vector<int32_t> getExpiredCallbacks() {
        std::lock_guard<std::mutex> lock(mMutex);
        return std::vector<int32_t>(mExpiredCallbacks);
    }

    int32_t waitForCallbacks(int32_t callbackCount, milliseconds timeout) {
        mCallbackCounter.tryWaitUntilCountIsAtLeast(callbackCount, timeout);
        return mCallbackCounter.get();
    }
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorCallbackSchedulerTest, TestScheduleRunsOnlyAfterDelay) {
    auto callbackDuration = 50ms;
    time_point<steady_clock> startTime = steady_clock::now();
    mScheduler->schedule(createCallback(1), callbackDuration);

    ASSERT_THAT(waitForCallbacks(1, callbackDuration + TEST_TIMEOUT), Eq(1));
    time_point<steady_clock> callbackTime = steady_clock::now();

    // Callback took at least the required duration to trigger.
    ASSERT_THAT(callbackTime, Ge(startTime + callbackDuration));
}

TEST_F(VibratorCallbackSchedulerTest, TestScheduleMultipleCallbacksRunsInDelayOrder) {
    // Schedule first callbacks long enough that all 3 will be scheduled together and run in order.
    mScheduler->schedule(createCallback(1), 50ms + 2 * TEST_TIMEOUT);
    mScheduler->schedule(createCallback(2), 50ms + TEST_TIMEOUT);
    mScheduler->schedule(createCallback(3), 50ms);

    // Callbacks triggered in the expected order based on the requested durations.
    ASSERT_THAT(waitForCallbacks(3, 50ms + 3 * TEST_TIMEOUT), Eq(3));
    ASSERT_THAT(getExpiredCallbacks(), ElementsAre(3, 2, 1));
}

TEST_F(VibratorCallbackSchedulerTest, TestDestructorDropsPendingCallbacksAndKillsThread) {
    // Schedule callback long enough that scheduler will be destroyed while it's still scheduled.
    mScheduler->schedule(createCallback(1), 100ms);
    mScheduler.reset(nullptr);

    // Should timeout waiting for callback to run.
    ASSERT_THAT(waitForCallbacks(1, 100ms + TEST_TIMEOUT), Eq(0));
    ASSERT_THAT(getExpiredCallbacks(), IsEmpty());
}
